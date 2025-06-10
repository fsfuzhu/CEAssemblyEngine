#include "CEAssemblyEngine.h"
#include "Utils/DebugHelper.h"
#include "CEScript.h"
#include "Symbol/SymbolManager.h"
#include "Scanner/PatternScanner.h"
#include "MemoryManager.h"
#include "Parser/CEScriptParser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <set>      // 新增：用于ContainsUnresolvedSymbols
#include <map>      // 新增：用于ReplaceSymbols
#include <cctype>   // 新增：用于std::isalpha

bool isX64RegisterName(const std::string& token) {
	static const std::regex regPattern(
		R"(^(r(1[0-5]|[8-9]|[abcd]x|sp|bp|si|di)|e[a-d]x|e(si|di|bp|sp)|[abcd][hl]|[rs]i|[rs]p|rip|xmm\d+|ymm\d+|st\d+)$)",
		std::regex::icase);
	return std::regex_match(token, regPattern);
}

CEAssemblyEngine::CEAssemblyEngine()
	: m_memoryManager(std::make_unique<MemoryManager>())
	, m_patternScanner(std::make_unique<PatternScanner>())
	, m_symbolManager(std::make_unique<SymbolManager>())
	, m_parser(std::make_unique<CEScriptParser>())
	, m_ksEngine(nullptr)
	, m_currentAddress(0)
	, m_currentScript(nullptr) {

	LOG_INFO("CEAssemblyEngine constructor called");

	// 初始化 Keystone
	ks_err err = ks_open(KS_ARCH_X86, KS_MODE_64, &m_ksEngine);
	if (err != KS_ERR_OK) {
		LOG_ERROR_F("Failed to initialize Keystone engine: %s", ks_strerror(err));
	}
	else {
		LOG_INFO("Keystone engine initialized successfully (x64 mode)");
	}
}

CEAssemblyEngine::~CEAssemblyEngine() {
	LOG_INFO("CEAssemblyEngine destructor called");
	if (m_ksEngine) {
		ks_close(m_ksEngine);
		LOG_INFO("Keystone engine closed");
	}
}

bool CEAssemblyEngine::AttachToProcess(DWORD pid) {
	LOG_INFO_F("Attaching to process with PID: %d", pid);
	if (m_memoryManager->AttachToProcess(pid)) {
		m_patternScanner->SetProcessManager(m_memoryManager.get());
		return true;
	}

	m_lastError = "Failed to attach to process";
	return false;
}

bool CEAssemblyEngine::AttachToProcess(const std::string& processName) {
	LOG_INFO_F("Attempting to attach to process: %s", processName.c_str());

	DWORD pid = MemoryManager::FindProcessByName(processName);
	if (pid == 0) {
		LOG_ERROR_F("Process '%s' not found", processName.c_str());
		m_lastError = "Process not found: " + processName;
		return false;
	}

	LOG_INFO_F("Found process '%s' with PID: %d", processName.c_str(), pid);
	return AttachToProcess(pid);
}

void CEAssemblyEngine::DetachFromProcess() {
	m_memoryManager->DetachFromProcess();
	m_patternScanner->SetProcessManager(nullptr);
}

bool CEAssemblyEngine::IsAttached() const {
	return m_memoryManager->IsAttached();
}

DWORD CEAssemblyEngine::GetTargetPID() const {
	return m_memoryManager->GetPID();
}

std::shared_ptr<CEScript> CEAssemblyEngine::CreateScript(const std::string& name) {
	LOG_INFO_F("Creating new script: '%s'", name.empty() ? "<unnamed>" : name.c_str());
	auto script = std::make_shared<CEScript>(this);

	std::string scriptName = name;
	if (scriptName.empty()) {
		scriptName = "Script_" + std::to_string(m_scripts.size() + 1);
	}

	script->SetName(scriptName);
	m_scripts[scriptName] = script;
	LOG_DEBUG_F("Total scripts: %zu", m_scripts.size());
	return script;
}

std::shared_ptr<CEScript> CEAssemblyEngine::GetScript(const std::string& name) {
	auto it = m_scripts.find(name);
	if (it != m_scripts.end()) {
		return it->second;
	}
	return nullptr;
}
void CEAssemblyEngine::AddPatch(uintptr_t address,
	const std::vector<uint8_t>& originalBytes,
	const std::vector<uint8_t>& newBytes) {
	PatchInfo patch;
	patch.address = address;
	patch.originalBytes = originalBytes;
	patch.newBytes = newBytes;
	m_patches.push_back(patch);
}

bool CEAssemblyEngine::ProcessEnableBlock(const std::vector<std::string>& lines) {
	m_patches.clear();
	m_currentAddress = 0;

	// 第一遍：处理命令，建立符号表
	LOG_DEBUG("=== Pass 1: Processing commands ===");
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::AOBSCANMODULE:
			if (!ProcessAobScanModule(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::ALLOC:
			if (!ProcessAlloc(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::LABEL:
			if (!ProcessLabel(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		case CommandType::REGISTERSYMBOL:
			if (!ProcessRegisterSymbol(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
				return false;
			}
			break;

		default:
			break;
		}
	}

	// 第二遍：处理汇编指令和标签定义
	LOG_DEBUG("=== Pass 2: Processing assembly and labels ===");
	std::vector<DelayedInstruction> delayedInstructions;

	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		if (cmd.type == CommandType::ASSEMBLY) {
			if (!line.empty() && line.back() == ':') {
				// 标签定义
				std::string labelName = line.substr(0, line.length() - 1);
				uintptr_t addr = 0;

				if (m_symbolManager->GetSymbolAddress(labelName, addr) && addr != 0) {
					// 已有地址的标签（如INJECT、newmem）
					m_currentAddress = addr;
					LOG_DEBUG_F("Label %s: current address = 0x%llX", labelName.c_str(), addr);
				}
				else {
					// 新标签，使用当前地址
					if (m_currentAddress != 0) {
						m_symbolManager->RegisterSymbol(labelName, m_currentAddress);
						LOG_DEBUG_F("Label %s: registered at 0x%llX", labelName.c_str(), m_currentAddress);
					}
					else {
						LOG_ERROR_F("Label %s has no context address", labelName.c_str());
						m_lastError = "Label has no context address: " + labelName;
						return false;
					}
				}
			}
			else {
				// 汇编指令
				uintptr_t instructionAddress = m_currentAddress;
				if (!ProcessAssemblyInstruction(line)) {
					// 处理失败，添加到延迟列表
					DelayedInstruction delayed;
					delayed.instruction = line;
					delayed.address = instructionAddress;
					delayedInstructions.push_back(delayed);
					LOG_DEBUG_F("Delaying instruction at 0x%llX: %s", instructionAddress, line.c_str());

					// 预估指令长度，更新当前地址
					std::istringstream iss(line);
					std::string op;
					iss >> op;
					std::transform(op.begin(), op.end(), op.begin(), ::tolower);

					if (op == "jmp" || op == "call") {
						m_currentAddress += 5; // 预估E9跳转5字节
					}
					else {
						m_currentAddress += 4; // 其他指令平均4字节
					}
				}
			}
		}
	}

	// 第三遍：处理延迟的指令（现在所有符号都应该已定义）
	LOG_DEBUG("=== Pass 3: Processing delayed instructions ===");
	for (const auto& delayed : delayedInstructions) {
		uintptr_t savedAddress = m_currentAddress;
		m_currentAddress = delayed.address;

		if (!ProcessAssemblyInstruction(delayed.instruction)) {
			LOG_ERROR_F("Failed to process delayed instruction at 0x%llX: %s",
				delayed.address, delayed.instruction.c_str());
			m_lastError = "Failed to process delayed instruction: " + delayed.instruction;
			return false;
		}

		m_currentAddress = savedAddress;
	}

	LOG_DEBUG("=== Enable block processing completed ===");
	return true;
}

bool CEAssemblyEngine::ProcessAssemblyInstruction(const std::string& line) {
	// Validate current address
	if (m_currentAddress == 0) {
		LOG_ERROR("Cannot process instruction without current address");
		m_lastError = "No current address set";
		return false;
	}

	LOG_DEBUG_F("Processing instruction: %s", line.c_str());

	// Extract opcode for special handling
	std::string opcode;
	std::istringstream lineStream(line);
	lineStream >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// Special handling for NOP instruction
	if (opcode == "nop") {
		int nopCount = 1;

		// Try to read count parameter
		std::string countStr;
		if (lineStream >> countStr) {
			try {
				nopCount = std::stoi(countStr);
			}
			catch (...) {
				nopCount = 1;
			}
		}

		// Generate NOP bytes
		std::vector<uint8_t> nopBytes(nopCount, 0x90);
		LOG_DEBUG_F("Generating %d NOP byte(s)", nopCount);

		return WriteBytes(nopBytes);
	}

	// Always perform symbol replacement first
	// This ensures all numbers are converted to hex format
	std::string processedLine = ReplaceSymbols(line);

	// Log transformation if changed
	if (processedLine != line) {
		LOG_DEBUG_F("Symbol replacement: %s -> %s", line.c_str(), processedLine.c_str());
	}

	// Prepare for assembly
	unsigned char* machineCode = nullptr;
	size_t codeSize = 0;
	size_t statements = 0;

	// Assemble the processed instruction
	LOG_TRACE_F("Assembling at 0x%llX: %s", m_currentAddress, processedLine.c_str());

	int asmResult = ks_asm(m_ksEngine,
		processedLine.c_str(),
		m_currentAddress,
		&machineCode,
		&codeSize,
		&statements);

	// Handle assembly result
	if (asmResult == KS_ERR_OK) {
		if (codeSize > 0) {
			// Success with generated code
			std::vector<uint8_t> bytes(machineCode, machineCode + codeSize);
			ks_free(machineCode);

			LOG_DEBUG_F("Assembly successful: %zu bytes", codeSize);
			return WriteBytes(bytes);
		}
		else {
			// Success but no code (label or directive)
			LOG_DEBUG("No machine code generated (label/directive)");
			return true;
		}
	}

	// Assembly failed
	ks_err error = ks_errno(m_ksEngine);
	LOG_DEBUG_F("Assembly failed: %s", ks_strerror(error));

	// Check if it's a jump instruction with unresolved symbol
	std::istringstream processedStream(processedLine);
	std::string processedOp;
	processedStream >> processedOp;
	std::transform(processedOp.begin(), processedOp.end(), processedOp.begin(), ::tolower);

	// Handle jump/call instructions
	if (processedOp == "jmp" || processedOp == "call" ||
		(processedOp.size() > 0 && processedOp[0] == 'j')) {

		std::string target;
		processedStream >> target;

		// Check if target is a symbol
		if (!target.empty() && (std::isalpha(target[0]) || target[0] == '_')) {
			uintptr_t targetAddr = 0;

			if (m_symbolManager->GetSymbolAddress(target, targetAddr)) {
				if (targetAddr != 0) {
					// Generate jump instruction
					LOG_DEBUG_F("Generating jump to %s (0x%llX)", target.c_str(), targetAddr);
					return ProcessJumpInstruction(processedOp, targetAddr);
				}
				else {
					// Forward reference
					LOG_DEBUG_F("Forward reference: %s", target.c_str());
					return false;
				}
			}
		}
	}

	// Final error
	LOG_ERROR_F("Failed to assemble: %s", processedLine.c_str());
	m_lastError = std::string("Assembly error: ") + ks_strerror(error);
	return false;
}


bool CEAssemblyEngine::ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr) {
	std::string op = opcode;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp") {
		// 计算相对偏移
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// E9相对跳转
			std::vector<uint8_t> jumpBytes = {
				0xE9,
				static_cast<uint8_t>(offset & 0xFF),
				static_cast<uint8_t>((offset >> 8) & 0xFF),
				static_cast<uint8_t>((offset >> 16) & 0xFF),
				static_cast<uint8_t>((offset >> 24) & 0xFF)
			};

			LOG_DEBUG_F("Generated E9 jump from 0x%llX to 0x%llX (offset: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
		else {
			// 距离太远，使用FF25绝对跳转
			// FF 25 00 00 00 00 [8字节目标地址]
			std::vector<uint8_t> jumpBytes = {
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // FF 25 00000000 (jmp [rip+0])
			};

			// 添加8字节目标地址
			for (int i = 0; i < 8; ++i) {
				jumpBytes.push_back((targetAddr >> (i * 8)) & 0xFF);
			}

			LOG_DEBUG_F("Generated FF25 absolute jump from 0x%llX to 0x%llX (distance: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
	}
	else if (op == "call") {
		// call指令
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			std::vector<uint8_t> callBytes = {
				0xE8,
				static_cast<uint8_t>(offset & 0xFF),
				static_cast<uint8_t>((offset >> 8) & 0xFF),
				static_cast<uint8_t>((offset >> 16) & 0xFF),
				static_cast<uint8_t>((offset >> 24) & 0xFF)
			};

			return WriteBytes(callBytes);
		}
		else {
			// call的远程调用可以使用其他方法
			LOG_ERROR_F("Call distance too far: %lld", offset);
			return false;
		}
	}

	return false;
}

bool CEAssemblyEngine::WriteBytes(const std::vector<uint8_t>& bytes) {
	if (bytes.empty() || m_currentAddress == 0) return false;

	// 保存原始字节
	std::vector<uint8_t> originalBytes(bytes.size());
	m_memoryManager->ReadMemory(m_currentAddress, originalBytes.data(), bytes.size());

	// 写入新字节
	DWORD oldProtect;
	if (m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(),
		PAGE_EXECUTE_READWRITE, &oldProtect)) {
		bool success = m_memoryManager->WriteMemory(m_currentAddress, bytes.data(), bytes.size());
		m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(), oldProtect, &oldProtect);

		if (success) {
			// 记录补丁
			AddPatch(m_currentAddress, originalBytes, bytes);
			LOG_TRACE_F("Wrote %zu bytes at 0x%llX", bytes.size(), m_currentAddress);

			// 更新当前地址
			m_currentAddress += bytes.size();
			return true;
		}
	}

	return false;
}

bool CEAssemblyEngine::ProcessAobScanModule(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 3) {
		m_lastError = "Invalid aobscanmodule syntax";
		return false;
	}

	std::string symbolName = cmd.parameters[0];
	std::string moduleName = cmd.parameters[1];

	std::string pattern;
	for (size_t i = 2; i < cmd.parameters.size(); ++i) {
		if (!pattern.empty()) pattern += " ";
		pattern += cmd.parameters[i];
	}

	uintptr_t address = m_patternScanner->ScanModule(moduleName, pattern);
	if (address == 0) {
		m_lastError = "Pattern not found";
		return false;
	}

	m_symbolManager->RegisterSymbol(symbolName, address);
	LOG_INFO_F("Symbol '%s' registered at 0x%llX", symbolName.c_str(), address);

	auto capturedVars = m_patternScanner->GetCapturedVariables();
	for (const auto& [name, data] : capturedVars) {
		m_symbolManager->RegisterCapturedData(name, data);
	}
	m_patternScanner->ClearCapturedVariables();

	return true;
}
bool CEAssemblyEngine::ProcessAlloc(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 2) {
		m_lastError = "Invalid alloc syntax";
		return false;
	}

	std::string allocName = cmd.parameters[0];

	size_t size = 0;
	std::string sizeStr = cmd.parameters[1];
	if (sizeStr[0] == '$') {
		size = std::stoull(sizeStr.substr(1), nullptr, 16);
	}
	else {
		size = std::stoull(sizeStr, nullptr, 10);
	}

	// 获取附近地址
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	uintptr_t allocAddr = 0;

	if (nearAddress != 0) {
		// 策略1: 优先在附近地址申请，检查是否在E9范围内
		allocAddr = m_memoryManager->AllocateNear(nearAddress, size, allocName);

		if (allocAddr != 0) {
			// 检查距离是否在E9范围内 (±2GB)
			int64_t distance = static_cast<int64_t>(allocAddr) - static_cast<int64_t>(nearAddress);
			if (distance >= -0x80000000LL && distance <= 0x7FFFFFFFLL) {
				LOG_INFO_F("Memory allocated near: %s at 0x%llX (distance from 0x%llX: %lld bytes, E9 compatible)",
					allocName.c_str(), allocAddr, nearAddress, distance);
			}
			else {
				LOG_INFO_F("Memory allocated far: %s at 0x%llX (distance from 0x%llX: %lld bytes, needs FF25)",
					allocName.c_str(), allocAddr, nearAddress, distance);

				// 距离太远，释放并尝试申请低位地址
				m_memoryManager->Deallocate(allocName);

				// 策略2: 申请低位地址，使用FF25跳转
				allocAddr = m_memoryManager->AllocateNear(0x10000000, size, allocName);
				if (allocAddr != 0) {
					LOG_INFO_F("Memory allocated low: %s at 0x%llX (will use FF25 jump)",
						allocName.c_str(), allocAddr);
				}
			}
		}
	}
	else {
		// 没有附近地址，直接申请低位地址
		allocAddr = m_memoryManager->AllocateNear(0x10000000, size, allocName);
		LOG_INFO_F("Memory allocated: %s at 0x%llX (no near address specified)",
			allocName.c_str(), allocAddr);
	}

	if (allocAddr == 0) {
		m_lastError = "Failed to allocate memory";
		return false;
	}

	m_symbolManager->RegisterSymbol(allocName, allocAddr, size);
	return true;
}

bool CEAssemblyEngine::ProcessLabel(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid label syntax";
		return false;
	}

	std::string labelName = cmd.parameters[0];
	m_symbolManager->RegisterSymbol(labelName, 0, 0, true);
	LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
	return true;
}

bool CEAssemblyEngine::ProcessRegisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid registersymbol syntax";
		return false;
	}
	// 这里可以实现全局符号注册逻辑
	return true;
}
std::string CEAssemblyEngine::ReplaceSymbols(const std::string& line) {
	LOG_TRACE_F("Symbol replacement input: %s", line.c_str());

	// Tokenizer state
	enum TokenType {
		TK_WHITESPACE,
		TK_OPCODE,
		TK_REGISTER,
		TK_NUMBER,
		TK_SYMBOL,
		TK_OPERATOR,
		TK_PUNCTUATION,
		TK_UNKNOWN
	};

	struct Token {
		TokenType type;
		std::string text;
	};

	std::vector<Token> tokens;
	size_t i = 0;

	// Tokenization phase
	while (i < line.length()) {
		Token token;

		// Whitespace
		if (std::isspace(line[i])) {
			token.type = TK_WHITESPACE;
			while (i < line.length() && std::isspace(line[i])) {
				token.text += line[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Punctuation
		if (line[i] == ',' || line[i] == '[' || line[i] == ']' ||
			line[i] == '(' || line[i] == ')' || line[i] == ':') {
			token.type = TK_PUNCTUATION;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		// Operators
		if (line[i] == '+' || line[i] == '-' || line[i] == '*') {
			token.type = TK_OPERATOR;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		// $ prefix (CE hex notation)
		if (line[i] == '$') {
			i++; // Skip $
			token.type = TK_NUMBER;
			std::string hexNum;
			while (i < line.length() && std::isxdigit(line[i])) {
				hexNum += line[i++];
			}
			token.text = "0x" + hexNum;
			tokens.push_back(token);
			LOG_TRACE_F("CE hex: $%s -> %s", hexNum.c_str(), token.text.c_str());
			continue;
		}

		// # prefix (immediate value)
		if (line[i] == '#') {
			i++; // Skip #
			token.type = TK_NUMBER;
			std::string num;
			while (i < line.length() && std::isdigit(line[i])) {
				num += line[i++];
			}
			// Keep as decimal
			token.text = num;
			tokens.push_back(token);
			LOG_TRACE_F("Immediate: #%s -> %s", num.c_str(), token.text.c_str());
			continue;
		}

		// 0x prefix
		if (i + 2 <= line.length() && line[i] == '0' &&
			(line[i + 1] == 'x' || line[i + 1] == 'X')) {
			token.type = TK_NUMBER;
			token.text = "0x";
			i += 2;
			while (i < line.length() && std::isxdigit(line[i])) {
				token.text += line[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Alphanumeric sequence
		if (std::isalnum(line[i]) || line[i] == '_') {
			std::string word;
			size_t start = i;

			while (i < line.length() && (std::isalnum(line[i]) || line[i] == '_')) {
				word += line[i++];
			}

			// Determine type
			std::string lowerWord = word;
			std::transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), ::tolower);

			// First token is usually opcode
			if (tokens.empty() || (tokens.size() > 0 &&
				tokens.back().type == TK_PUNCTUATION && tokens.back().text == ":")) {
				token.type = TK_OPCODE;
			}
			// Check if register
			else if (isX64RegisterName(lowerWord)) {
				token.type = TK_REGISTER;
			}
			// Check if pure number
			else if (std::all_of(word.begin(), word.end(),
				[](char c) { return std::isxdigit(c); })) {
				token.type = TK_NUMBER;
				// Add 0x prefix to all numbers
				token.text = "0x" + word;
				LOG_TRACE_F("Auto-hex: %s -> %s", word.c_str(), token.text.c_str());
				tokens.push_back(token);
				continue;
			}
			// Otherwise it's a symbol
			else {
				token.type = TK_SYMBOL;
			}

			token.text = word;
			tokens.push_back(token);
			continue;
		}

		// Unknown character
		token.type = TK_UNKNOWN;
		token.text = line[i++];
		tokens.push_back(token);
	}

	// Build result
	std::string result;

	for (size_t idx = 0; idx < tokens.size(); idx++) {
		const Token& tok = tokens[idx];

		if (tok.type == TK_SYMBOL) {
			// Check if it's a jump target
			bool isJumpTarget = false;

			// Look backward for opcode
			for (int j = idx - 1; j >= 0; j--) {
				if (tokens[j].type == TK_OPCODE) {
					std::string op = tokens[j].text;
					std::transform(op.begin(), op.end(), op.begin(), ::tolower);
					if (op == "jmp" || op == "call" ||
						(op.length() > 0 && op[0] == 'j')) {
						isJumpTarget = true;
					}
					break;
				}
				else if (tokens[j].type != TK_WHITESPACE) {
					break;
				}
			}

			if (!isJumpTarget) {
				// Try to resolve symbol
				uint64_t capturedVal;
				uintptr_t symbolAddr;

				if (m_symbolManager->GetCapturedValue(tok.text, capturedVal)) {
					result += std::to_string(capturedVal);
					LOG_DEBUG_F("Symbol %s -> captured %llu", tok.text.c_str(), capturedVal);
				}
				else if (m_symbolManager->GetSymbolAddress(tok.text, symbolAddr) &&
					symbolAddr != 0) {
					std::stringstream ss;
					ss << "0x" << std::hex << symbolAddr;
					result += ss.str();
					LOG_DEBUG_F("Symbol %s -> 0x%llX", tok.text.c_str(), symbolAddr);
				}
				else {
					result += tok.text;
				}
			}
			else {
				result += tok.text;
			}
		}
		else {
			result += tok.text;
		}
	}

	LOG_TRACE_F("Symbol replacement output: %s", result.c_str());
	return result;
}

bool CEAssemblyEngine::ProcessDisableBlock(const std::vector<std::string>& lines) {
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::DB:
			ProcessDbCommand(line);
			break;

		case CommandType::UNREGISTERSYMBOL:
			ProcessUnregisterSymbol(line);
			break;

		case CommandType::DEALLOC:
			ProcessDealloc(line);
			break;

		default:
			break;
		}
	}

	return true;
}

bool CEAssemblyEngine::ProcessDbCommand(const std::string& line) {
	// 从补丁信息中恢复原始字节
	for (const auto& patch : m_patches) {
		if (patch.address == m_currentAddress) {
			DWORD oldProtect;
			if (m_memoryManager->ProtectMemory(patch.address, patch.originalBytes.size(),
				PAGE_EXECUTE_READWRITE, &oldProtect)) {
				m_memoryManager->WriteMemory(patch.address, patch.originalBytes.data(),
					patch.originalBytes.size());
				m_memoryManager->ProtectMemory(patch.address, patch.originalBytes.size(),
					oldProtect, &oldProtect);
				return true;
			}
		}
	}
	return false;
}

bool CEAssemblyEngine::ProcessAssemblyBatch(const std::vector<std::string>& instructions, uintptr_t startAddress) {
	m_currentAddress = startAddress;

	// 尝试批量汇编所有指令
	std::string batchAssembly;
	for (const auto& line : instructions) {
		if (!batchAssembly.empty()) {
			batchAssembly += "\n";
		}
		batchAssembly += ReplaceSymbols(line);
	}

	LOG_DEBUG_F("Batch assembly at 0x%llX (%zu instructions):", startAddress, instructions.size());
	LOG_DEBUG_F("Batch content:\n%s", batchAssembly.c_str());

	unsigned char* encode;
	size_t size;
	size_t count;

	if (ks_asm(m_ksEngine, batchAssembly.c_str(), startAddress, &encode, &size, &count) == KS_ERR_OK) {
		std::vector<uint8_t> machineCode(encode, encode + size);
		ks_free(encode);

		bool success = WriteBytes(machineCode);
		LOG_DEBUG_F("Batch assembly result: %zu bytes, success=%d", size, success);
		return success;
	}
	else {
		// 批量失败，尝试逐条处理
		LOG_WARN_F("Batch assembly failed (%s), trying individual instructions",
			ks_strerror(ks_errno(m_ksEngine)));

		m_currentAddress = startAddress;
		for (const auto& line : instructions) {
			if (!ProcessAssemblyInstruction(line)) {
				return false;
			}
		}
		return true;
	}
}

bool CEAssemblyEngine::ProcessUnregisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid unregistersymbol syntax";
		return false;
	}

	m_symbolManager->UnregisterSymbol(cmd.parameters[0]);
	return true;
}

bool CEAssemblyEngine::ProcessDealloc(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid dealloc syntax";
		return false;
	}

	return m_memoryManager->Deallocate(cmd.parameters[0]);
}