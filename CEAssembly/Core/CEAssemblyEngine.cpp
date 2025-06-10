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
	if (m_currentAddress == 0) {
		LOG_ERROR("Cannot process instruction without current address");
		return false;
	}

	LOG_DEBUG_F("Processing instruction: %s", line.c_str());

	// 处理特殊的 nop 指令（支持 nop 3 这种语法）
	std::istringstream iss(line);
	std::string op;
	iss >> op;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "nop") {
		int count = 1;
		if (!(iss >> count)) count = 1;

		std::vector<uint8_t> nopBytes;
		for (int i = 0; i < count; ++i) {
			nopBytes.push_back(0x90);
		}

		return WriteBytes(nopBytes);
	}

	// 第一步：直接尝试让 Keystone 汇编原始行
	unsigned char* encode = nullptr;
	size_t size = 0;
	size_t count = 0;

	LOG_TRACE_F("First attempt: assembling @0x%llX : %s", m_currentAddress, line.c_str());
	int err = ks_asm(m_ksEngine, line.c_str(), m_currentAddress, &encode, &size, &count);

	if (err == KS_ERR_OK && size > 0) {
		// Keystone 成功汇编，说明这是有效的汇编指令
		std::vector<uint8_t> machineCode(encode, encode + size);
		ks_free(encode);
		LOG_DEBUG_F("Direct assembly successful: %zu bytes", size);
		return WriteBytes(machineCode);
	}
	else if (err == KS_ERR_OK && size == 0) {
		// Keystone 返回成功但没有生成代码，可能是标签
		LOG_DEBUG_F("Keystone returned empty result, likely a label: %s", line.c_str());
		return true;  // 标签不生成代码，但是成功的
	}

	// Keystone 失败了，检查错误类型
	ks_err ks_error = ks_errno(m_ksEngine);
	LOG_DEBUG_F("Keystone failed with error: %s", ks_strerror(ks_error));

	// 第二步：如果失败可能是因为包含我们的符号，尝试替换符号
	std::string processedLine = ReplaceSymbols(line);

	if (processedLine != line) {
		// 符号被替换了，再次尝试汇编
		LOG_DEBUG_F("After symbol replacement: %s -> %s", line.c_str(), processedLine.c_str());

		err = ks_asm(m_ksEngine, processedLine.c_str(), m_currentAddress, &encode, &size, &count);
		if (err == KS_ERR_OK && size > 0) {
			std::vector<uint8_t> machineCode(encode, encode + size);
			ks_free(encode);
			LOG_DEBUG_F("Assembly after symbol replacement successful: %zu bytes", size);
			return WriteBytes(machineCode);
		}
	}

	// 第三步：特殊处理跳转指令
	if (op == "jmp" || op == "call" || op.find("j") == 0) {
		std::string operand;
		iss.str(line);  // 重置流
		iss.clear();
		iss >> op >> operand;

		// 检查操作数是否可能是符号
		if (!operand.empty() && std::isalpha(operand[0])) {
			uintptr_t targetAddr;
			if (m_symbolManager->GetSymbolAddress(operand, targetAddr)) {
				if (targetAddr != 0) {
					// 符号已解析，自己生成跳转指令
					LOG_DEBUG_F("Jump to resolved symbol: %s -> 0x%llX", operand.c_str(), targetAddr);
					return ProcessJumpInstruction(op, targetAddr);
				}
				else {
					// 前向引用，延迟处理
					LOG_DEBUG_F("Forward reference detected: %s %s", op.c_str(), operand.c_str());
					return false;
				}
			}
		}
	}

	// 如果还是失败，可能真的是错误
	LOG_ERROR_F("Failed to assemble instruction: %s (Keystone error: %s)",
		line.c_str(), ks_strerror(ks_errno(m_ksEngine)));
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
	std::string result = line;

	LOG_TRACE_F("Symbol replacement input: %s", line.c_str());

	std::regex dollarHexRegex(R"(\$([0-9A-Fa-f]+))");
	result = std::regex_replace(result, dollarHexRegex, "0x$1");

	std::regex immediateRegex(R"(#(\d+))");
	result = std::regex_replace(result, immediateRegex, "$1");

	std::istringstream iss(result);
	std::string op;
	iss >> op;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp" || op == "call" || op.find("j") == 0) {
		std::string operand;
		iss >> operand;

		if (!operand.empty() && std::isalpha(operand[0])) {
			LOG_TRACE_F("Symbol replacement output: %s (jump target preserved)", result.c_str());
			return result;
		}
	}

	std::regex numberRegex(R"(\b([0-9A-Fa-f]+)\b)");
	std::smatch numberMatch;
	std::string tempResult = result;
	result = "";

	while (std::regex_search(tempResult, numberMatch, numberRegex)) {
		result += numberMatch.prefix();

		std::string numStr = numberMatch[1];
		std::string context = numberMatch.prefix().str();

		std::string prevToken;
		std::istringstream contextStream(context);
		std::string token;
		while (contextStream >> token) {
			prevToken = token;
		}
		std::transform(prevToken.begin(), prevToken.end(), prevToken.begin(), ::tolower);

		bool isControlFlow = false;
		if (context.length() > 0) {
			char lastChar = context[context.length() - 1];
			isControlFlow = (lastChar == '+' || lastChar == '-' || lastChar == '*' || lastChar == '[');
		}

		bool isRegister = isX64RegisterName(numStr) ||
			(numStr.length() <= 2 && prevToken == "r") ||
			(prevToken.length() >= 1 && prevToken[0] == 'r' && std::all_of(prevToken.begin() + 1, prevToken.end(), ::isdigit));
		bool hasHexFormat = (numStr.find("0x") == 0) || (numStr.find("0X") == 0) ||
			(context.find("0x" + numStr) != std::string::npos) ||
			(context.find("0X" + numStr) != std::string::npos);

		bool hasHexLetters = std::any_of(numStr.begin(), numStr.end(),
			[](char c) { return (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'); });

		if (!isRegister && !isControlFlow && !hasHexFormat) {
			result += "0x" + numStr;
			LOG_TRACE_F("Added 0x prefix to: %s -> 0x%s", numStr.c_str(), numStr.c_str());
		}
		else {
			result += numStr;
		}

		tempResult = numberMatch.suffix();
	}
	result += tempResult;

	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = result;
	std::map<std::string, std::string> replacements;

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		std::string lowerSymbol = symbol;
		std::transform(lowerSymbol.begin(), lowerSymbol.end(), lowerSymbol.begin(), ::tolower);

		if (isX64RegisterName(lowerSymbol)) {
			temp = match.suffix();
			continue;
		}

		uint64_t capturedValue;
		if (m_symbolManager->GetCapturedValue(symbol, capturedValue)) {
			replacements[symbol] = std::to_string(capturedValue);
			LOG_DEBUG_F("Symbol '%s' -> captured value %llu", symbol.c_str(), capturedValue);
		}
		else {
			uintptr_t symbolAddr;
			if (m_symbolManager->GetSymbolAddress(symbol, symbolAddr) && symbolAddr != 0) {
				std::stringstream ss;
				ss << "0x" << std::hex << symbolAddr;
				replacements[symbol] = ss.str();
				LOG_DEBUG_F("Symbol '%s' -> address 0x%llX", symbol.c_str(), symbolAddr);
			}
		}

		temp = match.suffix();
	}

	for (const auto& [symbol, replacement] : replacements) {
		std::regex symbolPattern("\\b" + symbol + "\\b");
		result = std::regex_replace(result, symbolPattern, replacement);
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