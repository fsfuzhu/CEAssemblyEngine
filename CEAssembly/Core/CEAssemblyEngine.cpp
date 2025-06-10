#include "CEAssemblyEngine.h"
#include "Utils/DebugHelper.h"
#include "CEScript.h"
#include "Symbol/SymbolManager.h"
#include "Scanner/PatternScanner.h"
#include "MemoryManager.h"
#include "Parser/CEScriptParser.h"
#include "asmjit/x86.h"
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

	// 处理特殊指令
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

	// 检查是否是跳转指令且包含符号
	if (op == "jmp" || op == "call" || op.find("j") == 0) {
		std::string operand;
		iss >> operand;

		// 检查操作数是否是符号（不是数字或寄存器）
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
			else {
				LOG_ERROR_F("Unknown symbol: %s", operand.c_str());
				return false;
			}
		}
	}

	// 替换符号后交给Keystone
	std::string processedLine = ReplaceSymbols(line);
	LOG_DEBUG_F("After symbol replacement: %s -> %s", line.c_str(), processedLine.c_str());

	// 对于简单指令，不需要检查未解析符号，直接尝试汇编
	if (op == "mov" || op == "add" || op == "sub" || op == "push" || op == "pop" ||
		op == "inc" || op == "dec" || op == "nop" || op == "lea" || op == "cmp" || op == "test") {
		LOG_DEBUG_F("Simple instruction, attempting direct assembly");
	}
	else {
		// 检查替换后是否还有未解析的符号
		if (ContainsUnresolvedSymbols(processedLine)) {
			LOG_DEBUG_F("Instruction contains unresolved symbols, delaying: %s", processedLine.c_str());
			return false; // 延迟处理
		}
	}

	unsigned char* encode;
	size_t size;
	size_t count;

	LOG_TRACE_F("Assembling @0x%llX : %s", m_currentAddress, processedLine.c_str());
	if (ks_asm(m_ksEngine, processedLine.c_str(), m_currentAddress, &encode, &size, &count) == KS_ERR_OK) {
		std::vector<uint8_t> machineCode(encode, encode + size);
		ks_free(encode);
		LOG_DEBUG_F("Assembly successful: %zu bytes", size);
		return WriteBytes(machineCode);
	}
	else {
		LOG_ERROR_F("Keystone error (%s) for line \"%s\"",
			ks_strerror(ks_errno(m_ksEngine)), processedLine.c_str());
		return false;
	}
}


bool CEAssemblyEngine::ContainsUnresolvedSymbols(const std::string& line) {
	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = line;

	LOG_TRACE_F("Checking unresolved symbols in: %s", line.c_str());

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		std::string lowerSymbol = symbol;
		std::transform(lowerSymbol.begin(), lowerSymbol.end(), lowerSymbol.begin(), ::tolower);

		LOG_TRACE_F("Found potential symbol: %s", symbol.c_str());

		// 【先判寄存器和指令，如果是，直接跳过】
		if (isX64RegisterName(lowerSymbol)) {
			LOG_TRACE_F("Symbol %s is a register/instruction", symbol.c_str());
			temp = match.suffix();
			continue;
		}

		// 再判符号表和捕获变量
		uintptr_t addr;
		uint64_t value;
		if (!m_symbolManager->GetSymbolAddress(symbol, addr) &&
			!m_symbolManager->GetCapturedValue(symbol, value)) {
			LOG_DEBUG_F("Unresolved symbol found: %s", symbol.c_str());
			return true;
		}
		else {
			LOG_TRACE_F("Symbol %s is resolved (user symbol or captured value)", symbol.c_str());
		}
		temp = match.suffix();
	}
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

	// 1. 替换 CE 格式的十六进制 $XX -> 0xXX
	std::regex dollarHexRegex(R"(\$([0-9A-Fa-f]+))");
	result = std::regex_replace(result, dollarHexRegex, "0x$1");

	// 2. 替换 #123 形式的立即数为十进制
	std::regex immediateRegex(R"(#(\d+))");
	result = std::regex_replace(result, immediateRegex, "$1");

	// 3. 检查是否是跳转指令，如果是则不替换操作数中的符号
	std::istringstream iss(result);
	std::string op;
	iss >> op;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp" || op == "call" || op.find("j") == 0) {
		std::string operand;
		iss >> operand;

		// 如果操作数是符号（字母开头），不进行替换
		if (!operand.empty() && std::isalpha(operand[0])) {
			LOG_TRACE_F("Symbol replacement output: %s (jump target preserved)", result.c_str());
			return result;
		}
	}

	// 4. 替换所有其他符号
	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = result;
	std::map<std::string, std::string> replacements;

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		std::string lowerSymbol = symbol;
		std::transform(lowerSymbol.begin(), lowerSymbol.end(), lowerSymbol.begin(), ::tolower);

		// 跳过寄存器和指令名
		//static const std::set<std::string> skipSymbols = {
		//	"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
		//	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		//	"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
		//	"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
		//	"ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
		//	"al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
		//	"mov", "add", "sub", "push", "pop", "call", "jmp","xor",
		//	"and", "or", "shl", "shr", "rol", "ror", "sar", "sal",
		//};

		if (isX64RegisterName(lowerSymbol)) {
			temp = match.suffix();
			continue;
		}

		// 检查是否是捕获的变量
		uint64_t capturedValue;
		if (m_symbolManager->GetCapturedValue(symbol, capturedValue)) {
			replacements[symbol] = std::to_string(capturedValue);
			LOG_DEBUG_F("Symbol '%s' -> captured value %llu", symbol.c_str(), capturedValue);
		}
		// 检查是否是地址符号
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

	// 应用所有替换
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