// CEAssemblyEngine.cpp
#include "CEAssemblyEngine.h"
#include "PassManager.h"
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
#include <set>
#include <map>
#include <cctype>
#include <unordered_set>

// 构造函数和析构函数
CEAssemblyEngine::CEAssemblyEngine()
	: m_memoryManager(std::make_unique<MemoryManager>())
	, m_patternScanner(std::make_unique<PatternScanner>())
	, m_symbolManager(std::make_unique<SymbolManager>())
	, m_parser(std::make_unique<CEScriptParser>())
	, m_passManager(std::make_unique<PassManager>())  // 初始化 PassManager
	, m_ksEngine(nullptr)
	, m_currentAddress(0)
	, m_currentScript(nullptr) {

	LOG_INFO("CEAssemblyEngine constructor called");

	// Initialize Keystone
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

// 进程管理
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

// 脚本管理
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

// 补丁管理
void CEAssemblyEngine::AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes,
	const std::vector<uint8_t>& newBytes) {
	PatchInfo patch;
	patch.address = address;
	patch.originalBytes = originalBytes;
	patch.newBytes = newBytes;
	m_patches.push_back(patch);
}
void CEAssemblyEngine::RestoreAllPatches(const std::vector<PatchInfo>& patches) {
	LOG_INFO_F("Restoring %zu patches", patches.size());

	for (const auto& patch : patches) {
		LOG_DEBUG_F("Restoring patch at 0x%llX (%zu bytes)",
			patch.address, patch.originalBytes.size());

		// 修改内存保护
		DWORD oldProtect;
		if (m_memoryManager->ProtectMemory(patch.address,
			patch.originalBytes.size(),
			PAGE_EXECUTE_READWRITE,
			&oldProtect)) {

			// 写回原始字节
			bool success = m_memoryManager->WriteMemory(patch.address,
				patch.originalBytes.data(),
				patch.originalBytes.size());

			// 恢复内存保护
			m_memoryManager->ProtectMemory(patch.address,
				patch.originalBytes.size(),
				oldProtect,
				&oldProtect);

			if (success) {
				LOG_DEBUG_F("Successfully restored patch at 0x%llX", patch.address);
			}
			else {
				LOG_ERROR_F("Failed to restore patch at 0x%llX", patch.address);
			}
		}
		else {
			LOG_ERROR_F("Failed to change protection at 0x%llX", patch.address);
		}
	}
}

// 主要处理函数
bool CEAssemblyEngine::ProcessEnableBlock(const std::vector<std::string>& lines) {
	LOG_INFO("Processing ENABLE block with PassManager");

	// 清理之前的状态
	m_patches.clear();
	m_currentAddress = 0;
	m_anonymousLabels.clear();
	m_allLabels.clear();

	// 使用 PassManager 执行多遍处理
	if (!m_passManager->RunAllPasses(lines, this)) {
		m_lastError = m_passManager->GetLastError();
		LOG_ERROR_F("PassManager failed: %s", m_lastError.c_str());
		return false;
	}

	LOG_INFO("ENABLE block processed successfully");
	return true;
}
bool CEAssemblyEngine::ProcessDisableBlock(const std::vector<std::string>& lines) {
	LOG_INFO("Processing DISABLE block");

	for (const auto& line : lines) {
		LOG_DEBUG_F("Processing DISABLE line: %s", line.c_str());

		// 检查是否是 "label: db ..." 格式
		if (line.find(':') != std::string::npos && line.find("db") != std::string::npos) {
			// 这是一个合并的db命令
			if (!ProcessDbCommand(line)) {
				LOG_ERROR_F("Failed to process db command: %s", line.c_str());
			}
			continue;
		}

		// 正常的命令解析
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::DB:
			ProcessDbCommand(line);
			break;

		case CommandType::UNREGISTERSYMBOL:
			ProcessUnregisterSymbol(line);
			break;

		case CommandType::DEALLOC:
			if (!ProcessDealloc(line)) {
				LOG_ERROR_F("Failed to process dealloc: %s", line.c_str());
			}
			break;

		case CommandType::ASSEMBLY:
			// 可能是标签行，检查是否有db
			if (line.find("db") != std::string::npos) {
				ProcessDbCommand(line);
			}
			break;

		default:
			break;
		}
	}

	return true;
}

// CE数字处理（新增）
std::string CEAssemblyEngine::ProcessCENumbers(const std::string& line) {
	std::string result;
	size_t i = 0;

	while (i < line.length()) {
		// 跳过并保留字符串引号内的内容
		if (line[i] == '"' || line[i] == '\'') {
			char quote = line[i];
			result += line[i++];
			while (i < line.length() && line[i] != quote) {
				result += line[i++];
			}
			if (i < line.length()) result += line[i++];
			continue;
		}

		// 检查是否是数字的开始
		if ((std::isdigit(line[i]) || line[i] == '#' || line[i] == '$') &&
			(i == 0 || !std::isalnum(line[i - 1]) && line[i - 1] != '_')) {

			std::string number;
			bool hasPrefix = false;

			// 处理前缀
			if (line[i] == '#') {
				// 十进制前缀，跳过它
				i++;
				hasPrefix = true;
				// 收集数字
				while (i < line.length() && std::isdigit(line[i])) {
					number += line[i++];
				}
				// 直接添加数字（不加0x，让Keystone当作十进制）
				result += number;
			}
			else if (line[i] == '$') {
				// CE十六进制前缀，替换为0x
				i++;
				hasPrefix = true;
				result += "0x";
				// 收集十六进制数字
				while (i < line.length() && std::isxdigit(line[i])) {
					number += line[i++];
				}
				result += number;
			}
			else if (i + 2 <= line.length() && line[i] == '0' &&
				(line[i + 1] == 'x' || line[i + 1] == 'X')) {
				// 已经有0x前缀，保持原样
				result += line[i++]; // 0
				result += line[i++]; // x
				while (i < line.length() && std::isxdigit(line[i])) {
					result += line[i++];
				}
			}
			else {
				// 无前缀的数字，需要判断上下文
				size_t numStart = i;

				// 收集数字
				while (i < line.length() && std::isxdigit(line[i])) {
					number += line[i++];
				}

				// 检查是否应该被当作十六进制
				bool shouldBeHex = true;

				// 特殊情况：如果后面紧跟着某些单位或特定上下文，可能是十进制
				// 例如：循环计数 "nop 5" 中的 5 应该是十进制
				if (i < line.length() && std::isalpha(line[i])) {
					// 如果数字后面紧跟字母，可能是标识符的一部分
					shouldBeHex = false;
					result += number;
				}
				else {
					// 检查特定指令上下文
					size_t prevSpace = line.rfind(' ', numStart - 1);
					if (prevSpace != std::string::npos) {
						std::string prevToken = line.substr(prevSpace + 1, numStart - prevSpace - 1);
						std::transform(prevToken.begin(), prevToken.end(), prevToken.begin(), ::tolower);

						// nop 指令的参数是十进制
						if (prevToken == "nop") {
							shouldBeHex = false;
						}
					}

					if (shouldBeHex) {
						// 检查是否全是数字（0-9）或包含十六进制字符（A-F）
						bool hasHexChars = false;
						for (char c : number) {
							if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
								hasHexChars = true;
								break;
							}
						}

						// 只有当确定是十六进制时才添加0x
						if (hasHexChars || IsInHexContext(line, numStart)) {
							result += "0x" + number;
						}
						else {
							// 可能是十进制，让后续处理决定
							result += "0x" + number;  // CE默认行为
						}
					}
					else {
						result += number;
					}
				}
			}
		}
		else {
			// 非数字字符，直接复制
			result += line[i++];
		}
	}

	return result;
}
bool CEAssemblyEngine::IsInHexContext(const std::string& line, size_t pos) {
	// 检查是否在方括号内（内存地址）
	size_t lastOpenBracket = line.rfind('[', pos);
	size_t lastCloseBracket = line.rfind(']', pos);

	if (lastOpenBracket != std::string::npos &&
		(lastCloseBracket == std::string::npos || lastOpenBracket > lastCloseBracket)) {
		return true;  // 在方括号内，应该是十六进制
	}

	// 检查是否在某些特定指令的参数位置
	size_t instrStart = line.rfind('\n', pos);
	if (instrStart == std::string::npos) instrStart = 0;
	else instrStart++;

	std::string instr = line.substr(instrStart, pos - instrStart);
	std::transform(instr.begin(), instr.end(), instr.begin(), ::tolower);

	// 这些指令的立即数通常是十六进制地址
	if (instr.find("jmp") != std::string::npos ||
		instr.find("call") != std::string::npos ||
		instr.find("lea") != std::string::npos) {
		return true;
	}

	return true;  // 默认CE行为：无前缀数字是十六进制
}

// 符号处理
std::string CEAssemblyEngine::ReplaceSymbolsForEstimation(const std::string& line) {
	// This function is similar to ReplaceSymbols but uses placeholder addresses for unknown symbols
	LOG_TRACE_F("Symbol replacement for estimation input: %s", line.c_str());

	// Process float conversions first
	std::string processedLine = line;
	size_t floatPos = processedLine.find("(float)");
	if (floatPos != std::string::npos) {
		// Extract value after (float)
		size_t valueStart = floatPos + 7; // length of "(float)"
		size_t valueEnd = valueStart;

		// Find end of value
		while (valueEnd < processedLine.length() &&
			(std::isdigit(processedLine[valueEnd]) ||
				processedLine[valueEnd] == '.' ||
				processedLine[valueEnd] == '-')) {
			valueEnd++;
		}

		std::string floatValueStr = processedLine.substr(valueStart, valueEnd - valueStart);
		float floatValue = std::stof(floatValueStr);

		// Extract opcode
		std::string opcode;
		std::istringstream lineStream(processedLine);
		lineStream >> opcode;
		std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

		// Process float for mov instruction
		if (opcode == "mov") {
			// Convert to bytes
			uint32_t floatBits = *reinterpret_cast<uint32_t*>(&floatValue);

			// Extract destination operand
			size_t commaPos = processedLine.find(',');
			if (commaPos != std::string::npos) {
				std::string dest = processedLine.substr(3, commaPos - 3);
				dest.erase(0, dest.find_first_not_of(" \t"));
				dest.erase(dest.find_last_not_of(" \t") + 1);

				// Build new instruction
				std::stringstream newInst;
				newInst << "mov dword ptr " << dest << ", 0x" << std::hex << floatBits;
				processedLine = newInst.str();
			}
		}
	}

	// Use complete tokenization logic from ReplaceSymbols
	enum TokenType {
		TK_WHITESPACE,
		TK_OPCODE,
		TK_REGISTER,
		TK_NUMBER,
		TK_SYMBOL,
		TK_OPERATOR,
		TK_PUNCTUATION,
		TK_SPECIAL,
		TK_TYPECAST,
		TK_SIZE_SPEC,  // 新增：大小指示符
		TK_UNKNOWN
	};

	struct Token {
		TokenType type;
		std::string text;
	};

	std::vector<Token> tokens;
	size_t i = 0;

	// Tokenization phase (same as ReplaceSymbols)
	while (i < processedLine.length()) {
		Token token;

		// Whitespace
		if (std::isspace(processedLine[i])) {
			token.type = TK_WHITESPACE;
			while (i < processedLine.length() && std::isspace(processedLine[i])) {
				token.text += processedLine[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Check @f, @b 
		if (processedLine[i] == '@' && i + 1 < processedLine.length()) {
			if (processedLine[i + 1] == 'f' || processedLine[i + 1] == 'b') {
				token.type = TK_SPECIAL;
				token.text = processedLine.substr(i, 2);
				i += 2;
				tokens.push_back(token);
				continue;
			}
		}

		// Punctuation
		if (processedLine[i] == ',' || processedLine[i] == '[' || processedLine[i] == ']' ||
			processedLine[i] == '(' || processedLine[i] == ')' || processedLine[i] == ':') {
			token.type = TK_PUNCTUATION;
			token.text = processedLine[i++];
			tokens.push_back(token);
			continue;
		}

		// Operators
		if (processedLine[i] == '+' || processedLine[i] == '-' || processedLine[i] == '*') {
			token.type = TK_OPERATOR;
			token.text = processedLine[i++];
			tokens.push_back(token);
			continue;
		}

		// $ prefix (CE hex notation)
		if (processedLine[i] == '$') {
			i++; // skip $
			token.type = TK_NUMBER;
			std::string hexNum;
			while (i < processedLine.length() && std::isxdigit(processedLine[i])) {
				hexNum += processedLine[i++];
			}
			token.text = "0x" + hexNum;
			tokens.push_back(token);
			continue;
		}

		// 0x prefix
		if (i + 2 <= processedLine.length() && processedLine[i] == '0' &&
			(processedLine[i + 1] == 'x' || processedLine[i + 1] == 'X')) {
			token.type = TK_NUMBER;
			token.text = "0x";
			i += 2;
			while (i < processedLine.length() && std::isxdigit(processedLine[i])) {
				token.text += processedLine[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// Alphanumeric sequences
		if (std::isalnum(processedLine[i]) || processedLine[i] == '_') {
			std::string word;
			while (i < processedLine.length() && (std::isalnum(processedLine[i]) || processedLine[i] == '_')) {
				word += processedLine[i++];
			}

			// Determine type
			std::string lowerWord = word;
			std::transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), ::tolower);

			// First word is usually opcode
			if (tokens.empty() || (tokens.size() > 0 &&
				tokens.back().type == TK_PUNCTUATION && tokens.back().text == ":")) {
				token.type = TK_OPCODE;
			}
			// Check if register
			else if (isX64RegisterName(lowerWord)) {
				token.type = TK_REGISTER;
			}
			// 检查是否是大小指示符
			else if (isSizeSpecifier(lowerWord)) {
				token.type = TK_SIZE_SPEC;
			}
			// Check if pure number (all hex digits)
			else if (std::all_of(word.begin(), word.end(),
				[](char c) { return std::isxdigit(c); })) {
				token.type = TK_NUMBER;
				token.text = "0x" + word;
				tokens.push_back(token);
				continue;
			}
			// Otherwise symbol
			else {
				token.type = TK_SYMBOL;
			}

			token.text = word;
			tokens.push_back(token);
			continue;
		}

		// Unknown character
		token.type = TK_UNKNOWN;
		token.text = processedLine[i++];
		tokens.push_back(token);
	}

	// 构建结果
	std::string result;
	for (size_t idx = 0; idx < tokens.size(); idx++) {
		const Token& tok = tokens[idx];

		if (tok.type == TK_SYMBOL) {
			// Try to resolve symbol
			uint64_t capturedVal;
			uintptr_t symbolAddr;

			LOG_DEBUG_F("Trying to resolve symbol: %s", tok.text.c_str());

			if (m_symbolManager->GetCapturedValue(tok.text, capturedVal)) {
				result += std::to_string(capturedVal);
				LOG_DEBUG_F("Symbol %s -> captured %llu", tok.text.c_str(), capturedVal);
			}
			else if (m_symbolManager->GetSymbolAddress(tok.text, symbolAddr)) {
				if (symbolAddr != 0) {
					std::stringstream ss;
					ss << "0x" << std::hex << symbolAddr;
					result += ss.str();
					LOG_DEBUG_F("Symbol %s -> 0x%llX", tok.text.c_str(), symbolAddr);
				}
				else {
					// Symbol found but address is 0
					result += tok.text;
					LOG_WARN_F("Symbol %s found but address is 0", tok.text.c_str());
				}
			}
			else {
				// Symbol not found, keep original
				result += tok.text;
				LOG_WARN_F("Symbol %s not found in symbol table", tok.text.c_str());
			}
		}
		else {
			// *** 新添加的else分支 ***
			// 处理所有非符号类型的token（寄存器、操作符、标点符号等）
			result += tok.text;
		}
	}

	LOG_TRACE_F("Symbol replacement for estimation output: %s", result.c_str());
	return result;
}
std::string CEAssemblyEngine::ReplaceSymbols(const std::string& line) {
	LOG_TRACE_F("Symbol replacement input: %s", line.c_str());

	enum TokenType {
		TK_WHITESPACE,
		TK_OPCODE,
		TK_REGISTER,
		TK_NUMBER,
		TK_SYMBOL,
		TK_OPERATOR,
		TK_PUNCTUATION,
		TK_SPECIAL,
		TK_TYPECAST,
		TK_SIZE_SPEC,  // 添加大小指示符类型
		TK_UNKNOWN
	};

	struct Token {
		TokenType type;
		std::string text;
	};

	std::vector<Token> tokens;
	size_t i = 0;

	// 分词阶段
	while (i < line.length()) {
		Token token;

		// 空白字符
		if (std::isspace(line[i])) {
			token.type = TK_WHITESPACE;
			while (i < line.length() && std::isspace(line[i])) {
				token.text += line[i++];
			}
			tokens.push_back(token);
			continue;
		}

		// 检查 @f, @b 
		if (line[i] == '@' && i + 1 < line.length()) {
			if (line[i + 1] == 'f' || line[i + 1] == 'b') {
				token.type = TK_SPECIAL;
				token.text = line.substr(i, 2);
				i += 2;
				tokens.push_back(token);
				continue;
			}
		}

		// 标点符号
		if (line[i] == ',' || line[i] == '[' || line[i] == ']' ||
			line[i] == '(' || line[i] == ')' || line[i] == ':') {
			token.type = TK_PUNCTUATION;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		// 运算符
		if (line[i] == '+' || line[i] == '-' || line[i] == '*') {
			token.type = TK_OPERATOR;
			token.text = line[i++];
			tokens.push_back(token);
			continue;
		}

		if (line[i] == '#') {
			i++; // 跳过 #
			token.type = TK_NUMBER;
			std::string decNum;
			while (i < line.length() && std::isdigit(line[i])) {
				decNum += line[i++];
			}
			token.text = decNum; // 直接使用十进制数，不加0x前缀
			tokens.push_back(token);
			continue;
		}

		// $ 前缀 (CE十六进制记法)
		if (line[i] == '$') {
			i++; // 跳过 $
			token.type = TK_NUMBER;
			std::string hexNum;
			while (i < line.length() && std::isxdigit(line[i])) {
				hexNum += line[i++];
			}
			token.text = "0x" + hexNum;
			tokens.push_back(token);
			continue;
		}

		// 0x 前缀
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

		// 字母数字序列
		if (std::isalnum(line[i]) || line[i] == '_') {
			std::string word;
			while (i < line.length() && (std::isalnum(line[i]) || line[i] == '_')) {
				word += line[i++];
			}

			// 确定类型
			std::string lowerWord = word;
			std::transform(lowerWord.begin(), lowerWord.end(), lowerWord.begin(), ::tolower);

			// 第一个词通常是操作码
			if (tokens.empty() || (tokens.size() > 0 &&
				tokens.back().type == TK_PUNCTUATION && tokens.back().text == ":")) {
				token.type = TK_OPCODE;
			}
			// 检查是否为寄存器
			else if (isX64RegisterName(lowerWord)) {
				token.type = TK_REGISTER;
			}
			// 添加：检查是否为大小指示符
			else if (isSizeSpecifier(lowerWord)) {
				token.type = TK_SIZE_SPEC;
			}
			else if (std::all_of(word.begin(), word.end(), ::isdigit)) {
				// 在CE中，纯数字默认是十六进制
				token.type = TK_NUMBER;
				token.text = "0x" + word; // CE风格：默认十六进制
				tokens.push_back(token);
				continue;
			}
			// 检查是否为十六进制数（不带0x前缀）
			else if (std::all_of(word.begin(), word.end(),
				[](char c) { return std::isxdigit(c); }) &&
				std::any_of(word.begin(), word.end(),
					[](char c) { return (c >= 'A' && c <= 'F') ||
					(c >= 'a' && c <= 'f'); })) {
				// 包含A-F的十六进制数
				token.type = TK_NUMBER;
				token.text = "0x" + word;
				tokens.push_back(token);
				continue;
			}
			// 其他情况为符号
			else {
				token.type = TK_SYMBOL;
			}

			token.text = word;
			tokens.push_back(token);
			continue;
		}

		// 未知字符
		token.type = TK_UNKNOWN;
		token.text = line[i++];
		tokens.push_back(token);
	}

	// 构建结果 - 这里是需要修复的部分
	std::string result;
	for (size_t idx = 0; idx < tokens.size(); idx++) {
		const Token& tok = tokens[idx];

		if (tok.type == TK_SYMBOL) {
			// Try to resolve symbol
			uint64_t capturedVal;
			uintptr_t symbolAddr;

			LOG_DEBUG_F("Trying to resolve symbol: %s", tok.text.c_str());

			// First check if it's a captured variable (like s1, s2)
			if (tok.text.length() >= 2 && tok.text[0] == 's' && std::isdigit(tok.text[1])) {
				// This might be a captured variable
				if (m_symbolManager->GetCapturedValue(tok.text, capturedVal)) {
					// For captured variables, we need to check if it's an offset or a value
					// In the context of [rax+s1], it's an offset, so convert to hex
					std::stringstream ss;
					ss << "0x" << std::hex << capturedVal;
					result += ss.str();
					LOG_DEBUG_F("Captured variable %s -> 0x%llX", tok.text.c_str(), capturedVal);
					continue;
				}
			}

			// Then check normal symbols
			if (m_symbolManager->GetSymbolAddress(tok.text, symbolAddr)) {
				if (symbolAddr != 0) {
					std::stringstream ss;
					ss << "0x" << std::hex << symbolAddr;
					result += ss.str();
					LOG_DEBUG_F("Symbol %s -> 0x%llX", tok.text.c_str(), symbolAddr);
				}
				else {
					// Symbol found but address is 0
					result += tok.text;
					LOG_WARN_F("Symbol %s found but address is 0", tok.text.c_str());
				}
			}
			else {
				// Symbol not found, keep original
				result += tok.text;
				LOG_WARN_F("Symbol %s not found in symbol table", tok.text.c_str());
			}
		}
		else {
			// 重要修复：添加这个else分支来处理非符号的token
			result += tok.text;
		}
	}

	LOG_TRACE_F("Symbol replacement output: %s", result.c_str());
	return result;
}

// 浮点数转换
std::string CEAssemblyEngine::ProcessFloatConversion(const std::string& line) {
	std::string result = line;

	size_t floatPos = result.find("(float)");
	while (floatPos != std::string::npos) {
		// Extract the float value
		size_t valueStart = floatPos + 7;
		size_t valueEnd = valueStart;

		// Find the end of the number
		while (valueEnd < result.length() &&
			(std::isdigit(result[valueEnd]) || result[valueEnd] == '.' || result[valueEnd] == '-')) {
			valueEnd++;
		}

		std::string floatValueStr = result.substr(valueStart, valueEnd - valueStart);
		float floatValue = std::stof(floatValueStr);
		uint32_t floatBits = *reinterpret_cast<uint32_t*>(&floatValue);

		// Extract opcode and check instruction type
		std::istringstream iss(result);
		std::string opcode;
		iss >> opcode;
		std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

		// For mov instructions with memory operands
		if (opcode == "mov") {
			// Find the comma that separates operands
			size_t commaPos = result.find(',');
			if (commaPos != std::string::npos && commaPos < floatPos) {
				// Extract destination operand
				std::string dest = result.substr(3, commaPos - 3); // skip "mov"
				dest.erase(0, dest.find_first_not_of(" \t"));
				dest.erase(dest.find_last_not_of(" \t") + 1);

				// Check if it's a memory operand
				if (dest.find('[') != std::string::npos) {
					// **关键修改：强制使用 dword ptr，即使已经有 ptr**
					size_t ptrPos = dest.find("ptr");
					if (ptrPos != std::string::npos) {
						// 找到 ptr 前面的大小指示符并替换为 dword
						size_t start = dest.find_last_of(" \t", ptrPos - 1);
						if (start == std::string::npos) start = 0;
						else start++;

						dest = dest.substr(0, start) + "dword" + dest.substr(ptrPos);
					}
					else {
						// 没有 ptr，在方括号前插入 dword ptr
						size_t bracketPos = dest.find('[');
						dest.insert(bracketPos, "dword ptr ");
					}

					// Build new instruction with hex value
					std::stringstream newInst;
					newInst << "mov " << dest << ", 0x" << std::hex << floatBits;
					result = newInst.str();

					LOG_DEBUG_F("Float conversion: %s -> %s", line.c_str(), result.c_str());
					return result; // Only process one float per call
				}
				else {
					// 对于非内存操作数（如寄存器），也要确保是32位操作
					// 直接替换浮点值为十六进制
					std::stringstream hexValue;
					hexValue << "0x" << std::hex << floatBits;
					result.replace(floatPos, valueEnd - floatPos, hexValue.str());

					LOG_DEBUG_F("Float conversion (register): %s -> %s", line.c_str(), result.c_str());
					return result;
				}
			}
		}

		// For other instructions or non-memory operands, just replace with hex
		std::stringstream hexValue;
		hexValue << "0x" << std::hex << floatBits;
		result.replace(floatPos, valueEnd - floatPos, hexValue.str());

		// Look for next occurrence
		floatPos = result.find("(float)", floatPos + hexValue.str().length());
	}

	return result;
}

// 智能汇编（新增）
bool CEAssemblyEngine::SmartAssemble(const std::string& instruction, uintptr_t address,
	std::vector<uint8_t>& machineCode, std::string& finalInstruction) {
	auto ksEngine = GetKeystoneEngine();
	if (!ksEngine) return false;

	// 尝试列表
	std::vector<std::string> attempts;
	attempts.push_back(instruction); // 原始指令

	// 检查是否包含内存操作数
	size_t bracketStart = instruction.find('[');
	if (bracketStart != std::string::npos) {
		size_t bracketEnd = instruction.find(']', bracketStart);
		if (bracketEnd != std::string::npos) {
			std::string memOperand = instruction.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

			// 1. 尝试添加 0x 前缀到偏移量
			std::string modifiedInst = instruction;
			size_t plusPos = memOperand.find('+');
			size_t minusPos = memOperand.find('-');

			if (plusPos != std::string::npos || minusPos != std::string::npos) {
				size_t opPos = (plusPos != std::string::npos) ? plusPos : minusPos;
				char opChar = (plusPos != std::string::npos) ? '+' : '-';

				std::string offset = memOperand.substr(opPos + 1);
				offset.erase(std::remove_if(offset.begin(), offset.end(), ::isspace), offset.end());

				// 如果偏移量是纯数字/十六进制，尝试添加 0x
				if (!offset.empty() && offset.find("0x") != 0 && offset[0] != '$' &&
					std::all_of(offset.begin(), offset.end(), ::isxdigit)) {

					std::string newMemOperand = memOperand.substr(0, opPos + 1) + "0x" + offset;
					modifiedInst = instruction.substr(0, bracketStart + 1) +
						newMemOperand + instruction.substr(bracketEnd);
					attempts.push_back(modifiedInst);
				}
			}

			// 2. 如果指令没有 ptr，尝试添加不同大小的 ptr
			if (instruction.find("ptr") == std::string::npos) {
				// 提取操作码和目标操作数
				std::istringstream iss(instruction);
				std::string opcode;
				iss >> opcode;
				std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

				// 根据指令类型决定尝试顺序
				std::vector<std::string> sizeSpecs;

				if (opcode == "mov" || opcode == "lea") {
					// 对于 mov，根据目标寄存器推测
					size_t commaPos = instruction.find(',');
					if (commaPos != std::string::npos && commaPos < bracketStart) {
						std::string dest = instruction.substr(opcode.length(), commaPos - opcode.length());
						dest.erase(0, dest.find_first_not_of(" \t"));
						dest.erase(dest.find_last_not_of(" \t") + 1);

						std::string destLower = dest;
						std::transform(destLower.begin(), destLower.end(), destLower.begin(), ::tolower);

						if (destLower[0] == 'r' && destLower != "rip") {
							sizeSpecs = { "qword ptr ", "dword ptr ", "word ptr ", "byte ptr " };
						}
						else if (destLower[0] == 'e') {
							sizeSpecs = { "dword ptr ", "qword ptr ", "word ptr ", "byte ptr " };
						}
						else {
							sizeSpecs = { "dword ptr ", "qword ptr ", "word ptr ", "byte ptr " };
						}
					}
				}
				else {
					// 默认尝试顺序
					sizeSpecs = { "dword ptr ", "qword ptr ", "word ptr ", "byte ptr " };
				}

				// 为每个基础变体（原始的和添加了0x的）生成带 ptr 的版本
				size_t baseAttempts = attempts.size();
				for (size_t i = 0; i < baseAttempts; ++i) {
					for (const auto& sizeSpec : sizeSpecs) {
						std::string withPtr = attempts[i];
						size_t bracket = withPtr.find('[');
						if (bracket != std::string::npos) {
							withPtr.insert(bracket, sizeSpec);
							attempts.push_back(withPtr);
						}
					}
				}
			}
		}
	}

	// 尝试所有变体
	for (const auto& attempt : attempts) {
		unsigned char* encode = nullptr;
		size_t size = 0;
		size_t count = 0;

		LOG_TRACE_F("Trying to assemble: %s", attempt.c_str());

		if (ks_asm(ksEngine, attempt.c_str(), address, &encode, &size, &count) == KS_ERR_OK) {
			if (size > 0) {
				machineCode.assign(encode, encode + size);
				ks_free(encode);
				finalInstruction = attempt;

				LOG_DEBUG_F("Smart assembly successful: '%s' -> '%s' (%zu bytes)",
					instruction.c_str(), attempt.c_str(), size);
				return true;
			}
			ks_free(encode);
		}
		else {
			ks_err err = ks_errno(ksEngine);
			LOG_TRACE_F("Failed with: %s", ks_strerror(err));
		}
	}

	// 所有尝试都失败了
	LOG_ERROR_F("Smart assembly failed for: %s (tried %zu variants)",
		instruction.c_str(), attempts.size());
	return false;
}

// 指令大小估算
size_t CEAssemblyEngine::EstimateInstructionSize(const std::string& line) {
	if (m_currentAddress == 0) {
		return 0;
	}

	// 提取操作码进行特殊处理
	std::string opcode;
	std::istringstream lineStream(line);
	lineStream >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// NOP指令特殊处理
	if (opcode == "nop") {
		int nopCount = 1;
		std::string countStr;
		if (lineStream >> countStr) {
			try {
				nopCount = std::stoi(countStr);
			}
			catch (...) {
				nopCount = 1;
			}
		}
		return nopCount;
	}

	// 数据定义指令特殊处理
	if (opcode == "db") return 1;
	if (opcode == "dw") return 2;
	if (opcode == "dd") return 4;
	if (opcode == "dq") return 8;

	// **添加：先处理浮点转换**
	std::string processedLine = line;
	if (line.find("(float)") != std::string::npos) {
		processedLine = ProcessFloatConversion(line);
		LOG_TRACE_F("Float conversion before estimation: %s -> %s", line.c_str(), processedLine.c_str());
	}

	// 使用临时符号替换来估算大小
	processedLine = ReplaceSymbolsForEstimation(processedLine);

	// 使用Keystone估算大小
	unsigned char* machineCode = nullptr;
	size_t codeSize = 0;
	size_t statements = 0;

	int asmResult = ks_asm(m_ksEngine,
		processedLine.c_str(),
		m_currentAddress,
		&machineCode,
		&codeSize,
		&statements);

	if (asmResult == KS_ERR_OK && codeSize > 0) {
		ks_free(machineCode);
		LOG_TRACE_F("Estimated size for '%s': %zu bytes", line.c_str(), codeSize);
		return codeSize;
	}

	// 如果Keystone失败，使用启发式方法估算
	LOG_TRACE_F("Keystone estimation failed for '%s', using heuristics", line.c_str());

	// 常见指令的默认大小
	if (opcode == "push" || opcode == "pop") return 1;
	if (opcode == "mov" && line.find("ptr") != std::string::npos) return 7; // mov with memory
	if (opcode == "jmp" || opcode == "call") return 5; // near jump/call
	if (opcode == "je" || opcode == "jne" || opcode == "jg" || opcode == "jl") return 2; // short conditional jump
	if (opcode == "cmp" && line.find("ptr") != std::string::npos) return 7; // cmp with memory
	if (opcode == "lea") return 7; // lea is typically 7 bytes
	if (opcode == "test") return 3; // test reg,reg
	if (opcode == "movss" || opcode == "movsd") return 4; // SSE moves

	// 默认返回5字节（保守估计）
	return 5;
}

// CE命令处理
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

	// Get near address
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	uintptr_t allocAddr = 0;

	if (nearAddress != 0) {
		// Strategy 1: Try to allocate near the address first
		allocAddr = m_memoryManager->AllocateNear(nearAddress, size, allocName);

		if (allocAddr != 0) {
			// Check if distance is within E9 range (±2GB)
			int64_t distance = static_cast<int64_t>(allocAddr) - static_cast<int64_t>(nearAddress);
			if (distance >= -0x80000000LL && distance <= 0x7FFFFFFFLL) {
				LOG_INFO_F("Memory allocated near: %s at 0x%llX (distance from 0x%llX: %lld bytes, E9 compatible)",
					allocName.c_str(), allocAddr, nearAddress, distance);
			}
			else {
				LOG_INFO_F("Memory allocated far: %s at 0x%llX (distance from 0x%llX: %lld bytes, needs FF25)",
					allocName.c_str(), allocAddr, nearAddress, distance);

				// Distance too far, release and try low address
				m_memoryManager->Deallocate(allocName);

				// Strategy 2: Request low address for FF25 jump
				allocAddr = m_memoryManager->AllocateNear(0x10000000, size, allocName);
				if (allocAddr != 0) {
					LOG_INFO_F("Memory allocated low: %s at 0x%llX (will use FF25 jump)",
						allocName.c_str(), allocAddr);
				}
			}
		}
	}
	else {
		// No near address, directly request low address
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

	// 注册所有标签（支持多标签声明）
	for (const auto& labelName : cmd.parameters) {
		m_symbolManager->RegisterSymbol(labelName, 0, 0, true);
		LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
	}

	return true;
}
bool CEAssemblyEngine::ProcessRegisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid registersymbol syntax";
		return false;
	}

	// 注册所有符号为全局符号
	for (const auto& symbolName : cmd.parameters) {
		// 获取符号当前地址（如果已存在）
		uintptr_t address = 0;
		m_symbolManager->GetSymbolAddress(symbolName, address);

		// 如果符号已有地址，保持地址，否则设为0
		m_symbolManager->RegisterSymbol(symbolName, address, 0, true);

		// TODO: 实现真正的全局符号注册逻辑
		LOG_INFO_F("Global symbol '%s' registered at 0x%llX", symbolName.c_str(), address);
	}

	return true;
}
bool CEAssemblyEngine::ProcessUnregisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid unregistersymbol syntax";
		return false;
	}

	// 注销所有指定的符号
	for (const auto& symbolName : cmd.parameters) {
		m_symbolManager->UnregisterSymbol(symbolName);
		LOG_DEBUG_F("Symbol '%s' unregistered", symbolName.c_str());
	}

	return true;
}
bool CEAssemblyEngine::ProcessDealloc(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid dealloc syntax";
		return false;
	}

	std::string allocName = cmd.parameters[0];
	LOG_INFO_F("Deallocating memory: %s", allocName.c_str());

	bool success = m_memoryManager->Deallocate(allocName);

	if (success) {
		LOG_INFO_F("Successfully deallocated: %s", allocName.c_str());

		// 同时从符号表中移除
		m_symbolManager->UnregisterSymbol(allocName);
	}
	else {
		LOG_ERROR_F("Failed to deallocate: %s", allocName.c_str());
		m_lastError = "Failed to deallocate memory: " + allocName;
	}

	return success;
}
bool CEAssemblyEngine::ProcessDbCommand(const std::string& line) {
	LOG_DEBUG_F("Processing DB command: %s", line.c_str());

	// 格式1: "label: db XX XX XX"
	// 格式2: "db XX XX XX" (当前地址)

	size_t colonPos = line.find(':');
	std::string bytePart;

	if (colonPos != std::string::npos) {
		// 格式1：有地址标签
		std::string addressPart = line.substr(0, colonPos);
		bytePart = line.substr(colonPos + 1);

		// 解析地址
		size_t plusPos = addressPart.find('+');
		if (plusPos != std::string::npos) {
			std::string baseName = addressPart.substr(0, plusPos);
			std::string offsetStr = addressPart.substr(plusPos + 1);

			uintptr_t baseAddr = 0;
			if (m_symbolManager->GetSymbolAddress(baseName, baseAddr) && baseAddr != 0) {
				try {
					size_t offset = std::stoull(offsetStr, nullptr, 16);
					m_currentAddress = baseAddr + offset;
					LOG_DEBUG_F("Resolved address: %s = 0x%llX + 0x%zX = 0x%llX",
						addressPart.c_str(), baseAddr, offset, m_currentAddress);
				}
				catch (...) {
					LOG_ERROR_F("Invalid offset: %s", offsetStr.c_str());
					return false;
				}
			}
			else {
				LOG_ERROR_F("Cannot resolve base address: %s", baseName.c_str());
				return false;
			}
		}
		else {
			// 简单标签
			if (!m_symbolManager->GetSymbolAddress(addressPart, m_currentAddress) ||
				m_currentAddress == 0) {
				LOG_ERROR_F("Cannot resolve address: %s", addressPart.c_str());
				return false;
			}
		}
	}
	else {
		// 格式2：使用当前地址
		bytePart = line;
		if (m_currentAddress == 0) {
			LOG_ERROR("No current address for db command");
			return false;
		}
	}

	// 去除前后空格
	bytePart.erase(0, bytePart.find_first_not_of(" \t"));
	bytePart.erase(bytePart.find_last_not_of(" \t") + 1);

	// 查找并跳过 "db" 关键字
	size_t dbPos = bytePart.find("db");
	if (dbPos != std::string::npos) {
		bytePart = bytePart.substr(dbPos + 2);
	}

	// 解析字节值 - 需要处理符号替换
	std::vector<uint8_t> bytes;
	std::istringstream iss(bytePart);
	std::string token;

	while (iss >> token) {
		// Check if it's a captured variable symbol
		if (token.length() >= 2 && token[0] == 's' && std::isdigit(token[1])) {
			uint64_t capturedVal;
			if (m_symbolManager->GetCapturedValue(token, capturedVal)) {
				// Captured value is typically a byte or word
				if (capturedVal <= 0xFF) {
					bytes.push_back(static_cast<uint8_t>(capturedVal));
					LOG_DEBUG_F("Captured variable %s = 0x%02X", token.c_str(), capturedVal);
				}
				else {
					// Multi-byte value, add as little-endian
					bytes.push_back(static_cast<uint8_t>(capturedVal & 0xFF));
					bytes.push_back(static_cast<uint8_t>((capturedVal >> 8) & 0xFF));
					LOG_DEBUG_F("Captured variable %s = 0x%04X", token.c_str(), capturedVal);
				}
				continue;
			}
		}

		// Normal hex byte
		try {
			unsigned long byte = std::stoul(token, nullptr, 16);
			if (byte > 0xFF) {
				LOG_ERROR_F("Invalid byte value: %s", token.c_str());
				continue;
			}
			bytes.push_back(static_cast<uint8_t>(byte));
		}
		catch (...) {
			LOG_ERROR_F("Failed to parse byte: %s", token.c_str());
		}
	}

	if (bytes.empty()) {
		LOG_ERROR("No bytes to write");
		return false;
	}

	LOG_INFO_F("Writing %zu bytes to 0x%llX", bytes.size(), m_currentAddress);

	// 写入字节
	DWORD oldProtect;
	if (!m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(),
		PAGE_EXECUTE_READWRITE, &oldProtect)) {
		LOG_ERROR_F("Failed to change memory protection (error: %d)", GetLastError());
		return false;
	}

	bool success = m_memoryManager->WriteMemory(m_currentAddress,
		bytes.data(),
		bytes.size());

	m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(),
		oldProtect, &oldProtect);

	if (success) {
		LOG_INFO_F("Successfully wrote %zu bytes to 0x%llX",
			bytes.size(), m_currentAddress);

		// 验证写入
		std::vector<uint8_t> verifyBuffer(bytes.size());
		if (m_memoryManager->ReadMemory(m_currentAddress, verifyBuffer.data(), bytes.size())) {
			bool match = true;
			for (size_t i = 0; i < bytes.size(); i++) {
				if (verifyBuffer[i] != bytes[i]) {
					match = false;
					break;
				}
			}
			LOG_DEBUG_F("Verification: %s", match ? "SUCCESS" : "FAILED");
		}
	}
	else {
		LOG_ERROR_F("Failed to write memory (error: %d)", GetLastError());
	}

	return success;
}

// 汇编指令处理
bool CEAssemblyEngine::ProcessAssemblyInstruction(const std::string& line) {
	if (m_currentAddress == 0) {
		LOG_ERROR("Cannot process instruction without current address");
		m_lastError = "No current address set";
		return false;
	}

	LOG_DEBUG_F("Processing instruction at 0x%llX: %s", m_currentAddress, line.c_str());

	// 提取操作码进行特殊处理
	std::string opcode;
	std::istringstream lineStream(line);
	lineStream >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// NOP指令特殊处理
	if (opcode == "nop") {
		int nopCount = 1;
		std::string countStr;
		if (lineStream >> countStr) {
			try {
				nopCount = std::stoi(countStr);
			}
			catch (...) {
				nopCount = 1;
			}
		}
		std::vector<uint8_t> nopBytes(nopCount, 0x90);
		LOG_DEBUG_F("Generating %d NOP byte(s)", nopCount);
		return WriteBytes(nopBytes);
	}

	// 数据定义指令特殊处理
	if (opcode == "dd" || opcode == "db" || opcode == "dw" || opcode == "dq") {
		return ProcessDataDirective(line);
	}

	// 处理指令
	std::string processedLine = line;

	// 1. 处理 (float) 转换
	processedLine = ProcessFloatConversion(processedLine);

	// 2. 执行符号替换
	processedLine = ReplaceSymbols(processedLine);

	// 3. 特殊处理 @f 和 @b 标签
	if (processedLine.find("@f") != std::string::npos ||
		processedLine.find("@b") != std::string::npos) {
		return ProcessCESpecialJump(line);
	}

	// 4. 修复CMP指令的特殊处理
	if (opcode == "cmp") {
		// 确保CMP指令格式正确
		size_t commaPos = processedLine.find(',');
		if (commaPos != std::string::npos) {
			std::string beforeComma = processedLine.substr(0, commaPos);
			std::string afterComma = processedLine.substr(commaPos + 1);

			// 去除空格
			afterComma.erase(0, afterComma.find_first_not_of(" \t"));
			afterComma.erase(afterComma.find_last_not_of(" \t") + 1);

			// 检查内存操作数
			if (beforeComma.find('[') != std::string::npos) {
				// 确定立即数大小
				std::string sizeSpec = "";

				try {
					// 解析立即数值
					unsigned long long value = 0;
					if (afterComma.find("0x") == 0) {
						value = std::stoull(afterComma, nullptr, 16);
					}
					else if (std::isdigit(afterComma[0])) {
						value = std::stoull(afterComma, nullptr, 10);
					}

					// 根据值大小选择合适的指令格式
					if (value <= 0x7F) {
						sizeSpec = "byte ptr ";
					}
					else if (value <= 0xFFFF) {
						sizeSpec = "word ptr ";
					}
					else {
						sizeSpec = "dword ptr ";
					}

					// 重建指令
					size_t bracketStart = beforeComma.find('[');
					if (beforeComma.find("ptr") == std::string::npos) {
						beforeComma.insert(bracketStart, sizeSpec);
					}

					processedLine = beforeComma + "," + afterComma;
					LOG_DEBUG_F("Modified CMP: %s", processedLine.c_str());
				}
				catch (...) {
					// 如果解析失败，添加默认的dword ptr
					if (beforeComma.find("ptr") == std::string::npos) {
						size_t bracketStart = beforeComma.find('[');
						beforeComma.insert(bracketStart, "dword ptr ");
						processedLine = beforeComma + "," + afterComma;
					}
				}
			}
		}
	}

	// 5. 特殊处理包含大立即数的 mov 指令
	if (opcode == "mov" && processedLine.find(",0x") != std::string::npos) {
		if (ProcessSpecialMovInstruction(processedLine)) {
			return true;
		}
	}

	// 准备汇编
	unsigned char* machineCode = nullptr;
	size_t codeSize = 0;
	size_t statements = 0;

	// 汇编处理后的指令
	LOG_TRACE_F("Assembling at 0x%llX: %s", m_currentAddress, processedLine.c_str());

	int asmResult = ks_asm(m_ksEngine,
		processedLine.c_str(),
		m_currentAddress,
		&machineCode,
		&codeSize,
		&statements);

	// 处理汇编结果
	if (asmResult == KS_ERR_OK) {
		if (codeSize > 0) {
			// 成功生成代码
			std::vector<uint8_t> bytes(machineCode, machineCode + codeSize);
			ks_free(machineCode);

			LOG_DEBUG_F("Assembly successful: %zu bytes", codeSize);

			// 调试输出生成的机器码
			std::stringstream hexDump;
			for (size_t i = 0; i < bytes.size(); i++) {
				hexDump << std::hex << std::setw(2) << std::setfill('0')
					<< (int)bytes[i] << " ";
			}
			LOG_TRACE_F("Machine code: %s", hexDump.str().c_str());

			return WriteBytes(bytes);
		}
		else {
			// 成功但无代码生成（标签或指示符）
			LOG_DEBUG("No machine code generated (label/directive)");
			return true;
		}
	}

	// 汇编失败 - 检查是否是符号问题（可以延迟处理）
	ks_err error = ks_errno(m_ksEngine);

	if (error == KS_ERR_ASM_SYMBOL_MISSING) {
		// 符号缺失，可以延迟处理
		LOG_DEBUG_F("Symbol missing, can be delayed: %s", processedLine.c_str());
		return false;
	}

	// 其他汇编错误
	LOG_ERROR_F("Failed to assemble: %s (error: %s)",
		processedLine.c_str(), ks_strerror(error));
	m_lastError = std::string("Assembly error: ") + ks_strerror(error);
	return false;
}
bool CEAssemblyEngine::ProcessAssemblyBatch(const std::vector<std::string>& instructions, uintptr_t startAddress) {
	m_currentAddress = startAddress;

	// Try to batch assemble all instructions
	std::string batchAssembly;
	for (const auto& line : instructions) {
		if (!batchAssembly.empty()) {
			batchAssembly += "\n";
		}
		batchAssembly += ReplaceSymbols(line);
	}

	// Preprocess anonymous labels BEFORE sending to Keystone
	batchAssembly = PreprocessAnonymousLabels(batchAssembly);

	LOG_DEBUG_F("Batch assembly at 0x%llX (%zu instructions):", startAddress, instructions.size());
	LOG_DEBUG_F("Preprocessed content:\n%s", batchAssembly.c_str());

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
		// Batch failed, try individual processing
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

// 特殊指令处理
bool CEAssemblyEngine::ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr) {
	std::string op = opcode;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp") {
		// Calculate relative offset
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// E9 relative jump
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
			// Distance too far, use FF25 absolute jump
			// FF 25 00 00 00 00 [8 byte target address]
			std::vector<uint8_t> jumpBytes = {
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // FF 25 00000000 (jmp [rip+0])
			};

			// Add 8 byte target address
			for (int i = 0; i < 8; ++i) {
				jumpBytes.push_back((targetAddr >> (i * 8)) & 0xFF);
			}

			LOG_DEBUG_F("Generated FF25 absolute jump from 0x%llX to 0x%llX (distance: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
	}
	else if (op == "call") {
		// call instruction
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
			// Call distance too far
			LOG_ERROR_F("Call distance too far: %lld", offset);
			return false;
		}
	}
	// Handle conditional jumps
	else if (op.length() > 0 && op[0] == 'j') {
		// Map of conditional jump mnemonics to their opcodes
		std::map<std::string, uint8_t> jumpOpcodes = {
			{"je", 0x74}, {"jz", 0x74},
			{"jne", 0x75}, {"jnz", 0x75},
			{"jg", 0x7F}, {"jnle", 0x7F},
			{"jge", 0x7D}, {"jnl", 0x7D},
			{"jl", 0x7C}, {"jnge", 0x7C},
			{"jle", 0x7E}, {"jng", 0x7E},
			{"ja", 0x77}, {"jnbe", 0x77},
			{"jae", 0x73}, {"jnb", 0x73}, {"jnc", 0x73},
			{"jb", 0x72}, {"jnae", 0x72}, {"jc", 0x72},
			{"jbe", 0x76}, {"jna", 0x76}
		};

		auto it = jumpOpcodes.find(op);
		if (it != jumpOpcodes.end()) {
			return GenerateConditionalJump(it->second, targetAddr);
		}
	}

	return false;
}
bool CEAssemblyEngine::ProcessSpecialMovInstruction(const std::string& line) {
	// Parse the instruction
	std::istringstream iss(line);
	std::string op, dest, src;
	iss >> op;

	// Get destination and source
	size_t commaPos = line.find(',');
	if (commaPos == std::string::npos) return false;

	dest = line.substr(op.length(), commaPos - op.length());
	src = line.substr(commaPos + 1);

	// Trim whitespace
	dest.erase(0, dest.find_first_not_of(" \t"));
	dest.erase(dest.find_last_not_of(" \t") + 1);
	src.erase(0, src.find_first_not_of(" \t"));
	src.erase(src.find_last_not_of(" \t") + 1);

	// Check if immediate value is too large
	if (src.find("0x") == 0) {
		try {
			unsigned long long value = std::stoull(src, nullptr, 16);

			// If value > 32 bits, we need special handling
			if (value > 0xFFFFFFFF) {
				LOG_ERROR_F("Immediate value too large for mov: %s", src.c_str());
				return false;
			}

			// For 32-bit values, add dword ptr if needed
			if (dest.find('[') != std::string::npos && dest.find("ptr") == std::string::npos) {
				std::string newLine = op + " dword ptr " + dest + "," + src;
				LOG_DEBUG_F("Trying with dword ptr: %s", newLine.c_str());

				unsigned char* machineCode = nullptr;
				size_t codeSize = 0;
				size_t statements = 0;

				int asmResult = ks_asm(m_ksEngine,
					newLine.c_str(),
					m_currentAddress,
					&machineCode,
					&codeSize,
					&statements);

				if (asmResult == KS_ERR_OK && codeSize > 0) {
					std::vector<uint8_t> bytes(machineCode, machineCode + codeSize);
					ks_free(machineCode);
					return WriteBytes(bytes);
				}
			}
		}
		catch (...) {
			// Not a valid number
		}
	}

	return false;
}
bool CEAssemblyEngine::ProcessDataDirective(const std::string& line) {
	std::istringstream iss(line);
	std::string directive;
	iss >> directive;
	std::transform(directive.begin(), directive.end(), directive.begin(), ::tolower);

	std::vector<uint8_t> dataBytes;

	if (directive == "db") {
		// Define byte
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			// Process the value through symbol replacement
			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid byte value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dw") {
		// Define word (2 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid word value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dd") {
		// Define dword (4 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid dword value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dq") {
		// Define qword (8 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long long val = std::stoull(processedValue, nullptr, 0);
				for (int i = 0; i < 8; i++) {
					dataBytes.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
				}
			}
			catch (...) {
				LOG_ERROR_F("Invalid qword value: %s", value.c_str());
				return false;
			}
		}
	}

	if (!dataBytes.empty()) {
		LOG_DEBUG_F("Data directive %s: %zu bytes", directive.c_str(), dataBytes.size());
		return WriteBytes(dataBytes);
	}

	return false;
}
bool CEAssemblyEngine::ProcessDataDirective(const std::string& line, std::vector<uint8_t>& dataBytes) {
	std::istringstream iss(line);
	std::string directive;
	iss >> directive;
	std::transform(directive.begin(), directive.end(), directive.begin(), ::tolower);

	dataBytes.clear();

	if (directive == "db") {
		// Define byte
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			// Process the value through symbol replacement
			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid byte value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dw") {
		// Define word (2 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid word value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dd") {
		// Define dword (4 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long val = std::stoul(processedValue, nullptr, 0);
				dataBytes.push_back(static_cast<uint8_t>(val & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
				dataBytes.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
			}
			catch (...) {
				LOG_ERROR_F("Invalid dword value: %s", value.c_str());
				return false;
			}
		}
	}
	else if (directive == "dq") {
		// Define qword (8 bytes)
		std::string value;
		while (iss >> value) {
			if (value == ",") continue;

			std::string processedValue = ReplaceSymbols(value);

			try {
				unsigned long long val = std::stoull(processedValue, nullptr, 0);
				for (int i = 0; i < 8; i++) {
					dataBytes.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
				}
			}
			catch (...) {
				LOG_ERROR_F("Invalid qword value: %s", value.c_str());
				return false;
			}
		}
	}

	if (!dataBytes.empty()) {
		LOG_DEBUG_F("Data directive %s: %zu bytes", directive.c_str(), dataBytes.size());
		return true;
	}

	return false;
}
bool CEAssemblyEngine::ProcessCESpecialJump(const std::string& line) {
	std::istringstream iss(line);
	std::string opcode;
	iss >> opcode;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	std::string target;
	iss >> target;

	if (target == "@f") {
		// Find next label (anonymous or named)
		uintptr_t nextLabel = FindNextLabel(m_currentAddress);
		if (nextLabel != 0) {
			LOG_DEBUG_F("Resolved @f from 0x%llX to 0x%llX", m_currentAddress, nextLabel);
			return ProcessJumpInstruction(opcode, nextLabel);
		}
		else {
			LOG_DEBUG_F("@f not resolved yet at 0x%llX, delaying", m_currentAddress);
			return false;
		}
	}
	else if (target == "@b") {
		// Find previous label (anonymous or named)
		uintptr_t prevLabel = FindPreviousLabel(m_currentAddress);
		if (prevLabel != 0) {
			LOG_DEBUG_F("Resolved @b from 0x%llX to 0x%llX", m_currentAddress, prevLabel);
			return ProcessJumpInstruction(opcode, prevLabel);
		}
		else {
			LOG_ERROR("@b: no previous label found");
			return false;
		}
	}

	return false;
}
bool CEAssemblyEngine::ProcessCESpecialJump(const std::string& line, uintptr_t address,
	std::vector<uint8_t>& machineCode) {
	std::istringstream iss(line);
	std::string opcode, target;
	iss >> opcode >> target;
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// 临时保存当前地址
	uintptr_t savedAddress = m_currentAddress;
	m_currentAddress = address;

	bool result = false;

	if (target == "@f") {
		uintptr_t nextLabel = FindNextLabel(address);
		if (nextLabel != 0) {
			LOG_DEBUG_F("Resolved @f from 0x%llX to 0x%llX", address, nextLabel);
			result = GenerateJumpBytes(opcode, address, nextLabel, machineCode);
		}
	}
	else if (target == "@b") {
		uintptr_t prevLabel = FindPreviousLabel(address);
		if (prevLabel != 0) {
			LOG_DEBUG_F("Resolved @b from 0x%llX to 0x%llX", address, prevLabel);
			result = GenerateJumpBytes(opcode, address, prevLabel, machineCode);
		}
	}

	// 恢复当前地址
	m_currentAddress = savedAddress;
	return result;
}

// 跳转指令生成
bool CEAssemblyEngine::GenerateJumpBytes(const std::string& opcode, uintptr_t fromAddr,
	uintptr_t toAddr, std::vector<uint8_t>& bytes) {
	bytes.clear();

	if (opcode == "jmp") {
		int64_t offset = toAddr - (fromAddr + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// E9 relative jump
			bytes.push_back(0xE9);
			bytes.push_back(static_cast<uint8_t>(offset & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 16) & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 24) & 0xFF));

			LOG_DEBUG_F("Generated E9 jump from 0x%llX to 0x%llX (offset: %lld)",
				fromAddr, toAddr, offset);
			return true;
		}
		else {
			// FF 25 absolute jump
			bytes.push_back(0xFF);
			bytes.push_back(0x25);
			bytes.push_back(0x00);
			bytes.push_back(0x00);
			bytes.push_back(0x00);
			bytes.push_back(0x00);

			// Add 8 byte target address
			for (int i = 0; i < 8; ++i) {
				bytes.push_back((toAddr >> (i * 8)) & 0xFF);
			}

			LOG_DEBUG_F("Generated FF25 absolute jump from 0x%llX to 0x%llX",
				fromAddr, toAddr);
			return true;
		}
	}
	else if (opcode == "call") {
		int64_t offset = toAddr - (fromAddr + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			bytes.push_back(0xE8);
			bytes.push_back(static_cast<uint8_t>(offset & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 16) & 0xFF));
			bytes.push_back(static_cast<uint8_t>((offset >> 24) & 0xFF));

			LOG_DEBUG_F("Generated E8 call from 0x%llX to 0x%llX", fromAddr, toAddr);
			return true;
		}
		else {
			LOG_ERROR_F("Call distance too far: %lld", offset);
			return false;
		}
	}
	else if (opcode.length() > 0 && opcode[0] == 'j') {
		// 条件跳转
		return GenerateConditionalJumpBytes(opcode, fromAddr, toAddr, bytes);
	}

	return false;
}
bool CEAssemblyEngine::GenerateConditionalJumpBytes(const std::string& opcode,
	uintptr_t fromAddr, uintptr_t toAddr,
	std::vector<uint8_t>& bytes) {
	// 条件跳转操作码映射
	static const std::map<std::string, uint8_t> jumpOpcodes = {
		{"je", 0x74}, {"jz", 0x74},
		{"jne", 0x75}, {"jnz", 0x75},
		{"jg", 0x7F}, {"jnle", 0x7F},
		{"jge", 0x7D}, {"jnl", 0x7D},
		{"jl", 0x7C}, {"jnge", 0x7C},
		{"jle", 0x7E}, {"jng", 0x7E},
		{"ja", 0x77}, {"jnbe", 0x77},
		{"jae", 0x73}, {"jnb", 0x73}, {"jnc", 0x73},
		{"jb", 0x72}, {"jnae", 0x72}, {"jc", 0x72},
		{"jbe", 0x76}, {"jna", 0x76}
	};

	auto it = jumpOpcodes.find(opcode);
	if (it == jumpOpcodes.end()) {
		LOG_ERROR_F("Unknown conditional jump: %s", opcode.c_str());
		return false;
	}

	bytes.clear();
	int64_t offset = toAddr - (fromAddr + 2); // Short jump is 2 bytes

	if (offset >= -128 && offset <= 127) {
		// Short jump
		bytes.push_back(it->second);
		bytes.push_back(static_cast<uint8_t>(offset & 0xFF));

		LOG_DEBUG_F("Generated short conditional jump (0x%02X) to 0x%llX",
			it->second, toAddr);
		return true;
	}
	else {
		// Near jump (0F 8x xx xx xx xx)
		offset = toAddr - (fromAddr + 6); // Near jump is 6 bytes
		bytes.push_back(0x0F);
		bytes.push_back(static_cast<uint8_t>(it->second + 0x10)); // Convert to near jump opcode
		bytes.push_back(static_cast<uint8_t>(offset & 0xFF));
		bytes.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
		bytes.push_back(static_cast<uint8_t>((offset >> 16) & 0xFF));
		bytes.push_back(static_cast<uint8_t>((offset >> 24) & 0xFF));

		LOG_DEBUG_F("Generated near conditional jump (0F %02X) to 0x%llX",
			it->second + 0x10, toAddr);
		return true;
	}
}
bool CEAssemblyEngine::GenerateConditionalJump(uint8_t opcode, uintptr_t targetAddr) {
	int64_t offset = targetAddr - (m_currentAddress + 2); // Short jump is 2 bytes

	if (offset >= -128 && offset <= 127) {
		// Short jump
		std::vector<uint8_t> jumpBytes = {
			opcode,
			static_cast<uint8_t>(offset & 0xFF)
		};
		LOG_DEBUG_F("Generated short conditional jump (0x%02X) to 0x%llX", opcode, targetAddr);
		return WriteBytes(jumpBytes);
	}
	else {
		// Near jump (0F 8x xx xx xx xx)
		offset = targetAddr - (m_currentAddress + 6); // Near jump is 6 bytes
		std::vector<uint8_t> jumpBytes = {
			0x0F,
			static_cast<uint8_t>(opcode + 0x10), // Convert to near jump opcode
			static_cast<uint8_t>(offset & 0xFF),
			static_cast<uint8_t>((offset >> 8) & 0xFF),
			static_cast<uint8_t>((offset >> 16) & 0xFF),
			static_cast<uint8_t>((offset >> 24) & 0xFF)
		};
		LOG_DEBUG_F("Generated near conditional jump (0F %02X) to 0x%llX", opcode + 0x10, targetAddr);
		return WriteBytes(jumpBytes);
	}
}


// 匿名标签处理
std::string CEAssemblyEngine::PreprocessAnonymousLabels(const std::string& code) {
	std::vector<std::string> lines;
	std::istringstream stream(code);
	std::string line;

	// Split into lines
	while (std::getline(stream, line)) {
		lines.push_back(line);
	}

	// First pass: Replace @@ with unique labels
	std::map<size_t, std::string> labelPositions; // line index -> label name
	int anonLabelCounter = 0;

	for (size_t i = 0; i < lines.size(); ++i) {
		std::string& currentLine = lines[i];

		// Trim whitespace
		size_t firstNonSpace = currentLine.find_first_not_of(" \t");
		if (firstNonSpace == std::string::npos) continue;

		// Check if it's an anonymous label
		if (currentLine.substr(firstNonSpace) == "@@:") {
			std::string newLabel = "__anon_label_" + std::to_string(anonLabelCounter++);
			labelPositions[i] = newLabel;
			currentLine = newLabel + ":";
			LOG_TRACE_F("Replaced @@ at line %zu with %s", i, newLabel.c_str());
		}
		// Check for any other label definition
		else if (currentLine.find(':') != std::string::npos &&
			currentLine.find("::") == std::string::npos) { // Not a C++ scope operator
			size_t colonPos = currentLine.find(':');
			std::string labelName = currentLine.substr(firstNonSpace, colonPos - firstNonSpace);
			// Remove any whitespace from label name
			labelName.erase(std::remove_if(labelName.begin(), labelName.end(), ::isspace), labelName.end());
			if (!labelName.empty()) {
				labelPositions[i] = labelName;
				LOG_TRACE_F("Found label %s at line %zu", labelName.c_str(), i);
			}
		}
	}

	// Second pass: Replace @f and @b with actual label names
	for (size_t i = 0; i < lines.size(); ++i) {
		std::string& currentLine = lines[i];

		// Replace @f with next label
		size_t atfPos = currentLine.find("@f");
		while (atfPos != std::string::npos) {
			// Find next label after current line
			std::string nextLabel;
			for (size_t j = i + 1; j < lines.size(); ++j) {
				if (labelPositions.find(j) != labelPositions.end()) {
					nextLabel = labelPositions[j];
					break;
				}
			}

			if (!nextLabel.empty()) {
				currentLine.replace(atfPos, 2, nextLabel);
				LOG_TRACE_F("Replaced @f at line %zu with %s", i, nextLabel.c_str());
			}
			else {
				LOG_ERROR_F("No forward label found for @f at line %zu", i);
				currentLine.replace(atfPos, 2, "__error_no_forward_label");
			}

			atfPos = currentLine.find("@f", atfPos + nextLabel.length());
		}

		// Replace @b with previous label
		size_t atbPos = currentLine.find("@b");
		while (atbPos != std::string::npos) {
			// Find previous label before current line
			std::string prevLabel;
			for (int j = i - 1; j >= 0; --j) {
				if (labelPositions.find(j) != labelPositions.end()) {
					prevLabel = labelPositions[j];
					break;
				}
			}

			if (!prevLabel.empty()) {
				currentLine.replace(atbPos, 2, prevLabel);
				LOG_TRACE_F("Replaced @b at line %zu with %s", i, prevLabel.c_str());
			}
			else {
				LOG_ERROR_F("No backward label found for @b at line %zu", i);
				currentLine.replace(atbPos, 2, "__error_no_backward_label");
			}

			atbPos = currentLine.find("@b", atbPos + prevLabel.length());
		}
	}

	// Reconstruct the code
	std::string result;
	for (const auto& line : lines) {
		if (!result.empty()) result += "\n";
		result += line;
	}

	return result;
}
uintptr_t CEAssemblyEngine::FindNextAnonymousLabel(uintptr_t fromAddress) {
	for (uintptr_t addr : m_anonymousLabels) {
		if (addr > fromAddress) {
			return addr;
		}
	}
	return 0;
}
uintptr_t CEAssemblyEngine::FindPreviousAnonymousLabel(uintptr_t fromAddress) {
	uintptr_t result = 0;
	for (uintptr_t addr : m_anonymousLabels) {
		if (addr < fromAddress) {
			result = addr;
		}
		else {
			break;
		}
	}
	return result;
}
uintptr_t CEAssemblyEngine::FindNextLabel(uintptr_t fromAddress) {
	// Find the next label after fromAddress using the ordered map
	for (const auto& [addr, name] : m_allLabels) {
		if (addr > fromAddress) {
			LOG_TRACE_F("Found next label '%s' at 0x%llX after 0x%llX",
				name.c_str(), addr, fromAddress);
			return addr;
		}
	}
	return 0;
}
uintptr_t CEAssemblyEngine::FindPreviousLabel(uintptr_t fromAddress) {
	uintptr_t result = 0;
	std::string resultName;

	// Find the previous label before fromAddress
	for (const auto& [addr, name] : m_allLabels) {
		if (addr < fromAddress) {
			result = addr;
			resultName = name;
		}
		else {
			break;  // Since map is ordered, we can stop here
		}
	}

	if (result != 0) {
		LOG_TRACE_F("Found previous label '%s' at 0x%llX before 0x%llX",
			resultName.c_str(), result, fromAddress);
	}

	return result;
}

// 内存写入
bool CEAssemblyEngine::WriteBytes(const std::vector<uint8_t>& bytes) {
	if (bytes.empty() || m_currentAddress == 0) return false;

	// Save original bytes
	std::vector<uint8_t> originalBytes(bytes.size());
	m_memoryManager->ReadMemory(m_currentAddress, originalBytes.data(), bytes.size());

	// Write new bytes
	DWORD oldProtect;
	if (m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(),
		PAGE_EXECUTE_READWRITE, &oldProtect)) {
		bool success = m_memoryManager->WriteMemory(m_currentAddress, bytes.data(), bytes.size());
		m_memoryManager->ProtectMemory(m_currentAddress, bytes.size(), oldProtect, &oldProtect);

		if (success) {
			// Record patch
			AddPatch(m_currentAddress, originalBytes, bytes);
			LOG_TRACE_F("Wrote %zu bytes at 0x%llX", bytes.size(), m_currentAddress);

			// Update current address
			m_currentAddress += bytes.size();
			return true;
		}
	}

	return false;
}

// 脚本清理
void CEAssemblyEngine::CleanupScript(CEScript* script) {
	if (!script) return;

	LOG_INFO("Cleaning up script resources");

	// 恢复所有补丁
	RestoreAllPatches(script->GetPatches());

	// 清理所有分配的内存
	m_memoryManager->ClearAllAllocations();
}