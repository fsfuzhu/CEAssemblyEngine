#include "CEAssemblyEngine.h"
#include "DebugHelper.h"
#include "CEScript.h"
#include "SymbolManager.h"
#include "PatternScanner.h"
#include "MemoryAllocator.h"
#include "ProcessManager.h"
#include "Parser/CEScriptParser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

CEAssemblyEngine::CEAssemblyEngine()
	: m_processManager(std::make_unique<ProcessManager>())
	, m_memoryAllocator(std::make_unique<MemoryAllocator>())
	, m_patternScanner(std::make_unique<PatternScanner>())
	, m_symbolManager(std::make_unique<SymbolManager>())
	, m_parser(std::make_unique<CEScriptParser>())
	, m_ksEngine(nullptr) {

	LOG_INFO("CEAssemblyEngine constructor called");

	// ��ʼ�� Keystone
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
	if (m_processManager->OpenProcess(pid)) {

		// �������������ʹ���ⲿ����
		m_patternScanner->SetProcessManager(m_processManager.get());
		m_memoryAllocator->SetProcessManager(m_processManager.get());

		return true;
	}

	m_lastError = "Failed to attach to process";
	return false;
}

bool CEAssemblyEngine::AttachToProcess(const std::string& processName) {
	LOG_INFO_F("Attempting to attach to process: %s", processName.c_str());

	DWORD pid = ProcessManager::FindProcessByName(processName);
	if (pid == 0) {
		LOG_ERROR_F("Process '%s' not found", processName.c_str());
		m_lastError = "Process not found: " + processName;
		return false;
	}

	LOG_INFO_F("Found process '%s' with PID: %d", processName.c_str(), pid);
	return AttachToProcess(pid);
}

void CEAssemblyEngine::DetachFromProcess() {
	m_processManager->CloseProcess();

	// �����������
	m_patternScanner->SetProcessManager(nullptr);
	m_memoryAllocator->SetProcessManager(nullptr);
}

bool CEAssemblyEngine::IsAttached() const {
	return  m_processManager->GetHandle() != nullptr;
}

DWORD CEAssemblyEngine::GetTargetPID() const {
	return m_processManager->GetPID();
}

std::shared_ptr<CEScript> CEAssemblyEngine::CreateScript(const std::string& name) {
	LOG_INFO_F("Creating new script: '%s'", name.empty() ? "<unnamed>" : name.c_str());
	auto script = std::make_shared<CEScript>(this);

	// ����ṩ�����ƣ�ʹ��������������һ��Ψһ����
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
static uintptr_t PageOf(uintptr_t addr) { return addr & ~0xFFFFuLL; } // 64 KB ��ҳ

MemoryAllocator::PoolInfo& CEAssemblyEngine::EnsureJumpTableNear(uintptr_t inject) {
	auto key = PageOf(inject);
	auto it = m_jumpPools.find(key);
	if (it != m_jumpPools.end()) return it->second;

	size_t poolSize = 0x400;                // һ�� 0x400 �㹻�� 64 ����
	uintptr_t base = m_memoryAllocator->AllocateNear(inject, poolSize,
		"jtbl_" + std::to_string(key));
	MemoryAllocator::PoolInfo pool{ base, poolSize, 0 };
	LOG_INFO_F("Jump-table pool 0x%llX�C0x%llX created",
		base, base + poolSize);
	return m_jumpPools[key] = pool;
}


bool CEAssemblyEngine::ProcessEnableBlock(const std::vector<std::string>& lines) {
	std::vector<std::string> codeLines;
	bool collectingCode = false;
	std::string currentLabel;

	// ��ղ�����¼
	m_patches.clear();

	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::AOBSCANMODULE:
			if (!ProcessAobScanModule(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

				return false;
			}
			collectingCode = false;
			break;

		case CommandType::ALLOC:
			if (!ProcessAlloc(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

				return false;
			}
			collectingCode = false;
			break;

		case CommandType::LABEL:
			if (!ProcessLabel(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

				return false;
			}
			collectingCode = false;
			break;

		case CommandType::REGISTERSYMBOL:
			if (!ProcessRegisterSymbol(line)) {
				LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

				return false;
			}
			collectingCode = false;
			break;

		case CommandType::ASSEMBLY:
		{
			// ����Ƿ��Ǳ�ǩ����
			if (line.back() == ':') {
				// �����֮ǰ�ռ��Ĵ��룬�Ȼ��
				if (!codeLines.empty() && m_currentAddress != 0) {
					std::vector<uint8_t> machineCode;
					if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
						LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

						return false;
					}

					// ����ԭʼ�ֽ�
					std::vector<uint8_t> originalBytes(machineCode.size());


					// ����̶�ȡ
					m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());



					// д�������

						// �����д��
					DWORD oldProtect;
					if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
						m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
						m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
					}



					// ��¼����
					AddPatch(m_currentAddress, originalBytes, machineCode);
					LOG_TRACE_F("Emit %zu bytes", machineCode.size());
					m_currentAddress += machineCode.size();
					codeLines.clear();
				}

				// �����±�ǩ
				std::string labelName = line.substr(0, line.length() - 1);
				uintptr_t addr;
				if (m_symbolManager->GetSymbolAddress(labelName, addr)) {
					if (addr == 0) {
						// �״�ȷ���� label ����ʵ��ַ
						addr = m_currentAddress;
						m_symbolManager->RegisterSymbol(labelName, addr);
					}
					m_currentAddress = addr;
					m_currentLabel = labelName;
					LOG_DEBUG_F("Label %s => 0x%llX", labelName.c_str(), addr);
				}
			}
			else {
				// �ռ�������
				codeLines.push_back(line);
			}
			break;
		}

		default:
			break;
		}
	}

	// ����ʣ��Ĵ���
	if (!codeLines.empty() && m_currentAddress != 0) {
		std::vector<uint8_t> machineCode;
		if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
			LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

			return false;
		}

		// ����ԭʼ�ֽ�
		std::vector<uint8_t> originalBytes(machineCode.size());


		// ����̶�ȡ
		m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());



		// д�������

			// �����д��
		DWORD oldProtect;
		if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
			m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
		}



		// ��¼����
		AddPatch(m_currentAddress, originalBytes, machineCode);
	}

	if (!codeLines.empty() && m_currentAddress != 0) {
		std::vector<uint8_t> machineCode;
		if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
			LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());

			return false;
		}

		// ����ԭʼ�ֽ�
		std::vector<uint8_t> originalBytes(machineCode.size());
		memcpy(originalBytes.data(), reinterpret_cast<void*>(m_currentAddress), machineCode.size());

		DWORD oldProtect;
		if (VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
			machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			memcpy(reinterpret_cast<void*>(m_currentAddress), machineCode.data(), machineCode.size());
			VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
				machineCode.size(), oldProtect, &oldProtect);

			// ��¼����
			AddPatch(m_currentAddress, originalBytes, machineCode);
		}
	}

	return true;
}

// ����ʣ��Ĵ���


bool CEAssemblyEngine::ProcessAobScanModule(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 3) {
		m_lastError = "Invalid aobscanmodule syntax";
		return false;
	}

	std::string symbolName = cmd.parameters[0];
	std::string moduleName = cmd.parameters[1];

	// �ϲ�ʣ�������Ϊ������
	std::string pattern;
	for (size_t i = 2; i < cmd.parameters.size(); ++i) {
		if (!pattern.empty()) pattern += " ";
		pattern += cmd.parameters[i];
	}

	// ִ��ɨ��
	uintptr_t address = m_patternScanner->ScanModule(moduleName, pattern);
	if (address == 0) {
		m_lastError = "Pattern not found";
		return false;
	}

	// ע�����
	m_symbolManager->RegisterSymbol(symbolName, address);

	// ע�Ჶ��ı���
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
	LOG_INFO_F("Processing Alloc: name=%s, size=%s",
		cmd.parameters[0].c_str(), cmd.parameters[1].c_str());

	std::string allocName = cmd.parameters[0];

	// ������С
	size_t size = 0;
	std::string sizeStr = cmd.parameters[1];
	if (sizeStr[0] == '$') {
		// ʮ������
		size = std::stoull(sizeStr.substr(1), nullptr, 16);
	}
	else {
		size = std::stoull(sizeStr, nullptr, 10);
	}

	// ��ȡ������ַ������ṩ��
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	// �����ڴ�
	uintptr_t allocAddr = m_memoryAllocator->AllocateNear(nearAddress, size, allocName);
	if (allocAddr == 0) {
		m_lastError = "Failed to allocate memory";
		return false;
	}
	LOG_INFO_F("Memory allocated at: 0x%llX (size=0x%zX)", allocAddr, size);
	// ע�����
	m_symbolManager->RegisterSymbol(allocName, allocAddr, size);
	LOG_DEBUG_F("Symbol '%s' registered for allocated memory", allocName.c_str());
	return true;
}

bool CEAssemblyEngine::ProcessLabel(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid label syntax";
		return false;
	}

	std::string labelName = cmd.parameters[0];

	// Labelͨ���ڴ�������ʱȷ����ַ
	// ����ֻ��Ԥע��
	m_symbolManager->RegisterSymbol(labelName, 0, 0, true);

	return true;
}

bool CEAssemblyEngine::ProcessRegisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid registersymbol syntax";
		return false;
	}

	// ����Ӧ���Ѿ����ڣ�����ֻ�Ǳ��Ϊע��
	// ʵ����Ϸ�У���Ὣ���ŵ��������ű�

	return true;
}

bool CEAssemblyEngine::AssembleCode(const std::vector<std::string>& codeLines,
	uintptr_t baseAddress,
	std::vector<uint8_t>& output) {

	output.clear();
	uintptr_t currentAddr = baseAddress;

	for (const auto& line : codeLines) {
		// �滻����
		std::string processedLine = ReplaceSymbols(line);
		std::istringstream iss(processedLine);
		std::string op;  iss >> op;
		std::transform(op.begin(), op.end(), op.begin(), ::tolower);

		if (op == "nop") {
			int count = 1;          // Ĭ�ϵ��� nop
			if (!(iss >> count))    // �������������־Ͷ�����
				count = 1;
			for (int i = 0; i < count; ++i) {
				output.push_back(0x90);   // 0x90 = NOP
			}
			currentAddr += count;
			continue;               // �����ͽ� keystone
		}
		// ����Ƿ���������Զ���ķ�����ת
		if (processedLine.find("jmp") != std::string::npos ||
			processedLine.find("call") != std::string::npos ||
			processedLine.find("je") != std::string::npos ||
			processedLine.find("jne") != std::string::npos) {

			std::vector<uint8_t> jumpCode;
			if (ProcessJumpInstructions(processedLine, currentAddr, jumpCode)) {
				output.insert(output.end(), jumpCode.begin(), jumpCode.end());
				currentAddr += jumpCode.size();
				continue;
			}
		}

		// ʹ��Keystone���
		unsigned char* encode;
		size_t size;
		size_t count;
		LOG_TRACE_F("Assembling @0x%llX : %s", currentAddr, processedLine.c_str());
		if (ks_asm(m_ksEngine, processedLine.c_str(), currentAddr, &encode, &size, &count) == KS_ERR_OK) {
			output.insert(output.end(), encode, encode + size);
			currentAddr += size;
			ks_free(encode);
		}
		else {
			LOG_ERROR_F("Keystone error (%s) for line \"%s\"",
				ks_strerror(ks_errno(m_ksEngine)), processedLine.c_str());
			m_lastError = "Assembly failed: " + processedLine;
			return false;
		}
	}

	return true;
}

bool CEAssemblyEngine::ProcessJumpInstructions(const std::string& instruction,
	uintptr_t currentAddress,
	std::vector<uint8_t>& output) {
	// ����ָ��
	std::istringstream iss(instruction);
	std::string opcode, operand;
	iss >> opcode >> operand;

	// ת��ΪСд
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// ���������Ƿ��Ƿ���
	uintptr_t targetAddress;
	if (!m_symbolManager->GetSymbolAddress(operand, targetAddress)) {
		return false;  // ���Ƿ��ţ���Keystone����
	}

	// �������ƫ��
	int64_t offset = targetAddress - (currentAddress + 5);  // 5��jmpָ��Ĵ�С

	// ����Ƿ����ʹ�ö���ת
	if (opcode == "jmp") {
		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// ʹ�ý���ת (E9 xx xx xx xx)
			output.push_back(0xE9);
			output.push_back(offset & 0xFF);
			output.push_back((offset >> 8) & 0xFF);
			output.push_back((offset >> 16) & 0xFF);
			output.push_back((offset >> 24) & 0xFF);
			return true;
		}
		else {
			MemoryAllocator::PoolInfo* pool = nullptr;
			uintptr_t slot = 0;

			while (true) {
				pool = &EnsureJumpTableNear(currentAddress);       // currentAddress = ע���
				if (pool->used + 0x10 > pool->size) { m_lastError = "Jump-table full"; return false; }

				slot = pool->base + pool->used;
				int64_t rel = slot - (currentAddress + 5);
				if (rel >= INT32_MIN && rel <= INT32_MAX) break;   // OK!

				// �۲��ɴ�ع�ռ�ò�ֱ���� mov/jmp
				/* ���� ԭ���� mov rax / jmp rax ���� ���� */
				output.insert(output.end(), { 0x48,0xB8 });
				for (int i = 0; i < 8; ++i) output.push_back((targetAddress >> (i * 8)) & 0xFF);
				output.insert(output.end(), { 0xFF,0xE0 });
				return true;
			}
			pool->used += 0x10;
			uint8_t stub[16] = { 0x48,0xB8 };                     // mov rax, imm64
			memcpy(stub + 2, &targetAddress, 8);
			stub[10] = 0xFF; stub[11] = 0xE0;                       // jmp rax
			memset(stub + 12, 0x90, 4);
			m_processManager->WriteMemory(slot, stub, 16);        // ͳһ�����д
			int32_t rel = (int32_t)(slot - (currentAddress + 5));
			output.insert(output.end(), { 0xE9,
				(uint8_t)rel, (uint8_t)(rel >> 8),
				(uint8_t)(rel >> 16), (uint8_t)(rel >> 24) });
			return true;
		}
	}
	else if (opcode == "call") {
		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// ʹ�ý����� (E8 xx xx xx xx)
			output.push_back(0xE8);
			output.push_back(offset & 0xFF);
			output.push_back((offset >> 8) & 0xFF);
			output.push_back((offset >> 16) & 0xFF);
			output.push_back((offset >> 24) & 0xFF);
			return true;
		}
	}

	return false;
}

std::string CEAssemblyEngine::ReplaceSymbols(const std::string& line) {
	std::string result = line;

	// ���Ҳ��滻���з���
	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = result;

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		uint64_t value;

		// ����Ƿ��ǲ���ı���
		if (m_symbolManager->GetCapturedValue(symbol, value)) {
			// �滻Ϊ������
			std::stringstream ss;
			ss << "0x" << std::hex << value;
			result = std::regex_replace(result, std::regex("\\b" + symbol + "\\b"), ss.str());
		}

		temp = match.suffix();
	}

	return result;
}

bool CEAssemblyEngine::ProcessDisableBlock(const std::vector<std::string>& lines) {
	// ����DISABLE�飬��Ҫ�ǻָ�ԭʼ�ֽ�
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::DB:
			// �ָ�ԭʼ�ֽ�
			// ����Ҫ֮ǰ�������Ϣ
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

	return m_memoryAllocator->Deallocate(cmd.parameters[0]);
}