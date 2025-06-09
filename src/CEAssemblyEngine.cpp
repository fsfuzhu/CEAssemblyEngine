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
	, m_ksEngine(nullptr)
	, m_currentAddress(0) {

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

	// ��һ�飺��������������ű�
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

	// �ڶ��飺���������
	struct DelayedInstruction {
		std::string instruction;
		uintptr_t address;
	};
	std::vector<DelayedInstruction> delayedInstructions;

	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		if (cmd.type == CommandType::ASSEMBLY) {
			if (!line.empty() && line.back() == ':') {
				// ��ǩ���壬���õ�ǰ��ַ
				std::string labelName = line.substr(0, line.length() - 1);
				uintptr_t addr = 0;

				if (m_symbolManager->GetSymbolAddress(labelName, addr) && addr != 0) {
					// ���е�ַ�ı�ǩ����INJECT��newmem��
					m_currentAddress = addr;
					LOG_DEBUG_F("Label %s: current address = 0x%llX", labelName.c_str(), addr);
				}
				else {
					// �±�ǩ��ʹ�õ�ǰ��ַ
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
				// ���ָ��
				uintptr_t instructionAddress = m_currentAddress;
				if (!ProcessAssemblyInstruction(line)) {
					// �������ʧ�ܣ�������ǰ�����ã���ӵ��ӳٴ���
					DelayedInstruction delayed;
					delayed.instruction = line;
					delayed.address = instructionAddress;
					delayedInstructions.push_back(delayed);
					LOG_DEBUG_F("Delaying instruction at 0x%llX: %s", instructionAddress, line.c_str());

					// Ԥ��ָ��ȣ����µ�ǰ��ַ
					std::istringstream iss(line);
					std::string op;
					iss >> op;
					std::transform(op.begin(), op.end(), op.begin(), ::tolower);

					if (op == "jmp" || op == "call") {
						m_currentAddress += 5; // Ԥ��E9��ת5�ֽ�
					}
					else {
						m_currentAddress += 4; // ����ָ��ƽ��4�ֽ�
					}
				}
			}
		}
	}

	// �����飺�����ӳٵ�ָ�ǰ�����ã�
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

	return true;
}

bool CEAssemblyEngine::ProcessAssemblyInstruction(const std::string& line) {
	if (m_currentAddress == 0) {
		LOG_ERROR("Cannot process instruction without current address");
		return false;
	}

	// ��������ָ��
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

	// ����Ƿ����������ת
	if (op == "jmp" || op == "call" || op.find("j") == 0) {
		std::string operand;
		iss >> operand;

		// ����Ƿ������ǵķ���
		uintptr_t targetAddr;
		if (m_symbolManager->GetSymbolAddress(operand, targetAddr)) {
			if (targetAddr != 0) {
				// �����ѽ�����������תָ��
				return ProcessJumpInstruction(op, targetAddr);
			}
			else {
				// ǰ�����ã���δ����
				return false;
			}
		}
	}

	// �滻���ź󽻸�Keystone
	std::string processedLine = ReplaceSymbols(line);

	unsigned char* encode;
	size_t size;
	size_t count;

	LOG_TRACE_F("Assembling @0x%llX : %s", m_currentAddress, processedLine.c_str());
	if (ks_asm(m_ksEngine, processedLine.c_str(), m_currentAddress, &encode, &size, &count) == KS_ERR_OK) {
		std::vector<uint8_t> machineCode(encode, encode + size);
		ks_free(encode);
		return WriteBytes(machineCode);
	}
	else {
		LOG_ERROR_F("Keystone error (%s) for line \"%s\"",
			ks_strerror(ks_errno(m_ksEngine)), processedLine.c_str());
		return false;
	}
}

bool CEAssemblyEngine::ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr) {
	std::string op = opcode;
	std::transform(op.begin(), op.end(), op.begin(), ::tolower);

	if (op == "jmp") {
		// �������ƫ��
		int64_t offset = targetAddr - (m_currentAddress + 5);

		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// E9�����ת
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
			// ����̫Զ��ʹ��FF25������ת
			// FF 25 00 00 00 00 [8�ֽ�Ŀ���ַ]
			std::vector<uint8_t> jumpBytes = {
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // FF 25 00000000 (jmp [rip+0])
			};

			// ���8�ֽ�Ŀ���ַ
			for (int i = 0; i < 8; ++i) {
				jumpBytes.push_back((targetAddr >> (i * 8)) & 0xFF);
			}

			LOG_DEBUG_F("Generated FF25 absolute jump from 0x%llX to 0x%llX (distance: %lld)",
				m_currentAddress, targetAddr, offset);
			return WriteBytes(jumpBytes);
		}
	}
	else if (op == "call") {
		// callָ��
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
			// call��Զ�̵��ÿ���ʹ����������
			LOG_ERROR_F("Call distance too far: %lld", offset);
			return false;
		}
	}

	return false;
}

bool CEAssemblyEngine::WriteBytes(const std::vector<uint8_t>& bytes) {
	if (bytes.empty() || m_currentAddress == 0) return false;

	// ����ԭʼ�ֽ�
	std::vector<uint8_t> originalBytes(bytes.size());
	m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), bytes.size());

	// д�����ֽ�
	DWORD oldProtect;
	if (m_processManager->ProtectMemory(m_currentAddress, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		bool success = m_processManager->WriteMemory(m_currentAddress, bytes.data(), bytes.size());
		m_processManager->ProtectMemory(m_currentAddress, bytes.size(), oldProtect, &oldProtect);

		if (success) {
			// ��¼����
			AddPatch(m_currentAddress, originalBytes, bytes);
			LOG_TRACE_F("Wrote %zu bytes at 0x%llX", bytes.size(), m_currentAddress);

			// ���µ�ǰ��ַ
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
	LOG_INFO_F("INJECT symbol registered at 0x%llX", address);

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

	// ��ȡ������ַ
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	uintptr_t allocAddr = 0;

	if (nearAddress != 0) {
		// ����1: �����ڸ�����ַ���룬����Ƿ���E9��Χ��
		allocAddr = m_memoryAllocator->AllocateNear(nearAddress, size, allocName);

		if (allocAddr != 0) {
			// �������Ƿ���E9��Χ�� (��2GB)
			int64_t distance = static_cast<int64_t>(allocAddr) - static_cast<int64_t>(nearAddress);
			if (distance >= -0x80000000LL && distance <= 0x7FFFFFFFLL) {
				LOG_INFO_F("Memory allocated near: %s at 0x%llX (distance from 0x%llX: %lld bytes, E9 compatible)",
					allocName.c_str(), allocAddr, nearAddress, distance);
			}
			else {
				LOG_INFO_F("Memory allocated far: %s at 0x%llX (distance from 0x%llX: %lld bytes, needs FF25)",
					allocName.c_str(), allocAddr, nearAddress, distance);

				// ����̫Զ���ͷŲ����������λ��ַ
				m_memoryAllocator->Deallocate(allocName);

				// ����2: �����λ��ַ��ʹ��FF25��ת
				allocAddr = m_memoryAllocator->AllocateNear(0x10000000, size, allocName + "_low");
				if (allocAddr != 0) {
					// ����ע����ȷ������
					m_memoryAllocator->Deallocate(allocName + "_low");
					allocAddr = m_memoryAllocator->AllocateNear(0x10000000, size, allocName);
					LOG_INFO_F("Memory allocated low: %s at 0x%llX (will use FF25 jump)",
						allocName.c_str(), allocAddr);
				}
			}
		}
	}
	else {
		// û�и�����ַ��ֱ�������λ��ַ
		allocAddr = m_memoryAllocator->AllocateNear(0x10000000, size, allocName);
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
	// �������ʵ��ȫ�ַ���ע���߼�
	return true;
}

std::string CEAssemblyEngine::ReplaceSymbols(const std::string& line) {
	std::string result = line;

	// �滻 #123 ��ʽ��������
	std::regex immediateRegex(R"(#(\d+))");
	result = std::regex_replace(result, immediateRegex, "0x$1");

	// ���Ҳ��滻����ı����������滻��ͨ���ţ�
	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = result;

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		uint64_t value;

		// ֻ�滻����ı��������滻��ͨ����
		if (m_symbolManager->GetCapturedValue(symbol, value)) {
			std::stringstream ss;
			ss << "0x" << std::hex << value;
			result = std::regex_replace(result, std::regex("\\b" + symbol + "\\b"), ss.str());
		}

		temp = match.suffix();
	}

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
	// �Ӳ�����Ϣ�лָ�ԭʼ�ֽ�
	for (const auto& patch : m_patches) {
		if (patch.address == m_currentAddress) {
			DWORD oldProtect;
			if (m_processManager->ProtectMemory(patch.address, patch.originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
				m_processManager->WriteMemory(patch.address, patch.originalBytes.data(), patch.originalBytes.size());
				m_processManager->ProtectMemory(patch.address, patch.originalBytes.size(), oldProtect, &oldProtect);
				return true;
			}
		}
	}
	return false;
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