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

	// ���û�ṩ���ƣ�ʹ����������һ��Ψһ����
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

// ��ȡҳ�����Ļ���ַ��������ת����飩
static uintptr_t PageOf(uintptr_t addr) {
	// ʹ��64KB���룬�������Ը���ϸ�ؿ�����ת��λ��
	return addr & ~0xFFFFuLL;
}

MemoryAllocator::PoolInfo& CEAssemblyEngine::EnsureJumpTableNear(uintptr_t inject) {
	auto key = PageOf(inject);
	auto it = m_jumpPools.find(key);
	if (it != m_jumpPools.end()) return it->second;

	// ������ת��أ�ÿ����1KB�����Դ�Ŷ����ת�
	size_t poolSize = 0x400;

	// ��ת�������ԣ���ע��㸽��Ѱ�Һ��ʵĸߵ�ַ
	uintptr_t base = 0;

	// ����Ľ�ͼ������ת���� 0x7FF775580000����INJECT�� 0x7FF775692E0A
	// ����Լ�� -0x112E0A��Լ1.07MB
	// ��������������ע���ǰ��2MB��Χ��Ѱ��

	// ����1����ע���֮ǰ0.5MB-2MB��Χ�ڷ��䣨��͵�ַ��
	for (size_t offset = 0x80000; offset <= 0x200000; offset += 0x10000) {
		if (inject > offset) {
			base = m_memoryAllocator->AllocateNear(inject - offset, poolSize,
				"jtbl_" + std::to_string(key) + "_low_" + std::to_string(offset));
			if (base != 0) {
				// ��֤�Ƿ���E9��ת�ķ�Χ�ڣ���2GB��
				int64_t rel = base - inject;
				if (rel >= INT32_MIN && rel <= INT32_MAX) {
					LOG_INFO_F("Allocated jump table at preferred location 0x%llX (-%llX from inject)",
						base, offset);
					break;
				}
				else {
					m_memoryAllocator->Deallocate("jtbl_" + std::to_string(key) + "_low_" + std::to_string(offset));
					base = 0;
				}
			}
		}
	}

	// ����2���������ʧ�ܣ���ע���֮��0.5MB-2MB��Χ�ڷ��䣨��ߵ�ַ��
	if (base == 0) {
		for (size_t offset = 0x80000; offset <= 0x200000; offset += 0x10000) {
			base = m_memoryAllocator->AllocateNear(inject + offset, poolSize,
				"jtbl_" + std::to_string(key) + "_high_" + std::to_string(offset));
			if (base != 0) {
				int64_t rel = base - inject;
				if (rel >= INT32_MIN && rel <= INT32_MAX) {
					LOG_INFO_F("Allocated jump table at alternate location 0x%llX (+%llX from inject)",
						base, offset);
					break;
				}
				else {
					m_memoryAllocator->Deallocate("jtbl_" + std::to_string(key) + "_high_" + std::to_string(offset));
					base = 0;
				}
			}
		}
	}

	// ����3���������ʧ�ܣ����ڴ�������Լ�����
	if (base == 0) {
		base = m_memoryAllocator->AllocateNear(inject, poolSize, "jtbl_" + std::to_string(key));
		if (base != 0) {
			// �����һ�η�Χ
			int64_t rel = base - inject;
			if (rel < INT32_MIN || rel > INT32_MAX) {
				LOG_ERROR_F("Jump table at 0x%llX is out of range from inject 0x%llX", base, inject);
				m_memoryAllocator->Deallocate("jtbl_" + std::to_string(key));
				throw std::runtime_error("Failed to allocate jump table within range");
			}
		}
	}

	if (base == 0) {
		LOG_ERROR_F("Failed to allocate jump table near 0x%llX", inject);
		throw std::runtime_error("Failed to allocate jump table");
	}

	MemoryAllocator::PoolInfo pool{ base, poolSize, 0 };
	LOG_INFO_F("Jump-table pool 0x%llX - 0x%llX created for inject point 0x%llX (distance: %lld bytes)",
		base, base + poolSize, inject, static_cast<int64_t>(base - inject));
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
					LOG_TRACE_F("Emit %zu bytes at 0x%llX", machineCode.size(), m_currentAddress);
					m_currentAddress += machineCode.size();
					codeLines.clear();
				}

				// �����±�ǩ
				std::string labelName = line.substr(0, line.length() - 1);
				uintptr_t addr = 0;

				// ����Ƿ��Ѿ��е�ַ
				if (m_symbolManager->GetSymbolAddress(labelName, addr) && addr != 0) {
					// �����Ѿ��е�ַ�ķ��ţ���INJECT��������ڴ棩��ʹ�øõ�ַ
					m_currentAddress = addr;
					m_currentLabel = labelName;
					LOG_DEBUG_F("Processing label %s at existing address 0x%llX", labelName.c_str(), addr);
				}
				else {
					// �����±�ǩ����code��return���������ǰ��ַ��Ч��ʹ�õ�ǰ��ַ
					if (m_currentAddress != 0) {
						m_symbolManager->RegisterSymbol(labelName, m_currentAddress);
						LOG_DEBUG_F("Registering label %s at current address 0x%llX", labelName.c_str(), m_currentAddress);
					}
					else {
						// �����ǰ��ַ��Ч��ע��Ϊǰ������
						m_symbolManager->RegisterSymbol(labelName, 0, 0, true);
						LOG_DEBUG_F("Registering forward reference label %s", labelName.c_str());
					}
					m_currentLabel = labelName;
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

	return true;
}

bool CEAssemblyEngine::ProcessAobScanModule(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.size() < 3) {
		m_lastError = "Invalid aobscanmodule syntax";
		return false;
	}

	std::string symbolName = cmd.parameters[0];
	std::string moduleName = cmd.parameters[1];

	// �ϲ�ʣ��������������
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
	// ʵ��Ӧ���У���Ὣ���ŵ��������ű�

	return true;
}

bool CEAssemblyEngine::AssembleCode(const std::vector<std::string>& codeLines,
	uintptr_t baseAddress,
	std::vector<uint8_t>& output) {

	output.clear();
	uintptr_t currentAddr = baseAddress;

	// �ṹ�����ڼ�¼�ӳٴ������ת
	struct DelayedJump {
		size_t outputOffset;     // ��output�е�ƫ��
		uintptr_t instructionAddr;  // ָ���ַ
		std::string instruction;    // ԭʼָ��
	};
	std::vector<DelayedJump> delayedJumps;

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
			continue;               // �����͸� keystone
		}

		// ����Ƿ������Ҫ�Զ���ķ�����ת
		if (op == "jmp" || op == "call" || op == "je" || op == "jne" ||
			op == "jg" || op == "jge" || op == "jl" || op == "jle" ||
			op == "ja" || op == "jae" || op == "jb" || op == "jbe") {

			std::string operand;
			iss >> operand;

			// �ȳ��Դ�����ת
			std::vector<uint8_t> jumpCode;
			if (ProcessJumpInstructions(processedLine, currentAddr, jumpCode)) {
				output.insert(output.end(), jumpCode.begin(), jumpCode.end());
				currentAddr += jumpCode.size();
				continue;
			}

			// ����Ƿ��ŵ���δ���壬��¼�����ӳٴ���
			uintptr_t targetAddr;
			if (!operand.empty() && !m_symbolManager->GetSymbolAddress(operand, targetAddr)) {
				// �������һ��ǰ�����õı�ǩ
				DelayedJump dj;
				dj.outputOffset = output.size();
				dj.instructionAddr = currentAddr;
				dj.instruction = processedLine;
				delayedJumps.push_back(dj);

				// ��ʱ���ռλ��
				if (op == "jmp") {
					// ΪFF 25ָ��Ԥ��6�ֽ�
					output.push_back(0x90);  // nop
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					currentAddr += 6;
				}
				else if (op == "call") {
					// callָ��ͨ����5�ֽ�
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					currentAddr += 5;
				}
				else {
					// ������ת��ʹ��6�ֽڵ���ʽ
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					currentAddr += 6;
				}
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

	// ���ڴ��������ӳٵ���ת
	for (const auto& dj : delayedJumps) {
		// ���ڱ�ǩӦ���Ѿ�������
		std::vector<uint8_t> jumpCode;
		if (ProcessJumpInstructions(dj.instruction, dj.instructionAddr, jumpCode)) {
			// �滻ռλ��
			if (jumpCode.size() == 5) {
				// ��׼��E9��ת��ֱ���滻
				memcpy(&output[dj.outputOffset], jumpCode.data(), jumpCode.size());
			}
			else if (jumpCode.size() == 6) {
				// FF 25��ת
				memcpy(&output[dj.outputOffset], jumpCode.data(), jumpCode.size());
			}
			else if (jumpCode.size() == 12) {
				// mov rax/jmp rax��ʽ����Ҫ����ռ�
				LOG_WARN_F("Delayed jump needs more space than reserved: %s", dj.instruction.c_str());
				// ��������Ƚϸ��ӣ�������Ҫ������֯����
			}
		}
		else {
			// �������Keystone���
			unsigned char* encode;
			size_t size;
			size_t count;
			if (ks_asm(m_ksEngine, dj.instruction.c_str(), dj.instructionAddr, &encode, &size, &count) == KS_ERR_OK) {
				if (size <= 6) {
					memcpy(&output[dj.outputOffset], encode, size);
				}
				ks_free(encode);
			}
			else {
				LOG_ERROR_F("Failed to resolve delayed jump: %s", dj.instruction.c_str());
				m_lastError = "Failed to resolve forward reference: " + dj.instruction;
				return false;
			}
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

	// ���⴦�����Ŀ���ַ����0��ǰ�����ã����ȷ���false
	if (targetAddress == 0) {
		return false;
	}

	// �ж��Ƿ��INJECT��ת��newmem����Ҫ��ת��
	bool isInjectToNewmem = (m_currentLabel == "INJECT" && operand.find("code") != std::string::npos) ||
		(m_currentLabel == "INJECT" && operand.find("newmem") != std::string::npos);

	// �ж��Ƿ��newmem����return��Ҳ��Ҫ��ת��
	bool isNewmemToReturn = (m_currentAddress < 0x7FF000000000) && operand == "return";

	if (opcode == "jmp") {
		// �������ƫ��
		int64_t offset = targetAddress - (currentAddress + 5);

		// �������Ҫ��ת������
		if (isInjectToNewmem || isNewmemToReturn) {
			// ȷ����ת��Ӧ�����ĸ�ע��㸽��
			uintptr_t injectPoint = currentAddress;
			if (isNewmemToReturn) {
				// ��newmem����ʱ����Ҫ�ҵ�ԭʼ��ע���
				std::vector<std::string> possibleInjectSymbols = { "INJECT", "Test", "Hook" };
				for (const auto& sym : possibleInjectSymbols) {
					uintptr_t addr;
					if (m_symbolManager->GetSymbolAddress(sym, addr) && addr != 0 && addr > 0x7FF000000000) {
						injectPoint = addr;
						LOG_DEBUG_F("Using inject point %s at 0x%llX for return jump", sym.c_str(), addr);
						break;
					}
				}
			}

			// ��ȡ�򴴽���ת���
			MemoryAllocator::PoolInfo* pool = &EnsureJumpTableNear(injectPoint);

			// ������ת����ĵ�ַ
			uintptr_t tableEntry = pool->base + pool->used;

			if (isInjectToNewmem) {
				// ��INJECT��ת����ת��ʹ��E9�����ת
				int64_t tableOffset = tableEntry - (currentAddress + 5);
				if (tableOffset < INT32_MIN || tableOffset > INT32_MAX) {
					LOG_ERROR_F("Jump table at 0x%llX is too far from inject point 0x%llX", tableEntry, currentAddress);
					return false;
				}

				// д����ת�����ݣ�FF 25 00000000 [8�ֽ�Ŀ���ַ]
				uint8_t jumpTableData[14] = { 0 };
				jumpTableData[0] = 0xFF;
				jumpTableData[1] = 0x25;
				jumpTableData[2] = 0x00;
				jumpTableData[3] = 0x00;
				jumpTableData[4] = 0x00;
				jumpTableData[5] = 0x00;
				memcpy(&jumpTableData[6], &targetAddress, 8);

				// д����ת��
				if (m_processManager && m_processManager->GetHandle()) {
					DWORD oldProtect;
					m_processManager->ProtectMemory(tableEntry, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
					m_processManager->WriteMemory(tableEntry, jumpTableData, 14);
					m_processManager->ProtectMemory(tableEntry, 14, oldProtect, &oldProtect);
				}

				pool->used += 16; // ���뵽16�ֽ�

				LOG_INFO_F("Created jump table at 0x%llX: FF 25 -> 0x%llX", tableEntry, targetAddress);

				// ����E9��ת����ת��
				output.push_back(0xE9);
				int32_t offset32 = static_cast<int32_t>(tableOffset);
				output.push_back(offset32 & 0xFF);
				output.push_back((offset32 >> 8) & 0xFF);
				output.push_back((offset32 >> 16) & 0xFF);
				output.push_back((offset32 >> 24) & 0xFF);
				return true;
			}
			else if (isNewmemToReturn) {
				// ��newmem����return����Ҫ�����µ���ת����
				// ���Ǵ�newmem��λ�ã�ʹ��FF 25��ת���洢return��ַ��λ��

				// ����ת���з���ռ�洢return��ַ
				uintptr_t returnAddressSlot = tableEntry;

				// д��return��ַ����ת��
				if (m_processManager && m_processManager->GetHandle()) {
					DWORD oldProtect;
					m_processManager->ProtectMemory(returnAddressSlot, 8, PAGE_READWRITE, &oldProtect);
					m_processManager->WriteMemory(returnAddressSlot, &targetAddress, 8);
					m_processManager->ProtectMemory(returnAddressSlot, 8, oldProtect, &oldProtect);
				}

				pool->used += 8;

				// ����ӵ�ǰλ�õ��洢��ַ��ƫ��
				int64_t slotOffset = returnAddressSlot - (currentAddress + 6);

				// �����ת��̫Զ��ʹ����һ�ַ�ʽ
				if (slotOffset < INT32_MIN || slotOffset > INT32_MAX) {
					// ����һ��������ת��
					LOG_INFO_F("Creating local jump for return from 0x%llX to 0x%llX", currentAddress, targetAddress);

					// ��newmem���洴��һ����ת����
					uintptr_t localJumpTable = (currentAddress + 0x100) & ~0xF; // ����

					// ���������ַ
					if (m_processManager && m_processManager->GetHandle()) {
						// ��д��FF 25 00000000ָ��
						uint8_t localJump[14] = { 0 };
						localJump[0] = 0xFF;
						localJump[1] = 0x25;
						localJump[2] = 0x00;
						localJump[3] = 0x00;
						localJump[4] = 0x00;
						localJump[5] = 0x00;
						memcpy(&localJump[6], &targetAddress, 8);

						DWORD oldProtect;
						m_processManager->ProtectMemory(localJumpTable, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
						m_processManager->WriteMemory(localJumpTable, localJump, 14);
						m_processManager->ProtectMemory(localJumpTable, 14, oldProtect, &oldProtect);
					}

					// ����E9��ת��������ת��
					int64_t localOffset = localJumpTable - (currentAddress + 5);
					output.push_back(0xE9);
					int32_t offset32 = static_cast<int32_t>(localOffset);
					output.push_back(offset32 & 0xFF);
					output.push_back((offset32 >> 8) & 0xFF);
					output.push_back((offset32 >> 16) & 0xFF);
					output.push_back((offset32 >> 24) & 0xFF);
					return true;
				}

				LOG_INFO_F("Creating FF 25 jump from 0x%llX to slot 0x%llX -> 0x%llX",
					currentAddress, returnAddressSlot, targetAddress);

				// ����FF 25ָ��
				output.push_back(0xFF);
				output.push_back(0x25);
				int32_t offset32 = static_cast<int32_t>(slotOffset);
				output.push_back(offset32 & 0xFF);
				output.push_back((offset32 >> 8) & 0xFF);
				output.push_back((offset32 >> 16) & 0xFF);
				output.push_back((offset32 >> 24) & 0xFF);
				return true;
			}
		}
		else if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
			// ��ͨ�Ľ���ת
			output.push_back(0xE9);
			output.push_back(offset & 0xFF);
			output.push_back((offset >> 8) & 0xFF);
			output.push_back((offset >> 16) & 0xFF);
			output.push_back((offset >> 24) & 0xFF);
			return true;
		}
		else {
			// ����̫Զ��ʹ��mov rax/jmp rax
			LOG_INFO_F("Using mov rax/jmp rax for far jump from 0x%llX to 0x%llX", currentAddress, targetAddress);
			output.push_back(0x48); output.push_back(0xB8); // mov rax, imm64
			for (int i = 0; i < 8; ++i) {
				output.push_back((targetAddress >> (i * 8)) & 0xFF);
			}
			output.push_back(0xFF); output.push_back(0xE0); // jmp rax
			return true;
		}
	}
	else if (opcode == "call") {
		// callָ��Ĵ���...
		int64_t offset = targetAddress - (currentAddress + 5);
		if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
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