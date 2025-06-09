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
	if (m_processManager->OpenProcess(pid)) {

		// 更新其他组件以使用外部进程
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

	// 重置其他组件
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

	// 如果没提供名称，使用索引生成一个唯一名称
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

// 获取页面对齐的基地址（用于跳转表分组）
static uintptr_t PageOf(uintptr_t addr) {
	// 使用64KB对齐，这样可以更精细地控制跳转表位置
	return addr & ~0xFFFFuLL;
}

MemoryAllocator::PoolInfo& CEAssemblyEngine::EnsureJumpTableNear(uintptr_t inject) {
	auto key = PageOf(inject);
	auto it = m_jumpPools.find(key);
	if (it != m_jumpPools.end()) return it->second;

	// 分配跳转表池（每个池1KB，可以存放多个跳转项）
	size_t poolSize = 0x400;

	// 跳转表分配策略：在注入点附近寻找合适的高地址
	uintptr_t base = 0;

	// 从你的截图看，跳转表在 0x7FF775580000，而INJECT在 0x7FF775692E0A
	// 差距大约是 -0x112E0A，约1.07MB
	// 所以我们优先在注入点前后2MB范围内寻找

	// 策略1：在注入点之前0.5MB-2MB范围内分配（向低地址）
	for (size_t offset = 0x80000; offset <= 0x200000; offset += 0x10000) {
		if (inject > offset) {
			base = m_memoryAllocator->AllocateNear(inject - offset, poolSize,
				"jtbl_" + std::to_string(key) + "_low_" + std::to_string(offset));
			if (base != 0) {
				// 验证是否在E9跳转的范围内（±2GB）
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

	// 策略2：如果上面失败，在注入点之后0.5MB-2MB范围内分配（向高地址）
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

	// 策略3：如果还是失败，让内存分配器自己决定
	if (base == 0) {
		base = m_memoryAllocator->AllocateNear(inject, poolSize, "jtbl_" + std::to_string(key));
		if (base != 0) {
			// 最后检查一次范围
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

	// 清空补丁记录
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
			// 检查是否是标签定义
			if (line.back() == ':') {
				// 如果有之前收集的代码，先汇编
				if (!codeLines.empty() && m_currentAddress != 0) {
					std::vector<uint8_t> machineCode;
					if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
						LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
						return false;
					}

					// 保存原始字节
					std::vector<uint8_t> originalBytes(machineCode.size());

					// 跨进程读取
					m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());

					// 写入机器码
					// 跨进程写入
					DWORD oldProtect;
					if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
						m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
						m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
					}

					// 记录补丁
					AddPatch(m_currentAddress, originalBytes, machineCode);
					LOG_TRACE_F("Emit %zu bytes at 0x%llX", machineCode.size(), m_currentAddress);
					m_currentAddress += machineCode.size();
					codeLines.clear();
				}

				// 处理新标签
				std::string labelName = line.substr(0, line.length() - 1);
				uintptr_t addr = 0;

				// 检查是否已经有地址
				if (m_symbolManager->GetSymbolAddress(labelName, addr) && addr != 0) {
					// 对于已经有地址的符号（如INJECT、分配的内存），使用该地址
					m_currentAddress = addr;
					m_currentLabel = labelName;
					LOG_DEBUG_F("Processing label %s at existing address 0x%llX", labelName.c_str(), addr);
				}
				else {
					// 对于新标签（如code、return），如果当前地址有效，使用当前地址
					if (m_currentAddress != 0) {
						m_symbolManager->RegisterSymbol(labelName, m_currentAddress);
						LOG_DEBUG_F("Registering label %s at current address 0x%llX", labelName.c_str(), m_currentAddress);
					}
					else {
						// 如果当前地址无效，注册为前向引用
						m_symbolManager->RegisterSymbol(labelName, 0, 0, true);
						LOG_DEBUG_F("Registering forward reference label %s", labelName.c_str());
					}
					m_currentLabel = labelName;
				}
			}
			else {
				// 收集汇编代码
				codeLines.push_back(line);
			}
			break;
		}

		default:
			break;
		}
	}

	// 处理剩余的代码
	if (!codeLines.empty() && m_currentAddress != 0) {
		std::vector<uint8_t> machineCode;
		if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
			LOG_ERROR_F("EnableBlock error : %s", m_lastError.c_str());
			return false;
		}

		// 保存原始字节
		std::vector<uint8_t> originalBytes(machineCode.size());

		// 跨进程读取
		m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());

		// 写入机器码
		// 跨进程写入
		DWORD oldProtect;
		if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
			m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
		}

		// 记录补丁
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

	// 合并剩余参数组成特征码
	std::string pattern;
	for (size_t i = 2; i < cmd.parameters.size(); ++i) {
		if (!pattern.empty()) pattern += " ";
		pattern += cmd.parameters[i];
	}

	// 执行扫描
	uintptr_t address = m_patternScanner->ScanModule(moduleName, pattern);
	if (address == 0) {
		m_lastError = "Pattern not found";
		return false;
	}

	// 注册符号
	m_symbolManager->RegisterSymbol(symbolName, address);

	// 注册捕获的变量
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

	// 解析大小
	size_t size = 0;
	std::string sizeStr = cmd.parameters[1];
	if (sizeStr[0] == '$') {
		// 十六进制
		size = std::stoull(sizeStr.substr(1), nullptr, 16);
	}
	else {
		size = std::stoull(sizeStr, nullptr, 10);
	}

	// 获取附近地址（如果提供）
	uintptr_t nearAddress = 0;
	if (cmd.parameters.size() > 2) {
		m_symbolManager->GetSymbolAddress(cmd.parameters[2], nearAddress);
	}

	// 分配内存
	uintptr_t allocAddr = m_memoryAllocator->AllocateNear(nearAddress, size, allocName);
	if (allocAddr == 0) {
		m_lastError = "Failed to allocate memory";
		return false;
	}
	LOG_INFO_F("Memory allocated at: 0x%llX (size=0x%zX)", allocAddr, size);
	// 注册符号
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

	// Label通常在代码生成时确定地址
	// 这里只是预注册
	m_symbolManager->RegisterSymbol(labelName, 0, 0, true);

	return true;
}

bool CEAssemblyEngine::ProcessRegisterSymbol(const std::string& line) {
	ParsedCommand cmd = m_parser->ParseLine(line);
	if (cmd.parameters.empty()) {
		m_lastError = "Invalid registersymbol syntax";
		return false;
	}

	// 符号应该已经存在，这里只是标记为注册
	// 实际应用中，这会将符号导出到符号表

	return true;
}

bool CEAssemblyEngine::AssembleCode(const std::vector<std::string>& codeLines,
	uintptr_t baseAddress,
	std::vector<uint8_t>& output) {

	output.clear();
	uintptr_t currentAddr = baseAddress;

	// 结构体用于记录延迟处理的跳转
	struct DelayedJump {
		size_t outputOffset;     // 在output中的偏移
		uintptr_t instructionAddr;  // 指令地址
		std::string instruction;    // 原始指令
	};
	std::vector<DelayedJump> delayedJumps;

	for (const auto& line : codeLines) {
		// 替换符号
		std::string processedLine = ReplaceSymbols(line);
		std::istringstream iss(processedLine);
		std::string op;  iss >> op;
		std::transform(op.begin(), op.end(), op.begin(), ::tolower);

		if (op == "nop") {
			int count = 1;          // 默认单个 nop
			if (!(iss >> count))    // 如果后面跟了数字就读出来
				count = 1;
			for (int i = 0; i < count; ++i) {
				output.push_back(0x90);   // 0x90 = NOP
			}
			currentAddr += count;
			continue;               // 不再送给 keystone
		}

		// 检查是否包含需要自定义的符号跳转
		if (op == "jmp" || op == "call" || op == "je" || op == "jne" ||
			op == "jg" || op == "jge" || op == "jl" || op == "jle" ||
			op == "ja" || op == "jae" || op == "jb" || op == "jbe") {

			std::string operand;
			iss >> operand;

			// 先尝试处理跳转
			std::vector<uint8_t> jumpCode;
			if (ProcessJumpInstructions(processedLine, currentAddr, jumpCode)) {
				output.insert(output.end(), jumpCode.begin(), jumpCode.end());
				currentAddr += jumpCode.size();
				continue;
			}

			// 如果是符号但还未定义，记录下来延迟处理
			uintptr_t targetAddr;
			if (!operand.empty() && !m_symbolManager->GetSymbolAddress(operand, targetAddr)) {
				// 这可能是一个前向引用的标签
				DelayedJump dj;
				dj.outputOffset = output.size();
				dj.instructionAddr = currentAddr;
				dj.instruction = processedLine;
				delayedJumps.push_back(dj);

				// 临时填充占位符
				if (op == "jmp") {
					// 为FF 25指令预留6字节
					output.push_back(0x90);  // nop
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					currentAddr += 6;
				}
				else if (op == "call") {
					// call指令通常是5字节
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					output.push_back(0x90);
					currentAddr += 5;
				}
				else {
					// 条件跳转，使用6字节的形式
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

		// 使用Keystone汇编
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

	// 现在处理所有延迟的跳转
	for (const auto& dj : delayedJumps) {
		// 现在标签应该已经定义了
		std::vector<uint8_t> jumpCode;
		if (ProcessJumpInstructions(dj.instruction, dj.instructionAddr, jumpCode)) {
			// 替换占位符
			if (jumpCode.size() == 5) {
				// 标准的E9跳转，直接替换
				memcpy(&output[dj.outputOffset], jumpCode.data(), jumpCode.size());
			}
			else if (jumpCode.size() == 6) {
				// FF 25跳转
				memcpy(&output[dj.outputOffset], jumpCode.data(), jumpCode.size());
			}
			else if (jumpCode.size() == 12) {
				// mov rax/jmp rax形式，需要更多空间
				LOG_WARN_F("Delayed jump needs more space than reserved: %s", dj.instruction.c_str());
				// 这种情况比较复杂，可能需要重新组织代码
			}
		}
		else {
			// 最后尝试用Keystone汇编
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
	// 解析指令
	std::istringstream iss(instruction);
	std::string opcode, operand;
	iss >> opcode >> operand;

	// 转换为小写
	std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

	// 检查操作数是否是符号
	uintptr_t targetAddress;
	if (!m_symbolManager->GetSymbolAddress(operand, targetAddress)) {
		return false;  // 不是符号，让Keystone处理
	}

	// 特殊处理：如果目标地址还是0（前向引用），先返回false
	if (targetAddress == 0) {
		return false;
	}

	// 判断是否从INJECT跳转到newmem（需要跳转表）
	bool isInjectToNewmem = (m_currentLabel == "INJECT" && operand.find("code") != std::string::npos) ||
		(m_currentLabel == "INJECT" && operand.find("newmem") != std::string::npos);

	// 判断是否从newmem跳回return（也需要跳转表）
	bool isNewmemToReturn = (m_currentAddress < 0x7FF000000000) && operand == "return";

	if (opcode == "jmp") {
		// 计算相对偏移
		int64_t offset = targetAddress - (currentAddress + 5);

		// 如果是需要跳转表的情况
		if (isInjectToNewmem || isNewmemToReturn) {
			// 确定跳转表应该在哪个注入点附近
			uintptr_t injectPoint = currentAddress;
			if (isNewmemToReturn) {
				// 从newmem跳回时，需要找到原始的注入点
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

			// 获取或创建跳转表池
			MemoryAllocator::PoolInfo* pool = &EnsureJumpTableNear(injectPoint);

			// 计算跳转表项的地址
			uintptr_t tableEntry = pool->base + pool->used;

			if (isInjectToNewmem) {
				// 从INJECT跳转到跳转表：使用E9相对跳转
				int64_t tableOffset = tableEntry - (currentAddress + 5);
				if (tableOffset < INT32_MIN || tableOffset > INT32_MAX) {
					LOG_ERROR_F("Jump table at 0x%llX is too far from inject point 0x%llX", tableEntry, currentAddress);
					return false;
				}

				// 写入跳转表内容：FF 25 00000000 [8字节目标地址]
				uint8_t jumpTableData[14] = { 0 };
				jumpTableData[0] = 0xFF;
				jumpTableData[1] = 0x25;
				jumpTableData[2] = 0x00;
				jumpTableData[3] = 0x00;
				jumpTableData[4] = 0x00;
				jumpTableData[5] = 0x00;
				memcpy(&jumpTableData[6], &targetAddress, 8);

				// 写入跳转表
				if (m_processManager && m_processManager->GetHandle()) {
					DWORD oldProtect;
					m_processManager->ProtectMemory(tableEntry, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
					m_processManager->WriteMemory(tableEntry, jumpTableData, 14);
					m_processManager->ProtectMemory(tableEntry, 14, oldProtect, &oldProtect);
				}

				pool->used += 16; // 对齐到16字节

				LOG_INFO_F("Created jump table at 0x%llX: FF 25 -> 0x%llX", tableEntry, targetAddress);

				// 生成E9跳转到跳转表
				output.push_back(0xE9);
				int32_t offset32 = static_cast<int32_t>(tableOffset);
				output.push_back(offset32 & 0xFF);
				output.push_back((offset32 >> 8) & 0xFF);
				output.push_back((offset32 >> 16) & 0xFF);
				output.push_back((offset32 >> 24) & 0xFF);
				return true;
			}
			else if (isNewmemToReturn) {
				// 从newmem跳回return：需要创建新的跳转表项
				// 但是从newmem的位置，使用FF 25跳转到存储return地址的位置

				// 在跳转表中分配空间存储return地址
				uintptr_t returnAddressSlot = tableEntry;

				// 写入return地址到跳转表
				if (m_processManager && m_processManager->GetHandle()) {
					DWORD oldProtect;
					m_processManager->ProtectMemory(returnAddressSlot, 8, PAGE_READWRITE, &oldProtect);
					m_processManager->WriteMemory(returnAddressSlot, &targetAddress, 8);
					m_processManager->ProtectMemory(returnAddressSlot, 8, oldProtect, &oldProtect);
				}

				pool->used += 8;

				// 计算从当前位置到存储地址的偏移
				int64_t slotOffset = returnAddressSlot - (currentAddress + 6);

				// 如果跳转表太远，使用另一种方式
				if (slotOffset < INT32_MIN || slotOffset > INT32_MAX) {
					// 创建一个本地跳转表
					LOG_INFO_F("Creating local jump for return from 0x%llX to 0x%llX", currentAddress, targetAddress);

					// 在newmem后面创建一个跳转表项
					uintptr_t localJumpTable = (currentAddress + 0x100) & ~0xF; // 对齐

					// 申请这个地址
					if (m_processManager && m_processManager->GetHandle()) {
						// 先写入FF 25 00000000指令
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

					// 生成E9跳转到本地跳转表
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

				// 生成FF 25指令
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
			// 普通的近跳转
			output.push_back(0xE9);
			output.push_back(offset & 0xFF);
			output.push_back((offset >> 8) & 0xFF);
			output.push_back((offset >> 16) & 0xFF);
			output.push_back((offset >> 24) & 0xFF);
			return true;
		}
		else {
			// 距离太远，使用mov rax/jmp rax
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
		// call指令的处理...
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

	// 查找并替换所有符号
	std::regex symbolRegex(R"(\b([a-zA-Z_]\w*)\b)");
	std::smatch match;
	std::string temp = result;

	while (std::regex_search(temp, match, symbolRegex)) {
		std::string symbol = match[1];
		uint64_t value;

		// 检查是否是捕获的变量
		if (m_symbolManager->GetCapturedValue(symbol, value)) {
			// 替换为立即数
			std::stringstream ss;
			ss << "0x" << std::hex << value;
			result = std::regex_replace(result, std::regex("\\b" + symbol + "\\b"), ss.str());
		}

		temp = match.suffix();
	}

	return result;
}

bool CEAssemblyEngine::ProcessDisableBlock(const std::vector<std::string>& lines) {
	// 处理DISABLE块，主要是恢复原始字节
	for (const auto& line : lines) {
		ParsedCommand cmd = m_parser->ParseLine(line);

		switch (cmd.type) {
		case CommandType::DB:
			// 恢复原始字节
			// 这需要之前保存的信息
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