#include "CEAssemblyEngine.h"
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
    : m_currentScript(nullptr)
    , m_isExternal(false) {
    m_processManager = std::make_unique<ProcessManager>();
    m_symbolManager = std::make_unique<SymbolManager>();
    m_patternScanner = std::make_unique<PatternScanner>();
    m_memoryAllocator = std::make_unique<MemoryAllocator>();
    m_parser = std::make_unique<CEScriptParser>();

    // 初始化Keystone引擎 (x64)
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &m_ksEngine) != KS_ERR_OK) {
        m_lastError = "Failed to initialize Keystone engine";
        m_ksEngine = nullptr;
    }
}

CEAssemblyEngine::~CEAssemblyEngine() {
    if (m_ksEngine) {
        ks_close(m_ksEngine);
    }
}

bool CEAssemblyEngine::AttachToProcess(DWORD pid) {
    if (m_processManager->OpenProcess(pid)) {
        m_isExternal = true;

        // 更新其他组件以使用外部进程
        m_patternScanner->SetProcessManager(m_processManager.get());
        m_memoryAllocator->SetProcessManager(m_processManager.get());

        return true;
    }

    m_lastError = "Failed to attach to process";
    return false;
}

bool CEAssemblyEngine::AttachToProcess(const std::string& processName) {
    DWORD pid = ProcessManager::FindProcessByName(processName);
    if (pid == 0) {
        m_lastError = "Process not found: " + processName;
        return false;
    }

    return AttachToProcess(pid);
}

void CEAssemblyEngine::DetachFromProcess() {
    m_processManager->CloseProcess();
    m_isExternal = false;

    // 重置其他组件
    m_patternScanner->SetProcessManager(nullptr);
    m_memoryAllocator->SetProcessManager(nullptr);
}

bool CEAssemblyEngine::IsAttached() const {
    return m_isExternal && m_processManager->GetHandle() != nullptr;
}

DWORD CEAssemblyEngine::GetTargetPID() const {
    return m_processManager->GetPID();
}

std::shared_ptr<CEScript> CEAssemblyEngine::CreateScript(const std::string& name) {
    auto script = std::make_shared<CEScript>(this);

    // 如果提供了名称，使用它；否则生成一个唯一名称
    std::string scriptName = name;
    if (scriptName.empty()) {
        scriptName = "Script_" + std::to_string(m_scripts.size() + 1);
    }

    script->SetName(scriptName);
    m_scripts[scriptName] = script;

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
                return false;
            }
            collectingCode = false;
            break;

        case CommandType::ALLOC:
            if (!ProcessAlloc(line)) {
                return false;
            }
            collectingCode = false;
            break;

        case CommandType::LABEL:
            if (!ProcessLabel(line)) {
                return false;
            }
            collectingCode = false;
            break;

        case CommandType::REGISTERSYMBOL:
            if (!ProcessRegisterSymbol(line)) {
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
                        return false;
                    }

                    // 保存原始字节
                    std::vector<uint8_t> originalBytes(machineCode.size());

                    if (m_isExternal) {
                        // 跨进程读取
                        m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());
                    }
                    else {
                        // 本进程读取
                        memcpy(originalBytes.data(), reinterpret_cast<void*>(m_currentAddress), machineCode.size());
                    }

                    // 写入机器码
                    if (m_isExternal) {
                        // 跨进程写入
                        DWORD oldProtect;
                        if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
                            m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
                        }
                    }
                    else {
                        // 本进程写入
                        DWORD oldProtect;
                        if (VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
                            machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            memcpy(reinterpret_cast<void*>(m_currentAddress), machineCode.data(), machineCode.size());
                            VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
                                machineCode.size(), oldProtect, &oldProtect);
                        }
                    }

                    // 记录补丁
                    AddPatch(m_currentAddress, originalBytes, machineCode);

                    m_currentAddress += machineCode.size();
                    codeLines.clear();
                }

                // 处理新标签
                std::string labelName = line.substr(0, line.length() - 1);
                uintptr_t addr;
                if (m_symbolManager->GetSymbolAddress(labelName, addr)) {
                    m_currentAddress = addr;
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
            return false;
        }

        // 保存原始字节
        std::vector<uint8_t> originalBytes(machineCode.size());

        if (m_isExternal) {
            // 跨进程读取
            m_processManager->ReadMemory(m_currentAddress, originalBytes.data(), machineCode.size());
        }
        else {
            // 本进程读取
            memcpy(originalBytes.data(), reinterpret_cast<void*>(m_currentAddress), machineCode.size());
        }

        // 写入机器码
        if (m_isExternal) {
            // 跨进程写入
            DWORD oldProtect;
            if (m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                m_processManager->WriteMemory(m_currentAddress, machineCode.data(), machineCode.size());
                m_processManager->ProtectMemory(m_currentAddress, machineCode.size(), oldProtect, &oldProtect);
            }
        }
        else {
            // 本进程写入
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
                machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(reinterpret_cast<void*>(m_currentAddress), machineCode.data(), machineCode.size());
                VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
                    machineCode.size(), oldProtect, &oldProtect);
            }
        }

        // 记录补丁
        AddPatch(m_currentAddress, originalBytes, machineCode);
    }

    if (!codeLines.empty() && m_currentAddress != 0) {
        std::vector<uint8_t> machineCode;
        if (!AssembleCode(codeLines, m_currentAddress, machineCode)) {
            return false;
        }

        // 保存原始字节
        std::vector<uint8_t> originalBytes(machineCode.size());
        memcpy(originalBytes.data(), reinterpret_cast<void*>(m_currentAddress), machineCode.size());

        DWORD oldProtect;
        if (VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
            machineCode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(reinterpret_cast<void*>(m_currentAddress), machineCode.data(), machineCode.size());
            VirtualProtect(reinterpret_cast<LPVOID>(m_currentAddress),
                machineCode.size(), oldProtect, &oldProtect);

            // 记录补丁
            AddPatch(m_currentAddress, originalBytes, machineCode);
        }
    }

    return true;
}

// 处理剩余的代码


bool CEAssemblyEngine::ProcessAobScanModule(const std::string& line) {
    ParsedCommand cmd = m_parser->ParseLine(line);
    if (cmd.parameters.size() < 3) {
        m_lastError = "Invalid aobscanmodule syntax";
        return false;
    }

    std::string symbolName = cmd.parameters[0];
    std::string moduleName = cmd.parameters[1];

    // 合并剩余参数作为特征码
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

    // 注册符号
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
    // 实际游戏中，这会将符号导出到符号表

    return true;
}

bool CEAssemblyEngine::AssembleCode(const std::vector<std::string>& codeLines,
    uintptr_t baseAddress,
    std::vector<uint8_t>& output) {
    output.clear();
    uintptr_t currentAddr = baseAddress;

    for (const auto& line : codeLines) {
        // 替换符号
        std::string processedLine = ReplaceSymbols(line);

        // 检查是否包含我们自定义的符号跳转
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

        // 使用Keystone汇编
        unsigned char* encode;
        size_t size;
        size_t count;

        if (ks_asm(m_ksEngine, processedLine.c_str(), currentAddr, &encode, &size, &count) == KS_ERR_OK) {
            output.insert(output.end(), encode, encode + size);
            currentAddr += size;
            ks_free(encode);
        }
        else {
            m_lastError = "Assembly failed: " + processedLine;
            return false;
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

    // 计算相对偏移
    int64_t offset = targetAddress - (currentAddress + 5);  // 5是jmp指令的大小

    // 检查是否可以使用短跳转
    if (opcode == "jmp") {
        if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
            // 使用近跳转 (E9 xx xx xx xx)
            output.push_back(0xE9);
            output.push_back(offset & 0xFF);
            output.push_back((offset >> 8) & 0xFF);
            output.push_back((offset >> 16) & 0xFF);
            output.push_back((offset >> 24) & 0xFF);
            return true;
        }
        else {
            // 需要远跳转，使用间接跳转
            // mov rax, targetAddress
            output.push_back(0x48);
            output.push_back(0xB8);
            for (int i = 0; i < 8; ++i) {
                output.push_back((targetAddress >> (i * 8)) & 0xFF);
            }
            // jmp rax
            output.push_back(0xFF);
            output.push_back(0xE0);
            return true;
        }
    }
    else if (opcode == "call") {
        if (offset >= -0x80000000LL && offset <= 0x7FFFFFFFLL) {
            // 使用近调用 (E8 xx xx xx xx)
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