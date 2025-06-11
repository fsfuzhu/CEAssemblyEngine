// PassManager.cpp - 修复所有编译错误的完整版本
#include "PassManager.h"
#include "Core/CEAssemblyEngine.h"
#include "Symbol/SymbolManager.h"
#include "Core/MemoryManager.h"
#include "Scanner/PatternScanner.h"
#include "Parser/CEScriptParser.h"
#include "Utils/DebugHelper.h"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <set>
#include <map>
#include <regex>
#include <unordered_set>
bool isX64RegisterName(const std::string& token);
// ==================== PassManager 实现 ====================

PassManager::PassManager() {
    // 使用新的两遍汇编策略
    AddPass(std::make_unique<PreprocessingPass>());
    AddPass(std::make_unique<SymbolCollectionPass>());
    AddPass(std::make_unique<TwoPassAssemblyPass>());
    AddPass(std::make_unique<CodeEmissionPass>());
}

PassManager::~PassManager() = default;

void PassManager::AddPass(std::unique_ptr<ProcessingPass> pass) {
    m_passes.push_back(std::move(pass));
}

bool PassManager::RunAllPasses(const std::vector<std::string>& lines, CEAssemblyEngine* engine) {
    LOG_INFO("=== Starting Multi-Pass Processing ===");

    // 将原始行转换为指令上下文
    ConvertLinesToInstructions(lines);

    if (m_instructions.empty()) {
        LOG_WARN("No instructions to process");
        return true;
    }

    // 执行每个 Pass
    for (size_t passIndex = 0; passIndex < m_passes.size(); ++passIndex) {
        auto& pass = m_passes[passIndex];
        LOG_INFO_F("=== Pass %zu: %s ===", passIndex + 1, pass->GetName().c_str());

        int maxIterations = pass->RequiresIteration() ? 10 : 1;
        bool stabilized = false;

        for (int iteration = 0; iteration < maxIterations && !stabilized; ++iteration) {
            if (iteration > 0) {
                LOG_DEBUG_F("  Iteration %d", iteration + 1);
            }

            PassResult result = pass->Execute(m_instructions, engine);

            if (!result.success) {
                m_lastError = "Pass " + pass->GetName() + " failed: " + result.errorMessage;
                LOG_ERROR(m_lastError.c_str());
                return false;
            }

            // 打印警告
            for (const auto& warning : result.warnings) {
                LOG_WARN_F("  Warning: %s", warning.c_str());
            }

            LOG_DEBUG_F("  Processed: %d, Modified: %d",
                result.instructionsProcessed, result.instructionsModified);

            // 检查是否稳定（没有修改）
            if (result.instructionsModified == 0) {
                stabilized = true;
            }
        }

        if (!stabilized && pass->RequiresIteration()) {
            LOG_WARN_F("Pass %s did not stabilize after %d iterations",
                pass->GetName().c_str(), maxIterations);
        }
    }

    LOG_INFO("=== Multi-Pass Processing Completed ===");
    return true;
}

void PassManager::ConvertLinesToInstructions(const std::vector<std::string>& lines) {
    m_instructions.clear();
    m_instructions.reserve(lines.size());

    CEScriptParser parser;

    for (const auto& line : lines) {
        InstructionContext ctx;
        ctx.originalLine = line;
        ctx.processedLine = line;

        // 解析命令
        ParsedCommand cmd = parser.ParseLine(line);
        ctx.commandType = cmd.type;
        ctx.parameters = cmd.parameters;

        // 检查是否是标签定义
        if (!line.empty() && line.back() == ':') {
            ctx.isLabelDef = true;
            ctx.labelName = line.substr(0, line.length() - 1);
        }

        m_instructions.push_back(ctx);
    }
}

void PassManager::GetStatistics(int& totalPasses, int& totalInstructions) const {
    totalPasses = static_cast<int>(m_passes.size());
    totalInstructions = static_cast<int>(m_instructions.size());
}

// ==================== PreprocessingPass 实现 ====================


PassResult PreprocessingPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_DEBUG_F("=== Pass 1: %s ===", GetName().c_str());

    // 完整的 x86/x64 寄存器集合
    static const std::set<std::string> allRegisters = {
        // 64位通用寄存器
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",

        // 32位通用寄存器
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",

        // 16位通用寄存器
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",

        // 8位通用寄存器
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",

        // 段寄存器
        "cs", "ds", "es", "fs", "gs", "ss",

        // 控制寄存器
        "cr0", "cr2", "cr3", "cr4", "cr8",

        // 调试寄存器
        "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",

        // MMX 寄存器
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",

        // XMM 寄存器 (SSE)
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",

        // YMM 寄存器 (AVX)
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
        "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",

        // ZMM 寄存器 (AVX-512)
        "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
        "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
        "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
        "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",

        // FPU 寄存器
        "st", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",

        // 特殊寄存器
        "rip", "eip", "ip",
        "rflags", "eflags", "flags"
    };

    // 汇编指令助记符集合（用于识别）
    static const std::set<std::string> mnemonics = {
        // 数据传输
        "mov", "movsx", "movzx", "movsxd", "movabs", "lea", "xchg", "push", "pop",
        "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",

        // 算术运算
        "add", "sub", "adc", "sbb", "mul", "imul", "div", "idiv", "inc", "dec", "neg",

        // 逻辑运算
        "and", "or", "xor", "not", "test", "cmp",

        // 移位和旋转
        "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr",

        // 跳转和调用
        "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "js", "jns", "jo", "jno", "jc", "jnc", "jp", "jnp", "jpe", "jpo",
        "jecxz", "jrcxz", "loop", "loope", "loopne", "call", "ret", "retn",

        // 字符串操作
        "movs", "movsb", "movsw", "movsd", "movsq",
        "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scas", "scasb", "scasw", "scasd", "scasq",
        "lods", "lodsb", "lodsw", "lodsd", "lodsq",
        "stos", "stosb", "stosw", "stosd", "stosq",
        "rep", "repe", "repz", "repne", "repnz",

        // SSE/AVX 指令
        "movss", "movsd", "movaps", "movups", "movapd", "movupd",
        "addss", "addsd", "addps", "addpd", "subss", "subsd", "subps", "subpd",
        "mulss", "mulsd", "mulps", "mulpd", "divss", "divsd", "divps", "divpd",
        "sqrtss", "sqrtsd", "sqrtps", "sqrtpd",
        "comiss", "comisd", "ucomiss", "ucomisd",
        "xorps", "xorpd", "pxor",

        // 其他
        "nop", "int", "int3", "syscall", "sysenter", "sysexit", "cpuid",
        "pause", "lock", "hlt", "cli", "sti", "cld", "std"
    };

    // 大小指示符
    static const std::set<std::string> sizeSpecifiers = {
        "byte", "word", "dword", "qword", "tbyte", "oword", "xmmword", "ymmword", "zmmword",
        "ptr", "near", "far", "short"
    };

    // 数据定义指令
    static const std::set<std::string> dataDirectives = {
        "db", "dw", "dd", "dq", "dt", "do", "dy", "dz"
    };

    for (auto& ctx : instructions) {
        result.instructionsProcessed++;

        if (ctx.originalLine.empty()) continue;

        // 1. 检查是否是标签定义（以冒号结尾）
        if (ctx.originalLine.back() == ':') {
            ctx.isLabelDef = true;
            ctx.labelName = ctx.originalLine.substr(0, ctx.originalLine.length() - 1);
            ctx.commandType = CommandType::ASSEMBLY;

            LOG_DEBUG_F("Label definition: %s", ctx.labelName.c_str());

            // 处理 label+offset 语法
            if (ctx.labelName.find('+') != std::string::npos) {
                ctx.needsSymbolResolution = true;
                size_t plusPos = ctx.labelName.find('+');
                std::string baseName = ctx.labelName.substr(0, plusPos);
                ctx.unresolvedSymbols.push_back(baseName);
                LOG_TRACE_F("Label with offset: %s (base: %s)", ctx.labelName.c_str(), baseName.c_str());
            }

            continue;
        }

        // 2. 处理 (float) 转换
        if (ctx.processedLine.find("(float)") != std::string::npos) {
            std::string processed = engine->ProcessFloatConversion(ctx.processedLine);
            if (processed != ctx.processedLine) {
                ctx.processedLine = processed;
                result.instructionsModified++;
                LOG_TRACE_F("Float conversion: %s -> %s", ctx.originalLine.c_str(), processed.c_str());
            }
        }

        // 3. 分析指令和符号依赖
        if (ctx.commandType == CommandType::ASSEMBLY && !ctx.isLabelDef) {
            // 详细的词法分析
            std::istringstream iss(ctx.processedLine);
            std::string firstToken;
            iss >> firstToken;

            if (!firstToken.empty()) {
                std::string lowerFirst = firstToken;
                std::transform(lowerFirst.begin(), lowerFirst.end(), lowerFirst.begin(), ::tolower);

                // 检查是否是数据定义
                if (dataDirectives.find(lowerFirst) != dataDirectives.end()) {
                    LOG_TRACE_F("Data directive: %s", ctx.originalLine.c_str());
                    // 数据定义可能包含符号
                    std::string token;
                    while (iss >> token) {
                        if (token != "," && !isdigit(token[0]) && token.find("0x") != 0) {
                            ctx.needsSymbolResolution = true;
                            ctx.unresolvedSymbols.push_back(token);
                        }
                    }
                    continue;
                }

                // 检查是否包含 @f 或 @b
                if (ctx.processedLine.find("@f") != std::string::npos ||
                    ctx.processedLine.find("@b") != std::string::npos) {
                    ctx.needsSymbolResolution = true;
                    LOG_TRACE_F("CE special jump: %s", ctx.originalLine.c_str());
                }

                // 重新开始分析，查找所有可能的符号
                iss.clear();
                iss.seekg(0);

                std::string token;
                bool inBrackets = false;
                bool afterComma = false;

                while (iss >> token) {
                    // 跳过分隔符
                    if (token == "," || token == "+" || token == "-" || token == "*") {
                        if (token == ",") afterComma = true;
                        continue;
                    }

                    // 处理方括号
                    if (token.find('[') != std::string::npos) inBrackets = true;
                    if (token.find(']') != std::string::npos) inBrackets = false;

                    // 去除方括号
                    size_t bracketPos = token.find('[');
                    if (bracketPos != std::string::npos) {
                        token = token.substr(bracketPos + 1);
                    }
                    bracketPos = token.find(']');
                    if (bracketPos != std::string::npos) {
                        token = token.substr(0, bracketPos);
                    }

                    // 转小写用于比较
                    std::string lowerToken = token;
                    std::transform(lowerToken.begin(), lowerToken.end(), lowerToken.begin(), ::tolower);

                    // 跳过已知的元素
                    if (allRegisters.find(lowerToken) != allRegisters.end()) continue;
                    if (mnemonics.find(lowerToken) != mnemonics.end()) continue;
                    if (sizeSpecifiers.find(lowerToken) != sizeSpecifiers.end()) continue;
                    if (token.empty()) continue;

                    // 检查是否是数字
                    bool isNumber = false;
                    if (isdigit(token[0]) || token[0] == '-') {
                        isNumber = true;
                    }
                    else if (token.find("0x") == 0 || token.find("0X") == 0) {
                        isNumber = true;
                    }
                    else if (token[0] == '$') {
                        // CE 的十六进制表示法
                        isNumber = true;
                    }

                    // 如果不是数字，可能是符号
                    if (!isNumber && !token.empty()) {
                        ctx.needsSymbolResolution = true;
                        ctx.unresolvedSymbols.push_back(token);
                        LOG_TRACE_F("Potential symbol: %s", token.c_str());
                    }
                }
            }
        }

        // 4. 特殊处理某些指令
        if (ctx.commandType == CommandType::ASSEMBLY) {
            std::string opcode;
            std::istringstream iss(ctx.processedLine);
            iss >> opcode;
            std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

            // NOP 指令特殊标记
            if (opcode == "nop") {
                LOG_TRACE_F("NOP instruction: %s", ctx.originalLine.c_str());
            }
        }
    }

    // 输出统计信息
    LOG_DEBUG_F("Preprocessing completed:");
    LOG_DEBUG_F("  Total instructions: %d", result.instructionsProcessed);
    LOG_DEBUG_F("  Modified instructions: %d", result.instructionsModified);

    int labelsCount = 0;
    int symbolsNeeded = 0;
    for (const auto& ctx : instructions) {
        if (ctx.isLabelDef) labelsCount++;
        if (ctx.needsSymbolResolution) symbolsNeeded++;
    }

    LOG_DEBUG_F("  Label definitions: %d", labelsCount);
    LOG_DEBUG_F("  Instructions needing symbol resolution: %d", symbolsNeeded);

    return result;
}

// ==================== SymbolCollectionPass 实现 ====================

PassResult SymbolCollectionPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    auto symbolMgr = engine->GetSymbolManager();
    auto memoryMgr = engine->GetMemoryManager();
    auto scanner = engine->GetPatternScanner();

    for (auto& ctx : instructions) {
        result.instructionsProcessed++;

        switch (ctx.commandType) {
        case CommandType::AOBSCANMODULE:
            if (ctx.parameters.size() >= 3) {
                std::string symbolName = ctx.parameters[0];
                std::string moduleName = ctx.parameters[1];

                // 构建模式字符串
                std::string pattern;
                for (size_t i = 2; i < ctx.parameters.size(); ++i) {
                    if (!pattern.empty()) pattern += " ";
                    pattern += ctx.parameters[i];
                }

                // 执行扫描
                uintptr_t address = scanner->ScanModule(moduleName, pattern);

                if (address == 0) {
                    result.success = false;
                    result.errorMessage = "Pattern not found for " + symbolName;
                    return result;
                }

                symbolMgr->RegisterSymbol(symbolName, address);
                LOG_INFO_F("Symbol '%s' found at 0x%llX", symbolName.c_str(), address);

                // 处理捕获的变量
                auto capturedVars = scanner->GetCapturedVariables();
                for (const auto& [name, data] : capturedVars) {
                    symbolMgr->RegisterCapturedData(name, data);
                }
                scanner->ClearCapturedVariables();
            }
            break;

        case CommandType::ALLOC:
            if (ctx.parameters.size() >= 2) {
                std::string allocName = ctx.parameters[0];

                // 解析大小
                size_t size = 0;
                std::string sizeStr = ctx.parameters[1];
                if (sizeStr[0] == '$') {
                    size = std::stoull(sizeStr.substr(1), nullptr, 16);
                }
                else {
                    size = std::stoull(sizeStr, nullptr, 10);
                }

                // 获取附近地址
                uintptr_t nearAddress = 0;
                if (ctx.parameters.size() > 2) {
                    symbolMgr->GetSymbolAddress(ctx.parameters[2], nearAddress);
                }

                // 分配内存
                uintptr_t allocAddr = memoryMgr->AllocateNear(nearAddress, size, allocName);
                if (allocAddr == 0) {
                    result.success = false;
                    result.errorMessage = "Failed to allocate memory for " + allocName;
                    return result;
                }

                symbolMgr->RegisterSymbol(allocName, allocAddr, size);
                LOG_INFO_F("Allocated %s at 0x%llX (size: 0x%zX)",
                    allocName.c_str(), allocAddr, size);
            }
            break;

        case CommandType::LABEL:
            if (!ctx.parameters.empty()) {
                std::string labelName = ctx.parameters[0];
                // 所有标签初始都注册为地址0，后续pass会更新
                symbolMgr->RegisterSymbol(labelName, 0, 0, true);
                LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
            }
            break;

        case CommandType::REGISTERSYMBOL:
            // 这个在后面的 Pass 中处理
            break;

        default:
            break;
        }
    }

    return result;
}

// ==================== TwoPassAssemblyPass 实现 ====================

PassResult TwoPassAssemblyPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_INFO_F("=== %s ===", GetName().c_str());

    // 收集所有匿名标签
    std::vector<uintptr_t> anonymousLabels;
    std::map<uintptr_t, std::string> allLabels;

    // 迭代直到稳定
    const int MAX_ITERATIONS = 10;
    bool stabilized = false;

    for (int iteration = 0; iteration < MAX_ITERATIONS && !stabilized; iteration++) {
        if (iteration > 0) {
            LOG_DEBUG_F("Iteration %d", iteration + 1);
        }

        // 第一遍：计算大小和分配地址
        LOG_DEBUG("Pass 1: Size calculation and address assignment");
        bool sizeChanged = CalculateSizesAndAddresses(instructions, engine, result.warnings);

        // 收集标签信息
        anonymousLabels.clear();
        allLabels.clear();
        for (const auto& ctx : instructions) {
            if (ctx.isLabelDef && ctx.address != 0) {
                if (ctx.labelName == "@@") {
                    anonymousLabels.push_back(ctx.address);
                }
                allLabels[ctx.address] = ctx.labelName;
            }
        }

        // 设置标签信息
        engine->SetAnonymousLabels(anonymousLabels);

        // After first pass, before second pass
        LOG_DEBUG("Registering all labels in symbol table");
        auto symbolMgr = engine->GetSymbolManager();  // Get the symbol manager
        for (const auto& ctx : instructions) {
            if (ctx.isLabelDef && ctx.address != 0) {
                symbolMgr->RegisterSymbol(ctx.labelName, ctx.address, 0, true);
                LOG_DEBUG_F("Registered label %s at 0x%llX",
                    ctx.labelName.c_str(), ctx.address);
            }
        }

        // 第二遍：生成机器码
        LOG_DEBUG("Pass 2: Machine code generation");
        bool codeGenSuccess = GenerateMachineCode(instructions, engine, result.warnings);

        if (!codeGenSuccess) {
            result.success = false;
            result.errorMessage = "Failed to generate machine code";
            return result;
        }

        // 检查是否稳定
        stabilized = !sizeChanged;

        // 统计
        result.instructionsProcessed = 0;
        result.instructionsModified = 0;
        for (const auto& ctx : instructions) {
            if (ctx.commandType == CommandType::ASSEMBLY && !ctx.isLabelDef) {
                result.instructionsProcessed++;
                if (ctx.assembled) {
                    result.instructionsModified++;
                }
            }
        }
    }

    if (!stabilized) {
        LOG_WARN_F("Assembly did not stabilize after %d iterations", MAX_ITERATIONS);
    }

    return result;
}

bool TwoPassAssemblyPass::CalculateSizesAndAddresses(std::vector<InstructionContext>& instructions,
    CEAssemblyEngine* engine,
    std::vector<std::string>& warnings) {
    auto symbolMgr = engine->GetSymbolManager();
    auto ksEngine = engine->GetKeystoneEngine();

    if (!ksEngine) {
        LOG_ERROR("Keystone engine not available");
        return false;
    }

    uintptr_t currentAddress = 0;
    bool anyAddressChanged = false;

    // First pass: process all labels to ensure they have addresses
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // Handle label definitions
        if (ctx.isLabelDef) {
            uintptr_t newAddress = 0;

            // Check if symbol already has an address (like newmem from alloc)
            uintptr_t symbolAddr = 0;
            if (symbolMgr->GetSymbolAddress(ctx.labelName, symbolAddr) && symbolAddr != 0) {
                newAddress = symbolAddr;
                LOG_DEBUG_F("Label %s using allocated address: 0x%llX",
                    ctx.labelName.c_str(), newAddress);
            }
            // Handle label+offset syntax
            else if (ctx.labelName.find('+') != std::string::npos) {
                size_t plusPos = ctx.labelName.find('+');
                std::string baseName = ctx.labelName.substr(0, plusPos);
                std::string offsetStr = ctx.labelName.substr(plusPos + 1);

                uintptr_t baseAddr = 0;
                if (symbolMgr->GetSymbolAddress(baseName, baseAddr) && baseAddr != 0) {
                    size_t offset = std::stoull(offsetStr, nullptr, 16);
                    newAddress = baseAddr + offset;
                }
            }

            // Update address
            if (newAddress != 0) {
                if (ctx.address != newAddress) {
                    anyAddressChanged = true;
                    ctx.address = newAddress;
                }
                currentAddress = newAddress;

                // Update symbol table
                symbolMgr->RegisterSymbol(ctx.labelName, newAddress, 0, true);
                LOG_TRACE_F("Label %s at 0x%llX", ctx.labelName.c_str(), newAddress);
            }
        }
    }

    // Second pass: process all instructions
    currentAddress = 0;
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // For labels, use their established address
        if (ctx.isLabelDef && ctx.address != 0) {
            currentAddress = ctx.address;

            // Make sure the label is registered in the symbol table
            symbolMgr->RegisterSymbol(ctx.labelName, currentAddress, 0, true);

            LOG_DEBUG_F("Setting current address to label %s: 0x%llX",
                ctx.labelName.c_str(), currentAddress);
            continue;
        }

        // Skip if no current address
        if (currentAddress == 0) {
            LOG_TRACE_F("Skipping instruction (no address): %s", ctx.originalLine.c_str());
            continue;
        }

        // Assign address to instruction
        if (ctx.address != currentAddress) {
            anyAddressChanged = true;
            ctx.address = currentAddress;
        }

        // Special instruction processing
        if (ProcessSpecialInstruction(ctx, engine)) {
            currentAddress += ctx.actualSize;
            ctx.sizeCalculated = true;
            continue;
        }

        // Prepare assembled instruction
        std::string asmLine = engine->ReplaceSymbols(ctx.processedLine);

        // Use Keystone to get instruction size
        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            if (ctx.actualSize != size) {
                anyAddressChanged = true;
                ctx.actualSize = size;
            }
            ctx.sizeCalculated = true;
            ks_free(encode);
        }
        else {
            // Use conservative estimate
            size_t estimatedSize = 8;
            if (ctx.actualSize != estimatedSize) {
                anyAddressChanged = true;
                ctx.actualSize = estimatedSize;
            }
        }

        currentAddress += ctx.actualSize;
    }

    return anyAddressChanged;
}

bool TwoPassAssemblyPass::GenerateMachineCode(std::vector<InstructionContext>& instructions,
    CEAssemblyEngine* engine,
    std::vector<std::string>& warnings) {
    auto ksEngine = engine->GetKeystoneEngine();
    if (!ksEngine) return false;

    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY || ctx.isLabelDef) continue;
        if (ctx.address == 0) {
            LOG_TRACE_F("Skipping instruction with no address: %s", ctx.originalLine.c_str());
            continue;
        }

        LOG_DEBUG_F("Processing instruction at 0x%llX: %s",
            ctx.address, ctx.originalLine.c_str());

        // If already has machine code, skip
        if (!ctx.machineCode.empty()) {
            ctx.assembled = true;
            continue;
        }

        // Special instruction processing
        if (ProcessSpecialInstruction(ctx, engine)) {
            ctx.assembled = true;
            continue;
        }

        // Process @f/@b jumps
        if (ctx.processedLine.find("@f") != std::string::npos ||
            ctx.processedLine.find("@b") != std::string::npos) {
            if (engine->ProcessCESpecialJump(ctx.processedLine, ctx.address, ctx.machineCode)) {
                ctx.assembled = true;
                continue;
            }
        }

        // 新增：特殊处理包含符号的jmp/call指令
        std::istringstream iss(ctx.processedLine);
        std::string opcode;
        iss >> opcode;
        std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

        if ((opcode == "jmp" || opcode == "call") && ctx.processedLine.find(' ') != std::string::npos) {
            std::string target;
            iss >> target;

            // 检查目标是否是符号
            auto symbolMgr = engine->GetSymbolManager();
            uintptr_t targetAddr = 0;

            if (symbolMgr->GetSymbolAddress(target, targetAddr) && targetAddr != 0) {
                // 直接生成跳转机器码
                if (engine->GenerateJumpBytes(opcode, ctx.address, targetAddr, ctx.machineCode)) {
                    ctx.assembled = true;
                    LOG_DEBUG_F("Generated %s to %s (0x%llX) directly",
                        opcode.c_str(), target.c_str(), targetAddr);
                    continue;
                }
            }
        }

        // Normal assembly
        std::string asmLine = engine->ReplaceSymbols(ctx.processedLine);
        LOG_DEBUG_F("Assembling at 0x%llX: '%s' -> '%s'",
            ctx.address, ctx.processedLine.c_str(), asmLine.c_str());

        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            ctx.machineCode.assign(encode, encode + size);
            ctx.assembled = true;
            ks_free(encode);
        }
        else {
            ks_err err = ks_errno(ksEngine);
            warnings.push_back("Assembly failed for '" + ctx.originalLine + "': " + ks_strerror(err));
        }
    }

    return true;
}

bool TwoPassAssemblyPass::ProcessSpecialInstruction(InstructionContext& ctx, CEAssemblyEngine* engine) {
    std::string opcode;
    std::istringstream iss(ctx.processedLine);
    iss >> opcode;
    std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

    // NOP 指令
    if (opcode == "nop") {
        int nopCount = 1;
        std::string arg;
        if (iss >> arg) {
            try {
                nopCount = std::stoi(arg);
            }
            catch (...) {
                nopCount = 1;
            }
        }

        ctx.actualSize = nopCount;
        ctx.machineCode.assign(nopCount, 0x90);
        return true;
    }

    // 数据指令
    if (opcode == "db" || opcode == "dw" || opcode == "dd" || opcode == "dq") {
        std::vector<uint8_t> dataBytes;
        if (engine->ProcessDataDirective(ctx.processedLine, dataBytes)) {
            ctx.actualSize = dataBytes.size();
            ctx.machineCode = std::move(dataBytes);
            return true;
        }
    }

    return false;
}

size_t TwoPassAssemblyPass::CalculateDataSize(const std::string& line) {
    std::istringstream iss(line);
    std::string directive;
    iss >> directive;
    std::transform(directive.begin(), directive.end(), directive.begin(), ::tolower);

    size_t multiplier = 1;
    if (directive == "db") multiplier = 1;
    else if (directive == "dw") multiplier = 2;
    else if (directive == "dd") multiplier = 4;
    else if (directive == "dq") multiplier = 8;
    else return 0;

    size_t count = 0;
    std::string value;
    while (iss >> value) {
        if (value != ",") count++;
    }

    return count * multiplier;
}

// ==================== CodeEmissionPass 实现 ====================
// 完整的代码写入 Pass 实现

PassResult CodeEmissionPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_INFO_F("=== Pass: %s ===", GetName().c_str());

    auto memoryMgr = engine->GetMemoryManager();
    if (!memoryMgr) {
        result.success = false;
        result.errorMessage = "Memory manager not available";
        LOG_ERROR("Memory manager not available");
        return result;
    }

    // 检查是否已附加到进程
    if (!memoryMgr->IsAttached()) {
        result.success = false;
        result.errorMessage = "Not attached to any process";
        LOG_ERROR("Not attached to any process");
        return result;
    }

    // 收集所有需要写入的指令
    struct WriteOperation {
        uintptr_t address;
        std::vector<uint8_t> originalBytes;
        std::vector<uint8_t> newBytes;
        std::string description;
        bool critical;  // 是否是关键操作（如主要的 hook 点）
    };

    std::vector<WriteOperation> writeOps;

    // 第一步：准备所有写入操作
    LOG_DEBUG("Preparing write operations...");

    for (const auto& ctx : instructions) {
        if (ctx.machineCode.empty() || ctx.address == 0) continue;
        if (ctx.isLabelDef) continue;  // 跳过标签定义

        WriteOperation op;
        op.address = ctx.address;
        op.newBytes = ctx.machineCode;
        op.originalBytes.resize(ctx.machineCode.size());
        op.description = ctx.originalLine;

        // 判断是否是关键操作
        op.critical = false;
        if (ctx.originalLine.find("jmp") == 0 || ctx.originalLine.find("call") == 0) {
            // 主要的跳转和调用通常是关键的
            op.critical = true;
        }

        writeOps.push_back(op);
    }

    if (writeOps.empty()) {
        LOG_INFO("No code to write");
        return result;
    }

    LOG_INFO_F("Preparing to write %zu operations", writeOps.size());

    // 第二步：读取所有原始字节
    LOG_DEBUG("Reading original bytes...");

    for (auto& op : writeOps) {
        if (!memoryMgr->ReadMemory(op.address, op.originalBytes.data(), op.originalBytes.size())) {
            LOG_WARN_F("Failed to read original bytes at 0x%llX (size: %zu)",
                op.address, op.originalBytes.size());
            result.warnings.push_back("Failed to read original bytes at 0x" +
                std::to_string(op.address));

            // 对于非关键操作，继续；对于关键操作，失败
            if (op.critical) {
                result.success = false;
                result.errorMessage = "Failed to read critical memory region";
                return result;
            }
        }
        else {
            // 记录原始字节（用于调试）
            if (DebugHelper::GetLevel() >= DebugLevel::Trace) {
                std::stringstream hexDump;
                hexDump << "Original bytes at 0x" << std::hex << op.address << ": ";
                for (size_t i = 0; i < op.originalBytes.size() && i < 16; i++) {
                    hexDump << std::setw(2) << std::setfill('0')
                        << (int)op.originalBytes[i] << " ";
                }
                if (op.originalBytes.size() > 16) hexDump << "...";
                LOG_TRACE(hexDump.str().c_str());
            }
        }
    }

    // 第三步：批量修改内存保护
    LOG_DEBUG("Changing memory protection...");

    struct ProtectionChange {
        uintptr_t address;
        size_t size;
        DWORD oldProtect;
        bool changed;
    };

    std::vector<ProtectionChange> protChanges;

    // 合并相邻的内存区域以减少保护更改次数
    for (const auto& op : writeOps) {
        bool merged = false;

        // 尝试与现有的保护更改合并
        for (auto& prot : protChanges) {
            // 如果地址相邻或重叠
            if (op.address >= prot.address &&
                op.address <= prot.address + prot.size + 0x1000) {  // 4KB 容差

                // 扩展区域
                uintptr_t endAddr = std::max(prot.address + prot.size,
                    op.address + op.newBytes.size());
                prot.size = endAddr - prot.address;
                merged = true;
                break;
            }
        }

        if (!merged) {
            ProtectionChange prot;
            prot.address = op.address;
            prot.size = op.newBytes.size();
            prot.oldProtect = 0;
            prot.changed = false;
            protChanges.push_back(prot);
        }
    }

    // 执行内存保护更改
    for (auto& prot : protChanges) {
        if (memoryMgr->ProtectMemory(prot.address, prot.size,
            PAGE_EXECUTE_READWRITE, &prot.oldProtect)) {
            prot.changed = true;
            LOG_DEBUG_F("Changed protection at 0x%llX (size: 0x%zX, old: 0x%X)",
                prot.address, prot.size, prot.oldProtect);
        }
        else {
            LOG_ERROR_F("Failed to change protection at 0x%llX (error: %d)",
                prot.address, GetLastError());
            result.warnings.push_back("Failed to change protection at 0x" +
                std::to_string(prot.address));
        }
    }

    // 第四步：写入新代码
    LOG_DEBUG("Writing new code...");

    int successCount = 0;
    int failCount = 0;

    for (const auto& op : writeOps) {
        result.instructionsProcessed++;

        if (!memoryMgr->WriteMemory(op.address, op.newBytes.data(), op.newBytes.size())) {
            DWORD error = GetLastError();
            LOG_ERROR_F("Failed to write %zu bytes at 0x%llX (error: %d): %s",
                op.newBytes.size(), op.address, error, op.description.c_str());

            result.warnings.push_back("Failed to write at 0x" + std::to_string(op.address) +
                " (" + op.description + ")");
            failCount++;

            if (op.critical) {
                result.success = false;
                result.errorMessage = "Failed to write critical instruction";
            }
        }
        else {
            // 记录补丁信息
            engine->AddPatch(op.address, op.originalBytes, op.newBytes);

            successCount++;
            result.instructionsModified++;

            LOG_DEBUG_F("Wrote %zu bytes at 0x%llX: %s",
                op.newBytes.size(), op.address, op.description.c_str());

            // 详细的调试输出
            if (DebugHelper::GetLevel() >= DebugLevel::Trace) {
                std::stringstream hexDump;
                hexDump << "  New bytes: ";
                for (size_t i = 0; i < op.newBytes.size() && i < 32; i++) {
                    hexDump << std::hex << std::setw(2) << std::setfill('0')
                        << (int)op.newBytes[i] << " ";
                }
                if (op.newBytes.size() > 32) hexDump << "...";
                LOG_TRACE(hexDump.str().c_str());
            }
        }
    }

    // 第五步：恢复内存保护
    LOG_DEBUG("Restoring memory protection...");

    for (const auto& prot : protChanges) {
        if (prot.changed) {
            DWORD dummy;
            if (!memoryMgr->ProtectMemory(prot.address, prot.size, prot.oldProtect, &dummy)) {
                LOG_WARN_F("Failed to restore protection at 0x%llX (error: %d)",
                    prot.address, GetLastError());
            }
            else {
                LOG_TRACE_F("Restored protection at 0x%llX", prot.address);
            }
        }
    }

    // 第六步：刷新指令缓存（重要！）
    if (successCount > 0) {
        HANDLE hProcess = memoryMgr->GetHandle();
        if (hProcess) {
            for (const auto& op : writeOps) {
                if (!FlushInstructionCache(hProcess, (LPCVOID)op.address, op.newBytes.size())) {
                    LOG_WARN_F("Failed to flush instruction cache at 0x%llX", op.address);
                }
            }
            LOG_DEBUG("Instruction cache flushed");
        }
    }

    // 生成详细的报告
    LOG_INFO("=== Code Emission Summary ===");
    LOG_INFO_F("Total operations: %zu", writeOps.size());
    LOG_INFO_F("Successful writes: %d", successCount);
    LOG_INFO_F("Failed writes: %d", failCount);
    LOG_INFO_F("Protection changes: %zu regions", protChanges.size());

    if (!result.warnings.empty()) {
        LOG_WARN_F("Warnings: %zu", result.warnings.size());
        for (const auto& warning : result.warnings) {
            LOG_WARN_F("  - %s", warning.c_str());
        }
    }

    // 如果有关键操作失败，整体失败
    if (!result.success) {
        LOG_ERROR("Code emission failed due to critical errors");
    }
    else if (failCount > 0) {
        LOG_WARN("Code emission completed with some failures");
    }
    else {
        LOG_INFO("Code emission completed successfully");
    }

    return result;
}