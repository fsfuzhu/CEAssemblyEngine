// PassManager.cpp
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

// 辅助函数实现
bool isX64RegisterName(const std::string& token) {
    // 转换为小写进行比较
    std::string lower = token;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // 使用正则表达式进行更精确的匹配
    static const std::regex regPattern(
        R"(^()"
        // 64位通用寄存器
        R"(r(ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])|)"
        // 32位通用寄存器
        R"(e(ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])d|)"
        // 16位通用寄存器
        R"((ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])w|)"
        // 8位通用寄存器
        R"([abcd][hl]|(si|di|bp|sp)l|r(8|9|1[0-5])b|)"
        // 段寄存器
        R"([cdefgs]s|)"
        // 控制和调试寄存器
        R"(cr[0234]|cr8|dr[0-7]|)"
        // MMX寄存器
        R"(mm[0-7]|)"
        // XMM寄存器 (SSE)
        R"(xmm(1[0-5]|[0-9])|)"
        // YMM寄存器 (AVX)
        R"(ymm(1[0-5]|[0-9])|)"
        // ZMM寄存器 (AVX-512)
        R"(zmm(3[01]|[12][0-9]|[0-9])|)"
        // FPU寄存器
        R"(st[0-7]?|)"
        // 特殊寄存器
        R"(rip|eip|ip|rflags|eflags|flags)"
        R"()$)",
        std::regex::icase | std::regex::optimize
    );

    return std::regex_match(lower, regPattern);
}
bool isX64Mnemonic(const std::string& token) {
    static const std::unordered_set<std::string> mnemonics = {
        // 数据传输指令
        "mov", "movabs", "movsx", "movsxd", "movzx", "lea", "xchg",
        "push", "pop", "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",
        "pusha", "popa", "pushad", "popad",
        "xlatb", "bswap", "cmpxchg", "cmpxchg8b", "cmpxchg16b",

        // 算术指令
        "add", "adc", "sub", "sbb", "imul", "mul", "idiv", "div",
        "inc", "dec", "neg", "cmp", "daa", "das", "aaa", "aas", "aam", "aad",

        // 逻辑指令
        "and", "or", "xor", "not", "test",

        // 移位和旋转指令
        "sal", "sar", "shl", "shr", "shld", "shrd",
        "rol", "ror", "rcl", "rcr",

        // 位操作指令
        "bt", "btc", "btr", "bts", "bsf", "bsr", "popcnt", "lzcnt", "tzcnt",

        // 控制转移指令
        "jmp", "jmpf", "ljmp",
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
        "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
        "jcxz", "jecxz", "jrcxz",
        "loop", "loope", "loopz", "loopne", "loopnz",
        "call", "ret", "retn", "retf", "iret", "iretd", "iretq",
        "int", "int3", "into", "bound",
        "enter", "leave",

        // 字符串指令
        "movs", "movsb", "movsw", "movsd", "movsq",
        "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scas", "scasb", "scasw", "scasd", "scasq",
        "lods", "lodsb", "lodsw", "lodsd", "lodsq",
        "stos", "stosb", "stosw", "stosd", "stosq",
        "rep", "repe", "repz", "repne", "repnz",

        // 标志控制指令
        "stc", "clc", "cmc", "std", "cld", "sti", "cli",
        "lahf", "sahf", "pushf", "popf",

        // 杂项指令
        "nop", "ud2", "cpuid", "rdtsc", "rdtscp", "rdpmc",
        "wbinvd", "invd", "invlpg", "invpcid",
        "hlt", "wait", "fwait", "pause", "mfence", "sfence", "lfence",
        "prefetch", "prefetchw", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta",
        "clflush", "clflushopt", "clwb",

        // x87 FPU 指令
        "fld", "fst", "fstp", "fild", "fist", "fistp", "fbld", "fbstp",
        "fxch", "fcmove", "fcmovne", "fcmovb", "fcmovbe", "fcmovnb", "fcmovnbe", "fcmovu", "fcmovnu",
        "fadd", "faddp", "fiadd", "fsub", "fsubp", "fisub", "fsubr", "fsubrp", "fisubr",
        "fmul", "fmulp", "fimul", "fdiv", "fdivp", "fidiv", "fdivr", "fdivrp", "fidivr",
        "fprem", "fprem1", "fabs", "fchs", "frndint", "fscale", "fsqrt", "fxtract",
        "fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp", "ficom", "ficomp", "fcomi", "fucomi", "fcomip", "fucomip",
        "fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1",
        "finit", "fninit", "fclex", "fnclex", "fstcw", "fnstcw", "fldcw", "fstenv", "fnstenv", "fldenv", "fsave", "fnsave", "frstor",
        "ffree", "fdecstp", "fincstp", "fstsw", "fnstsw", "fxsave", "fxrstor",

        // MMX 指令
        "emms", "movd", "movq",
        "packsswb", "packssdw", "packuswb", "punpckhbw", "punpckhwd", "punpckhdq", "punpcklbw", "punpcklwd", "punpckldq",
        "paddb", "paddw", "paddd", "paddsb", "paddsw", "paddusb", "paddusw",
        "psubb", "psubw", "psubd", "psubsb", "psubsw", "psubusb", "psubusw",
        "pmulhw", "pmullw", "pmaddwd",
        "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd",
        "pand", "pandn", "por", "pxor",
        "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",

        // SSE/SSE2/SSE3/SSSE3/SSE4 指令
        "movaps", "movups", "movapd", "movupd", "movdqa", "movdqu", "movss", "movsd", "movlps", "movhps", "movlpd", "movhpd",
        "movmskps", "movmskpd", "movntps", "movntpd", "movnti", "movntdq",
        "addps", "addpd", "addss", "addsd", "subps", "subpd", "subss", "subsd",
        "mulps", "mulpd", "mulss", "mulsd", "divps", "divpd", "divss", "divsd",
        "sqrtps", "sqrtpd", "sqrtss", "sqrtsd", "rsqrtps", "rsqrtss", "rcpps", "rcpss",
        "maxps", "maxpd", "maxss", "maxsd", "minps", "minpd", "minss", "minsd",
        "cmpps", "cmppd", "cmpss", "cmpsd", "comiss", "comisd", "ucomiss", "ucomisd",
        "andps", "andpd", "andnps", "andnpd", "orps", "orpd", "xorps", "xorpd",
        "shufps", "shufpd", "unpckhps", "unpckhpd", "unpcklps", "unpcklpd",
        "cvtps2pd", "cvtpd2ps", "cvtps2dq", "cvtdq2ps", "cvttps2dq", "cvtpd2dq", "cvttpd2dq", "cvtdq2pd",
        "cvtps2pi", "cvtpd2pi", "cvttps2pi", "cvttpd2pi", "cvtpi2ps", "cvtpi2pd",
        "cvtss2si", "cvtsd2si", "cvttss2si", "cvttsd2si", "cvtsi2ss", "cvtsi2sd",
        "maskmovq", "maskmovdqu", "pmovmskb", "pextrw", "pinsrw",
        "pshufw", "pshufd", "pshufhw", "pshuflw",
        "ldmxcsr", "stmxcsr",

        // AVX/AVX2 指令 (v前缀版本)
        "vaddps", "vaddpd", "vaddss", "vaddsd", "vsubps", "vsubpd", "vsubss", "vsubsd",
        "vmulps", "vmulpd", "vmulss", "vmulsd", "vdivps", "vdivpd", "vdivss", "vdivsd",
        "vsqrtps", "vsqrtpd", "vsqrtss", "vsqrtsd",
        "vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovss", "vmovsd", "vmovdqa", "vmovdqu",
        "vxorps", "vxorpd", "vandps", "vandpd", "vorps", "vorpd",
        "vcmpps", "vcmppd", "vcmpss", "vcmpsd",
        "vshufps", "vshufpd", "vperm2f128", "vbroadcastss", "vbroadcastsd",

        // 系统指令
        "lgdt", "sgdt", "lidt", "sidt", "lldt", "sldt", "ltr", "str",
        "lmsw", "smsw", "clts", "arpl", "lar", "lsl", "verr", "verw",
        "invlpg", "invpcid", "wbinvd", "invd",
        "mov", // mov to/from control/debug registers
        "lfs", "lgs", "lss",
        "syscall", "sysret", "sysenter", "sysexit",
        "rdmsr", "wrmsr", "rdpmc", "rdtsc", "rdtscp",
        "xsave", "xsavec", "xsaveopt", "xsaves", "xrstor", "xrstors",
        "xgetbv", "xsetbv",

        // 虚拟化指令
        "vmcall", "vmlaunch", "vmresume", "vmxoff", "vmxon",
        "invept", "invvpid", "vmfunc",
        "vmclear", "vmptrld", "vmptrst", "vmread", "vmwrite",

        // 其他扩展指令
        "crc32", "popcnt", "lzcnt", "tzcnt", "bextr", "blsi", "blsmsk", "blsr",
        "bzhi", "mulx", "pdep", "pext", "rorx", "sarx", "shlx", "shrx",
        "adcx", "adox", "clac", "stac",
        "xabort", "xacquire", "xbegin", "xend", "xrelease", "xtest",

        // 加密指令
        "aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc", "aeskeygenassist",
        "pclmulqdq", "sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4",
        "sha256msg1", "sha256msg2", "sha256rnds2"
    };

    std::string lower = token;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    return mnemonics.find(lower) != mnemonics.end();
}
bool isSizeSpecifier(const std::string& token) {
    static const std::unordered_set<std::string> sizeSpecs = {
        "byte", "word", "dword", "qword", "tbyte", "oword", "xmmword", "ymmword", "zmmword",
        "ptr", "near", "far", "short"
    };

    std::string lower = token;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    return sizeSpecs.find(lower) != sizeSpecs.end();
}
bool isDataDirective(const std::string& token) {
    static const std::unordered_set<std::string> dataDirectives = {
        "db", "dw", "dd", "dq", "dt", "do", "dy", "dz",
        "byte", "word", "dword", "qword", "tbyte", "real4", "real8", "real10"
    };

    std::string lower = token;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    return dataDirectives.find(lower) != dataDirectives.end();
}

// PassManager 实现
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

// PreprocessingPass 实现
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

    // 处理匿名标签
    int anonLabelCounter = 0;
    std::map<size_t, std::string> labelMapping; // instruction index -> label name

    // Phase 1: 替换 @@ 为唯一标签
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& ctx = instructions[i];

        // 检查是否是匿名标签定义
        if (ctx.originalLine == "@@:") {
            std::string uniqueLabel = "__anon_" + std::to_string(anonLabelCounter++);
            ctx.processedLine = uniqueLabel + ":";
            ctx.isLabelDef = true;
            ctx.labelName = uniqueLabel;
            ctx.commandType = CommandType::ASSEMBLY;
            labelMapping[i] = uniqueLabel;

            LOG_DEBUG_F("Converted @@ to %s at line %zu", uniqueLabel.c_str(), i);
            result.instructionsModified++;
        }
        // 检查普通标签（包括偏移标签）
        else if (!ctx.originalLine.empty() && ctx.originalLine.back() == ':') {
            ctx.isLabelDef = true;
            ctx.labelName = ctx.originalLine.substr(0, ctx.originalLine.length() - 1);
            ctx.commandType = CommandType::ASSEMBLY;

            // 检测是否是偏移标签
            size_t plusPos = ctx.labelName.find('+');
            if (plusPos != std::string::npos) {
                ctx.isOffsetLabel = true;
                ctx.baseLabel = ctx.labelName.substr(0, plusPos);
                ctx.offsetStr = ctx.labelName.substr(plusPos + 1);

                // 标记需要符号解析
                ctx.needsSymbolResolution = true;
                ctx.unresolvedSymbols.push_back(ctx.baseLabel);

                LOG_DEBUG_F("Detected offset label: %s = %s + %s",
                    ctx.labelName.c_str(), ctx.baseLabel.c_str(), ctx.offsetStr.c_str());
            }

            labelMapping[i] = ctx.labelName;
        }
    }

    // Phase 2: 替换 @f 和 @b
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& ctx = instructions[i];

        if (ctx.processedLine.find("@f") != std::string::npos ||
            ctx.processedLine.find("@b") != std::string::npos) {

            std::string processed = ctx.processedLine;

            // 替换 @f 为下一个标签
            size_t pos = processed.find("@f");
            while (pos != std::string::npos) {
                std::string nextLabel;
                for (size_t j = i + 1; j < instructions.size(); ++j) {
                    if (labelMapping.find(j) != labelMapping.end()) {
                        nextLabel = labelMapping[j];
                        break;
                    }
                }

                if (!nextLabel.empty()) {
                    processed.replace(pos, 2, nextLabel);
                    LOG_TRACE_F("Replaced @f with %s in: %s", nextLabel.c_str(), ctx.originalLine.c_str());
                }
                else {
                    result.warnings.push_back("No forward label found for @f at: " + ctx.originalLine);
                    processed.replace(pos, 2, "__no_forward_label");
                }

                pos = processed.find("@f", pos + 1);
            }

            // 替换 @b 为上一个标签
            pos = processed.find("@b");
            while (pos != std::string::npos) {
                std::string prevLabel;
                for (int j = i - 1; j >= 0; --j) {
                    if (labelMapping.find(j) != labelMapping.end()) {
                        prevLabel = labelMapping[j];
                        break;
                    }
                }

                if (!prevLabel.empty()) {
                    processed.replace(pos, 2, prevLabel);
                    LOG_TRACE_F("Replaced @b with %s in: %s", prevLabel.c_str(), ctx.originalLine.c_str());
                }
                else {
                    result.warnings.push_back("No backward label found for @b at: " + ctx.originalLine);
                    processed.replace(pos, 2, "__no_backward_label");
                }

                pos = processed.find("@b", pos + 1);
            }

            if (processed != ctx.processedLine) {
                ctx.processedLine = processed;
                result.instructionsModified++;
            }
        }
    }

    // 继续其他预处理
    for (auto& ctx : instructions) {
        result.instructionsProcessed++;

        if (ctx.originalLine.empty()) continue;

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

                // 检查是否包含 @f 或 @b（虽然应该已经被替换）
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

                    // 特别检查捕获的变量（如 s1, s2）
                    if (!isNumber && token.length() >= 2 && token[0] == 's' && std::isdigit(token[1])) {
                        // 这是一个捕获的变量
                        ctx.needsSymbolResolution = true;
                        ctx.unresolvedSymbols.push_back(token);
                        LOG_TRACE_F("Captured variable symbol: %s", token.c_str());
                    }
                    // 如果不是数字，可能是符号
                    else if (!isNumber && !token.empty()) {
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

// SymbolCollectionPass 实现
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

                    // 调试输出捕获的值
                    uint64_t value = 0;
                    for (size_t i = 0; i < data.size() && i < 8; ++i) {
                        value |= static_cast<uint64_t>(data[i]) << (i * 8);
                    }
                    LOG_DEBUG_F("Captured variable '%s' = 0x%llX (%zu bytes)",
                        name.c_str(), value, data.size());
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
            // 支持多标签声明
            for (const auto& labelName : ctx.parameters) {
                // 所有标签初始注册为地址0，后续pass会更新
                symbolMgr->RegisterSymbol(labelName, 0, 0, true);
                LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
            }
            break;

        case CommandType::REGISTERSYMBOL:
            // 支持多符号注册
            for (const auto& symbolName : ctx.parameters) {
                // 获取符号当前地址
                uintptr_t address = 0;
                symbolMgr->GetSymbolAddress(symbolName, address);

                // 标记为全局符号（保持现有地址）
                symbolMgr->RegisterSymbol(symbolName, address, 0, true);
                LOG_DEBUG_F("Symbol '%s' marked as global at 0x%llX",
                    symbolName.c_str(), address);
            }
            break;

        default:
            break;
        }
    }

    return result;
}

// TwoPassAssemblyPass 实现
PassResult TwoPassAssemblyPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_INFO_F("=== %s ===", GetName().c_str());

    // 收集所有匿名标签
    std::vector<uintptr_t> anonymousLabels;
    std::map<uintptr_t, std::string> allLabels;

    // 迭代直到稳定
    const int MAX_ITERATIONS = 100;
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

        // 在第二遍之前，确保所有标签都在符号表中
        LOG_DEBUG("Registering all labels in symbol table");
        auto symbolMgr = engine->GetSymbolManager();
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
    CEAssemblyEngine* engine, std::vector<std::string>& warnings) {
    auto symbolMgr = engine->GetSymbolManager();
    auto ksEngine = engine->GetKeystoneEngine();

    if (!ksEngine) {
        LOG_ERROR("Keystone engine not available");
        return false;
    }

    uintptr_t currentAddress = 0;
    bool anyAddressChanged = false;

    // 第一轮：处理所有非偏移标签
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // 处理普通标签定义（非偏移）
        if (ctx.isLabelDef && !ctx.isOffsetLabel) {
            uintptr_t newAddress = 0;

            // 检查符号是否已有地址（如从 alloc 分配的 newmem）
            uintptr_t symbolAddr = 0;
            if (symbolMgr->GetSymbolAddress(ctx.labelName, symbolAddr) && symbolAddr != 0) {
                newAddress = symbolAddr;
                LOG_DEBUG_F("Label %s using allocated address: 0x%llX",
                    ctx.labelName.c_str(), newAddress);
            }

            // 更新地址
            if (newAddress != 0) {
                if (ctx.address != newAddress) {
                    anyAddressChanged = true;
                    ctx.address = newAddress;
                }
                currentAddress = newAddress;

                // 更新符号表
                symbolMgr->RegisterSymbol(ctx.labelName, newAddress, 0, true);
                LOG_TRACE_F("Label %s at 0x%llX", ctx.labelName.c_str(), newAddress);
            }
        }
    }

    // 第二轮：处理偏移标签（此时基础标签地址应该已确定）
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        if (ctx.isLabelDef && ctx.isOffsetLabel) {
            uintptr_t baseAddr = 0;
            if (symbolMgr->GetSymbolAddress(ctx.baseLabel, baseAddr) && baseAddr != 0) {
                size_t offset = 0;

                // 解析偏移值（支持十进制和十六进制）
                try {
                    if (ctx.offsetStr.find("0x") == 0 || ctx.offsetStr.find("0X") == 0) {
                        offset = std::stoull(ctx.offsetStr, nullptr, 16);
                    }
                    else if (ctx.offsetStr[0] == '$') {
                        offset = std::stoull(ctx.offsetStr.substr(1), nullptr, 16);
                    }
                    else {
                        // 默认为十六进制（CE风格）
                        offset = std::stoull(ctx.offsetStr, nullptr, 16);
                    }
                }
                catch (...) {
                    LOG_ERROR_F("Invalid offset value: %s", ctx.offsetStr.c_str());
                    warnings.push_back("Invalid offset in label: " + ctx.labelName);
                    continue;
                }

                uintptr_t newAddress = baseAddr + offset;

                if (ctx.address != newAddress) {
                    anyAddressChanged = true;
                    ctx.address = newAddress;
                }

                // 注册偏移标签
                symbolMgr->RegisterSymbol(ctx.labelName, newAddress, 0, true);
                LOG_DEBUG_F("Offset label %s = %s + 0x%zX = 0x%llX",
                    ctx.labelName.c_str(), ctx.baseLabel.c_str(), offset, newAddress);
            }
            else {
                warnings.push_back("Base symbol not found for offset label: " + ctx.labelName);
                LOG_ERROR_F("Base symbol '%s' not found for offset label '%s'",
                    ctx.baseLabel.c_str(), ctx.labelName.c_str());
            }
        }
    }

    // 第三轮：处理所有指令，计算大小
    currentAddress = 0;
    size_t instructionIndex = 0;

    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // 对于标签，使用其确定的地址
        if (ctx.isLabelDef) {
            if (ctx.address != 0) {
                currentAddress = ctx.address;
                LOG_DEBUG_F("Setting current address to label %s: 0x%llX",
                    ctx.labelName.c_str(), currentAddress);
            }
            else if (currentAddress != 0) {
                // **重要修复：如果标签没有预定义地址，使用当前地址**
                ctx.address = currentAddress;
                symbolMgr->RegisterSymbol(ctx.labelName, currentAddress, 0, true);
                LOG_DEBUG_F("Assigning current address to label %s: 0x%llX",
                    ctx.labelName.c_str(), currentAddress);
            }
            // 标签本身不占用空间
            continue;
        }

        // 跳过没有当前地址的指令
        if (currentAddress == 0) {
            LOG_TRACE_F("Skipping instruction (no address): %s", ctx.originalLine.c_str());
            continue;
        }

        // 分配地址给指令
        if (ctx.address != currentAddress) {
            anyAddressChanged = true;
            ctx.address = currentAddress;
        }

        // 特殊指令处理
        if (ProcessSpecialInstruction(ctx, engine)) {
            currentAddress += ctx.actualSize;
            ctx.sizeCalculated = true;
            instructionIndex++;
            continue;
        }

        // 准备汇编的行
        std::string asmLine = ctx.processedLine;

        // 处理浮点转换
        if (asmLine.find("(float)") != std::string::npos) {
            asmLine = engine->ProcessFloatConversion(asmLine);
        }
        asmLine = PrepareCEStyleHex(asmLine);

        // 额外处理：确保方括号内的纯数字有0x前缀
        size_t bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

            // 查找 + 或 - 后面的偏移量
            size_t opPos = content.find_last_of("+-");
            if (opPos != std::string::npos) {
                std::string offsetPart = content.substr(opPos + 1);
                offsetPart.erase(0, offsetPart.find_first_not_of(" \t"));
                offsetPart.erase(offsetPart.find_last_not_of(" \t") + 1);

                // 如果是纯数字且没有0x前缀，添加它
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {

                    std::string newContent = content.substr(0, opPos + 1) + "0x" + offsetPart;
                    asmLine = asmLine.substr(0, bracketStart + 1) + newContent + asmLine.substr(bracketEnd);

                    // 更新搜索位置
                    bracketEnd = bracketStart + 1 + newContent.length();
                }
            }

            bracketStart = asmLine.find('[', bracketEnd);
        }

        // **转换为RIP相对寻址**
        asmLine = ConvertToRipRelative(asmLine, ctx);

        // 设置指令索引
        for (auto& ref : ctx.ripReferences) {
            ref.instructionIndex = instructionIndex;
        }

        // 使用 Keystone 获取指令大小
        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            if (ctx.actualSize != size) {
                anyAddressChanged = true;
                ctx.actualSize = size;
            }
            ctx.sizeCalculated = true;

            // 如果使用了RIP占位符，保存临时机器码
            if (ctx.usedRipPlaceholder) {
                ctx.machineCode.assign(encode, encode + size);
            }

            ks_free(encode);

            LOG_TRACE_F("Instruction at 0x%llX: '%s' size = %zu bytes",
                ctx.address, ctx.originalLine.c_str(), size);
        }
        else {
            // 汇编失败 - 尝试 SmartAssemble
            ks_err err = ks_errno(ksEngine);
            LOG_DEBUG_F("Failed to assemble for size, trying SmartAssemble: %s", asmLine.c_str());

            std::vector<uint8_t> machineCode;
            std::string finalInstruction;

            if (engine->SmartAssemble(asmLine, ctx.address, machineCode, finalInstruction)) {
                size_t smartSize = machineCode.size();
                if (ctx.actualSize != smartSize) {
                    anyAddressChanged = true;
                    ctx.actualSize = smartSize;
                }
                ctx.sizeCalculated = true;

                // 如果使用了RIP占位符，保存机器码
                if (ctx.usedRipPlaceholder) {
                    ctx.machineCode = machineCode;
                }

                LOG_DEBUG_F("SmartAssemble size calculation succeeded: %zu bytes for '%s'",
                    smartSize, ctx.originalLine.c_str());
            }
            else {
                LOG_ERROR_F("Failed to assemble for size: %s (error: %s)", asmLine.c_str(), ks_strerror(err));
                warnings.push_back("Size calculation failed for: " + ctx.originalLine);

                // 使用保守估计
                size_t estimatedSize = 8;

                // 特殊处理一些常见指令
                std::istringstream iss(ctx.processedLine);
                std::string opcode;
                iss >> opcode;
                std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

                if (opcode == "push" || opcode == "pop") estimatedSize = 1;
                else if (opcode == "je" || opcode == "jne" || opcode == "jg" || opcode == "jl") estimatedSize = 2;
                else if (opcode == "jmp" || opcode == "call") estimatedSize = 5;

                if (ctx.actualSize != estimatedSize) {
                    anyAddressChanged = true;
                    ctx.actualSize = estimatedSize;
                }
            }
        }  // 确保这个大括号存在！

        currentAddress += ctx.actualSize;
        instructionIndex++;
    }

    // 第四轮：确保所有匿名标签都已分配地址
    for (auto& ctx : instructions) {
        if (ctx.isLabelDef && ctx.labelName.find("__anon_") == 0) {
            if (ctx.address != 0) {
                symbolMgr->RegisterSymbol(ctx.labelName, ctx.address, 0, true);
                LOG_DEBUG_F("Registering anonymous label %s at 0x%llX",
                    ctx.labelName.c_str(), ctx.address);
            }
        }
    }

    return anyAddressChanged;
}
bool TwoPassAssemblyPass::GenerateMachineCode(std::vector<InstructionContext>& instructions,
    CEAssemblyEngine* engine, std::vector<std::string>& warnings) {
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

        // 如果已经有机器码（使用了RIP占位符）
        if (!ctx.machineCode.empty() && ctx.usedRipPlaceholder) {
            // 修正RIP偏移
            if (!FixRipOffsets(ctx, engine)) {
                warnings.push_back("Failed to fix RIP offsets for: " + ctx.originalLine);
                return false;
            }
            ctx.assembled = true;
            continue;
        }

        // 如果已经汇编过，跳过
        if (!ctx.machineCode.empty()) {
            ctx.assembled = true;
            continue;
        }

        // 特殊指令处理
        if (ProcessSpecialInstruction(ctx, engine)) {
            ctx.assembled = true;
            continue;
        }

        // 处理 @f/@b 跳转
        if (ctx.processedLine.find("@f") != std::string::npos ||
            ctx.processedLine.find("@b") != std::string::npos) {
            if (engine->ProcessCESpecialJump(ctx.processedLine, ctx.address, ctx.machineCode)) {
                ctx.assembled = true;
                continue;
            }
        }

        // 新增：特殊处理jmp/call指令
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

        // 在GenerateMachineCode 函数中，处理负偏移
        std::string asmLine = ctx.processedLine;

        // 处理浮点转换
        if (asmLine.find("(float)") != std::string::npos) {
            asmLine = engine->ProcessFloatConversion(asmLine);
        }

        // 确保处理方括号内的所有数字
        asmLine = PrepareCEStyleHex(asmLine);

        // 额外处理：确保方括号内的纯数字有0x前缀
        size_t bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

            // 查找 + 或 - 后面的偏移量
            size_t opPos = content.find_last_of("+-");
            if (opPos != std::string::npos) {
                std::string offsetPart = content.substr(opPos + 1);
                offsetPart.erase(0, offsetPart.find_first_not_of(" \t"));
                offsetPart.erase(offsetPart.find_last_not_of(" \t") + 1);

                // 如果是纯数字且没有0x前缀，添加它
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {

                    std::string newContent = content.substr(0, opPos + 1) + "0x" + offsetPart;
                    asmLine = asmLine.substr(0, bracketStart + 1) + newContent + asmLine.substr(bracketEnd);

                    // 更新搜索位置
                    bracketEnd = bracketStart + 1 + newContent.length();
                }
            }

            bracketStart = asmLine.find('[', bracketEnd);
        }

        // 处理负偏移，如 [rdx-0C]
        bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
            size_t minusPos = content.find('-');

            if (minusPos != std::string::npos && minusPos > 0) {
                std::string regPart = content.substr(0, minusPos);
                std::string offsetPart = content.substr(minusPos + 1);

                // 去除空格
                regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
                offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

                // 检查是否是寄存器
                if (isX64RegisterName(regPart)) {
                    try {
                        // 解析偏移值
                        unsigned int offset = 0;
                        if (offsetPart.find("0x") == 0 || offsetPart.find("0X") == 0) {
                            offset = std::stoul(offsetPart.substr(2), nullptr, 16);
                        }
                        else if (std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {
                            // CE风格：纯十六进制数字
                            offset = std::stoul(offsetPart, nullptr, 16);
                        }
                        else {
                            offset = std::stoul(offsetPart, nullptr, 10);
                        }

                        // 转换为补码形式
                        unsigned int negOffset = (~offset + 1) & 0xFFFFFFFF;

                        // 构建新的内存操作数
                        std::stringstream newOperand;
                        newOperand << "[" << regPart << "+0x" << std::hex << negOffset << "]";

                        // 替换原来的操作数
                        asmLine = asmLine.substr(0, bracketStart) +
                            newOperand.str() +
                            asmLine.substr(bracketEnd + 1);

                        LOG_DEBUG_F("Converted negative offset: [%s-%s] -> %s",
                            regPart.c_str(), offsetPart.c_str(), newOperand.str().c_str());

                        // 更新搜索位置
                        bracketEnd = bracketStart + newOperand.str().length();
                    }
                    catch (...) {
                        // 解析失败，保持原样
                    }
                }
            }

            // 查找下一个方括号
            bracketStart = asmLine.find('[', bracketEnd);
        }

        // 转换为RIP相对寻址（如果还没转换）
        if (!ctx.usedRipPlaceholder) {
            asmLine = ConvertToRipRelative(asmLine, ctx);
        }

        // 替换其他符号
        asmLine = engine->ReplaceSymbols(asmLine);

        LOG_DEBUG_F("Assembling at 0x%llX: '%s' -> '%s'",
            ctx.address, ctx.processedLine.c_str(), asmLine.c_str());

        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            ctx.machineCode.assign(encode, encode + size);
            ks_free(encode);

            // 如果使用了RIP占位符，修正偏移
            if (ctx.usedRipPlaceholder) {
                if (!FixRipOffsets(ctx, engine)) {
                    warnings.push_back("Failed to fix RIP offsets for: " + ctx.originalLine);
                    return false;
                }
            }

            ctx.assembled = true;
        }
        else {
            ks_err err = ks_errno(ksEngine);
            LOG_DEBUG_F("Initial assembly failed, trying SmartAssemble for: %s", asmLine.c_str());

            // 尝试使用 SmartAssemble
            std::vector<uint8_t> machineCode;
            std::string finalInstruction;

            if (engine->SmartAssemble(asmLine, ctx.address, machineCode, finalInstruction)) {
                ctx.machineCode = machineCode;
                ctx.assembled = true;
                LOG_DEBUG_F("SmartAssemble succeeded with: %s", finalInstruction.c_str());
            }
            else {
                warnings.push_back("Assembly failed for '" + ctx.originalLine + "': " + ks_strerror(err));
                LOG_ERROR_F("Both regular and smart assembly failed for: %s", ctx.originalLine.c_str());
            }
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
std::string TwoPassAssemblyPass::ConvertToRipRelative(const std::string& line, InstructionContext& ctx) {
    // 解析指令
    std::istringstream iss(line);
    std::string opcode;
    iss >> opcode;
    std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

    // 特殊处理不需要转换的指令
    if (opcode == "nop" || opcode == "ret" || opcode == "retn" ||
        opcode == "push" || opcode == "pop") {
        return line;
    }

    // 数据定义指令不需要转换
    if (opcode == "db" || opcode == "dw" || opcode == "dd" || opcode == "dq") {
        return line;
    }

    // 跳转指令不需要RIP转换（它们有自己的相对寻址）
    if (opcode == "jmp" || opcode == "call" || opcode == "je" || opcode == "jne" ||
        opcode == "jg" || opcode == "jl" || opcode == "jge" || opcode == "jle") {
        return line;
    }

    std::string result = line;

    // 查找内存操作数 [symbol]
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string memOperand = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

        // 去除空格
        memOperand.erase(std::remove_if(memOperand.begin(), memOperand.end(), ::isspace), memOperand.end());

        // 检查是否已经是RIP相对寻址
        if (memOperand.find("rip") != std::string::npos) {
            bracketStart = result.find('[', bracketEnd);
            continue;
        }

        // 检查是否是纯符号（不是寄存器，不包含+/-等复杂表达式）
        bool isPureSymbol = true;

        // 检查是否包含寄存器
        if (isX64RegisterName(memOperand)) {
            isPureSymbol = false;
        }

        // 检查是否是复杂表达式
        if (memOperand.find('+') != std::string::npos ||
            memOperand.find('*') != std::string::npos) {
            isPureSymbol = false;
        }

        // 特殊处理 reg-offset 格式（如 rdx-0C）
        if (memOperand.find('-') != std::string::npos) {
            size_t minusPos = memOperand.find('-');
            std::string beforeMinus = memOperand.substr(0, minusPos);
            if (isX64RegisterName(beforeMinus)) {
                isPureSymbol = false;
            }
        }

        if (isPureSymbol && !memOperand.empty()) {
            // 记录RIP引用
            RipReference ref;
            ref.instructionIndex = 0;
            ref.symbolName = memOperand;
            ref.ripOffsetPosition = 0;
            ref.is32bit = true;

            ctx.ripReferences.push_back(ref);
            ctx.usedRipPlaceholder = true;

            // 智能处理大小指示符
            size_t ptrPos = result.rfind("ptr", bracketStart);
            bool hasSizeSpec = (ptrPos != std::string::npos && ptrPos < bracketStart);

            if (!hasSizeSpec) {
                // 没有大小指示符，需要根据上下文决定是否添加

                // 对于mov指令，需要检查源操作数
                if (opcode == "mov") {
                    // 提取源操作数（逗号后面的部分）
                    size_t commaPos = result.find(',', bracketEnd);
                    if (commaPos != std::string::npos) {
                        std::string srcOperand = result.substr(commaPos + 1);
                        srcOperand.erase(0, srcOperand.find_first_not_of(" \t"));
                        srcOperand.erase(srcOperand.find_last_not_of(" \t") + 1);

                        // 如果源操作数是64位寄存器，不需要大小指示符
                        std::string lowerSrc = srcOperand;
                        std::transform(lowerSrc.begin(), lowerSrc.end(), lowerSrc.begin(), ::tolower);

                        if (lowerSrc == "rax" || lowerSrc == "rbx" || lowerSrc == "rcx" ||
                            lowerSrc == "rdx" || lowerSrc == "rsi" || lowerSrc == "rdi" ||
                            lowerSrc == "rbp" || lowerSrc == "rsp" ||
                            lowerSrc.find("r8") == 0 || lowerSrc.find("r9") == 0 ||
                            lowerSrc.find("r10") == 0 || lowerSrc.find("r11") == 0 ||
                            lowerSrc.find("r12") == 0 || lowerSrc.find("r13") == 0 ||
                            lowerSrc.find("r14") == 0 || lowerSrc.find("r15") == 0) {
                            // 64位寄存器，不需要大小指示符
                            result = result.substr(0, bracketStart + 1) + "rip+0" +
                                result.substr(bracketEnd);
                        }
                        else if (srcOperand.find("0x") != std::string::npos ||
                            std::isdigit(srcOperand[0])) {
                            // 立即数，需要dword ptr
                            result = result.substr(0, bracketStart) + "dword ptr [rip+0" +
                                result.substr(bracketEnd);
                        }
                        else {
                            // 其他情况，默认不加大小指示符
                            result = result.substr(0, bracketStart + 1) + "rip+0" +
                                result.substr(bracketEnd);
                        }
                    }
                }
                else if (opcode == "cmp") {
                    // cmp 默认使用 dword ptr（除非已有大小指示符）
                    result = result.substr(0, bracketStart) + "dword ptr [rip+0" +
                        result.substr(bracketEnd);
                }
                else {
                    // 其他指令，默认不加大小指示符
                    result = result.substr(0, bracketStart + 1) + "rip+0" +
                        result.substr(bracketEnd);
                }
            }
            else {
                // 已有大小指示符，只替换方括号内的内容
                result = result.substr(0, bracketStart + 1) + "rip+0" +
                    result.substr(bracketEnd);
            }

            LOG_DEBUG_F("Converted [%s] to RIP-relative in: %s -> %s",
                memOperand.c_str(), line.c_str(), result.c_str());
        }

        // 查找下一个
        bracketStart = result.find('[', bracketEnd);
    }

    return result;
}
std::string TwoPassAssemblyPass::PrepareCEStyleHex(const std::string& line) {
    std::string result = line;

    // 查找方括号内的内容
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string content = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
        std::string newContent = content;

        // 查找 + 或 - 符号
        size_t opPos = content.find('+');
        bool isPlus = true;
        if (opPos == std::string::npos) {
            opPos = content.find('-');
            isPlus = false;
        }

        if (opPos != std::string::npos) {
            std::string regPart = content.substr(0, opPos);
            std::string offsetPart = content.substr(opPos + 1);

            // 去除空格
            regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
            offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

            // 如果是寄存器+偏移的格式
            if (isX64RegisterName(regPart)) {
                // 检查偏移是否需要添加 0x 前缀
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    offsetPart[0] != '$') {

                    // CE 风格：方括号内的数字默认是十六进制
                    // 不管是否包含 A-F，都添加 0x 前缀
                    bool isNumeric = std::all_of(offsetPart.begin(), offsetPart.end(),
                        [](char c) { return std::isxdigit(c); });

                    if (isNumeric) {
                        newContent = regPart + (isPlus ? "+0x" : "-0x") + offsetPart;
                        result = result.substr(0, bracketStart + 1) + newContent + result.substr(bracketEnd);

                        LOG_DEBUG_F("Fixed CE-style hex: [%s] -> [%s]", content.c_str(), newContent.c_str());

                        // 更新搜索位置
                        bracketEnd = bracketStart + 1 + newContent.length();
                    }
                }
            }
        }

        // 查找下一个方括号
        bracketStart = result.find('[', bracketEnd);
    }

    return result;
}
std::string TwoPassAssemblyPass::ProcessNegativeOffset(const std::string& line) {
    std::string result = line;

    // 查找 [寄存器-偏移] 模式
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string memOperand = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

        // 查找减号
        size_t minusPos = memOperand.find('-');
        if (minusPos != std::string::npos && minusPos > 0) {
            std::string regPart = memOperand.substr(0, minusPos);
            std::string offsetPart = memOperand.substr(minusPos + 1);

            // 去除空格
            regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
            offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

            // 检查是否是寄存器
            if (isX64RegisterName(regPart)) {
                // 解析偏移值
                unsigned int offset = 0;
                bool parsed = false;

                try {
                    if (offsetPart.find("0x") == 0 || offsetPart.find("0X") == 0) {
                        offset = std::stoul(offsetPart.substr(2), nullptr, 16);
                        parsed = true;
                    }
                    else if (std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {
                        offset = std::stoul(offsetPart, nullptr, 16);
                        parsed = true;
                    }
                }
                catch (...) {
                    parsed = false;
                }

                if (parsed) {
                    // 转换为补码形式
                    unsigned int negOffset = (~offset + 1) & 0xFFFFFFFF;

                    // 构建新的内存操作数
                    std::stringstream newOperand;
                    newOperand << "[" << regPart << "+0x" << std::hex << negOffset << "]";

                    // 替换原来的操作数
                    result = result.substr(0, bracketStart) +
                        newOperand.str() +
                        result.substr(bracketEnd + 1);

                    LOG_DEBUG_F("Converted negative offset: [%s-%s] -> %s",
                        regPart.c_str(), offsetPart.c_str(), newOperand.str().c_str());
                }
            }
        }

        // 查找下一个
        bracketStart = result.find('[', bracketEnd);
    }

    return result;
}
bool TwoPassAssemblyPass::FixRipOffsets(InstructionContext& ctx, CEAssemblyEngine* engine) {
    if (!ctx.usedRipPlaceholder || ctx.ripReferences.empty()) {
        return true;
    }

    auto symbolMgr = engine->GetSymbolManager();

    for (auto& ref : ctx.ripReferences) {
        // 获取目标符号地址
        uintptr_t targetAddr = 0;
        if (!symbolMgr->GetSymbolAddress(ref.symbolName, targetAddr) || targetAddr == 0) {
            LOG_ERROR_F("Cannot resolve symbol for RIP fixup: %s", ref.symbolName.c_str());
            return false;
        }

        // 计算RIP相对偏移
        uintptr_t ripAddr = ctx.address + ctx.actualSize;
        int32_t ripOffset = static_cast<int32_t>(targetAddr - ripAddr);

        // 在机器码中查找 RIP 相对寻址的模式
        bool found = false;

        for (size_t i = 0; i <= ctx.machineCode.size() - 4; i++) {
            bool isRipInstruction = false;

            // 检查常见的 RIP 相对寻址模式
            if (i >= 3) {
                // mov [rip+disp32],reg 模式: 48 89 05
                if (ctx.machineCode[i - 3] == 0x48 &&
                    ctx.machineCode[i - 2] == 0x89 &&
                    ctx.machineCode[i - 1] == 0x05) {
                    isRipInstruction = true;
                }
                // mov reg,[rip+disp32] 模式: 48 8B 05
                else if (ctx.machineCode[i - 3] == 0x48 &&
                    ctx.machineCode[i - 2] == 0x8B &&
                    ctx.machineCode[i - 1] == 0x05) {
                    isRipInstruction = true;
                }
            }
            if (i >= 2) {
                // cmp dword ptr [rip+disp32],imm8 模式: 83 3D
                if (ctx.machineCode[i - 2] == 0x83 &&
                    ctx.machineCode[i - 1] == 0x3D) {
                    isRipInstruction = true;
                }
                // cmp dword ptr [rip+disp32],imm32 模式: 81 3D
                else if (ctx.machineCode[i - 2] == 0x81 &&
                    ctx.machineCode[i - 1] == 0x3D) {
                    isRipInstruction = true;
                }
            }
            if (i >= 1) {
                // 通用检查：ModR/M 字节的低3位是否为101(5) 且 Mod=00
                uint8_t modRM = ctx.machineCode[i - 1];
                if ((modRM & 0xC7) == 0x05) { // Mod=00, R/M=101
                    isRipInstruction = true;
                }
            }

            if (isRipInstruction) {
                // 读取当前的32位值
                int32_t currentOffset = *reinterpret_cast<int32_t*>(&ctx.machineCode[i]);

                // 检查是否需要更新（可能是0或者是旧的偏移值）
                if (currentOffset == 0 || currentOffset != ripOffset) {
                    // 写入正确的偏移
                    *reinterpret_cast<int32_t*>(&ctx.machineCode[i]) = ripOffset;
                    found = true;

                    LOG_DEBUG_F("Fixed RIP offset for %s: 0x%X -> 0x%X at position %zu",
                        ref.symbolName.c_str(), currentOffset, ripOffset, i);
                    break;
                }
                else {
                    // 偏移已经正确
                    found = true;
                    LOG_DEBUG_F("RIP offset for %s already correct: 0x%X at position %zu",
                        ref.symbolName.c_str(), ripOffset, i);
                    break;
                }
            }
        }

        if (!found) {
            // 打印机器码以帮助调试
            std::stringstream hexDump;
            hexDump << "Machine code for " << ctx.originalLine << ": ";
            for (size_t i = 0; i < ctx.machineCode.size() && i < 16; i++) {
                hexDump << std::hex << std::setw(2) << std::setfill('0')
                    << (int)ctx.machineCode[i] << " ";
            }
            LOG_ERROR(hexDump.str().c_str());

            LOG_ERROR_F("Failed to find RIP pattern in instruction: %s", ctx.originalLine.c_str());
            return false;
        }
    }

    return true;
}

// CodeEmissionPass 实现
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
        bool critical;  // 是否是关键操作（如重要的 hook 点）
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
            // 重要的跳转和调用通常是关键的
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