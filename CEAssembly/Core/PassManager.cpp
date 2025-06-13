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

// ��������ʵ��
bool isX64RegisterName(const std::string& token) {
    // ת��ΪСд���бȽ�
    std::string lower = token;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // ʹ��������ʽ���и���ȷ��ƥ��
    static const std::regex regPattern(
        R"(^()"
        // 64λͨ�üĴ���
        R"(r(ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])|)"
        // 32λͨ�üĴ���
        R"(e(ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])d|)"
        // 16λͨ�üĴ���
        R"((ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])w|)"
        // 8λͨ�üĴ���
        R"([abcd][hl]|(si|di|bp|sp)l|r(8|9|1[0-5])b|)"
        // �μĴ���
        R"([cdefgs]s|)"
        // ���ƺ͵��ԼĴ���
        R"(cr[0234]|cr8|dr[0-7]|)"
        // MMX�Ĵ���
        R"(mm[0-7]|)"
        // XMM�Ĵ��� (SSE)
        R"(xmm(1[0-5]|[0-9])|)"
        // YMM�Ĵ��� (AVX)
        R"(ymm(1[0-5]|[0-9])|)"
        // ZMM�Ĵ��� (AVX-512)
        R"(zmm(3[01]|[12][0-9]|[0-9])|)"
        // FPU�Ĵ���
        R"(st[0-7]?|)"
        // ����Ĵ���
        R"(rip|eip|ip|rflags|eflags|flags)"
        R"()$)",
        std::regex::icase | std::regex::optimize
    );

    return std::regex_match(lower, regPattern);
}
bool isX64Mnemonic(const std::string& token) {
    static const std::unordered_set<std::string> mnemonics = {
        // ���ݴ���ָ��
        "mov", "movabs", "movsx", "movsxd", "movzx", "lea", "xchg",
        "push", "pop", "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",
        "pusha", "popa", "pushad", "popad",
        "xlatb", "bswap", "cmpxchg", "cmpxchg8b", "cmpxchg16b",

        // ����ָ��
        "add", "adc", "sub", "sbb", "imul", "mul", "idiv", "div",
        "inc", "dec", "neg", "cmp", "daa", "das", "aaa", "aas", "aam", "aad",

        // �߼�ָ��
        "and", "or", "xor", "not", "test",

        // ��λ����תָ��
        "sal", "sar", "shl", "shr", "shld", "shrd",
        "rol", "ror", "rcl", "rcr",

        // λ����ָ��
        "bt", "btc", "btr", "bts", "bsf", "bsr", "popcnt", "lzcnt", "tzcnt",

        // ����ת��ָ��
        "jmp", "jmpf", "ljmp",
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
        "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
        "jcxz", "jecxz", "jrcxz",
        "loop", "loope", "loopz", "loopne", "loopnz",
        "call", "ret", "retn", "retf", "iret", "iretd", "iretq",
        "int", "int3", "into", "bound",
        "enter", "leave",

        // �ַ���ָ��
        "movs", "movsb", "movsw", "movsd", "movsq",
        "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scas", "scasb", "scasw", "scasd", "scasq",
        "lods", "lodsb", "lodsw", "lodsd", "lodsq",
        "stos", "stosb", "stosw", "stosd", "stosq",
        "rep", "repe", "repz", "repne", "repnz",

        // ��־����ָ��
        "stc", "clc", "cmc", "std", "cld", "sti", "cli",
        "lahf", "sahf", "pushf", "popf",

        // ����ָ��
        "nop", "ud2", "cpuid", "rdtsc", "rdtscp", "rdpmc",
        "wbinvd", "invd", "invlpg", "invpcid",
        "hlt", "wait", "fwait", "pause", "mfence", "sfence", "lfence",
        "prefetch", "prefetchw", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta",
        "clflush", "clflushopt", "clwb",

        // x87 FPU ָ��
        "fld", "fst", "fstp", "fild", "fist", "fistp", "fbld", "fbstp",
        "fxch", "fcmove", "fcmovne", "fcmovb", "fcmovbe", "fcmovnb", "fcmovnbe", "fcmovu", "fcmovnu",
        "fadd", "faddp", "fiadd", "fsub", "fsubp", "fisub", "fsubr", "fsubrp", "fisubr",
        "fmul", "fmulp", "fimul", "fdiv", "fdivp", "fidiv", "fdivr", "fdivrp", "fidivr",
        "fprem", "fprem1", "fabs", "fchs", "frndint", "fscale", "fsqrt", "fxtract",
        "fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp", "ficom", "ficomp", "fcomi", "fucomi", "fcomip", "fucomip",
        "fsin", "fcos", "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1",
        "finit", "fninit", "fclex", "fnclex", "fstcw", "fnstcw", "fldcw", "fstenv", "fnstenv", "fldenv", "fsave", "fnsave", "frstor",
        "ffree", "fdecstp", "fincstp", "fstsw", "fnstsw", "fxsave", "fxrstor",

        // MMX ָ��
        "emms", "movd", "movq",
        "packsswb", "packssdw", "packuswb", "punpckhbw", "punpckhwd", "punpckhdq", "punpcklbw", "punpcklwd", "punpckldq",
        "paddb", "paddw", "paddd", "paddsb", "paddsw", "paddusb", "paddusw",
        "psubb", "psubw", "psubd", "psubsb", "psubsw", "psubusb", "psubusw",
        "pmulhw", "pmullw", "pmaddwd",
        "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd",
        "pand", "pandn", "por", "pxor",
        "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",

        // SSE/SSE2/SSE3/SSSE3/SSE4 ָ��
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

        // AVX/AVX2 ָ�� (vǰ׺�汾)
        "vaddps", "vaddpd", "vaddss", "vaddsd", "vsubps", "vsubpd", "vsubss", "vsubsd",
        "vmulps", "vmulpd", "vmulss", "vmulsd", "vdivps", "vdivpd", "vdivss", "vdivsd",
        "vsqrtps", "vsqrtpd", "vsqrtss", "vsqrtsd",
        "vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovss", "vmovsd", "vmovdqa", "vmovdqu",
        "vxorps", "vxorpd", "vandps", "vandpd", "vorps", "vorpd",
        "vcmpps", "vcmppd", "vcmpss", "vcmpsd",
        "vshufps", "vshufpd", "vperm2f128", "vbroadcastss", "vbroadcastsd",

        // ϵͳָ��
        "lgdt", "sgdt", "lidt", "sidt", "lldt", "sldt", "ltr", "str",
        "lmsw", "smsw", "clts", "arpl", "lar", "lsl", "verr", "verw",
        "invlpg", "invpcid", "wbinvd", "invd",
        "mov", // mov to/from control/debug registers
        "lfs", "lgs", "lss",
        "syscall", "sysret", "sysenter", "sysexit",
        "rdmsr", "wrmsr", "rdpmc", "rdtsc", "rdtscp",
        "xsave", "xsavec", "xsaveopt", "xsaves", "xrstor", "xrstors",
        "xgetbv", "xsetbv",

        // ���⻯ָ��
        "vmcall", "vmlaunch", "vmresume", "vmxoff", "vmxon",
        "invept", "invvpid", "vmfunc",
        "vmclear", "vmptrld", "vmptrst", "vmread", "vmwrite",

        // ������չָ��
        "crc32", "popcnt", "lzcnt", "tzcnt", "bextr", "blsi", "blsmsk", "blsr",
        "bzhi", "mulx", "pdep", "pext", "rorx", "sarx", "shlx", "shrx",
        "adcx", "adox", "clac", "stac",
        "xabort", "xacquire", "xbegin", "xend", "xrelease", "xtest",

        // ����ָ��
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

// PassManager ʵ��
PassManager::PassManager() {
    // ʹ���µ����������
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

    // ��ԭʼ��ת��Ϊָ��������
    ConvertLinesToInstructions(lines);

    if (m_instructions.empty()) {
        LOG_WARN("No instructions to process");
        return true;
    }

    // ִ��ÿ�� Pass
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

            // ��ӡ����
            for (const auto& warning : result.warnings) {
                LOG_WARN_F("  Warning: %s", warning.c_str());
            }

            LOG_DEBUG_F("  Processed: %d, Modified: %d",
                result.instructionsProcessed, result.instructionsModified);

            // ����Ƿ��ȶ���û���޸ģ�
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

        // ��������
        ParsedCommand cmd = parser.ParseLine(line);
        ctx.commandType = cmd.type;
        ctx.parameters = cmd.parameters;

        // ����Ƿ��Ǳ�ǩ����
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

// PreprocessingPass ʵ��
PassResult PreprocessingPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_DEBUG_F("=== Pass 1: %s ===", GetName().c_str());

    // ������ x86/x64 �Ĵ�������
    static const std::set<std::string> allRegisters = {
        // 64λͨ�üĴ���
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",

        // 32λͨ�üĴ���
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",

        // 16λͨ�üĴ���
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",

        // 8λͨ�üĴ���
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",

        // �μĴ���
        "cs", "ds", "es", "fs", "gs", "ss",

        // ���ƼĴ���
        "cr0", "cr2", "cr3", "cr4", "cr8",

        // ���ԼĴ���
        "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",

        // MMX �Ĵ���
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",

        // XMM �Ĵ��� (SSE)
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",

        // YMM �Ĵ��� (AVX)
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
        "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",

        // ZMM �Ĵ��� (AVX-512)
        "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
        "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
        "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
        "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",

        // FPU �Ĵ���
        "st", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",

        // ����Ĵ���
        "rip", "eip", "ip",
        "rflags", "eflags", "flags"
    };

    // ���ָ�����Ƿ����ϣ�����ʶ��
    static const std::set<std::string> mnemonics = {
        // ���ݴ���
        "mov", "movsx", "movzx", "movsxd", "movabs", "lea", "xchg", "push", "pop",
        "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",

        // ��������
        "add", "sub", "adc", "sbb", "mul", "imul", "div", "idiv", "inc", "dec", "neg",

        // �߼�����
        "and", "or", "xor", "not", "test", "cmp",

        // ��λ����ת
        "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr",

        // ��ת�͵���
        "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "js", "jns", "jo", "jno", "jc", "jnc", "jp", "jnp", "jpe", "jpo",
        "jecxz", "jrcxz", "loop", "loope", "loopne", "call", "ret", "retn",

        // �ַ�������
        "movs", "movsb", "movsw", "movsd", "movsq",
        "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scas", "scasb", "scasw", "scasd", "scasq",
        "lods", "lodsb", "lodsw", "lodsd", "lodsq",
        "stos", "stosb", "stosw", "stosd", "stosq",
        "rep", "repe", "repz", "repne", "repnz",

        // SSE/AVX ָ��
        "movss", "movsd", "movaps", "movups", "movapd", "movupd",
        "addss", "addsd", "addps", "addpd", "subss", "subsd", "subps", "subpd",
        "mulss", "mulsd", "mulps", "mulpd", "divss", "divsd", "divps", "divpd",
        "sqrtss", "sqrtsd", "sqrtps", "sqrtpd",
        "comiss", "comisd", "ucomiss", "ucomisd",
        "xorps", "xorpd", "pxor",

        // ����
        "nop", "int", "int3", "syscall", "sysenter", "sysexit", "cpuid",
        "pause", "lock", "hlt", "cli", "sti", "cld", "std"
    };

    // ��Сָʾ��
    static const std::set<std::string> sizeSpecifiers = {
        "byte", "word", "dword", "qword", "tbyte", "oword", "xmmword", "ymmword", "zmmword",
        "ptr", "near", "far", "short"
    };

    // ���ݶ���ָ��
    static const std::set<std::string> dataDirectives = {
        "db", "dw", "dd", "dq", "dt", "do", "dy", "dz"
    };

    // ����������ǩ
    int anonLabelCounter = 0;
    std::map<size_t, std::string> labelMapping; // instruction index -> label name

    // Phase 1: �滻 @@ ΪΨһ��ǩ
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& ctx = instructions[i];

        // ����Ƿ���������ǩ����
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
        // �����ͨ��ǩ������ƫ�Ʊ�ǩ��
        else if (!ctx.originalLine.empty() && ctx.originalLine.back() == ':') {
            ctx.isLabelDef = true;
            ctx.labelName = ctx.originalLine.substr(0, ctx.originalLine.length() - 1);
            ctx.commandType = CommandType::ASSEMBLY;

            // ����Ƿ���ƫ�Ʊ�ǩ
            size_t plusPos = ctx.labelName.find('+');
            if (plusPos != std::string::npos) {
                ctx.isOffsetLabel = true;
                ctx.baseLabel = ctx.labelName.substr(0, plusPos);
                ctx.offsetStr = ctx.labelName.substr(plusPos + 1);

                // �����Ҫ���Ž���
                ctx.needsSymbolResolution = true;
                ctx.unresolvedSymbols.push_back(ctx.baseLabel);

                LOG_DEBUG_F("Detected offset label: %s = %s + %s",
                    ctx.labelName.c_str(), ctx.baseLabel.c_str(), ctx.offsetStr.c_str());
            }

            labelMapping[i] = ctx.labelName;
        }
    }

    // Phase 2: �滻 @f �� @b
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto& ctx = instructions[i];

        if (ctx.processedLine.find("@f") != std::string::npos ||
            ctx.processedLine.find("@b") != std::string::npos) {

            std::string processed = ctx.processedLine;

            // �滻 @f Ϊ��һ����ǩ
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

            // �滻 @b Ϊ��һ����ǩ
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

    // ��������Ԥ����
    for (auto& ctx : instructions) {
        result.instructionsProcessed++;

        if (ctx.originalLine.empty()) continue;

        // 2. ���� (float) ת��
        if (ctx.processedLine.find("(float)") != std::string::npos) {
            std::string processed = engine->ProcessFloatConversion(ctx.processedLine);
            if (processed != ctx.processedLine) {
                ctx.processedLine = processed;
                result.instructionsModified++;
                LOG_TRACE_F("Float conversion: %s -> %s", ctx.originalLine.c_str(), processed.c_str());
            }
        }

        // 3. ����ָ��ͷ�������
        if (ctx.commandType == CommandType::ASSEMBLY && !ctx.isLabelDef) {
            // ��ϸ�Ĵʷ�����
            std::istringstream iss(ctx.processedLine);
            std::string firstToken;
            iss >> firstToken;

            if (!firstToken.empty()) {
                std::string lowerFirst = firstToken;
                std::transform(lowerFirst.begin(), lowerFirst.end(), lowerFirst.begin(), ::tolower);

                // ����Ƿ������ݶ���
                if (dataDirectives.find(lowerFirst) != dataDirectives.end()) {
                    LOG_TRACE_F("Data directive: %s", ctx.originalLine.c_str());
                    // ���ݶ�����ܰ�������
                    std::string token;
                    while (iss >> token) {
                        if (token != "," && !isdigit(token[0]) && token.find("0x") != 0) {
                            ctx.needsSymbolResolution = true;
                            ctx.unresolvedSymbols.push_back(token);
                        }
                    }
                    continue;
                }

                // ����Ƿ���� @f �� @b����ȻӦ���Ѿ����滻��
                if (ctx.processedLine.find("@f") != std::string::npos ||
                    ctx.processedLine.find("@b") != std::string::npos) {
                    ctx.needsSymbolResolution = true;
                    LOG_TRACE_F("CE special jump: %s", ctx.originalLine.c_str());
                }

                // ���¿�ʼ�������������п��ܵķ���
                iss.clear();
                iss.seekg(0);

                std::string token;
                bool inBrackets = false;
                bool afterComma = false;

                while (iss >> token) {
                    // �����ָ���
                    if (token == "," || token == "+" || token == "-" || token == "*") {
                        if (token == ",") afterComma = true;
                        continue;
                    }

                    // ��������
                    if (token.find('[') != std::string::npos) inBrackets = true;
                    if (token.find(']') != std::string::npos) inBrackets = false;

                    // ȥ��������
                    size_t bracketPos = token.find('[');
                    if (bracketPos != std::string::npos) {
                        token = token.substr(bracketPos + 1);
                    }
                    bracketPos = token.find(']');
                    if (bracketPos != std::string::npos) {
                        token = token.substr(0, bracketPos);
                    }

                    // תСд���ڱȽ�
                    std::string lowerToken = token;
                    std::transform(lowerToken.begin(), lowerToken.end(), lowerToken.begin(), ::tolower);

                    // ������֪��Ԫ��
                    if (allRegisters.find(lowerToken) != allRegisters.end()) continue;
                    if (mnemonics.find(lowerToken) != mnemonics.end()) continue;
                    if (sizeSpecifiers.find(lowerToken) != sizeSpecifiers.end()) continue;
                    if (token.empty()) continue;

                    // ����Ƿ�������
                    bool isNumber = false;
                    if (isdigit(token[0]) || token[0] == '-') {
                        isNumber = true;
                    }
                    else if (token.find("0x") == 0 || token.find("0X") == 0) {
                        isNumber = true;
                    }
                    else if (token[0] == '$') {
                        // CE ��ʮ�����Ʊ�ʾ��
                        isNumber = true;
                    }

                    // �ر��鲶��ı������� s1, s2��
                    if (!isNumber && token.length() >= 2 && token[0] == 's' && std::isdigit(token[1])) {
                        // ����һ������ı���
                        ctx.needsSymbolResolution = true;
                        ctx.unresolvedSymbols.push_back(token);
                        LOG_TRACE_F("Captured variable symbol: %s", token.c_str());
                    }
                    // ����������֣������Ƿ���
                    else if (!isNumber && !token.empty()) {
                        ctx.needsSymbolResolution = true;
                        ctx.unresolvedSymbols.push_back(token);
                        LOG_TRACE_F("Potential symbol: %s", token.c_str());
                    }
                }
            }
        }

        // 4. ���⴦��ĳЩָ��
        if (ctx.commandType == CommandType::ASSEMBLY) {
            std::string opcode;
            std::istringstream iss(ctx.processedLine);
            iss >> opcode;
            std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

            // NOP ָ��������
            if (opcode == "nop") {
                LOG_TRACE_F("NOP instruction: %s", ctx.originalLine.c_str());
            }
        }
    }

    // ���ͳ����Ϣ
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

// SymbolCollectionPass ʵ��
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

                // ����ģʽ�ַ���
                std::string pattern;
                for (size_t i = 2; i < ctx.parameters.size(); ++i) {
                    if (!pattern.empty()) pattern += " ";
                    pattern += ctx.parameters[i];
                }

                // ִ��ɨ��
                uintptr_t address = scanner->ScanModule(moduleName, pattern);

                if (address == 0) {
                    result.success = false;
                    result.errorMessage = "Pattern not found for " + symbolName;
                    return result;
                }

                symbolMgr->RegisterSymbol(symbolName, address);
                LOG_INFO_F("Symbol '%s' found at 0x%llX", symbolName.c_str(), address);

                // ������ı���
                auto capturedVars = scanner->GetCapturedVariables();
                for (const auto& [name, data] : capturedVars) {
                    symbolMgr->RegisterCapturedData(name, data);

                    // ������������ֵ
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

                // ������С
                size_t size = 0;
                std::string sizeStr = ctx.parameters[1];
                if (sizeStr[0] == '$') {
                    size = std::stoull(sizeStr.substr(1), nullptr, 16);
                }
                else {
                    size = std::stoull(sizeStr, nullptr, 10);
                }

                // ��ȡ������ַ
                uintptr_t nearAddress = 0;
                if (ctx.parameters.size() > 2) {
                    symbolMgr->GetSymbolAddress(ctx.parameters[2], nearAddress);
                }

                // �����ڴ�
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
            // ֧�ֶ��ǩ����
            for (const auto& labelName : ctx.parameters) {
                // ���б�ǩ��ʼע��Ϊ��ַ0������pass�����
                symbolMgr->RegisterSymbol(labelName, 0, 0, true);
                LOG_DEBUG_F("Label '%s' declared", labelName.c_str());
            }
            break;

        case CommandType::REGISTERSYMBOL:
            // ֧�ֶ����ע��
            for (const auto& symbolName : ctx.parameters) {
                // ��ȡ���ŵ�ǰ��ַ
                uintptr_t address = 0;
                symbolMgr->GetSymbolAddress(symbolName, address);

                // ���Ϊȫ�ַ��ţ��������е�ַ��
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

// TwoPassAssemblyPass ʵ��
PassResult TwoPassAssemblyPass::Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) {
    PassResult result;
    result.success = true;

    LOG_INFO_F("=== %s ===", GetName().c_str());

    // �ռ�����������ǩ
    std::vector<uintptr_t> anonymousLabels;
    std::map<uintptr_t, std::string> allLabels;

    // ����ֱ���ȶ�
    const int MAX_ITERATIONS = 100;
    bool stabilized = false;

    for (int iteration = 0; iteration < MAX_ITERATIONS && !stabilized; iteration++) {
        if (iteration > 0) {
            LOG_DEBUG_F("Iteration %d", iteration + 1);
        }

        // ��һ�飺�����С�ͷ����ַ
        LOG_DEBUG("Pass 1: Size calculation and address assignment");
        bool sizeChanged = CalculateSizesAndAddresses(instructions, engine, result.warnings);

        // �ռ���ǩ��Ϣ
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

        // ���ñ�ǩ��Ϣ
        engine->SetAnonymousLabels(anonymousLabels);

        // �ڵڶ���֮ǰ��ȷ�����б�ǩ���ڷ��ű���
        LOG_DEBUG("Registering all labels in symbol table");
        auto symbolMgr = engine->GetSymbolManager();
        for (const auto& ctx : instructions) {
            if (ctx.isLabelDef && ctx.address != 0) {
                symbolMgr->RegisterSymbol(ctx.labelName, ctx.address, 0, true);
                LOG_DEBUG_F("Registered label %s at 0x%llX",
                    ctx.labelName.c_str(), ctx.address);
            }
        }

        // �ڶ��飺���ɻ�����
        LOG_DEBUG("Pass 2: Machine code generation");
        bool codeGenSuccess = GenerateMachineCode(instructions, engine, result.warnings);

        if (!codeGenSuccess) {
            result.success = false;
            result.errorMessage = "Failed to generate machine code";
            return result;
        }

        // ����Ƿ��ȶ�
        stabilized = !sizeChanged;

        // ͳ��
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

    // ��һ�֣��������з�ƫ�Ʊ�ǩ
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // ������ͨ��ǩ���壨��ƫ�ƣ�
        if (ctx.isLabelDef && !ctx.isOffsetLabel) {
            uintptr_t newAddress = 0;

            // �������Ƿ����е�ַ����� alloc ����� newmem��
            uintptr_t symbolAddr = 0;
            if (symbolMgr->GetSymbolAddress(ctx.labelName, symbolAddr) && symbolAddr != 0) {
                newAddress = symbolAddr;
                LOG_DEBUG_F("Label %s using allocated address: 0x%llX",
                    ctx.labelName.c_str(), newAddress);
            }

            // ���µ�ַ
            if (newAddress != 0) {
                if (ctx.address != newAddress) {
                    anyAddressChanged = true;
                    ctx.address = newAddress;
                }
                currentAddress = newAddress;

                // ���·��ű�
                symbolMgr->RegisterSymbol(ctx.labelName, newAddress, 0, true);
                LOG_TRACE_F("Label %s at 0x%llX", ctx.labelName.c_str(), newAddress);
            }
        }
    }

    // �ڶ��֣�����ƫ�Ʊ�ǩ����ʱ������ǩ��ַӦ����ȷ����
    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        if (ctx.isLabelDef && ctx.isOffsetLabel) {
            uintptr_t baseAddr = 0;
            if (symbolMgr->GetSymbolAddress(ctx.baseLabel, baseAddr) && baseAddr != 0) {
                size_t offset = 0;

                // ����ƫ��ֵ��֧��ʮ���ƺ�ʮ�����ƣ�
                try {
                    if (ctx.offsetStr.find("0x") == 0 || ctx.offsetStr.find("0X") == 0) {
                        offset = std::stoull(ctx.offsetStr, nullptr, 16);
                    }
                    else if (ctx.offsetStr[0] == '$') {
                        offset = std::stoull(ctx.offsetStr.substr(1), nullptr, 16);
                    }
                    else {
                        // Ĭ��Ϊʮ�����ƣ�CE���
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

                // ע��ƫ�Ʊ�ǩ
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

    // �����֣���������ָ������С
    currentAddress = 0;
    size_t instructionIndex = 0;

    for (auto& ctx : instructions) {
        if (ctx.commandType != CommandType::ASSEMBLY) continue;

        // ���ڱ�ǩ��ʹ����ȷ���ĵ�ַ
        if (ctx.isLabelDef) {
            if (ctx.address != 0) {
                currentAddress = ctx.address;
                LOG_DEBUG_F("Setting current address to label %s: 0x%llX",
                    ctx.labelName.c_str(), currentAddress);
            }
            else if (currentAddress != 0) {
                // **��Ҫ�޸��������ǩû��Ԥ�����ַ��ʹ�õ�ǰ��ַ**
                ctx.address = currentAddress;
                symbolMgr->RegisterSymbol(ctx.labelName, currentAddress, 0, true);
                LOG_DEBUG_F("Assigning current address to label %s: 0x%llX",
                    ctx.labelName.c_str(), currentAddress);
            }
            // ��ǩ����ռ�ÿռ�
            continue;
        }

        // ����û�е�ǰ��ַ��ָ��
        if (currentAddress == 0) {
            LOG_TRACE_F("Skipping instruction (no address): %s", ctx.originalLine.c_str());
            continue;
        }

        // �����ַ��ָ��
        if (ctx.address != currentAddress) {
            anyAddressChanged = true;
            ctx.address = currentAddress;
        }

        // ����ָ���
        if (ProcessSpecialInstruction(ctx, engine)) {
            currentAddress += ctx.actualSize;
            ctx.sizeCalculated = true;
            instructionIndex++;
            continue;
        }

        // ׼��������
        std::string asmLine = ctx.processedLine;

        // ������ת��
        if (asmLine.find("(float)") != std::string::npos) {
            asmLine = engine->ProcessFloatConversion(asmLine);
        }
        asmLine = PrepareCEStyleHex(asmLine);

        // ���⴦��ȷ���������ڵĴ�������0xǰ׺
        size_t bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

            // ���� + �� - �����ƫ����
            size_t opPos = content.find_last_of("+-");
            if (opPos != std::string::npos) {
                std::string offsetPart = content.substr(opPos + 1);
                offsetPart.erase(0, offsetPart.find_first_not_of(" \t"));
                offsetPart.erase(offsetPart.find_last_not_of(" \t") + 1);

                // ����Ǵ�������û��0xǰ׺�������
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {

                    std::string newContent = content.substr(0, opPos + 1) + "0x" + offsetPart;
                    asmLine = asmLine.substr(0, bracketStart + 1) + newContent + asmLine.substr(bracketEnd);

                    // ��������λ��
                    bracketEnd = bracketStart + 1 + newContent.length();
                }
            }

            bracketStart = asmLine.find('[', bracketEnd);
        }

        // **ת��ΪRIP���Ѱַ**
        asmLine = ConvertToRipRelative(asmLine, ctx);

        // ����ָ������
        for (auto& ref : ctx.ripReferences) {
            ref.instructionIndex = instructionIndex;
        }

        // ʹ�� Keystone ��ȡָ���С
        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            if (ctx.actualSize != size) {
                anyAddressChanged = true;
                ctx.actualSize = size;
            }
            ctx.sizeCalculated = true;

            // ���ʹ����RIPռλ����������ʱ������
            if (ctx.usedRipPlaceholder) {
                ctx.machineCode.assign(encode, encode + size);
            }

            ks_free(encode);

            LOG_TRACE_F("Instruction at 0x%llX: '%s' size = %zu bytes",
                ctx.address, ctx.originalLine.c_str(), size);
        }
        else {
            // ���ʧ�� - ���� SmartAssemble
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

                // ���ʹ����RIPռλ�������������
                if (ctx.usedRipPlaceholder) {
                    ctx.machineCode = machineCode;
                }

                LOG_DEBUG_F("SmartAssemble size calculation succeeded: %zu bytes for '%s'",
                    smartSize, ctx.originalLine.c_str());
            }
            else {
                LOG_ERROR_F("Failed to assemble for size: %s (error: %s)", asmLine.c_str(), ks_strerror(err));
                warnings.push_back("Size calculation failed for: " + ctx.originalLine);

                // ʹ�ñ��ع���
                size_t estimatedSize = 8;

                // ���⴦��һЩ����ָ��
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
        }  // ȷ����������Ŵ��ڣ�

        currentAddress += ctx.actualSize;
        instructionIndex++;
    }

    // �����֣�ȷ������������ǩ���ѷ����ַ
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

        // ����Ѿ��л����루ʹ����RIPռλ����
        if (!ctx.machineCode.empty() && ctx.usedRipPlaceholder) {
            // ����RIPƫ��
            if (!FixRipOffsets(ctx, engine)) {
                warnings.push_back("Failed to fix RIP offsets for: " + ctx.originalLine);
                return false;
            }
            ctx.assembled = true;
            continue;
        }

        // ����Ѿ�����������
        if (!ctx.machineCode.empty()) {
            ctx.assembled = true;
            continue;
        }

        // ����ָ���
        if (ProcessSpecialInstruction(ctx, engine)) {
            ctx.assembled = true;
            continue;
        }

        // ���� @f/@b ��ת
        if (ctx.processedLine.find("@f") != std::string::npos ||
            ctx.processedLine.find("@b") != std::string::npos) {
            if (engine->ProcessCESpecialJump(ctx.processedLine, ctx.address, ctx.machineCode)) {
                ctx.assembled = true;
                continue;
            }
        }

        // ���������⴦��jmp/callָ��
        std::istringstream iss(ctx.processedLine);
        std::string opcode;
        iss >> opcode;
        std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

        if ((opcode == "jmp" || opcode == "call") && ctx.processedLine.find(' ') != std::string::npos) {
            std::string target;
            iss >> target;

            // ���Ŀ���Ƿ��Ƿ���
            auto symbolMgr = engine->GetSymbolManager();
            uintptr_t targetAddr = 0;

            if (symbolMgr->GetSymbolAddress(target, targetAddr) && targetAddr != 0) {
                // ֱ��������ת������
                if (engine->GenerateJumpBytes(opcode, ctx.address, targetAddr, ctx.machineCode)) {
                    ctx.assembled = true;
                    LOG_DEBUG_F("Generated %s to %s (0x%llX) directly",
                        opcode.c_str(), target.c_str(), targetAddr);
                    continue;
                }
            }
        }

        // ��GenerateMachineCode �����У�����ƫ��
        std::string asmLine = ctx.processedLine;

        // ������ת��
        if (asmLine.find("(float)") != std::string::npos) {
            asmLine = engine->ProcessFloatConversion(asmLine);
        }

        // ȷ�����������ڵ���������
        asmLine = PrepareCEStyleHex(asmLine);

        // ���⴦��ȷ���������ڵĴ�������0xǰ׺
        size_t bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

            // ���� + �� - �����ƫ����
            size_t opPos = content.find_last_of("+-");
            if (opPos != std::string::npos) {
                std::string offsetPart = content.substr(opPos + 1);
                offsetPart.erase(0, offsetPart.find_first_not_of(" \t"));
                offsetPart.erase(offsetPart.find_last_not_of(" \t") + 1);

                // ����Ǵ�������û��0xǰ׺�������
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {

                    std::string newContent = content.substr(0, opPos + 1) + "0x" + offsetPart;
                    asmLine = asmLine.substr(0, bracketStart + 1) + newContent + asmLine.substr(bracketEnd);

                    // ��������λ��
                    bracketEnd = bracketStart + 1 + newContent.length();
                }
            }

            bracketStart = asmLine.find('[', bracketEnd);
        }

        // ����ƫ�ƣ��� [rdx-0C]
        bracketStart = asmLine.find('[');
        while (bracketStart != std::string::npos) {
            size_t bracketEnd = asmLine.find(']', bracketStart);
            if (bracketEnd == std::string::npos) break;

            std::string content = asmLine.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
            size_t minusPos = content.find('-');

            if (minusPos != std::string::npos && minusPos > 0) {
                std::string regPart = content.substr(0, minusPos);
                std::string offsetPart = content.substr(minusPos + 1);

                // ȥ���ո�
                regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
                offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

                // ����Ƿ��ǼĴ���
                if (isX64RegisterName(regPart)) {
                    try {
                        // ����ƫ��ֵ
                        unsigned int offset = 0;
                        if (offsetPart.find("0x") == 0 || offsetPart.find("0X") == 0) {
                            offset = std::stoul(offsetPart.substr(2), nullptr, 16);
                        }
                        else if (std::all_of(offsetPart.begin(), offsetPart.end(), ::isxdigit)) {
                            // CE��񣺴�ʮ����������
                            offset = std::stoul(offsetPart, nullptr, 16);
                        }
                        else {
                            offset = std::stoul(offsetPart, nullptr, 10);
                        }

                        // ת��Ϊ������ʽ
                        unsigned int negOffset = (~offset + 1) & 0xFFFFFFFF;

                        // �����µ��ڴ������
                        std::stringstream newOperand;
                        newOperand << "[" << regPart << "+0x" << std::hex << negOffset << "]";

                        // �滻ԭ���Ĳ�����
                        asmLine = asmLine.substr(0, bracketStart) +
                            newOperand.str() +
                            asmLine.substr(bracketEnd + 1);

                        LOG_DEBUG_F("Converted negative offset: [%s-%s] -> %s",
                            regPart.c_str(), offsetPart.c_str(), newOperand.str().c_str());

                        // ��������λ��
                        bracketEnd = bracketStart + newOperand.str().length();
                    }
                    catch (...) {
                        // ����ʧ�ܣ�����ԭ��
                    }
                }
            }

            // ������һ��������
            bracketStart = asmLine.find('[', bracketEnd);
        }

        // ת��ΪRIP���Ѱַ�������ûת����
        if (!ctx.usedRipPlaceholder) {
            asmLine = ConvertToRipRelative(asmLine, ctx);
        }

        // �滻��������
        asmLine = engine->ReplaceSymbols(asmLine);

        LOG_DEBUG_F("Assembling at 0x%llX: '%s' -> '%s'",
            ctx.address, ctx.processedLine.c_str(), asmLine.c_str());

        unsigned char* encode = nullptr;
        size_t size = 0;
        size_t count = 0;

        if (ks_asm(ksEngine, asmLine.c_str(), ctx.address, &encode, &size, &count) == KS_ERR_OK) {
            ctx.machineCode.assign(encode, encode + size);
            ks_free(encode);

            // ���ʹ����RIPռλ��������ƫ��
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

            // ����ʹ�� SmartAssemble
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

    // NOP ָ��
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

    // ����ָ��
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
    // ����ָ��
    std::istringstream iss(line);
    std::string opcode;
    iss >> opcode;
    std::transform(opcode.begin(), opcode.end(), opcode.begin(), ::tolower);

    // ���⴦����Ҫת����ָ��
    if (opcode == "nop" || opcode == "ret" || opcode == "retn" ||
        opcode == "push" || opcode == "pop") {
        return line;
    }

    // ���ݶ���ָ���Ҫת��
    if (opcode == "db" || opcode == "dw" || opcode == "dd" || opcode == "dq") {
        return line;
    }

    // ��תָ���ҪRIPת�����������Լ������Ѱַ��
    if (opcode == "jmp" || opcode == "call" || opcode == "je" || opcode == "jne" ||
        opcode == "jg" || opcode == "jl" || opcode == "jge" || opcode == "jle") {
        return line;
    }

    std::string result = line;

    // �����ڴ������ [symbol]
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string memOperand = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

        // ȥ���ո�
        memOperand.erase(std::remove_if(memOperand.begin(), memOperand.end(), ::isspace), memOperand.end());

        // ����Ƿ��Ѿ���RIP���Ѱַ
        if (memOperand.find("rip") != std::string::npos) {
            bracketStart = result.find('[', bracketEnd);
            continue;
        }

        // ����Ƿ��Ǵ����ţ����ǼĴ�����������+/-�ȸ��ӱ��ʽ��
        bool isPureSymbol = true;

        // ����Ƿ�����Ĵ���
        if (isX64RegisterName(memOperand)) {
            isPureSymbol = false;
        }

        // ����Ƿ��Ǹ��ӱ��ʽ
        if (memOperand.find('+') != std::string::npos ||
            memOperand.find('*') != std::string::npos) {
            isPureSymbol = false;
        }

        // ���⴦�� reg-offset ��ʽ���� rdx-0C��
        if (memOperand.find('-') != std::string::npos) {
            size_t minusPos = memOperand.find('-');
            std::string beforeMinus = memOperand.substr(0, minusPos);
            if (isX64RegisterName(beforeMinus)) {
                isPureSymbol = false;
            }
        }

        if (isPureSymbol && !memOperand.empty()) {
            // ��¼RIP����
            RipReference ref;
            ref.instructionIndex = 0;
            ref.symbolName = memOperand;
            ref.ripOffsetPosition = 0;
            ref.is32bit = true;

            ctx.ripReferences.push_back(ref);
            ctx.usedRipPlaceholder = true;

            // ���ܴ����Сָʾ��
            size_t ptrPos = result.rfind("ptr", bracketStart);
            bool hasSizeSpec = (ptrPos != std::string::npos && ptrPos < bracketStart);

            if (!hasSizeSpec) {
                // û�д�Сָʾ������Ҫ���������ľ����Ƿ����

                // ����movָ���Ҫ���Դ������
                if (opcode == "mov") {
                    // ��ȡԴ�����������ź���Ĳ��֣�
                    size_t commaPos = result.find(',', bracketEnd);
                    if (commaPos != std::string::npos) {
                        std::string srcOperand = result.substr(commaPos + 1);
                        srcOperand.erase(0, srcOperand.find_first_not_of(" \t"));
                        srcOperand.erase(srcOperand.find_last_not_of(" \t") + 1);

                        // ���Դ��������64λ�Ĵ���������Ҫ��Сָʾ��
                        std::string lowerSrc = srcOperand;
                        std::transform(lowerSrc.begin(), lowerSrc.end(), lowerSrc.begin(), ::tolower);

                        if (lowerSrc == "rax" || lowerSrc == "rbx" || lowerSrc == "rcx" ||
                            lowerSrc == "rdx" || lowerSrc == "rsi" || lowerSrc == "rdi" ||
                            lowerSrc == "rbp" || lowerSrc == "rsp" ||
                            lowerSrc.find("r8") == 0 || lowerSrc.find("r9") == 0 ||
                            lowerSrc.find("r10") == 0 || lowerSrc.find("r11") == 0 ||
                            lowerSrc.find("r12") == 0 || lowerSrc.find("r13") == 0 ||
                            lowerSrc.find("r14") == 0 || lowerSrc.find("r15") == 0) {
                            // 64λ�Ĵ���������Ҫ��Сָʾ��
                            result = result.substr(0, bracketStart + 1) + "rip+0" +
                                result.substr(bracketEnd);
                        }
                        else if (srcOperand.find("0x") != std::string::npos ||
                            std::isdigit(srcOperand[0])) {
                            // ����������Ҫdword ptr
                            result = result.substr(0, bracketStart) + "dword ptr [rip+0" +
                                result.substr(bracketEnd);
                        }
                        else {
                            // ���������Ĭ�ϲ��Ӵ�Сָʾ��
                            result = result.substr(0, bracketStart + 1) + "rip+0" +
                                result.substr(bracketEnd);
                        }
                    }
                }
                else if (opcode == "cmp") {
                    // cmp Ĭ��ʹ�� dword ptr���������д�Сָʾ����
                    result = result.substr(0, bracketStart) + "dword ptr [rip+0" +
                        result.substr(bracketEnd);
                }
                else {
                    // ����ָ�Ĭ�ϲ��Ӵ�Сָʾ��
                    result = result.substr(0, bracketStart + 1) + "rip+0" +
                        result.substr(bracketEnd);
                }
            }
            else {
                // ���д�Сָʾ����ֻ�滻�������ڵ�����
                result = result.substr(0, bracketStart + 1) + "rip+0" +
                    result.substr(bracketEnd);
            }

            LOG_DEBUG_F("Converted [%s] to RIP-relative in: %s -> %s",
                memOperand.c_str(), line.c_str(), result.c_str());
        }

        // ������һ��
        bracketStart = result.find('[', bracketEnd);
    }

    return result;
}
std::string TwoPassAssemblyPass::PrepareCEStyleHex(const std::string& line) {
    std::string result = line;

    // ���ҷ������ڵ�����
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string content = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
        std::string newContent = content;

        // ���� + �� - ����
        size_t opPos = content.find('+');
        bool isPlus = true;
        if (opPos == std::string::npos) {
            opPos = content.find('-');
            isPlus = false;
        }

        if (opPos != std::string::npos) {
            std::string regPart = content.substr(0, opPos);
            std::string offsetPart = content.substr(opPos + 1);

            // ȥ���ո�
            regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
            offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

            // ����ǼĴ���+ƫ�Ƶĸ�ʽ
            if (isX64RegisterName(regPart)) {
                // ���ƫ���Ƿ���Ҫ��� 0x ǰ׺
                if (!offsetPart.empty() &&
                    offsetPart.find("0x") != 0 &&
                    offsetPart.find("0X") != 0 &&
                    offsetPart[0] != '$') {

                    // CE ��񣺷������ڵ�����Ĭ����ʮ������
                    // �����Ƿ���� A-F������� 0x ǰ׺
                    bool isNumeric = std::all_of(offsetPart.begin(), offsetPart.end(),
                        [](char c) { return std::isxdigit(c); });

                    if (isNumeric) {
                        newContent = regPart + (isPlus ? "+0x" : "-0x") + offsetPart;
                        result = result.substr(0, bracketStart + 1) + newContent + result.substr(bracketEnd);

                        LOG_DEBUG_F("Fixed CE-style hex: [%s] -> [%s]", content.c_str(), newContent.c_str());

                        // ��������λ��
                        bracketEnd = bracketStart + 1 + newContent.length();
                    }
                }
            }
        }

        // ������һ��������
        bracketStart = result.find('[', bracketEnd);
    }

    return result;
}
std::string TwoPassAssemblyPass::ProcessNegativeOffset(const std::string& line) {
    std::string result = line;

    // ���� [�Ĵ���-ƫ��] ģʽ
    size_t bracketStart = result.find('[');
    while (bracketStart != std::string::npos) {
        size_t bracketEnd = result.find(']', bracketStart);
        if (bracketEnd == std::string::npos) break;

        std::string memOperand = result.substr(bracketStart + 1, bracketEnd - bracketStart - 1);

        // ���Ҽ���
        size_t minusPos = memOperand.find('-');
        if (minusPos != std::string::npos && minusPos > 0) {
            std::string regPart = memOperand.substr(0, minusPos);
            std::string offsetPart = memOperand.substr(minusPos + 1);

            // ȥ���ո�
            regPart.erase(std::remove_if(regPart.begin(), regPart.end(), ::isspace), regPart.end());
            offsetPart.erase(std::remove_if(offsetPart.begin(), offsetPart.end(), ::isspace), offsetPart.end());

            // ����Ƿ��ǼĴ���
            if (isX64RegisterName(regPart)) {
                // ����ƫ��ֵ
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
                    // ת��Ϊ������ʽ
                    unsigned int negOffset = (~offset + 1) & 0xFFFFFFFF;

                    // �����µ��ڴ������
                    std::stringstream newOperand;
                    newOperand << "[" << regPart << "+0x" << std::hex << negOffset << "]";

                    // �滻ԭ���Ĳ�����
                    result = result.substr(0, bracketStart) +
                        newOperand.str() +
                        result.substr(bracketEnd + 1);

                    LOG_DEBUG_F("Converted negative offset: [%s-%s] -> %s",
                        regPart.c_str(), offsetPart.c_str(), newOperand.str().c_str());
                }
            }
        }

        // ������һ��
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
        // ��ȡĿ����ŵ�ַ
        uintptr_t targetAddr = 0;
        if (!symbolMgr->GetSymbolAddress(ref.symbolName, targetAddr) || targetAddr == 0) {
            LOG_ERROR_F("Cannot resolve symbol for RIP fixup: %s", ref.symbolName.c_str());
            return false;
        }

        // ����RIP���ƫ��
        uintptr_t ripAddr = ctx.address + ctx.actualSize;
        int32_t ripOffset = static_cast<int32_t>(targetAddr - ripAddr);

        // �ڻ������в��� RIP ���Ѱַ��ģʽ
        bool found = false;

        for (size_t i = 0; i <= ctx.machineCode.size() - 4; i++) {
            bool isRipInstruction = false;

            // ��鳣���� RIP ���Ѱַģʽ
            if (i >= 3) {
                // mov [rip+disp32],reg ģʽ: 48 89 05
                if (ctx.machineCode[i - 3] == 0x48 &&
                    ctx.machineCode[i - 2] == 0x89 &&
                    ctx.machineCode[i - 1] == 0x05) {
                    isRipInstruction = true;
                }
                // mov reg,[rip+disp32] ģʽ: 48 8B 05
                else if (ctx.machineCode[i - 3] == 0x48 &&
                    ctx.machineCode[i - 2] == 0x8B &&
                    ctx.machineCode[i - 1] == 0x05) {
                    isRipInstruction = true;
                }
            }
            if (i >= 2) {
                // cmp dword ptr [rip+disp32],imm8 ģʽ: 83 3D
                if (ctx.machineCode[i - 2] == 0x83 &&
                    ctx.machineCode[i - 1] == 0x3D) {
                    isRipInstruction = true;
                }
                // cmp dword ptr [rip+disp32],imm32 ģʽ: 81 3D
                else if (ctx.machineCode[i - 2] == 0x81 &&
                    ctx.machineCode[i - 1] == 0x3D) {
                    isRipInstruction = true;
                }
            }
            if (i >= 1) {
                // ͨ�ü�飺ModR/M �ֽڵĵ�3λ�Ƿ�Ϊ101(5) �� Mod=00
                uint8_t modRM = ctx.machineCode[i - 1];
                if ((modRM & 0xC7) == 0x05) { // Mod=00, R/M=101
                    isRipInstruction = true;
                }
            }

            if (isRipInstruction) {
                // ��ȡ��ǰ��32λֵ
                int32_t currentOffset = *reinterpret_cast<int32_t*>(&ctx.machineCode[i]);

                // ����Ƿ���Ҫ���£�������0�����Ǿɵ�ƫ��ֵ��
                if (currentOffset == 0 || currentOffset != ripOffset) {
                    // д����ȷ��ƫ��
                    *reinterpret_cast<int32_t*>(&ctx.machineCode[i]) = ripOffset;
                    found = true;

                    LOG_DEBUG_F("Fixed RIP offset for %s: 0x%X -> 0x%X at position %zu",
                        ref.symbolName.c_str(), currentOffset, ripOffset, i);
                    break;
                }
                else {
                    // ƫ���Ѿ���ȷ
                    found = true;
                    LOG_DEBUG_F("RIP offset for %s already correct: 0x%X at position %zu",
                        ref.symbolName.c_str(), ripOffset, i);
                    break;
                }
            }
        }

        if (!found) {
            // ��ӡ�������԰�������
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

// CodeEmissionPass ʵ��
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

    // ����Ƿ��Ѹ��ӵ�����
    if (!memoryMgr->IsAttached()) {
        result.success = false;
        result.errorMessage = "Not attached to any process";
        LOG_ERROR("Not attached to any process");
        return result;
    }

    // �ռ�������Ҫд���ָ��
    struct WriteOperation {
        uintptr_t address;
        std::vector<uint8_t> originalBytes;
        std::vector<uint8_t> newBytes;
        std::string description;
        bool critical;  // �Ƿ��ǹؼ�����������Ҫ�� hook �㣩
    };

    std::vector<WriteOperation> writeOps;

    // ��һ����׼������д�����
    LOG_DEBUG("Preparing write operations...");

    for (const auto& ctx : instructions) {
        if (ctx.machineCode.empty() || ctx.address == 0) continue;
        if (ctx.isLabelDef) continue;  // ������ǩ����

        WriteOperation op;
        op.address = ctx.address;
        op.newBytes = ctx.machineCode;
        op.originalBytes.resize(ctx.machineCode.size());
        op.description = ctx.originalLine;

        // �ж��Ƿ��ǹؼ�����
        op.critical = false;
        if (ctx.originalLine.find("jmp") == 0 || ctx.originalLine.find("call") == 0) {
            // ��Ҫ����ת�͵���ͨ���ǹؼ���
            op.critical = true;
        }

        writeOps.push_back(op);
    }

    if (writeOps.empty()) {
        LOG_INFO("No code to write");
        return result;
    }

    LOG_INFO_F("Preparing to write %zu operations", writeOps.size());

    // �ڶ�������ȡ����ԭʼ�ֽ�
    LOG_DEBUG("Reading original bytes...");

    for (auto& op : writeOps) {
        if (!memoryMgr->ReadMemory(op.address, op.originalBytes.data(), op.originalBytes.size())) {
            LOG_WARN_F("Failed to read original bytes at 0x%llX (size: %zu)",
                op.address, op.originalBytes.size());
            result.warnings.push_back("Failed to read original bytes at 0x" +
                std::to_string(op.address));

            // ���ڷǹؼ����������������ڹؼ�������ʧ��
            if (op.critical) {
                result.success = false;
                result.errorMessage = "Failed to read critical memory region";
                return result;
            }
        }
        else {
            // ��¼ԭʼ�ֽڣ����ڵ��ԣ�
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

    // �������������޸��ڴ汣��
    LOG_DEBUG("Changing memory protection...");

    struct ProtectionChange {
        uintptr_t address;
        size_t size;
        DWORD oldProtect;
        bool changed;
    };

    std::vector<ProtectionChange> protChanges;

    // �ϲ����ڵ��ڴ������Լ��ٱ������Ĵ���
    for (const auto& op : writeOps) {
        bool merged = false;

        // ���������еı������ĺϲ�
        for (auto& prot : protChanges) {
            // �����ַ���ڻ��ص�
            if (op.address >= prot.address &&
                op.address <= prot.address + prot.size + 0x1000) {  // 4KB �ݲ�

                // ��չ����
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

    // ִ���ڴ汣������
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

    // ���Ĳ���д���´���
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
            // ��¼������Ϣ
            engine->AddPatch(op.address, op.originalBytes, op.newBytes);

            successCount++;
            result.instructionsModified++;

            LOG_DEBUG_F("Wrote %zu bytes at 0x%llX: %s",
                op.newBytes.size(), op.address, op.description.c_str());

            // ��ϸ�ĵ������
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

    // ���岽���ָ��ڴ汣��
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

    // ��������ˢ��ָ��棨��Ҫ����
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

    // ������ϸ�ı���
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

    // ����йؼ�����ʧ�ܣ�����ʧ��
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