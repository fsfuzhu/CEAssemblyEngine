// PassManager.h - ��鴦��������������޸İ棩
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <Windows.h>

// ǰ������
class CEAssemblyEngine;
class SymbolManager;
class MemoryManager;
class PatternScanner;
enum class CommandType;

// RIP������Ϣ
struct RipReference {
    size_t instructionIndex;     // ָ������
    std::string symbolName;      // ���õķ�����
    size_t ripOffsetPosition;    // RIPƫ���ڻ������е�λ��
    bool is32bit;                // �Ƿ���32λƫ�ƣ�true������8λ��false��
};

// ָ����м��ʾ
struct InstructionContext {
    // ������Ϣ
    std::string originalLine;        // ԭʼ��
    std::string processedLine;       // ��������
    CommandType commandType;         // ��������
    std::vector<std::string> parameters;  // ����

    // ��ַ�ʹ�С��Ϣ
    uintptr_t address = 0;          // ָ���ַ
    size_t actualSize = 0;          // ʵ�ʴ�С���ɻ����ȷ����
    std::vector<uint8_t> machineCode;    // ������

    // ��ǩ��Ϣ
    bool isLabelDef = false;        // �Ƿ��Ǳ�ǩ����
    std::string labelName;          // ��ǩ����

    // ƫ�Ʊ�ǩ���
    bool isOffsetLabel = false;     // �Ƿ���ƫ�Ʊ�ǩ���� newmem+200��
    std::string baseLabel;          // ������ǩ������ "newmem"��
    std::string offsetStr;          // ƫ���ַ������� "200"��

    // ״̬���
    bool needsSymbolResolution = false;   // ��Ҫ���Ž���
    bool sizeCalculated = false;          // ��С�Ѽ���
    bool assembled = false;               // �ѻ��
    bool usedRipPlaceholder = false;      // ʹ����RIPռλ��

    // ��������
    std::vector<std::string> unresolvedSymbols;  // δ�����ķ���

    // RIP����
    std::vector<RipReference> ripReferences;     // RIP�����б�
};

// Pass ִ�н��
struct PassResult {
    bool success = true;
    std::string errorMessage;
    std::vector<std::string> warnings;
    int instructionsProcessed = 0;
    int instructionsModified = 0;
};

// Pass ����
class ProcessingPass {
public:
    virtual ~ProcessingPass() = default;

    // ��ȡ Pass ����
    virtual std::string GetName() const = 0;

    // ִ�� Pass
    virtual PassResult Execute(
        std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine
    ) = 0;

    // �Ƿ���Ҫ�ظ�ִ��ֱ���ȶ�
    virtual bool RequiresIteration() const { return false; }
};

// Pass 1: Ԥ���������ʶ��
class PreprocessingPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Preprocessing"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 2: �����ռ������� aobscanmodule, alloc, label �ȣ�
class SymbolCollectionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Symbol Collection"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 3: �����ࣨ��ַ���� + �������ɣ�
class TwoPassAssemblyPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Two-Pass Assembly"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
    bool RequiresIteration() const override { return true; }

private:
    // ��һ�飺�����С�ͷ����ַ��ʹ��RIPռλ����
    bool CalculateSizesAndAddresses(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // �ڶ��飺���ɻ����루����RIPƫ�ƣ�
    bool GenerateMachineCode(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // ��������
    bool ProcessSpecialInstruction(InstructionContext& ctx, CEAssemblyEngine* engine);
    size_t CalculateDataSize(const std::string& line);

    // �������������滻ΪRIP���Ѱַ
    std::string ConvertToRipRelative(const std::string& line, InstructionContext& ctx);

    // ����������RIPƫ��
    bool FixRipOffsets(InstructionContext& ctx, CEAssemblyEngine* engine);
};

// Pass 4: ����д��
class CodeEmissionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Code Emission"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass ������
class PassManager {
public:
    PassManager();
    ~PassManager();

    // ��� Pass
    void AddPass(std::unique_ptr<ProcessingPass> pass);

    // ִ������ Pass
    bool RunAllPasses(
        const std::vector<std::string>& lines,
        CEAssemblyEngine* engine
    );

    // ��ȡ���Ĵ�����Ϣ
    std::string GetLastError() const { return m_lastError; }

    // ��ȡ������ָ��
    const std::vector<InstructionContext>& GetInstructions() const { return m_instructions; }

    // ��ȡִ��ͳ��
    void GetStatistics(int& totalPasses, int& totalInstructions) const;

private:
    std::vector<std::unique_ptr<ProcessingPass>> m_passes;
    std::vector<InstructionContext> m_instructions;
    std::string m_lastError;

    // ��ԭʼ��ת��Ϊָ��������
    void ConvertLinesToInstructions(const std::vector<std::string>& lines);
};