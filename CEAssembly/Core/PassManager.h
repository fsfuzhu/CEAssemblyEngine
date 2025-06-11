// PassManager.h - 多遍处理管理器
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <Windows.h>

// 前向声明
class CEAssemblyEngine;
class SymbolManager;
class MemoryManager;
class PatternScanner;
enum class CommandType;

// 指令的中间表示
struct InstructionContext {
    // 基本信息
    std::string originalLine;        // 原始行
    std::string processedLine;       // 处理后的行
    CommandType commandType;         // 命令类型
    std::vector<std::string> parameters;  // 参数

    // 地址和大小信息
    uintptr_t address = 0;          // 指令地址
    size_t actualSize = 0;          // 实际大小（由汇编器确定）
    std::vector<uint8_t> machineCode;    // 机器码

    // 标签信息
    bool isLabelDef = false;        // 是否是标签定义
    std::string labelName;          // 标签名称

    // 状态标记
    bool needsSymbolResolution = false;   // 需要符号解析
    bool sizeCalculated = false;          // 大小已计算
    bool assembled = false;               // 已汇编

    // 符号依赖
    std::vector<std::string> unresolvedSymbols;  // 未解析的符号
};

// Pass 执行结果
struct PassResult {
    bool success = true;
    std::string errorMessage;
    std::vector<std::string> warnings;
    int instructionsProcessed = 0;
    int instructionsModified = 0;
};

// Pass 基类
class ProcessingPass {
public:
    virtual ~ProcessingPass() = default;

    // 获取 Pass 名称
    virtual std::string GetName() const = 0;

    // 执行 Pass
    virtual PassResult Execute(
        std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine
    ) = 0;

    // 是否需要重复执行直到稳定
    virtual bool RequiresIteration() const { return false; }
};

// Pass 1: 预处理和命令识别
class PreprocessingPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Preprocessing"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 2: 符号收集（处理 aobscanmodule, alloc, label 等）
class SymbolCollectionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Symbol Collection"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 3: 两遍汇编（地址分配 + 代码生成）
class TwoPassAssemblyPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Two-Pass Assembly"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
    bool RequiresIteration() const override { return true; }

private:
    // 第一遍：计算大小和分配地址
    bool CalculateSizesAndAddresses(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // 第二遍：生成机器码
    bool GenerateMachineCode(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // 辅助方法
    bool ProcessSpecialInstruction(InstructionContext& ctx, CEAssemblyEngine* engine);
    size_t CalculateDataSize(const std::string& line);
};

// Pass 4: 代码写入
class CodeEmissionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Code Emission"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 管理器
class PassManager {
public:
    PassManager();
    ~PassManager();

    // 添加 Pass
    void AddPass(std::unique_ptr<ProcessingPass> pass);

    // 执行所有 Pass
    bool RunAllPasses(
        const std::vector<std::string>& lines,
        CEAssemblyEngine* engine
    );

    // 获取最后的错误信息
    std::string GetLastError() const { return m_lastError; }

    // 获取处理后的指令
    const std::vector<InstructionContext>& GetInstructions() const { return m_instructions; }

    // 获取执行统计
    void GetStatistics(int& totalPasses, int& totalInstructions) const;

private:
    std::vector<std::unique_ptr<ProcessingPass>> m_passes;
    std::vector<InstructionContext> m_instructions;
    std::string m_lastError;

    // 将原始行转换为指令上下文
    void ConvertLinesToInstructions(const std::vector<std::string>& lines);
};