// PassManager.h - Multi-pass processing manager
#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <Windows.h>

// Forward declarations
class CEAssemblyEngine;
class SymbolManager;
class MemoryManager;
class PatternScanner;
enum class CommandType;

// RIP reference information
struct RipReference {
    size_t instructionIndex;
    std::string symbolName;
    size_t ripOffsetPosition;
    bool is32bit;
};

// Instruction context
struct InstructionContext {
    // Basic information
    std::string originalLine;
    std::string processedLine;
    CommandType commandType;
    std::vector<std::string> parameters;

    // Address and size information
    uintptr_t address = 0;
    size_t actualSize = 0;
    std::vector<uint8_t> machineCode;

    // Label information
    bool isLabelDef = false;
    std::string labelName;

    // Offset label related
    bool isOffsetLabel = false;
    std::string baseLabel;
    std::string offsetStr;

    // Status flags
    bool needsSymbolResolution = false;
    bool sizeCalculated = false;
    bool assembled = false;
    bool usedRipPlaceholder = false;

    // Symbol dependencies
    std::vector<std::string> unresolvedSymbols;

    // RIP references
    std::vector<RipReference> ripReferences;
};

// Pass execution result
struct PassResult {
    bool success = true;
    std::string errorMessage;
    std::vector<std::string> warnings;
    int instructionsProcessed = 0;
    int instructionsModified = 0;
};

// Base class for processing passes
class ProcessingPass {
public:
    virtual ~ProcessingPass() = default;

    virtual std::string GetName() const = 0;
    virtual PassResult Execute(
        std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine
    ) = 0;
    virtual bool RequiresIteration() const { return false; }
};

// Pass 1: Preprocessing and command identification
class PreprocessingPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Preprocessing"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 2: Symbol collection (aobscanmodule, alloc, label, etc.)
class SymbolCollectionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Symbol Collection"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass 3: Two-pass assembly (address allocation + code generation)
class TwoPassAssemblyPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Two-Pass Assembly"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
    bool RequiresIteration() const override { return true; }

private:
    // First pass: calculate sizes and allocate addresses
    bool CalculateSizesAndAddresses(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // Second pass: generate machine code
    bool GenerateMachineCode(std::vector<InstructionContext>& instructions,
        CEAssemblyEngine* engine,
        std::vector<std::string>& warnings);

    // Helper methods
    bool ProcessSpecialInstruction(InstructionContext& ctx, CEAssemblyEngine* engine);
    size_t CalculateDataSize(const std::string& line);
    std::string ConvertToRipRelative(const std::string& line, InstructionContext& ctx);
    std::string PrepareCEStyleHex(const std::string& line);
    std::string ProcessNegativeOffset(const std::string& line);
    bool FixRipOffsets(InstructionContext& ctx, CEAssemblyEngine* engine);
};

// Pass 4: Code emission
class CodeEmissionPass : public ProcessingPass {
public:
    std::string GetName() const override { return "Code Emission"; }
    PassResult Execute(std::vector<InstructionContext>& instructions, CEAssemblyEngine* engine) override;
};

// Pass Manager
class PassManager {
public:
    PassManager();
    ~PassManager();

    // Add a processing pass
    void AddPass(std::unique_ptr<ProcessingPass> pass);

    // Run all passes
    bool RunAllPasses(
        const std::vector<std::string>& lines,
        CEAssemblyEngine* engine
    );

    // Get error information
    std::string GetLastError() const { return m_lastError; }

    // Get processed instructions
    const std::vector<InstructionContext>& GetInstructions() const { return m_instructions; }

    // Get statistics
    void GetStatistics(int& totalPasses, int& totalInstructions) const;

private:
    std::vector<std::unique_ptr<ProcessingPass>> m_passes;
    std::vector<InstructionContext> m_instructions;
    std::string m_lastError;

    // Convert raw lines to instruction contexts
    void ConvertLinesToInstructions(const std::vector<std::string>& lines);
};

// Helper functions (defined in cpp)
bool isX64RegisterName(const std::string& token);
bool isX64Mnemonic(const std::string& token);
bool isSizeSpecifier(const std::string& token);
bool isDataDirective(const std::string& token);