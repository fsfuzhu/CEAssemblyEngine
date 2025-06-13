// CEAssemblyEngine.h - CE Assembly Engine Main Class
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <Windows.h>
#include <keystone/keystone.h>

// Forward declarations
class SymbolManager;
class PatternScanner;
class MemoryManager;
class CEScriptParser;
class CEScript;
class PassManager;

// Command types
enum class CommandType {
    AOBSCANMODULE,
    ALLOC,
    LABEL,
    REGISTERSYMBOL,
    UNREGISTERSYMBOL,
    DEALLOC,
    DB,
    ASSEMBLY,
    UNKNOWN
};

// Parsed command structure
struct ParsedCommand {
    CommandType type;
    std::vector<std::string> parameters;
    std::string rawLine;
};

// Patch information
struct PatchInfo {
    uintptr_t address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> newBytes;
};

// CE Assembly Engine class
class CEAssemblyEngine {
public:
    CEAssemblyEngine();
    ~CEAssemblyEngine();

    // Process management
    bool AttachToProcess(DWORD pid);
    bool AttachToProcess(const std::string& processName);
    void DetachFromProcess();
    bool IsAttached() const;
    DWORD GetTargetPID() const;

    // Script management
    std::shared_ptr<CEScript> CreateScript(const std::string& name = "");
    std::shared_ptr<CEScript> GetScript(const std::string& name);

    // Error handling
    std::string GetLastError() const { return m_lastError; }

    // Get component pointers (for advanced usage)
    SymbolManager* GetSymbolManager() { return m_symbolManager.get(); }
    MemoryManager* GetMemoryManager() { return m_memoryManager.get(); }
    PatternScanner* GetPatternScanner() { return m_patternScanner.get(); }
    ks_engine* GetKeystoneEngine() { return m_ksEngine; }
    PassManager* GetPassManager() { return m_passManager.get(); }

    // Patch management
    void RestoreAllPatches(const std::vector<PatchInfo>& patches);
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes,
        const std::vector<uint8_t>& newBytes);
    std::vector<PatchInfo>* GetPatchList() { return &m_patches; }

    // Public utility methods (used by PassManager)
    std::string ProcessFloatConversion(const std::string& line);
    std::string ProcessCENumbers(const std::string& line);
    std::string ReplaceSymbols(const std::string& line);
    std::string ReplaceSymbolsForEstimation(const std::string& line);
    size_t EstimateInstructionSize(const std::string& line);

    // Special instruction processing
    bool ProcessCESpecialJump(const std::string& line, uintptr_t address, std::vector<uint8_t>& machineCode);
    bool ProcessDataDirective(const std::string& line, std::vector<uint8_t>& dataBytes);
    bool GenerateJumpBytes(const std::string& opcode, uintptr_t fromAddr,
        uintptr_t toAddr, std::vector<uint8_t>& bytes);
    bool GenerateConditionalJumpBytes(const std::string& opcode, uintptr_t fromAddr,
        uintptr_t toAddr, std::vector<uint8_t>& bytes);

    // Smart assembly with automatic fixing
    bool SmartAssemble(const std::string& instruction, uintptr_t address,
        std::vector<uint8_t>& machineCode, std::string& finalInstruction);

    // Anonymous label management
    void SetAnonymousLabels(const std::vector<uintptr_t>& labels) { m_anonymousLabels = labels; }

    // Friend classes for private access
    friend class CEScript;
    friend class PassManager;

private:
    // Script processing (used by CEScript)
    void SetCurrentScript(CEScript* script) { m_currentScript = script; }
    bool ProcessEnableBlock(const std::vector<std::string>& lines);
    bool ProcessDisableBlock(const std::vector<std::string>& lines);
    std::vector<PatchInfo> GetPatches() const { return m_patches; }
    void CleanupScript(CEScript* script);

    // CE command processing (internal)
    bool ProcessAobScanModule(const std::string& line);
    bool ProcessAlloc(const std::string& line);
    bool ProcessLabel(const std::string& line);
    bool ProcessRegisterSymbol(const std::string& line);
    bool ProcessUnregisterSymbol(const std::string& line);
    bool ProcessDealloc(const std::string& line);
    bool ProcessDbCommand(const std::string& line);

    // Assembly instruction processing (internal)
    bool ProcessAssemblyInstruction(const std::string& line);
    bool ProcessAssemblyBatch(const std::vector<std::string>& instructions, uintptr_t startAddress);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool ProcessSpecialMovInstruction(const std::string& line);
    bool ProcessDataDirective(const std::string& line);
    bool ProcessCESpecialJump(const std::string& line);
    bool WriteBytes(const std::vector<uint8_t>& bytes);

    // Helper functions
    bool GenerateConditionalJump(uint8_t opcode, uintptr_t targetAddr);
    bool IsInHexContext(const std::string& line, size_t pos);
    std::string PreprocessAnonymousLabels(const std::string& code);

    // Anonymous label tracking
    std::vector<uintptr_t> m_anonymousLabels;
    std::map<uintptr_t, std::string> m_allLabels;  // address -> label name
    uintptr_t FindNextAnonymousLabel(uintptr_t fromAddress);
    uintptr_t FindPreviousAnonymousLabel(uintptr_t fromAddress);
    uintptr_t FindNextLabel(uintptr_t fromAddress);
    uintptr_t FindPreviousLabel(uintptr_t fromAddress);

    // Member variables
    std::unique_ptr<MemoryManager> m_memoryManager;
    std::unique_ptr<SymbolManager> m_symbolManager;
    std::unique_ptr<PatternScanner> m_patternScanner;
    std::unique_ptr<CEScriptParser> m_parser;
    std::unique_ptr<PassManager> m_passManager;

    ks_engine* m_ksEngine;
    std::string m_lastError;
    CEScript* m_currentScript;
    uintptr_t m_currentAddress;

    // Script collection
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // Patch information
    std::vector<PatchInfo> m_patches;
};