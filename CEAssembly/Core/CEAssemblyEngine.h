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

    // Friend class to allow CEScript access to private methods
    friend class CEScript;

private:
    struct DelayedInstruction {
        std::string instruction;
        uintptr_t address;
    };

    // Set current script context
    void SetCurrentScript(CEScript* script) { m_currentScript = script; }

    // Process script blocks
    bool ProcessEnableBlock(const std::vector<std::string>& lines);
    bool ProcessDisableBlock(const std::vector<std::string>& lines);

    // Get patch information
    std::vector<PatchInfo> GetPatches() const { return m_patches; }

    // Process CE commands
    bool ProcessAobScanModule(const std::string& line);
    bool ProcessAlloc(const std::string& line);
    bool ProcessLabel(const std::string& line);
    bool ProcessRegisterSymbol(const std::string& line);
    bool ProcessUnregisterSymbol(const std::string& line);
    bool ProcessDealloc(const std::string& line);
    bool ProcessDbCommand(const std::string& line);

    // Assembly instruction processing
    bool ProcessAssemblyInstruction(const std::string& line);
    std::string ProcessFloatConversion(const std::string& line);
    bool ProcessAssemblyBatch(const std::vector<std::string>& instructions, uintptr_t startAddress);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool WriteBytes(const std::vector<uint8_t>& bytes);

    // Symbol replacement
    std::string ReplaceSymbols(const std::string& line);

    // Add patch record
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes,
        const std::vector<uint8_t>& newBytes);

    // Helper functions for special instruction processing
    bool ProcessDataDirective(const std::string& line);
    bool ProcessCESpecialJump(const std::string& line);
    bool GenerateConditionalJump(uint8_t opcode, uintptr_t targetAddr);
    bool ProcessSpecialMovInstruction(const std::string& line);

    // For tracking anonymous labels (@@)
    std::vector<uintptr_t> m_anonymousLabels;

    // For tracking all labels in order
    std::map<uintptr_t, std::string> m_allLabels;  // address -> label name ("@@" for anonymous)

    // Helper to find next/previous anonymous label
    uintptr_t FindNextAnonymousLabel(uintptr_t fromAddress);
    uintptr_t FindPreviousAnonymousLabel(uintptr_t fromAddress);

    // Helper to find next/previous label (any type)
    uintptr_t FindNextLabel(uintptr_t fromAddress);
    uintptr_t FindPreviousLabel(uintptr_t fromAddress);

    // Member variables
    std::unique_ptr<MemoryManager> m_memoryManager;     // Memory management
    std::unique_ptr<SymbolManager> m_symbolManager;     // Symbol management
    std::unique_ptr<PatternScanner> m_patternScanner;   // Pattern scanner
    std::unique_ptr<CEScriptParser> m_parser;           // Script parser

    ks_engine* m_ksEngine;                               // Keystone engine
    std::string m_lastError;                             // Last error message
    CEScript* m_currentScript;                           // Current script context

    // Script collection
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // Patch information
    std::vector<PatchInfo> m_patches;

    // Current processing address
    uintptr_t m_currentAddress;
};