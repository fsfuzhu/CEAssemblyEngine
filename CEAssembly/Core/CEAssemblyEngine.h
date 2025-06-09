// CEAssemblyEngine.h - CE汇编引擎主类
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <Windows.h>
#include <keystone/keystone.h>

// 前向声明
class SymbolManager;
class PatternScanner;
class MemoryManager;
class CEScriptParser;
class CEScript;

// 命令类型
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

// 解析后的命令
struct ParsedCommand {
    CommandType type;
    std::vector<std::string> parameters;
    std::string rawLine;
};

// 补丁信息
struct PatchInfo {
    uintptr_t address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> newBytes;
};

// CE汇编引擎主类
class CEAssemblyEngine {
public:
    CEAssemblyEngine();
    ~CEAssemblyEngine();

    // 目标进程管理
    bool AttachToProcess(DWORD pid);
    bool AttachToProcess(const std::string& processName);
    void DetachFromProcess();
    bool IsAttached() const;
    DWORD GetTargetPID() const;

    // 脚本管理
    std::shared_ptr<CEScript> CreateScript(const std::string& name = "");
    std::shared_ptr<CEScript> GetScript(const std::string& name);

    // 获取错误信息
    std::string GetLastError() const { return m_lastError; }

    // 获取管理器（高级用法）
    SymbolManager* GetSymbolManager() { return m_symbolManager.get(); }
    MemoryManager* GetMemoryManager() { return m_memoryManager.get(); }

    // 友元类，允许CEScript访问内部方法
    friend class CEScript;

private:
    // 设置当前脚本上下文
    void SetCurrentScript(CEScript* script) { m_currentScript = script; }

    // 处理脚本块
    bool ProcessEnableBlock(const std::vector<std::string>& lines);
    bool ProcessDisableBlock(const std::vector<std::string>& lines);

    // 获取补丁信息
    std::vector<PatchInfo> GetPatches() const { return m_patches; }

    // 处理CE命令
    bool ProcessAobScanModule(const std::string& line);
    bool ProcessAlloc(const std::string& line);
    bool ProcessLabel(const std::string& line);
    bool ProcessRegisterSymbol(const std::string& line);
    bool ProcessUnregisterSymbol(const std::string& line);
    bool ProcessDealloc(const std::string& line);
    bool ProcessDbCommand(const std::string& line);

    // 汇编指令处理
    bool ProcessAssemblyInstruction(const std::string& line);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool WriteBytes(const std::vector<uint8_t>& bytes);

    // 符号替换
    std::string ReplaceSymbols(const std::string& line);

    // 添加补丁记录
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes,
        const std::vector<uint8_t>& newBytes);

    // 成员变量
    std::unique_ptr<MemoryManager> m_memoryManager;     // 统一的内存管理器
    std::unique_ptr<SymbolManager> m_symbolManager;     // 符号管理器
    std::unique_ptr<PatternScanner> m_patternScanner;   // 模式扫描器
    std::unique_ptr<CEScriptParser> m_parser;           // 脚本解析器

    ks_engine* m_ksEngine;                               // Keystone汇编引擎
    std::string m_lastError;                             // 最后错误信息
    CEScript* m_currentScript;                           // 当前脚本上下文

    // 管理的脚本集合
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // 补丁信息
    std::vector<PatchInfo> m_patches;

    // 当前处理地址
    uintptr_t m_currentAddress;
};