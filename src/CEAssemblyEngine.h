#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <Windows.h>
#include <keystone/keystone.h>
#include "MemoryAllocator.h"

// 前向声明
class SymbolManager;
class PatternScanner;
class MemoryAllocator;
class CEScriptParser;
class CEScript;
class ProcessManager;

// 脚本块类型
enum class BlockType {
    ENABLE,
    DISABLE,
    NONE
};

// 符号类型
enum class SymbolType {
    ADDRESS,
    LABEL,
    VARIABLE
};

// 符号信息
struct Symbol {
    std::string name;
    SymbolType type;
    uintptr_t address;
    size_t size;
    std::vector<uint8_t> originalBytes;
};

// 通配符捕获信息
struct WildcardCapture {
    std::string name;
    size_t offset;
    size_t size;
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

    // 创建新脚本
    std::shared_ptr<CEScript> CreateScript(const std::string& name = "");

    // 获取已创建的脚本
    std::shared_ptr<CEScript> GetScript(const std::string& name);

    // 获取错误信息
    std::string GetLastError() const { return m_lastError; }

    // 获取符号管理器（高级用法）
    SymbolManager* GetSymbolManager() { return m_symbolManager.get(); }

    // 获取进程管理器（高级用法）
    ProcessManager* GetProcessManager() { return m_processManager.get(); }

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

    // 汇编代码
    bool AssembleCode(const std::vector<std::string>& codeLines, uintptr_t baseAddress, std::vector<uint8_t>& output);

    // 处理跳转和符号引用
    bool ProcessJumpInstructions(const std::string& instruction, uintptr_t currentAddress, std::vector<uint8_t>& output);

    // 替换符号
    std::string ReplaceSymbols(const std::string& line);

    // 汇编指令处理
    bool ProcessAssemblyInstruction(const std::string& line);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool WriteBytes(const std::vector<uint8_t>& bytes);
    bool ProcessDbCommand(const std::string& line);

    // 成员变量
    std::unique_ptr<ProcessManager> m_processManager;
    std::unique_ptr<SymbolManager> m_symbolManager;
    std::unique_ptr<PatternScanner> m_patternScanner;
    std::unique_ptr<MemoryAllocator> m_memoryAllocator;
    std::unique_ptr<CEScriptParser> m_parser;

    ks_engine* m_ksEngine;
    std::string m_lastError;
    std::string m_targetModule;

    // 当前脚本上下文
    CEScript* m_currentScript;

    // 管理的脚本集合
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // 补丁信息
    std::vector<PatchInfo> m_patches;

    // 当前处理地址
    uintptr_t m_currentAddress;

    // 添加补丁记录
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes, const std::vector<uint8_t>& newBytes);
};