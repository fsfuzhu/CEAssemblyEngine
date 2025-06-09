// CEAssemblyEngine.h - CE�����������
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <Windows.h>
#include <keystone/keystone.h>

// ǰ������
class SymbolManager;
class PatternScanner;
class MemoryManager;
class CEScriptParser;
class CEScript;

// ��������
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

// �����������
struct ParsedCommand {
    CommandType type;
    std::vector<std::string> parameters;
    std::string rawLine;
};

// ������Ϣ
struct PatchInfo {
    uintptr_t address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> newBytes;
};

// CE�����������
class CEAssemblyEngine {
public:
    CEAssemblyEngine();
    ~CEAssemblyEngine();

    // Ŀ����̹���
    bool AttachToProcess(DWORD pid);
    bool AttachToProcess(const std::string& processName);
    void DetachFromProcess();
    bool IsAttached() const;
    DWORD GetTargetPID() const;

    // �ű�����
    std::shared_ptr<CEScript> CreateScript(const std::string& name = "");
    std::shared_ptr<CEScript> GetScript(const std::string& name);

    // ��ȡ������Ϣ
    std::string GetLastError() const { return m_lastError; }

    // ��ȡ���������߼��÷���
    SymbolManager* GetSymbolManager() { return m_symbolManager.get(); }
    MemoryManager* GetMemoryManager() { return m_memoryManager.get(); }

    // ��Ԫ�࣬����CEScript�����ڲ�����
    friend class CEScript;

private:
    // ���õ�ǰ�ű�������
    void SetCurrentScript(CEScript* script) { m_currentScript = script; }

    // ����ű���
    bool ProcessEnableBlock(const std::vector<std::string>& lines);
    bool ProcessDisableBlock(const std::vector<std::string>& lines);

    // ��ȡ������Ϣ
    std::vector<PatchInfo> GetPatches() const { return m_patches; }

    // ����CE����
    bool ProcessAobScanModule(const std::string& line);
    bool ProcessAlloc(const std::string& line);
    bool ProcessLabel(const std::string& line);
    bool ProcessRegisterSymbol(const std::string& line);
    bool ProcessUnregisterSymbol(const std::string& line);
    bool ProcessDealloc(const std::string& line);
    bool ProcessDbCommand(const std::string& line);

    // ���ָ���
    bool ProcessAssemblyInstruction(const std::string& line);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool WriteBytes(const std::vector<uint8_t>& bytes);

    // �����滻
    std::string ReplaceSymbols(const std::string& line);

    // ��Ӳ�����¼
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes,
        const std::vector<uint8_t>& newBytes);

    // ��Ա����
    std::unique_ptr<MemoryManager> m_memoryManager;     // ͳһ���ڴ������
    std::unique_ptr<SymbolManager> m_symbolManager;     // ���Ź�����
    std::unique_ptr<PatternScanner> m_patternScanner;   // ģʽɨ����
    std::unique_ptr<CEScriptParser> m_parser;           // �ű�������

    ks_engine* m_ksEngine;                               // Keystone�������
    std::string m_lastError;                             // ��������Ϣ
    CEScript* m_currentScript;                           // ��ǰ�ű�������

    // ����Ľű�����
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // ������Ϣ
    std::vector<PatchInfo> m_patches;

    // ��ǰ�����ַ
    uintptr_t m_currentAddress;
};