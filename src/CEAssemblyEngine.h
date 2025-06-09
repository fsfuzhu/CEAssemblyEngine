#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <Windows.h>
#include <keystone/keystone.h>
#include "MemoryAllocator.h"

// ǰ������
class SymbolManager;
class PatternScanner;
class MemoryAllocator;
class CEScriptParser;
class CEScript;
class ProcessManager;

// �ű�������
enum class BlockType {
    ENABLE,
    DISABLE,
    NONE
};

// ��������
enum class SymbolType {
    ADDRESS,
    LABEL,
    VARIABLE
};

// ������Ϣ
struct Symbol {
    std::string name;
    SymbolType type;
    uintptr_t address;
    size_t size;
    std::vector<uint8_t> originalBytes;
};

// ͨ���������Ϣ
struct WildcardCapture {
    std::string name;
    size_t offset;
    size_t size;
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

    // �����½ű�
    std::shared_ptr<CEScript> CreateScript(const std::string& name = "");

    // ��ȡ�Ѵ����Ľű�
    std::shared_ptr<CEScript> GetScript(const std::string& name);

    // ��ȡ������Ϣ
    std::string GetLastError() const { return m_lastError; }

    // ��ȡ���Ź��������߼��÷���
    SymbolManager* GetSymbolManager() { return m_symbolManager.get(); }

    // ��ȡ���̹��������߼��÷���
    ProcessManager* GetProcessManager() { return m_processManager.get(); }

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

    // ������
    bool AssembleCode(const std::vector<std::string>& codeLines, uintptr_t baseAddress, std::vector<uint8_t>& output);

    // ������ת�ͷ�������
    bool ProcessJumpInstructions(const std::string& instruction, uintptr_t currentAddress, std::vector<uint8_t>& output);

    // �滻����
    std::string ReplaceSymbols(const std::string& line);

    // ���ָ���
    bool ProcessAssemblyInstruction(const std::string& line);
    bool ProcessJumpInstruction(const std::string& opcode, uintptr_t targetAddr);
    bool WriteBytes(const std::vector<uint8_t>& bytes);
    bool ProcessDbCommand(const std::string& line);

    // ��Ա����
    std::unique_ptr<ProcessManager> m_processManager;
    std::unique_ptr<SymbolManager> m_symbolManager;
    std::unique_ptr<PatternScanner> m_patternScanner;
    std::unique_ptr<MemoryAllocator> m_memoryAllocator;
    std::unique_ptr<CEScriptParser> m_parser;

    ks_engine* m_ksEngine;
    std::string m_lastError;
    std::string m_targetModule;

    // ��ǰ�ű�������
    CEScript* m_currentScript;

    // ����Ľű�����
    std::unordered_map<std::string, std::shared_ptr<CEScript>> m_scripts;

    // ������Ϣ
    std::vector<PatchInfo> m_patches;

    // ��ǰ�����ַ
    uintptr_t m_currentAddress;

    // ��Ӳ�����¼
    void AddPatch(uintptr_t address, const std::vector<uint8_t>& originalBytes, const std::vector<uint8_t>& newBytes);
};