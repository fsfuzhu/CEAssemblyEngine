// ProcessManager.h
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string fullPath;
};

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    // �򿪽���
    bool OpenProcess(DWORD pid);
    bool OpenProcess(const std::string& processName);

    // �رս��̾��
    void CloseProcess();

    // ��ȡ���̾��
    HANDLE GetHandle() const { return m_hProcess; }
    DWORD GetPID() const { return m_pid; }

    // ��д�ڴ�
    bool ReadMemory(uintptr_t address, void* buffer, size_t size);
    bool WriteMemory(uintptr_t address, const void* data, size_t size);

    // �ڴ汣��
    bool ProtectMemory(uintptr_t address, size_t size, DWORD newProtect, DWORD* oldProtect);

    // ����/�ͷ��ڴ�
    uintptr_t AllocateMemory(size_t size, uintptr_t nearAddress = 0);
    bool FreeMemory(uintptr_t address);

    // ��ȡģ����Ϣ
    uintptr_t GetModuleBase(const std::string& moduleName);
    size_t GetModuleSize(const std::string& moduleName);

    // ��̬������ö�ٽ���
    static std::vector<ProcessInfo> EnumerateProcesses();
    static DWORD FindProcessByName(const std::string& processName);

private:
    HANDLE m_hProcess;
    DWORD m_pid;

    // ��������
    MODULEENTRY32 GetModuleInfo(const std::string& moduleName);
};
