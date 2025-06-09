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

    // 打开进程
    bool OpenProcess(DWORD pid);
    bool OpenProcess(const std::string& processName);

    // 关闭进程句柄
    void CloseProcess();

    // 获取进程句柄
    HANDLE GetHandle() const { return m_hProcess; }
    DWORD GetPID() const { return m_pid; }

    // 读写内存
    bool ReadMemory(uintptr_t address, void* buffer, size_t size);
    bool WriteMemory(uintptr_t address, const void* data, size_t size);

    // 内存保护
    bool ProtectMemory(uintptr_t address, size_t size, DWORD newProtect, DWORD* oldProtect);

    // 分配/释放内存
    uintptr_t AllocateMemory(size_t size, uintptr_t nearAddress = 0);
    bool FreeMemory(uintptr_t address);

    // 获取模块信息
    uintptr_t GetModuleBase(const std::string& moduleName);
    size_t GetModuleSize(const std::string& moduleName);

    // 静态方法：枚举进程
    static std::vector<ProcessInfo> EnumerateProcesses();
    static DWORD FindProcessByName(const std::string& processName);

private:
    HANDLE m_hProcess;
    DWORD m_pid;

    // 辅助方法
    MODULEENTRY32 GetModuleInfo(const std::string& moduleName);
};
