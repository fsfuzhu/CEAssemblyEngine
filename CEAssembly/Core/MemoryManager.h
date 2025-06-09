// MemoryManager.h - 统一的内存和进程管理器
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <unordered_map>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string fullPath;
};

struct Allocation {
    uintptr_t address;
    size_t size;
    std::string name;
};

class MemoryManager {
public:
    MemoryManager();
    ~MemoryManager();

    // 进程管理
    bool AttachToProcess(DWORD pid);
    bool AttachToProcess(const std::string& processName);
    void DetachFromProcess();
    bool IsAttached() const { return m_hProcess != nullptr; }
    HANDLE GetHandle() const { return m_hProcess; }
    DWORD GetPID() const { return m_pid; }

    // 内存操作
    bool ReadMemory(uintptr_t address, void* buffer, size_t size);
    bool WriteMemory(uintptr_t address, const void* data, size_t size);
    bool ProtectMemory(uintptr_t address, size_t size, DWORD newProtect, DWORD* oldProtect);

    // 内存分配管理
    uintptr_t AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name);
    bool Deallocate(const std::string& name);
    uintptr_t GetAllocation(const std::string& name) const;
    void ClearAllAllocations();

    // 模块信息
    uintptr_t GetModuleBase(const std::string& moduleName);
    size_t GetModuleSize(const std::string& moduleName);

    // 静态工具方法
    static std::vector<ProcessInfo> EnumerateProcesses();
    static DWORD FindProcessByName(const std::string& processName);

private:
    HANDLE m_hProcess;
    DWORD m_pid;
    std::unordered_map<std::string, Allocation> m_allocations;

    // 内部方法
    MODULEENTRY32 GetModuleInfo(const std::string& moduleName);
    uintptr_t AllocateMemoryInternal(size_t size, uintptr_t nearAddress = 0);
    uintptr_t SearchMemoryRange(uintptr_t startAddr, uintptr_t endAddr, size_t allocSize, bool upward);
    bool FreeMemoryInternal(uintptr_t address);
    uintptr_t FindSuitableAddress(uintptr_t nearAddress, size_t size);
};