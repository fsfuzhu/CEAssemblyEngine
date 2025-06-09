// MemoryAllocator.h
#pragma once
#include <Windows.h>
#include <unordered_map>
#include <string>

// 前向声明
class ProcessManager;

class MemoryAllocator {
public:
    MemoryAllocator();
    ~MemoryAllocator();

    // 设置进程管理器（用于跨进程分配）
    void SetProcessManager(ProcessManager* pm) { m_processManager = pm; }

    // 在指定地址附近分配内存
    uintptr_t AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name);

    // 释放分配的内存
    bool Deallocate(const std::string& name);

    // 获取已分配内存的地址
    uintptr_t GetAllocation(const std::string& name) const;

    // 清理所有分配
    void ClearAll();

private:
    // 查找合适的内存地址
    uintptr_t FindSuitableAddress(uintptr_t nearAddress, size_t size);

    struct Allocation {
        uintptr_t address;
        size_t size;
    };

    std::unordered_map<std::string, Allocation> m_allocations;
    ProcessManager* m_processManager;  // 可选，用于跨进程
};