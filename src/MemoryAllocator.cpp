// MemoryAllocator.cpp
#include "MemoryAllocator.h"
#include "ProcessManager.h"
#include <vector>
#include <algorithm>

MemoryAllocator::MemoryAllocator() : m_processManager(nullptr) {}

MemoryAllocator::~MemoryAllocator() {
    ClearAll();
}

uintptr_t MemoryAllocator::AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name) {
    // 检查是否已经分配
    if (m_allocations.find(name) != m_allocations.end()) {
        return m_allocations[name].address;
    }

    uintptr_t address = 0;

    if (m_processManager && m_processManager->GetHandle()) {
        // 跨进程分配
        address = m_processManager->AllocateMemory(size, nearAddress);
    }
    else {
        // 本进程分配
        address = FindSuitableAddress(nearAddress, size);
    }

    if (address) {
        Allocation alloc;
        alloc.address = address;
        alloc.size = size;
        m_allocations[name] = alloc;
    }

    return address;
}

bool MemoryAllocator::Deallocate(const std::string& name) {
    auto it = m_allocations.find(name);
    if (it != m_allocations.end()) {
        if (m_processManager && m_processManager->GetHandle()) {
            // 跨进程释放
            m_processManager->FreeMemory(it->second.address);
        }
        else {
            // 本进程释放
            VirtualFree(reinterpret_cast<LPVOID>(it->second.address), 0, MEM_RELEASE);
        }

        m_allocations.erase(it);
        return true;
    }
    return false;
}

void MemoryAllocator::ClearAll() {
    for (const auto& pair : m_allocations) {
        if (m_processManager && m_processManager->GetHandle()) {
            m_processManager->FreeMemory(pair.second.address);
        }
        else {
            VirtualFree(reinterpret_cast<LPVOID>(pair.second.address), 0, MEM_RELEASE);
        }
    }
    m_allocations.clear();
}

uintptr_t MemoryAllocator::FindSuitableAddress(uintptr_t nearAddress, size_t size) {
    // 计算搜索范围（在2GB范围内寻找，这是x64跳转指令的限制）
    const size_t searchRange = 0x7FFFFFFF;  // 2GB - 1
    uintptr_t minAddr = (nearAddress > searchRange) ? nearAddress - searchRange : 0x10000;
    uintptr_t maxAddr = nearAddress + searchRange;

    // 对齐到页边界
    size_t allocSize = (size + 0xFFF) & ~0xFFF;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t currentAddr = minAddr;

    // 向上搜索
    while (currentAddr < maxAddr) {
        if (VirtualQuery(reinterpret_cast<LPVOID>(currentAddr), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= allocSize) {
                // 尝试在自由区域分配
                LPVOID allocated = VirtualAlloc(
                    reinterpret_cast<LPVOID>(currentAddr),
                    allocSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );

                if (allocated) {
                    return reinterpret_cast<uintptr_t>(allocated);
                }
            }
            currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        else {
            currentAddr += 0x10000;  // 跳过64KB
        }
    }

    // 向下搜索
    currentAddr = nearAddress;
    while (currentAddr > minAddr) {
        if (VirtualQuery(reinterpret_cast<LPVOID>(currentAddr - allocSize), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= allocSize) {
                LPVOID allocated = VirtualAlloc(
                    reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)),
                    allocSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                );

                if (allocated) {
                    return reinterpret_cast<uintptr_t>(allocated);
                }
            }

            if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) > allocSize) {
                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) - allocSize;
            }
            else {
                break;
            }
        }
        else {
            if (currentAddr > 0x10000) {
                currentAddr -= 0x10000;
            }
            else {
                break;
            }
        }
    }

    return 0;
}

uintptr_t MemoryAllocator::AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name) {
    // 检查是否已经分配
    if (m_allocations.find(name) != m_allocations.end()) {
        return m_allocations[name].address;
    }

    uintptr_t address = FindSuitableAddress(nearAddress, size);
    if (address) {
        Allocation alloc;
        alloc.address = address;
        alloc.size = size;
        m_allocations[name] = alloc;
    }

    return address;
}

bool MemoryAllocator::Deallocate(const std::string& name) {
    auto it = m_allocations.find(name);
    if (it != m_allocations.end()) {
        VirtualFree(reinterpret_cast<LPVOID>(it->second.address), 0, MEM_RELEASE);
        m_allocations.erase(it);
        return true;
    }
    return false;
}

uintptr_t MemoryAllocator::GetAllocation(const std::string& name) const {
    auto it = m_allocations.find(name);
    if (it != m_allocations.end()) {
        return it->second.address;
    }
    return 0;
}

void MemoryAllocator::ClearAll() {
    for (const auto& pair : m_allocations) {
        VirtualFree(reinterpret_cast<LPVOID>(pair.second.address), 0, MEM_RELEASE);
    }
    m_allocations.clear();
}