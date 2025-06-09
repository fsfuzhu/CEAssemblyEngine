// MemoryManager.cpp
#include "MemoryManager.h"
#include "Utils\DebugHelper.h"
#include <algorithm>
#include <Psapi.h>

MemoryManager::MemoryManager() : m_hProcess(nullptr), m_pid(0) {}

MemoryManager::~MemoryManager() {
    ClearAllAllocations();
    DetachFromProcess();
}

bool MemoryManager::AttachToProcess(DWORD pid) {
    DetachFromProcess();

    m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (m_hProcess) {
        m_pid = pid;
        LOG_INFO_F("Attached to process PID: %d", pid);
        return true;
    }

    LOG_ERROR_F("Failed to attach to process PID: %d", pid);
    return false;
}

bool MemoryManager::AttachToProcess(const std::string& processName) {
    DWORD pid = FindProcessByName(processName);
    if (pid != 0) {
        return AttachToProcess(pid);
    }

    LOG_ERROR_F("Process '%s' not found", processName.c_str());
    return false;
}

void MemoryManager::DetachFromProcess() {
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
        m_pid = 0;
        LOG_INFO("Detached from process");
    }
}

bool MemoryManager::ReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (!m_hProcess) return false;

    SIZE_T bytesRead;
    bool success = ReadProcessMemory(m_hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytesRead) && bytesRead == size;

    if (!success) {
        LOG_ERROR_F("Failed to read memory at 0x%llX (size: %zu)", address, size);
    }
    return success;
}

bool MemoryManager::WriteMemory(uintptr_t address, const void* data, size_t size) {
    if (!m_hProcess) return false;

    SIZE_T bytesWritten;
    bool success = WriteProcessMemory(m_hProcess,
        reinterpret_cast<LPVOID>(address),
        data,
        size,
        &bytesWritten) && bytesWritten == size;

    if (!success) {
        LOG_ERROR_F("Failed to write memory at 0x%llX (size: %zu)", address, size);
    }
    return success;
}

bool MemoryManager::ProtectMemory(uintptr_t address, size_t size, DWORD newProtect, DWORD* oldProtect) {
    if (!m_hProcess) return false;

    bool success = VirtualProtectEx(m_hProcess,
        reinterpret_cast<LPVOID>(address),
        size,
        newProtect,
        oldProtect);

    if (!success) {
        LOG_ERROR_F("Failed to protect memory at 0x%llX", address);
    }
    return success;
}

uintptr_t MemoryManager::AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name) {
    // 检查是否已经分配
    if (m_allocations.find(name) != m_allocations.end()) {
        LOG_WARN_F("Allocation '%s' already exists", name.c_str());
        return m_allocations[name].address;
    }

    uintptr_t address = 0;

    if (m_hProcess) {
        // 跨进程分配
        address = AllocateMemoryInternal(size, nearAddress);
    }
    else {
        // 本进程分配
        address = FindSuitableAddress(nearAddress, size);
    }

    if (address) {
        Allocation alloc;
        alloc.address = address;
        alloc.size = size;
        alloc.name = name;
        m_allocations[name] = alloc;

        LOG_INFO_F("Allocated memory: %s at 0x%llX (size: 0x%zX)",
            name.c_str(), address, size);
    }
    else {
        LOG_ERROR_F("Failed to allocate memory: %s (size: 0x%zX)", name.c_str(), size);
    }

    return address;
}

bool MemoryManager::Deallocate(const std::string& name) {
    auto it = m_allocations.find(name);
    if (it != m_allocations.end()) {
        bool success = FreeMemoryInternal(it->second.address);
        if (success) {
            LOG_INFO_F("Deallocated memory: %s", name.c_str());
            m_allocations.erase(it);
        }
        return success;
    }

    LOG_WARN_F("Allocation '%s' not found for deallocation", name.c_str());
    return false;
}

uintptr_t MemoryManager::GetAllocation(const std::string& name) const {
    auto it = m_allocations.find(name);
    if (it != m_allocations.end()) {
        return it->second.address;
    }
    return 0;
}

void MemoryManager::ClearAllAllocations() {
    for (const auto& pair : m_allocations) {
        FreeMemoryInternal(pair.second.address);
        LOG_INFO_F("Freed allocation: %s", pair.first.c_str());
    }
    m_allocations.clear();
}

uintptr_t MemoryManager::GetModuleBase(const std::string& moduleName) {
    if (m_hProcess) {
        MODULEENTRY32 modEntry = GetModuleInfo(moduleName);
        return reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
    }
    else {
        // 本进程
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        return reinterpret_cast<uintptr_t>(hModule);
    }
}

size_t MemoryManager::GetModuleSize(const std::string& moduleName) {
    if (m_hProcess) {
        MODULEENTRY32 modEntry = GetModuleInfo(moduleName);
        return modEntry.modBaseSize;
    }
    else {
        // 本进程
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (hModule) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
                return modInfo.SizeOfImage;
            }
        }
        return 0;
    }
}

std::vector<ProcessInfo> MemoryManager::EnumerateProcesses() {
    std::vector<ProcessInfo> processes;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32 procEntry = { 0 };
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &procEntry)) {
        do {
            ProcessInfo info;
            info.pid = procEntry.th32ProcessID;
            info.name = procEntry.szExeFile;

            HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (hProc) {
                char fullPath[MAX_PATH];
                if (GetModuleFileNameExA(hProc, nullptr, fullPath, MAX_PATH)) {
                    info.fullPath = fullPath;
                }
                CloseHandle(hProc);
            }

            processes.push_back(info);
        } while (Process32Next(hSnap, &procEntry));
    }

    CloseHandle(hSnap);
    return processes;
}

DWORD MemoryManager::FindProcessByName(const std::string& processName) {
    auto processes = EnumerateProcesses();

    std::string searchName = processName;
    std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);

    for (const auto& proc : processes) {
        std::string procName = proc.name;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);

        if (procName == searchName) {
            return proc.pid;
        }
    }

    return 0;
}

MODULEENTRY32 MemoryManager::GetModuleInfo(const std::string& moduleName) {
    MODULEENTRY32 modEntry = { 0 };
    modEntry.dwSize = sizeof(MODULEENTRY32);

    if (!m_hProcess || !m_pid) return modEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (hSnap == INVALID_HANDLE_VALUE) return modEntry;

    if (Module32First(hSnap, &modEntry)) {
        do {
            std::string modName = modEntry.szModule;
            std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);

            std::string searchName = moduleName;
            std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);

            if (modName == searchName) {
                CloseHandle(hSnap);
                return modEntry;
            }
        } while (Module32Next(hSnap, &modEntry));
    }

    CloseHandle(hSnap);
    modEntry = { 0 };
    modEntry.dwSize = sizeof(MODULEENTRY32);
    return modEntry;
}

uintptr_t MemoryManager::AllocateMemoryInternal(size_t size, uintptr_t nearAddress) {
    if (!m_hProcess) return 0;

    // 对齐到页边界
    size_t allocSize = (size + 0xFFF) & ~0xFFF;

    LOG_DEBUG_F("Attempting to allocate %zu bytes near 0x%llX", allocSize, nearAddress);

    if (nearAddress != 0) {
        // 策略1: 优先在目标地址附近的小范围内搜索（±512MB）
        const std::vector<size_t> searchRanges = {
            0x20000000,   // ±512MB
            0x40000000,   // ±1GB  
            0x60000000,   // ±1.5GB
            0x7FFFFFFF    // ±2GB (E9最大范围)
        };

        for (size_t searchRange : searchRanges) {
            LOG_DEBUG_F("Searching in range ±%zu MB", searchRange / (1024 * 1024));

            // 计算搜索边界
            uintptr_t minAddr = (nearAddress > searchRange) ? nearAddress - searchRange : 0x10000;
            uintptr_t maxAddr = nearAddress + searchRange;

            // 确保不超过用户空间
            if (maxAddr > 0x7FFFFFFFFFFF) {
                maxAddr = 0x7FFFFFFFFFFF;
            }

            // 策略1a: 先向上搜索（地址增长方向）
            uintptr_t result = SearchMemoryRange(nearAddress, maxAddr, allocSize, true);
            if (result != 0) {
                int64_t distance = static_cast<int64_t>(result) - static_cast<int64_t>(nearAddress);
                LOG_INFO_F("Found memory above target: 0x%llX (distance: %lld bytes)", result, distance);
                return result;
            }

            // 策略1b: 再向下搜索（地址减少方向）
            result = SearchMemoryRange(minAddr, nearAddress, allocSize, false);
            if (result != 0) {
                int64_t distance = static_cast<int64_t>(result) - static_cast<int64_t>(nearAddress);
                LOG_INFO_F("Found memory below target: 0x%llX (distance: %lld bytes)", result, distance);
                return result;
            }
        }

        LOG_WARN("Failed to find suitable memory in E9 range, trying system allocation");
    }

    // 策略2: 系统默认分配
    LPVOID allocated = VirtualAllocEx(m_hProcess,
        nullptr,
        allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    uintptr_t result = reinterpret_cast<uintptr_t>(allocated);
    if (result != 0) {
        LOG_INFO_F("System allocated memory at: 0x%llX", result);
    }

    return result;
}

uintptr_t MemoryManager::SearchMemoryRange(uintptr_t startAddr, uintptr_t endAddr, size_t allocSize, bool upward) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t currentAddr = upward ? startAddr : endAddr - allocSize;
    uintptr_t step = upward ? 0x10000 : -0x10000;  // 64KB步长

    LOG_TRACE_F("Searching range 0x%llX - 0x%llX, direction: %s",
        startAddr, endAddr, upward ? "up" : "down");

    int attempts = 0;
    const int maxAttempts = (endAddr - startAddr) / 0x10000;

    while ((upward ? currentAddr < endAddr : currentAddr >= startAddr) && attempts++ < maxAttempts) {

        // 查询内存状态
        if (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) {

            // 检查是否是空闲内存且足够大
            if (mbi.State == MEM_FREE && mbi.RegionSize >= allocSize) {

                // 尝试在这个位置分配
                uintptr_t allocAddr = upward ? currentAddr :
                    (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize - allocSize);

                // 确保地址在搜索范围内
                if (allocAddr >= startAddr && allocAddr + allocSize <= endAddr) {

                    LPVOID allocated = VirtualAllocEx(m_hProcess,
                        reinterpret_cast<LPVOID>(allocAddr),
                        allocSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);

                    if (allocated) {
                        LOG_DEBUG_F("Successfully allocated at preferred address: 0x%llX", allocAddr);
                        return allocAddr;
                    }

                    // 如果指定地址失败，尝试在这个空闲区域的任意位置分配
                    allocated = VirtualAllocEx(m_hProcess,
                        mbi.BaseAddress,
                        allocSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);

                    if (allocated) {
                        uintptr_t actualAddr = reinterpret_cast<uintptr_t>(allocated);
                        if (actualAddr >= startAddr && actualAddr + allocSize <= endAddr) {
                            LOG_DEBUG_F("Successfully allocated in free region: 0x%llX", actualAddr);
                            return actualAddr;
                        }
                        else {
                            // 地址超出范围，释放并继续搜索
                            VirtualFreeEx(m_hProcess, allocated, 0, MEM_RELEASE);
                        }
                    }
                }
            }

            // 移动到下一个区域
            if (upward) {
                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
            else {
                currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) - 0x10000;
            }
        }
        else {
            // 查询失败，跳过
            currentAddr += step;
        }
    }

    LOG_TRACE_F("No suitable memory found in range (attempts: %d)", attempts);
    return 0;
}

bool MemoryManager::FreeMemoryInternal(uintptr_t address) {
    if (m_hProcess) {
        return VirtualFreeEx(m_hProcess, reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
    }
    else {
        return VirtualFree(reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
    }
}

uintptr_t MemoryManager::FindSuitableAddress(uintptr_t nearAddress, size_t size) {
    // 本进程内存分配逻辑
    const size_t searchRange = 0x7FFFFFFF;  // 2GB
    uintptr_t minAddr = (nearAddress > searchRange) ? nearAddress - searchRange : 0x10000;
    uintptr_t maxAddr = nearAddress + searchRange;

    size_t allocSize = (size + 0xFFF) & ~0xFFF;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t currentAddr = minAddr;

    // 向前搜索
    while (currentAddr < maxAddr) {
        if (VirtualQuery(reinterpret_cast<LPVOID>(currentAddr), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= allocSize) {
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
            currentAddr += 0x10000;
        }
    }

    return 0;
}