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

    if (nearAddress != 0) {
        // 尝试在附近地址分配（用于跳转）
        const size_t searchRange = 0x7FFFFFFF;  // 2GB
        uintptr_t minAddr = (nearAddress > searchRange) ? nearAddress - searchRange : 0x10000;
        uintptr_t maxAddr = nearAddress + searchRange;

        // 搜索可用内存
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t currentAddr = minAddr;

        while (currentAddr < maxAddr) {
            if (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= allocSize) {
                    LPVOID allocated = VirtualAllocEx(m_hProcess,
                        reinterpret_cast<LPVOID>(currentAddr),
                        allocSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
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
    }

    // 如果附近分配失败，使用默认分配
    LPVOID allocated = VirtualAllocEx(m_hProcess,
        nullptr,
        allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    return reinterpret_cast<uintptr_t>(allocated);
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