// ProcessManager.cpp
#include "ProcessManager.h"
#include <algorithm>
#include <Psapi.h>

ProcessManager::ProcessManager() : m_hProcess(nullptr), m_pid(0) {}

ProcessManager::~ProcessManager() {
    CloseProcess();
}

bool ProcessManager::OpenProcess(DWORD pid) {
    CloseProcess();

    m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (m_hProcess) {
        m_pid = pid;
        return true;
    }
    return false;
}

bool ProcessManager::OpenProcess(const std::string& processName) {
    DWORD pid = FindProcessByName(processName);
    if (pid != 0) {
        return OpenProcess(pid);
    }
    return false;
}

void ProcessManager::CloseProcess() {
    if (m_hProcess) {
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
        m_pid = 0;
    }
}

bool ProcessManager::ReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (!m_hProcess) return false;

    SIZE_T bytesRead;
    return ReadProcessMemory(m_hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &bytesRead) && bytesRead == size;
}

bool ProcessManager::WriteMemory(uintptr_t address, const void* data, size_t size) {
    if (!m_hProcess) return false;

    SIZE_T bytesWritten;
    return WriteProcessMemory(m_hProcess,
        reinterpret_cast<LPVOID>(address),
        data,
        size,
        &bytesWritten) && bytesWritten == size;
}

bool ProcessManager::ProtectMemory(uintptr_t address, size_t size, DWORD newProtect, DWORD* oldProtect) {
    if (!m_hProcess) return false;

    return VirtualProtectEx(m_hProcess,
        reinterpret_cast<LPVOID>(address),
        size,
        newProtect,
        oldProtect);
}

uintptr_t ProcessManager::AllocateMemory(size_t size, uintptr_t nearAddress) {
    if (!m_hProcess) return 0;

    // 对齐到页边界
    size_t allocSize = (size + 0xFFF) & ~0xFFF;

    if (nearAddress != 0) {
        // 尝试在附近分配（用于短跳转）
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

bool ProcessManager::FreeMemory(uintptr_t address) {
    if (!m_hProcess) return false;

    return VirtualFreeEx(m_hProcess,
        reinterpret_cast<LPVOID>(address),
        0,
        MEM_RELEASE);
}

uintptr_t ProcessManager::GetModuleBase(const std::string& moduleName) {
    MODULEENTRY32 modEntry = GetModuleInfo(moduleName);
    return reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
}

size_t ProcessManager::GetModuleSize(const std::string& moduleName) {
    MODULEENTRY32 modEntry = GetModuleInfo(moduleName);
    return modEntry.modBaseSize;
}

MODULEENTRY32 ProcessManager::GetModuleInfo(const std::string& moduleName) {
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

std::vector<ProcessInfo> ProcessManager::EnumerateProcesses() {
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

            // 尝试获取完整路径
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

DWORD ProcessManager::FindProcessByName(const std::string& processName) {
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