// PatternScanner.cpp
#include "PatternScanner.h"
#include "ProcessManager.h"
#include <sstream>
#include <Psapi.h>
#include <algorithm>

PatternScanner::PatternScanner() : m_processManager(nullptr) {}

PatternScanner::~PatternScanner() {}

std::vector<PatternByte> PatternScanner::ParsePattern(const std::string& pattern) {
    std::vector<PatternByte> result;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        PatternByte pb;
        pb.captureName = "";
        pb.captureSize = 0;

        // 检查是否是通配符
        if (token == "?" || token == "??") {
            pb.isWildcard = true;
            pb.value = 0;
            result.push_back(pb);
            if (token == "??") {
                result.push_back(pb);  // ?? 相当于两个 ?
            }
        }
        else if (token == "*") {
            // * 相当于 ??
            pb.isWildcard = true;
            pb.value = 0;
            result.push_back(pb);
            result.push_back(pb);
        }
        else if (token.find('.') != std::string::npos) {
            // 处理捕获变量，如 s1.2
            size_t dotPos = token.find('.');
            std::string varName = token.substr(0, dotPos);
            size_t captureSize = std::stoi(token.substr(dotPos + 1));

            // 添加捕获字节
            for (size_t i = 0; i < captureSize; ++i) {
                pb.isWildcard = true;
                pb.value = 0;
                if (i == 0) {
                    pb.captureName = varName;
                    pb.captureSize = captureSize;
                }
                else {
                    pb.captureName = "";
                    pb.captureSize = 0;
                }
                result.push_back(pb);
            }
        }
        else {
            // 普通字节
            pb.isWildcard = false;
            pb.value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
            result.push_back(pb);
        }
    }

    return result;
}

uintptr_t PatternScanner::ScanModule(const std::string& moduleName, const std::string& pattern) {
    uintptr_t moduleBase = 0;
    size_t moduleSize = 0;

    if (m_processManager && m_processManager->GetHandle()) {
        // 跨进程扫描
        moduleBase = m_processManager->GetModuleBase(moduleName);
        moduleSize = m_processManager->GetModuleSize(moduleName);
    }
    else {
        // 本进程扫描
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) {
            return 0;
        }

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
            return 0;
        }

        moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        moduleSize = modInfo.SizeOfImage;
    }

    if (moduleBase == 0 || moduleSize == 0) {
        return 0;
    }

    std::vector<PatternByte> parsedPattern = ParsePattern(pattern);
    return ScanMemory(moduleBase, moduleSize, parsedPattern);
}

uintptr_t PatternScanner::ScanMemory(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern) {
    if (pattern.empty()) {
        return 0;
    }

    // 为跨进程扫描分配缓冲区
    std::vector<uint8_t> buffer;
    uint8_t* scanData = nullptr;

    if (m_processManager && m_processManager->GetHandle()) {
        // 跨进程：读取整个区域到缓冲区
        buffer.resize(size);
        if (!m_processManager->ReadMemory(start, buffer.data(), size)) {
            return 0;
        }
        scanData = buffer.data();
    }
    else {
        // 本进程：直接使用指针
        scanData = reinterpret_cast<uint8_t*>(start);
    }

    // 扫描
    for (size_t i = 0; i <= size - pattern.size(); ++i) {
        bool found = true;

        // 检查当前位置是否匹配
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].isWildcard && scanData[i + j] != pattern[j].value) {
                found = false;
                break;
            }
        }

        if (found) {
            // 捕获变量数据
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (!pattern[j].captureName.empty()) {
                    std::vector<uint8_t> capturedData;
                    for (size_t k = 0; k < pattern[j].captureSize; ++k) {
                        capturedData.push_back(scanData[i + j + k]);
                    }
                    m_capturedVariables[pattern[j].captureName] = capturedData;
                }
            }

            return start + i;
        }
    }

    return 0;
}