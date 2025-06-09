// PatternScanner.cpp - ģʽɨ����ʵ��
#include "PatternScanner.h"
#include "Core\MemoryManager.h"
#include "Utils\DebugHelper.h"
#include <sstream>
#include <Psapi.h>
#include <algorithm>

PatternScanner::PatternScanner() : m_memoryManager(nullptr) {}

PatternScanner::~PatternScanner() {}

std::vector<PatternByte> PatternScanner::ParsePattern(const std::string& pattern) {
    std::vector<PatternByte> result;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        PatternByte pb;
        pb.captureName = "";
        pb.captureSize = 0;

        // ����Ƿ���ͨ���
        if (token == "?" || token == "??") {
            pb.isWildcard = true;
            pb.value = 0;
            result.push_back(pb);
            if (token == "??") {
                result.push_back(pb);  // ?? �൱������ ?
            }
        }
        else if (token == "*") {
            // * �൱�� ??
            pb.isWildcard = true;
            pb.value = 0;
            result.push_back(pb);
            result.push_back(pb);
        }
        else if (token.find('.') != std::string::npos) {
            // ������������� s1.2
            size_t dotPos = token.find('.');
            std::string varName = token.substr(0, dotPos);
            size_t captureSize = std::stoi(token.substr(dotPos + 1));

            // ��Ӳ����ֽ�
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
            // ��ͨ�ֽ�
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

    LOG_INFO_F("ScanModule -> module=%s, pattern=\"%s\"",
        moduleName.c_str(), pattern.c_str());

    if (m_memoryManager && m_memoryManager->IsAttached()) {
        // �����ɨ��
        moduleBase = m_memoryManager->GetModuleBase(moduleName);
        moduleSize = m_memoryManager->GetModuleSize(moduleName);
    }
    else {
        // ������ɨ��
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) {
            LOG_ERROR_F("Module '%s' not found", moduleName.c_str());
            return 0;
        }

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
            LOG_ERROR("Failed to get module information");
            return 0;
        }

        moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        moduleSize = modInfo.SizeOfImage;
    }

    if (moduleBase == 0 || moduleSize == 0) {
        LOG_ERROR("Invalid module base or size");
        return 0;
    }

    std::vector<PatternByte> parsedPattern = ParsePattern(pattern);
    return ScanMemory(moduleBase, moduleSize, parsedPattern);
}

uintptr_t PatternScanner::ScanMemory(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern) {
    if (pattern.empty()) {
        LOG_ERROR("Empty pattern");
        return 0;
    }

    // Ϊ�����ɨ����仺����
    std::vector<uint8_t> buffer;
    uint8_t* scanData = nullptr;

    if (m_memoryManager && m_memoryManager->IsAttached()) {
        // ����̣���ȡ�������򵽻�����
        buffer.resize(size);
        if (!m_memoryManager->ReadMemory(start, buffer.data(), size)) {
            LOG_ERROR("Failed to read memory for scanning");
            return 0;
        }
        scanData = buffer.data();
    }
    else {
        // �����̣�ֱ��ʹ��ָ��
        scanData = reinterpret_cast<uint8_t*>(start);
    }

    // ɨ��
    for (size_t i = 0; i <= size - pattern.size(); ++i) {
        bool found = true;

        // ��鵱ǰλ���Ƿ�ƥ��
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].isWildcard && scanData[i + j] != pattern[j].value) {
                found = false;
                break;
            }
        }

        if (found) {
            // �����������
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (!pattern[j].captureName.empty()) {
                    std::vector<uint8_t> capturedData;
                    for (size_t k = 0; k < pattern[j].captureSize; ++k) {
                        capturedData.push_back(scanData[i + j + k]);
                    }
                    m_capturedVariables[pattern[j].captureName] = capturedData;

                    // ��¼�����ֵ�������ã�
                    uint64_t value = 0;
                    for (size_t k = 0; k < capturedData.size() && k < 8; ++k) {
                        value |= static_cast<uint64_t>(capturedData[k]) << (k * 8);
                    }
                    LOG_DEBUG_F("Captured variable '%s' = 0x%llX",
                        pattern[j].captureName.c_str(), value);
                }
            }

            LOG_INFO_F("Pattern found @ 0x%llX", start + i);
            return start + i;
        }
    }

    LOG_WARN("Pattern not found");
    return 0;
}