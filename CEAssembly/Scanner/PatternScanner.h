// PatternScanner.h - ģʽɨ����
#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <unordered_map>

// ǰ������
class MemoryManager;

struct PatternByte {
    bool isWildcard;
    uint8_t value;
    std::string captureName;  // �� "s1"
    size_t captureSize;       // �� 2 (���� s1.2)
};

class PatternScanner {
public:
    PatternScanner();
    ~PatternScanner();

    // �����ڴ�����������ڿ����ɨ�裩
    void SetProcessManager(MemoryManager* mm) { m_memoryManager = mm; }

    // ɨ��ģ���е�������
    uintptr_t ScanModule(const std::string& moduleName, const std::string& pattern);

    // ��ȡ����ı���
    std::unordered_map<std::string, std::vector<uint8_t>> GetCapturedVariables() const {
        return m_capturedVariables;
    }

    // ��ղ���ı���
    void ClearCapturedVariables() { m_capturedVariables.clear(); }

private:
    // �����������ַ���
    std::vector<PatternByte> ParsePattern(const std::string& pattern);

    // ɨ���ڴ�
    uintptr_t ScanMemory(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern);

    // ����ı�������
    std::unordered_map<std::string, std::vector<uint8_t>> m_capturedVariables;

    MemoryManager* m_memoryManager;
};