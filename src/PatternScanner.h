// PatternScanner.h
#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <unordered_map>

// 前向声明
class ProcessManager;

struct PatternByte {
    bool isWildcard;
    uint8_t value;
    std::string captureName;  // 如 "s1"
    size_t captureSize;       // 如 2 (来自 s1.2)
};

class PatternScanner {
public:
    PatternScanner();
    ~PatternScanner();

    // 设置进程管理器（用于跨进程扫描）
    void SetProcessManager(ProcessManager* pm) { m_processManager = pm; }

    // 扫描模块中的特征码
    uintptr_t ScanModule(const std::string& moduleName, const std::string& pattern);

    // 获取捕获的变量
    std::unordered_map<std::string, std::vector<uint8_t>> GetCapturedVariables() const { return m_capturedVariables; }

    // 清空捕获的变量
    void ClearCapturedVariables() { m_capturedVariables.clear(); }

private:
    // 解析特征码字符串
    std::vector<PatternByte> ParsePattern(const std::string& pattern);

    // 扫描内存
    uintptr_t ScanMemory(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern);

    // 捕获的变量数据
    std::unordered_map<std::string, std::vector<uint8_t>> m_capturedVariables;

    // 进程管理器（可选，用于跨进程）
    ProcessManager* m_processManager;
};