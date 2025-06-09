
// SymbolManager.h
#pragma once
#include <string>
#include <unordered_map>
#include <Windows.h>

struct SymbolInfo {
    uintptr_t address;
    size_t size;
    bool isLabel;
    std::vector<uint8_t> capturedData;  // 用于存储通配符捕获的数据
};

class SymbolManager {
public:
    // 注册符号
    void RegisterSymbol(const std::string& name, uintptr_t address, size_t size = 0, bool isLabel = false);

    // 注册捕获的数据（如 s1.2）
    void RegisterCapturedData(const std::string& name, const std::vector<uint8_t>& data);

    // 获取符号地址
    bool GetSymbolAddress(const std::string& name, uintptr_t& address) const;

    // 获取符号信息
    bool GetSymbolInfo(const std::string& name, SymbolInfo& info) const;

    // 获取捕获的数据值
    bool GetCapturedValue(const std::string& name, uint64_t& value) const;

    // 注销符号
    void UnregisterSymbol(const std::string& name);

    // 清空所有符号
    void Clear();

    // 判断符号是否存在
    bool SymbolExists(const std::string& name) const;

private:
    std::unordered_map<std::string, SymbolInfo> m_symbols;
};