
// SymbolManager.h
#pragma once
#include <string>
#include <unordered_map>
#include <Windows.h>

struct SymbolInfo {
    uintptr_t address;
    size_t size;
    bool isLabel;
    std::vector<uint8_t> capturedData;  // ���ڴ洢ͨ������������
};

class SymbolManager {
public:
    // ע�����
    void RegisterSymbol(const std::string& name, uintptr_t address, size_t size = 0, bool isLabel = false);

    // ע�Ჶ������ݣ��� s1.2��
    void RegisterCapturedData(const std::string& name, const std::vector<uint8_t>& data);

    // ��ȡ���ŵ�ַ
    bool GetSymbolAddress(const std::string& name, uintptr_t& address) const;

    // ��ȡ������Ϣ
    bool GetSymbolInfo(const std::string& name, SymbolInfo& info) const;

    // ��ȡ���������ֵ
    bool GetCapturedValue(const std::string& name, uint64_t& value) const;

    // ע������
    void UnregisterSymbol(const std::string& name);

    // ������з���
    void Clear();

    // �жϷ����Ƿ����
    bool SymbolExists(const std::string& name) const;

private:
    std::unordered_map<std::string, SymbolInfo> m_symbols;
};