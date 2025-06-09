// SymbolManager.cpp
#include "SymbolManager.h"
#include <algorithm>

void SymbolManager::RegisterSymbol(const std::string& name, uintptr_t address, size_t size, bool isLabel) {
    SymbolInfo info;
    info.address = address;
    info.size = size;
    info.isLabel = isLabel;
    m_symbols[name] = info;
}

void SymbolManager::RegisterCapturedData(const std::string& name, const std::vector<uint8_t>& data) {
    if (m_symbols.find(name) != m_symbols.end()) {
        m_symbols[name].capturedData = data;
    }
    else {
        SymbolInfo info;
        info.address = 0;
        info.size = data.size();
        info.isLabel = false;
        info.capturedData = data;
        m_symbols[name] = info;
    }
}

bool SymbolManager::GetSymbolAddress(const std::string& name, uintptr_t& address) const {
    auto it = m_symbols.find(name);
    if (it != m_symbols.end()) {
        address = it->second.address;
        return true;
    }
    return false;
}

bool SymbolManager::GetSymbolInfo(const std::string& name, SymbolInfo& info) const {
    auto it = m_symbols.find(name);
    if (it != m_symbols.end()) {
        info = it->second;
        return true;
    }
    return false;
}

bool SymbolManager::GetCapturedValue(const std::string& name, uint64_t& value) const {
    auto it = m_symbols.find(name);
    if (it != m_symbols.end() && !it->second.capturedData.empty()) {
        value = 0;
        const auto& data = it->second.capturedData;
        for (size_t i = 0; i < data.size() && i < 8; ++i) {
            value |= static_cast<uint64_t>(data[i]) << (i * 8);
        }
        return true;
    }
    return false;
}

void SymbolManager::UnregisterSymbol(const std::string& name) {
    m_symbols.erase(name);
}

void SymbolManager::Clear() {
    m_symbols.clear();
}

bool SymbolManager::SymbolExists(const std::string& name) const {
    return m_symbols.find(name) != m_symbols.end();
}