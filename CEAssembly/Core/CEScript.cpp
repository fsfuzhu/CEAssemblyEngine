// CEScript.cpp
#include "CEScript.h"
#include "Utils\DebugHelper.h"
#include "CEAssemblyEngine.h"  // 需要包含以获取PatchInfo定义
#include "Parser/CEScriptParser.h"
#include <fstream>
#include <sstream>

CEScript::CEScript(CEAssemblyEngine* engine)
    : m_engine(engine)
    , m_loaded(false)
    , m_enabled(false) {
}

CEScript::~CEScript() {
    // 如果脚本仍处于启用状态，自动禁用
    if (m_enabled) {
        Disable();
    }
}

bool CEScript::Load(const std::string& scriptContent) {
    if (m_enabled) {
        m_lastError = "Cannot load script while it is enabled";
        return false;
    }

    // 清空之前的内容
    m_enableBlock.clear();
    m_disableBlock.clear();

    // 使用解析器分离ENABLE和DISABLE块
    CEScriptParser parser;
    if (!parser.ParseScript(scriptContent)) {
        m_lastError = "Failed to parse script content";
        return false;
    }

    // 获取解析结果
    m_enableBlock = parser.GetEnableBlock();
    m_disableBlock = parser.GetDisableBlock();

    LOG_INFO_F("Script \"%s\" loaded. ENABLE=%zu lines, DISABLE=%zu lines",
        m_name.c_str(), m_enableBlock.size(), m_disableBlock.size());

    if (m_enableBlock.empty() && m_disableBlock.empty()) {
        m_lastError = "No valid [ENABLE] or [DISABLE] blocks found";
        return false;
    }

    m_loaded = true;
    return true;
}

bool CEScript::LoadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        m_lastError = "Failed to open file: " + filename;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    // 使用文件名作为脚本名称
    size_t lastSlash = filename.find_last_of("/\\");
    m_name = (lastSlash != std::string::npos) ? filename.substr(lastSlash + 1) : filename;

    return Load(buffer.str());
}

bool CEScript::Enable() {
    if (!m_loaded) {
        m_lastError = "Script not loaded";
        return false;
    }

    if (m_enabled) {
        m_lastError = "Script already enabled";
        return false;
    }

    LOG_INFO_F("Enabling script \"%s\"", m_name.c_str());

    // 清空之前的补丁信息
    m_patches.clear();

    // 设置引擎的脚本上下文
    m_engine->SetCurrentScript(this);

    // 执行ENABLE块
    if (!m_engine->ProcessEnableBlock(m_enableBlock)) {
        m_lastError = m_engine->GetLastError();
        LOG_ERROR_F("Enable failed : %s", m_lastError.c_str());
        return false;
    }

    LOG_INFO("Enable success");

    // 获取所有的补丁信息
    m_patches = m_engine->GetPatches();

    m_enabled = true;
    return true;
}

bool CEScript::Disable() {
    if (!m_loaded) {
        m_lastError = "Script not loaded";
        return false;
    }

    if (!m_enabled) {
        m_lastError = "Script not enabled";
        return false;
    }

    // 设置引擎的脚本上下文
    m_engine->SetCurrentScript(this);

    // 如果有DISABLE块，执行它
    if (!m_disableBlock.empty()) {
        if (!m_engine->ProcessDisableBlock(m_disableBlock)) {
            m_lastError = m_engine->GetLastError();
            return false;
        }
    }
    else {
        // 如果没有DISABLE块，自动恢复原始字节
        for (const auto& patch : m_patches) {
            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<LPVOID>(patch.address),
                patch.originalBytes.size(),
                PAGE_EXECUTE_READWRITE,
                &oldProtect)) {
                memcpy(reinterpret_cast<void*>(patch.address),
                    patch.originalBytes.data(),
                    patch.originalBytes.size());
                VirtualProtect(reinterpret_cast<LPVOID>(patch.address),
                    patch.originalBytes.size(),
                    oldProtect,
                    &oldProtect);
            }
        }
    }

    m_enabled = false;
    return true;
}