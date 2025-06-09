// CEScript.cpp
#include "CEScript.h"
#include "CEAssemblyEngine.h"  // ��Ҫ�����Ի�ȡPatchInfo����
#include "Parser/CEScriptParser.h"
#include <fstream>
#include <sstream>

CEScript::CEScript(CEAssemblyEngine* engine)
    : m_engine(engine)
    , m_loaded(false)
    , m_enabled(false) {
}

CEScript::~CEScript() {
    // ����ű��Դ�������״̬���Զ�����
    if (m_enabled) {
        Disable();
    }
}

bool CEScript::Load(const std::string& scriptContent) {
    if (m_enabled) {
        m_lastError = "Cannot load script while it is enabled";
        return false;
    }

    // ���֮ǰ������
    m_enableBlock.clear();
    m_disableBlock.clear();

    // ʹ�ý���������ENABLE��DISABLE��
    CEScriptParser parser;
    parser.ParseScript(scriptContent, m_enableBlock, m_disableBlock);

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

    // ʹ���ļ�����Ϊ�ű�����
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

    // ���֮ǰ�Ĳ�����Ϣ
    m_patches.clear();

    // ��������Ľű�������
    m_engine->SetCurrentScript(this);

    // ִ��ENABLE��
    if (!m_engine->ProcessEnableBlock(m_enableBlock)) {
        m_lastError = m_engine->GetLastError();
        return false;
    }

    // ��ȡ���еĲ�����Ϣ
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

    // ��������Ľű�������
    m_engine->SetCurrentScript(this);

    // �����DISABLE�飬ִ����
    if (!m_disableBlock.empty()) {
        if (!m_engine->ProcessDisableBlock(m_disableBlock)) {
            m_lastError = m_engine->GetLastError();
            return false;
        }
    }
    else {
        // ���û��DISABLE�飬�Զ��ָ�ԭʼ�ֽ�
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