// CEScript.h
#pragma once
#include <string>
#include <vector>
#include <memory>

// ǰ������
class CEAssemblyEngine;
struct PatchInfo;  // ʹ��CEAssemblyEngine�ж����PatchInfo

// CE�ű��� - ��װ�����ű�
class CEScript {
public:
    CEScript(CEAssemblyEngine* engine);
    ~CEScript();

    // ���ؽű�����
    bool Load(const std::string& scriptContent);
    bool LoadFromFile(const std::string& filename);

    // ִ�нű�
    bool Enable();   // ִ��[ENABLE]����
    bool Disable();  // ִ��[DISABLE]����

    // ״̬��ѯ
    bool IsLoaded() const { return m_loaded; }
    bool IsEnabled() const { return m_enabled; }

    // ��ȡ�ű���Ϣ
    std::string GetName() const { return m_name; }
    void SetName(const std::string& name) { m_name = name; }

    // ��ȡ������Ϣ
    std::string GetLastError() const { return m_lastError; }

private:
    CEAssemblyEngine* m_engine;
    std::string m_name;
    std::vector<std::string> m_enableBlock;
    std::vector<std::string> m_disableBlock;
    bool m_loaded;
    bool m_enabled;
    std::string m_lastError;

    // ���油����Ϣ���ڻָ�
    std::vector<PatchInfo> m_patches;
};