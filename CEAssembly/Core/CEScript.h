// CEScript.h
#pragma once
#include <string>
#include <vector>
#include <memory>

// 前向声明
class CEAssemblyEngine;
struct PatchInfo;  // 使用CEAssemblyEngine中定义的PatchInfo

// CE脚本类 - 封装单个脚本
class CEScript {
public:
    CEScript(CEAssemblyEngine* engine);
    ~CEScript();

    // 加载脚本内容
    bool Load(const std::string& scriptContent);
    bool LoadFromFile(const std::string& filename);

    // 执行脚本
    bool Enable();   // 执行[ENABLE]部分
    bool Disable();  // 执行[DISABLE]部分

    // 状态查询
    bool IsLoaded() const { return m_loaded; }
    bool IsEnabled() const { return m_enabled; }

    // 获取脚本信息
    std::string GetName() const { return m_name; }
    void SetName(const std::string& name) { m_name = name; }

    // 获取错误信息
    std::string GetLastError() const { return m_lastError; }

private:
    CEAssemblyEngine* m_engine;
    std::string m_name;
    std::vector<std::string> m_enableBlock;
    std::vector<std::string> m_disableBlock;
    bool m_loaded;
    bool m_enabled;
    std::string m_lastError;

    // 保存补丁信息用于恢复
    std::vector<PatchInfo> m_patches;
};