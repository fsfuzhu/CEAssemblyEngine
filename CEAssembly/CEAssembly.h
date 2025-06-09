// CEAssembly.h - CE汇编引擎统一包含文件
#pragma once

// Windows API
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

// 标准库
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <cstdint>
#include <regex>

// Keystone
#include <keystone/keystone.h>

// 前向声明所有类
class CEAssemblyEngine;
class CEScript;
class MemoryManager;
class SymbolManager;
class PatternScanner;
class CEScriptParser;

// 包含所有头文件 - 按依赖顺序
#include "Core\MemoryManager.h"
#include "Symbol\SymbolManager.h"
#include "Scanner\PatternScanner.h"
#include "Parser\CEScriptParser.h"
#include "Utils\StringUtils.h"
#include "Core\CEAssemblyEngine.h"
#include "Core\CEScript.h"

// 链接库
#pragma comment(lib, "psapi.lib")

// 导出的命名空间
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;
    using MemMgr = MemoryManager;

    // 便捷函数
    inline std::shared_ptr<CEScript> CreateAndLoadScript(CEAssemblyEngine& engine,
        const std::string& name,
        const std::string& content) {
        auto script = engine.CreateScript(name);
        if (script && script->Load(content)) {
            return script;
        }
        return nullptr;
    }

    inline std::shared_ptr<CEScript> CreateAndLoadScriptFromFile(CEAssemblyEngine& engine,
        const std::string& filename) {
        auto script = engine.CreateScript();
        if (script && script->LoadFromFile(filename)) {
            return script;
        }
        return nullptr;
    }

    // 快速进程查找
    inline DWORD FindProcess(const std::string& processName) {
        return MemoryManager::FindProcessByName(processName);
    }

    // 列出所有进程
    inline void ListProcesses() {
        auto processes = MemoryManager::EnumerateProcesses();
        std::cout << "=== 进程列表 ===" << std::endl;
        for (const auto& proc : processes) {
            std::cout << std::setw(30) << std::left << proc.name
                << " PID: " << std::setw(8) << proc.pid
                << std::endl;
        }
    }

    // 创建基本的游戏修改器示例
    class SimpleGameTrainer {
    private:
        CEAssemblyEngine m_engine;
        std::shared_ptr<CEScript> m_script;

    public:
        bool AttachToGame(const std::string& processName) {
            return m_engine.AttachToProcess(processName);
        }

        bool LoadScript(const std::string& scriptContent) {
            m_script = m_engine.CreateScript("MainScript");
            return m_script && m_script->Load(scriptContent);
        }

        bool LoadScriptFromFile(const std::string& filename) {
            m_script = m_engine.CreateScript();
            return m_script && m_script->LoadFromFile(filename);
        }

        bool EnableHack() {
            return m_script && m_script->Enable();
        }

        bool DisableHack() {
            return m_script && m_script->Disable();
        }

        void Detach() {
            m_engine.DetachFromProcess();
        }

        CEAssemblyEngine& GetEngine() { return m_engine; }
    };
}

// 使用 CEAssembly 命名空间
using namespace CEAssembly;