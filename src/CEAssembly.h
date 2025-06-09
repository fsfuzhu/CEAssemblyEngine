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
class ProcessManager;
class SymbolManager;
class PatternScanner;
class MemoryAllocator;
class CEScriptParser;

// 包含所有头文件 - 按依赖顺序
#include "ProcessManager.h"      // 进程管理（独立）
#include "SymbolManager.h"       // 符号管理（独立）
#include "PatternScanner.h"      // 特征码扫描（依赖 ProcessManager）
#include "MemoryAllocator.h"     // 内存分配（依赖 ProcessManager）
#include "Parser/CEScriptParser.h" // 脚本解析（独立）
#include "CEAssemblyEngine.h"    // 主引擎（依赖以上所有）
#include "CEScript.h"            // 脚本类（依赖 CEAssemblyEngine）
#include "Utils/StringUtils.h"   // 工具类（独立）

// 链接库
#pragma comment(lib, "psapi.lib")

// 可选：游戏修改器示例
#ifdef INCLUDE_EXAMPLES
#include "Examples/GameTrainer.h"
#include "Examples/RemoteGameTrainer.h"
#endif

// 导出的命名空间
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;
    using ProcMgr = ProcessManager;

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
        return ProcessManager::FindProcessByName(processName);
    }

    // 列出所有进程
    inline void ListProcesses() {
        auto processes = ProcessManager::EnumerateProcesses();
        std::cout << "=== 进程列表 ===" << std::endl;
        for (const auto& proc : processes) {
            std::cout << std::setw(30) << std::left << proc.name
                << " PID: " << std::setw(8) << proc.pid
                << std::endl;
        }
    }
}

// 使用 CEAssembly 命名空间
using namespace CEAssembly;