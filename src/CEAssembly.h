// CEAssembly.h - CE汇编引擎统一包含文件
#pragma once

// Windows API
#include <Windows.h>

// 标准库
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

// CE汇编引擎核心组件 - 按依赖顺序包含
#include "ProcessManager.h"      // 进程管理
#include "CEAssemblyEngine.h"    // 定义 PatchInfo 等基础结构
#include "CEScript.h"            // 使用 PatchInfo
#include "SymbolManager.h"       // 符号管理
#include "PatternScanner.h"      // 特征码扫描
#include "MemoryAllocator.h"     // 内存分配
#include "Parser/CEScriptParser.h" // 脚本解析
#include "Utils/StringUtils.h"   // 字符串工具

// 可选：游戏修改器示例
#ifdef INCLUDE_EXAMPLES
#include "GameTrainer.h"
#endif

// 导出的命名空间
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;

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
}