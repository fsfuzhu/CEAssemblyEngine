// CEAssembly.h - CE�������ͳһ�����ļ�
#pragma once

// Windows API
#include <Windows.h>

// ��׼��
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

// CE������������� - ������˳�����
#include "ProcessManager.h"      // ���̹���
#include "CEAssemblyEngine.h"    // ���� PatchInfo �Ȼ����ṹ
#include "CEScript.h"            // ʹ�� PatchInfo
#include "SymbolManager.h"       // ���Ź���
#include "PatternScanner.h"      // ������ɨ��
#include "MemoryAllocator.h"     // �ڴ����
#include "Parser/CEScriptParser.h" // �ű�����
#include "Utils/StringUtils.h"   // �ַ�������

// ��ѡ����Ϸ�޸���ʾ��
#ifdef INCLUDE_EXAMPLES
#include "GameTrainer.h"
#endif

// �����������ռ�
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;

    // ��ݺ���
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