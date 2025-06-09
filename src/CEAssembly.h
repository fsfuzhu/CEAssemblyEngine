// CEAssembly.h - CE�������ͳһ�����ļ�
#pragma once

// Windows API
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

// ��׼��
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

// ǰ������������
class CEAssemblyEngine;
class CEScript;
class ProcessManager;
class SymbolManager;
class PatternScanner;
class MemoryAllocator;
class CEScriptParser;

// ��������ͷ�ļ� - ������˳��
#include "ProcessManager.h"      // ���̹���������
#include "SymbolManager.h"       // ���Ź���������
#include "PatternScanner.h"      // ������ɨ�裨���� ProcessManager��
#include "MemoryAllocator.h"     // �ڴ���䣨���� ProcessManager��
#include "Parser/CEScriptParser.h" // �ű�������������
#include "CEAssemblyEngine.h"    // �����棨�����������У�
#include "CEScript.h"            // �ű��ࣨ���� CEAssemblyEngine��
#include "Utils/StringUtils.h"   // �����ࣨ������

// ���ӿ�
#pragma comment(lib, "psapi.lib")

// ��ѡ����Ϸ�޸���ʾ��
#ifdef INCLUDE_EXAMPLES
#include "Examples/GameTrainer.h"
#include "Examples/RemoteGameTrainer.h"
#endif

// �����������ռ�
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;
    using ProcMgr = ProcessManager;

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

    // ���ٽ��̲���
    inline DWORD FindProcess(const std::string& processName) {
        return ProcessManager::FindProcessByName(processName);
    }

    // �г����н���
    inline void ListProcesses() {
        auto processes = ProcessManager::EnumerateProcesses();
        std::cout << "=== �����б� ===" << std::endl;
        for (const auto& proc : processes) {
            std::cout << std::setw(30) << std::left << proc.name
                << " PID: " << std::setw(8) << proc.pid
                << std::endl;
        }
    }
}

// ʹ�� CEAssembly �����ռ�
using namespace CEAssembly;