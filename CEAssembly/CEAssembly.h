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
class MemoryManager;
class SymbolManager;
class PatternScanner;
class CEScriptParser;

// ��������ͷ�ļ� - ������˳��
#include "Core\MemoryManager.h"
#include "Symbol\SymbolManager.h"
#include "Scanner\PatternScanner.h"
#include "Parser\CEScriptParser.h"
#include "Utils\StringUtils.h"
#include "Core\CEAssemblyEngine.h"
#include "Core\CEScript.h"

// ���ӿ�
#pragma comment(lib, "psapi.lib")

// �����������ռ�
namespace CEAssembly {
    using Engine = CEAssemblyEngine;
    using Script = CEScript;
    using Parser = CEScriptParser;
    using MemMgr = MemoryManager;

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
        return MemoryManager::FindProcessByName(processName);
    }

    // �г����н���
    inline void ListProcesses() {
        auto processes = MemoryManager::EnumerateProcesses();
        std::cout << "=== �����б� ===" << std::endl;
        for (const auto& proc : processes) {
            std::cout << std::setw(30) << std::left << proc.name
                << " PID: " << std::setw(8) << proc.pid
                << std::endl;
        }
    }

    // ������������Ϸ�޸���ʾ��
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

// ʹ�� CEAssembly �����ռ�
using namespace CEAssembly;