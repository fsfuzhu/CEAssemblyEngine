// CEScriptParser.cpp - CE�ű�������ʵ��
#include "Core/CEAssemblyEngine.h"
#include "CEScriptParser.h"
#include "Utils/DebugHelper.h"
#include <sstream>
#include <algorithm>
#include <regex>

CEScriptParser::CEScriptParser() {}
CEScriptParser::~CEScriptParser() {}

bool CEScriptParser::ParseScript(const std::string& content) {
    Clear();

    std::istringstream stream(content);
    std::string line;
    bool inEnableBlock = false;
    bool inDisableBlock = false;
    std::string pendingLine; // ���ںϲ�����

    while (std::getline(stream, line)) {
        // �����У�ȥ��ע�ͺͿհ�
        line = ProcessLine(line);
        if (line.empty()) continue;

        // ������
        if (line == "[ENABLE]") {
            // �����δ������У������
            if (!pendingLine.empty()) {
                if (inEnableBlock) m_enableBlock.push_back(pendingLine);
                else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
                pendingLine.clear();
            }

            inEnableBlock = true;
            inDisableBlock = false;
            continue;
        }
        else if (line == "[DISABLE]") {
            // �����δ������У������
            if (!pendingLine.empty()) {
                if (inEnableBlock) m_enableBlock.push_back(pendingLine);
                else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
                pendingLine.clear();
            }

            inEnableBlock = false;
            inDisableBlock = true;
            continue;
        }
        if (!line.empty() && line.back() == ':') {
            // �������У��ȴ���һ��
            pendingLine = line;
            continue;
        }
        if (!pendingLine.empty() && line.find("db") == 0) {
            // �ϲ�Ϊһ��
            line = pendingLine + " " + line;
            pendingLine.clear();
        }
        else if (!pendingLine.empty()) {
            // ǰһ�в���Ҫ�ϲ��ģ��������
            if (inEnableBlock) m_enableBlock.push_back(pendingLine);
            else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
            pendingLine.clear();
        }
        // ���⴦����ǩ���� (��: label(health armor player location))
        if (inEnableBlock && line.find("label(") == 0 && line.find(" ") != std::string::npos) {
            // ��ȡ�����ڵ�����
            size_t start = line.find('(') + 1;
            size_t end = line.find(')', start);
            if (end != std::string::npos) {
                std::string labelsStr = line.substr(start, end - start);

                // ���ո�ָ��ǩ
                std::istringstream labelStream(labelsStr);
                std::string label;
                while (labelStream >> label) {
                    std::string labelLine = "label(" + label + ")";
                    m_enableBlock.push_back(labelLine);
                }
                continue;
            }
        }

        // ��ӵ���Ӧ�Ŀ�
        if (inEnableBlock) {
            m_enableBlock.push_back(line);
        }
        else if (inDisableBlock) {
            m_disableBlock.push_back(line);
        }
    }
    if (!pendingLine.empty()) {
        if (inEnableBlock) m_enableBlock.push_back(pendingLine);
        else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
    }
    return !m_enableBlock.empty();
}

ParsedCommand CEScriptParser::ParseLine(const std::string& line) {
    ParsedCommand cmd;
    cmd.rawLine = line;
    cmd.type = GetCommandType(line);

    // ����Ǵ����ŵ�������⴦��
    size_t parenPos = line.find('(');
    if (parenPos != std::string::npos) {
        // ��ȡ������
        std::string commandName = line.substr(0, parenPos);
        // ȥ���հ�
        commandName.erase(0, commandName.find_first_not_of(" \t"));
        commandName.erase(commandName.find_last_not_of(" \t") + 1);

        // ����ƥ���������
        size_t endParen = line.find(')', parenPos);
        if (endParen != std::string::npos) {
            // ��ȡ�����ڵĲ���
            std::string params = line.substr(parenPos + 1, endParen - parenPos - 1);

            // �����ŷָ����
            std::istringstream paramStream(params);
            std::string param;

            while (std::getline(paramStream, param, ',')) {
                // ȥ���հ�
                param.erase(0, param.find_first_not_of(" \t"));
                param.erase(param.find_last_not_of(" \t") + 1);
                if (!param.empty()) {
                    cmd.parameters.push_back(param);
                }
            }

            LOG_DEBUG_F("Parsed command '%s' with %zu parameters",
                commandName.c_str(), cmd.parameters.size());
            for (size_t i = 0; i < cmd.parameters.size(); ++i) {
                LOG_DEBUG_F("  param[%zu] = '%s'", i, cmd.parameters[i].c_str());
            }
        }
    }
    else {
        // û�����ŵ�������ո�ָ�
        std::istringstream iss(line);
        std::string token;
        bool firstToken = true;

        while (iss >> token) {
            if (firstToken) {
                firstToken = false;
                // ��һ��token����������ָ����Ҫ����
                if (cmd.type != CommandType::ASSEMBLY) {
                    continue;
                }
            }
            cmd.parameters.push_back(token);
        }
    }

    return cmd;
}

void CEScriptParser::Clear() {
    m_enableBlock.clear();
    m_disableBlock.clear();
}

std::string CEScriptParser::ProcessLine(const std::string& line) {
    // ȥ��ע��
    size_t commentPos = line.find("//");
    std::string processed = (commentPos != std::string::npos) ? line.substr(0, commentPos) : line;

    // ȥ��ǰ��հ�
    processed.erase(0, processed.find_first_not_of(" \t\r\n"));
    processed.erase(processed.find_last_not_of(" \t\r\n") + 1);

    return processed;
}

CommandType CEScriptParser::GetCommandType(const std::string& line) {
    if (line.empty()) return CommandType::UNKNOWN;

    // ��ǩ���壨��ð�Ž�β��
    if (line.back() == ':') {
        return CommandType::ASSEMBLY;  // ��ǩ������Ļ��ָ��
    }

    // ��ȡ������
    std::string command;
    size_t spacePos = line.find(' ');
    size_t parenPos = line.find('(');

    if (parenPos != std::string::npos && (spacePos == std::string::npos || parenPos < spacePos)) {
        command = line.substr(0, parenPos);
    }
    else if (spacePos != std::string::npos) {
        command = line.substr(0, spacePos);
    }
    else {
        command = line;
    }

    // ת��ΪСд
    std::transform(command.begin(), command.end(), command.begin(), ::tolower);

    // ƥ����������
    if (command == "aobscanmodule") return CommandType::AOBSCANMODULE;
    if (command == "alloc") return CommandType::ALLOC;
    if (command == "label") return CommandType::LABEL;
    if (command == "registersymbol") return CommandType::REGISTERSYMBOL;
    if (command == "unregistersymbol") return CommandType::UNREGISTERSYMBOL;
    if (command == "dealloc") return CommandType::DEALLOC;
    if (command == "db") return CommandType::DB;

    // Ĭ��Ϊ���ָ��
    return CommandType::ASSEMBLY;
}