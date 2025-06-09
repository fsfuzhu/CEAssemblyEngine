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

    while (std::getline(stream, line)) {
        // �����У�ȥ���հ׺�ע��
        line = ProcessLine(line);
        if (line.empty()) continue;

        // ������
        if (line == "[ENABLE]") {
            inEnableBlock = true;
            inDisableBlock = false;
            continue;
        }
        else if (line == "[DISABLE]") {
            inEnableBlock = false;
            inDisableBlock = true;
            continue;
        }

        // ��ӵ���Ӧ�Ŀ�
        if (inEnableBlock) {
            m_enableBlock.push_back(line);
        }
        else if (inDisableBlock) {
            m_disableBlock.push_back(line);
        }
    }

    return !m_enableBlock.empty();
}

ParsedCommand CEScriptParser::ParseLine(const std::string& line) {
    ParsedCommand cmd;
    cmd.rawLine = line;
    cmd.type = GetCommandType(line);

    // ��ȡ����
    std::istringstream iss(line);
    std::string token;
    bool firstToken = true;

    while (iss >> token) {
        if (firstToken) {
            firstToken = false;
            // ��һ��token����������˻��ָ�
            if (cmd.type != CommandType::ASSEMBLY) {
                continue;
            }
        }

        // ��������
        if (token.find('(') != std::string::npos) {
            size_t start = token.find('(');
            size_t end = line.find(')', start);
            if (end != std::string::npos) {
                std::string params = line.substr(start + 1, end - start - 1);
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
                break;
            }
        }
        else {
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