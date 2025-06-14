// CEScriptParser.cpp - CE脚本解析器实现（完整修复版）
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
    std::string pendingLine; // 用于合并多行

    while (std::getline(stream, line)) {
        // 处理行：去掉注释和空白
        line = ProcessLine(line);
        if (line.empty()) continue;

        // 检查块标记
        if (line == "[ENABLE]") {
            // 如果有未处理的行，先添加
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
            // 如果有未处理的行，先添加
            if (!pendingLine.empty()) {
                if (inEnableBlock) m_enableBlock.push_back(pendingLine);
                else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
                pendingLine.clear();
            }

            inEnableBlock = false;
            inDisableBlock = true;
            continue;
        }

        // Check if this is a label definition
        if (!line.empty() && line.back() == ':') {
            // First, add any pending line
            if (!pendingLine.empty()) {
                if (inEnableBlock) m_enableBlock.push_back(pendingLine);
                else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
                pendingLine.clear();
            }

            // Check if the next line is a db command
            std::streampos currentPos = stream.tellg();
            std::string nextLine;
            if (std::getline(stream, nextLine)) {
                nextLine = ProcessLine(nextLine);
                if (!nextLine.empty() && nextLine.find("db") == 0) {
                    // Merge label with db command
                    line = line + " " + nextLine;
                }
                else {
                    // Not a db command, so rewind
                    stream.seekg(currentPos);
                }
            }
        }

        // Add the line to appropriate block
        if (inEnableBlock) {
            m_enableBlock.push_back(line);
        }
        else if (inDisableBlock) {
            m_disableBlock.push_back(line);
        }
    }

    // Don't forget any pending line at the end
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

    // 如果是带括号的命令，特殊处理
    size_t parenPos = line.find('(');
    if (parenPos != std::string::npos) {
        // 提取命令名
        std::string commandName = line.substr(0, parenPos);
        // 去除空白
        commandName.erase(0, commandName.find_first_not_of(" \t"));
        commandName.erase(commandName.find_last_not_of(" \t") + 1);

        // 转换为小写用于比较
        std::string lowerCommand = commandName;
        std::transform(lowerCommand.begin(), lowerCommand.end(), lowerCommand.begin(), ::tolower);

        // 查找匹配的右括号
        size_t endParen = line.find(')', parenPos);
        if (endParen != std::string::npos) {
            // 提取括号内的参数
            std::string params = line.substr(parenPos + 1, endParen - parenPos - 1);

            // 特殊处理 label、registersymbol 和 unregistersymbol 命令 - 按空格分隔多个标签
            if (lowerCommand == "label" || lowerCommand == "registersymbol" ||
                lowerCommand == "unregistersymbol") {
                // 按空格分隔多个标签
                std::istringstream paramStream(params);
                std::string param;

                while (paramStream >> param) {
                    // 去除可能的逗号（支持两种格式）
                    if (!param.empty() && param.back() == ',') {
                        param.pop_back();
                    }
                    if (!param.empty()) {
                        cmd.parameters.push_back(param);
                    }
                }
            }
            else {
                // 其他命令按逗号分隔参数
                std::istringstream paramStream(params);
                std::string param;

                while (std::getline(paramStream, param, ',')) {
                    param.erase(0, param.find_first_not_of(" \t"));
                    param.erase(param.find_last_not_of(" \t") + 1);
                    if (!param.empty()) {
                        cmd.parameters.push_back(param);
                    }
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
        // 没有括号的命令，按空格分隔
        std::istringstream iss(line);
        std::string token;
        bool firstToken = true;

        while (iss >> token) {
            if (firstToken) {
                firstToken = false;
                // 第一个token是命令本身，汇编指令需要保留
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
    // 去除注释
    size_t commentPos = line.find("//");
    std::string processed = (commentPos != std::string::npos) ? line.substr(0, commentPos) : line;

    // 去除前后空白
    processed.erase(0, processed.find_first_not_of(" \t\r\n"));
    processed.erase(processed.find_last_not_of(" \t\r\n") + 1);

    return processed;
}

CommandType CEScriptParser::GetCommandType(const std::string& line) {
    if (line.empty()) return CommandType::UNKNOWN;

    // 标签定义（以冒号结尾）
    if (line.back() == ':') {
        return CommandType::ASSEMBLY;  // 标签是特殊的汇编指令
    }

    // 提取命令名
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

    // 转换为小写
    std::transform(command.begin(), command.end(), command.begin(), ::tolower);

    // 匹配命令类型
    if (command == "aobscanmodule") return CommandType::AOBSCANMODULE;
    if (command == "alloc") return CommandType::ALLOC;
    if (command == "label") return CommandType::LABEL;
    if (command == "registersymbol") return CommandType::REGISTERSYMBOL;
    if (command == "unregistersymbol") return CommandType::UNREGISTERSYMBOL;
    if (command == "dealloc") return CommandType::DEALLOC;
    if (command == "db") return CommandType::DB;

    // 默认为汇编指令
    return CommandType::ASSEMBLY;
}