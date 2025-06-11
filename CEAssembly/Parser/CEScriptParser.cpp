// CEScriptParser.cpp - CE脚本解析器实现
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
        if (!line.empty() && line.back() == ':') {
            // 保存这行，等待下一行
            pendingLine = line;
            continue;
        }
        if (!pendingLine.empty() && line.find("db") == 0) {
            // 合并为一行
            line = pendingLine + " " + line;
            pendingLine.clear();
        }
        else if (!pendingLine.empty()) {
            // 前一行不是要合并的，单独添加
            if (inEnableBlock) m_enableBlock.push_back(pendingLine);
            else if (inDisableBlock) m_disableBlock.push_back(pendingLine);
            pendingLine.clear();
        }
        // 特殊处理多标签声明 (如: label(health armor player location))
        if (inEnableBlock && line.find("label(") == 0 && line.find(" ") != std::string::npos) {
            // 提取括号内的内容
            size_t start = line.find('(') + 1;
            size_t end = line.find(')', start);
            if (end != std::string::npos) {
                std::string labelsStr = line.substr(start, end - start);

                // 按空格分割标签
                std::istringstream labelStream(labelsStr);
                std::string label;
                while (labelStream >> label) {
                    std::string labelLine = "label(" + label + ")";
                    m_enableBlock.push_back(labelLine);
                }
                continue;
            }
        }

        // 添加到相应的块
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

    // 如果是带括号的命令，特殊处理
    size_t parenPos = line.find('(');
    if (parenPos != std::string::npos) {
        // 提取命令名
        std::string commandName = line.substr(0, parenPos);
        // 去除空白
        commandName.erase(0, commandName.find_first_not_of(" \t"));
        commandName.erase(commandName.find_last_not_of(" \t") + 1);

        // 查找匹配的右括号
        size_t endParen = line.find(')', parenPos);
        if (endParen != std::string::npos) {
            // 提取括号内的参数
            std::string params = line.substr(parenPos + 1, endParen - parenPos - 1);

            // 按逗号分割参数
            std::istringstream paramStream(params);
            std::string param;

            while (std::getline(paramStream, param, ',')) {
                // 去除空白
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
        // 没有括号的命令，按空格分割
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