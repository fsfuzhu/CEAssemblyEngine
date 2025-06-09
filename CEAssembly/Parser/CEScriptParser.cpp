// CEScriptParser.cpp
#include "CEScriptParser.h"
#include <algorithm>
#include <sstream>

void CEScriptParser::ParseScript(const std::string& script,
    std::vector<std::string>& enableBlock,
    std::vector<std::string>& disableBlock) {
    std::istringstream iss(script);
    std::string line;
    bool inEnableBlock = false;
    bool inDisableBlock = false;

    while (std::getline(iss, line)) {
        std::string cleanedLine = CleanLine(line);
        if (cleanedLine.empty()) continue;

        // ת��Ϊ��д���бȽ�
        std::string upperLine = cleanedLine;
        std::transform(upperLine.begin(), upperLine.end(), upperLine.begin(), ::toupper);

        if (upperLine == "[ENABLE]") {
            inEnableBlock = true;
            inDisableBlock = false;
        }
        else if (upperLine == "[DISABLE]") {
            inEnableBlock = false;
            inDisableBlock = true;
        }
        else if (inEnableBlock) {
            enableBlock.push_back(cleanedLine);
        }
        else if (inDisableBlock) {
            disableBlock.push_back(cleanedLine);
        }
    }
}

std::string CEScriptParser::CleanLine(const std::string& line) {
    std::string result = line;

    // �Ƴ�ע��
    size_t commentPos = result.find("//");
    if (commentPos != std::string::npos) {
        result = result.substr(0, commentPos);
    }

    // ȥ����β�հ�
    size_t start = result.find_first_not_of(" \t\r\n");
    size_t end = result.find_last_not_of(" \t\r\n");

    if (start == std::string::npos) {
        return "";
    }

    return result.substr(start, end - start + 1);
}

ParsedCommand CEScriptParser::ParseLine(const std::string& line) {
    ParsedCommand cmd;
    cmd.rawLine = line;

    // ����Ƿ��Ǳ�ǩ���壨��ð�Ž�β��
    if (!line.empty() && line.back() == ':') {
        cmd.type = CommandType::ASSEMBLY;  // ��ǩ������Ϊ���ָ���
        cmd.parameters.push_back(line);
        return cmd;
    }

    // �ҵ���һ�����ŵ�λ��
    size_t openParen = line.find('(');
    size_t closeParen = line.find_last_of(')');

    if (openParen != std::string::npos && closeParen != std::string::npos && closeParen > openParen) {
        // ����һ����������
        std::string funcName = line.substr(0, openParen);
        std::string params = line.substr(openParen + 1, closeParen - openParen - 1);

        // ��������
        funcName = CleanLine(funcName);

        // ת��������Ϊ��д
        std::transform(funcName.begin(), funcName.end(), funcName.begin(), ::toupper);

        // ȷ����������
        if (funcName == "AOBSCANMODULE") {
            cmd.type = CommandType::AOBSCANMODULE;
        }
        else if (funcName == "ALLOC") {
            cmd.type = CommandType::ALLOC;
        }
        else if (funcName == "LABEL") {
            cmd.type = CommandType::LABEL;
        }
        else if (funcName == "REGISTERSYMBOL") {
            cmd.type = CommandType::REGISTERSYMBOL;
        }
        else if (funcName == "UNREGISTERSYMBOL") {
            cmd.type = CommandType::UNREGISTERSYMBOL;
        }
        else if (funcName == "DEALLOC") {
            cmd.type = CommandType::DEALLOC;
        }
        else {
            cmd.type = CommandType::UNKNOWN;
        }

        // �ָ����
        cmd.parameters = SplitParameters(params);
    }
    else {
        // ����Ƿ���dbָ��
        std::string upperLine = line;
        std::transform(upperLine.begin(), upperLine.end(), upperLine.begin(), ::toupper);

        if (upperLine.length() >= 3 && upperLine.substr(0, 3) == "DB ") {
            cmd.type = CommandType::DB;
            cmd.parameters.push_back(line.substr(3));
        }
        else if (IsAssemblyInstruction(line)) {
            cmd.type = CommandType::ASSEMBLY;
            cmd.parameters.push_back(line);
        }
        else {
            cmd.type = CommandType::UNKNOWN;
        }
    }

    return cmd;
}

std::vector<std::string> CEScriptParser::SplitParameters(const std::string& params) {
    std::vector<std::string> result;
    std::string current;
    bool inQuotes = false;

    for (char c : params) {
        if (c == '"') {
            inQuotes = !inQuotes;
        }
        else if (c == ',' && !inQuotes) {
            // ȥ��������β�հ�
            std::string trimmed = CleanLine(current);
            if (!trimmed.empty()) {
                result.push_back(trimmed);
            }
            current.clear();
        }
        else {
            current += c;
        }
    }

    // ������һ������
    if (!current.empty()) {
        std::string trimmed = CleanLine(current);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }
    }

    return result;
}

bool CEScriptParser::IsAssemblyInstruction(const std::string& line) {
    // �����Ļ��ָ��ǰ׺
    static const std::vector<std::string> asmInstructions = {
        "MOV", "LEA", "PUSH", "POP", "CALL", "JMP", "JE", "JNE", "JZ", "JNZ",
        "ADD", "SUB", "XOR", "AND", "OR", "CMP", "TEST", "NOP", "RET",
        "INC", "DEC", "MUL", "DIV", "SHL", "SHR", "ROL", "ROR",
        "JG", "JGE", "JL", "JLE", "JA", "JAE", "JB", "JBE"
    };

    std::string upperLine = line;
    std::transform(upperLine.begin(), upperLine.end(), upperLine.begin(), ::toupper);

    // ��ǩ���壨��ð�Ž�β��
    if (!line.empty() && line.back() == ':') {
        return true;
    }

    // ����Ƿ��Ի��ָ�ʼ
    for (const auto& instruction : asmInstructions) {
        if (upperLine.find(instruction) == 0) {
            // ȷ�������ǿո��Ʊ�����ַ�����β
            if (upperLine.length() == instruction.length() ||
                upperLine[instruction.length()] == ' ' ||
                upperLine[instruction.length()] == '\t') {
                return true;
            }
        }
    }

    return false;
}