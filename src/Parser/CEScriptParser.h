// CEScriptParser.h
#pragma once
#include <string>
#include <vector>
#include <regex>

enum class CommandType {
    AOBSCANMODULE,
    ALLOC,
    LABEL,
    REGISTERSYMBOL,
    UNREGISTERSYMBOL,
    DEALLOC,
    DB,
    ASSEMBLY,
    UNKNOWN
};

struct ParsedCommand {
    CommandType type;
    std::vector<std::string> parameters;
    std::string rawLine;
};

class CEScriptParser {
public:
    // �����ű�������ENABLE��DISABLE��
    void ParseScript(const std::string& script,
        std::vector<std::string>& enableBlock,
        std::vector<std::string>& disableBlock);

    // ������������
    ParsedCommand ParseLine(const std::string& line);

    // �����У�ȥ��ע�ͺͿհף�
    std::string CleanLine(const std::string& line);

    // �ж��Ƿ��ǻ��ָ��
    bool IsAssemblyInstruction(const std::string& line);

private:
    // �ָ����
    std::vector<std::string> SplitParameters(const std::string& params);
};