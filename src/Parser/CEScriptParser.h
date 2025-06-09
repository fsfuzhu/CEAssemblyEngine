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
    // 解析脚本，分离ENABLE和DISABLE块
    void ParseScript(const std::string& script,
        std::vector<std::string>& enableBlock,
        std::vector<std::string>& disableBlock);

    // 解析单行命令
    ParsedCommand ParseLine(const std::string& line);

    // 清理行（去除注释和空白）
    std::string CleanLine(const std::string& line);

    // 判断是否是汇编指令
    bool IsAssemblyInstruction(const std::string& line);

private:
    // 分割参数
    std::vector<std::string> SplitParameters(const std::string& params);
};