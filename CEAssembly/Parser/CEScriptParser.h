// CEScriptParser.h - CE脚本解析器
#pragma once
#include <string>
#include <vector>

// 前向声明
struct ParsedCommand;
enum class CommandType;

class CEScriptParser {
public:
    CEScriptParser();
    ~CEScriptParser();

    // 解析脚本内容
    bool ParseScript(const std::string& content);

    // 获取解析后的块
    std::vector<std::string> GetEnableBlock() const { return m_enableBlock; }
    std::vector<std::string> GetDisableBlock() const { return m_disableBlock; }

    // 解析单行命令（由CEAssemblyEngine使用）
    ParsedCommand ParseLine(const std::string& line);

    // 清空解析结果
    void Clear();

private:
    // 解析后的块
    std::vector<std::string> m_enableBlock;
    std::vector<std::string> m_disableBlock;

    // 处理行
    std::string ProcessLine(const std::string& line);

    // 判断命令类型
    CommandType GetCommandType(const std::string& line);
};