// CEScriptParser.h - CE�ű�������
#pragma once
#include <string>
#include <vector>

// ǰ������
struct ParsedCommand;
enum class CommandType;

class CEScriptParser {
public:
    CEScriptParser();
    ~CEScriptParser();

    // �����ű�����
    bool ParseScript(const std::string& content);

    // ��ȡ������Ŀ�
    std::vector<std::string> GetEnableBlock() const { return m_enableBlock; }
    std::vector<std::string> GetDisableBlock() const { return m_disableBlock; }

    // �������������CEAssemblyEngineʹ�ã�
    ParsedCommand ParseLine(const std::string& line);

    // ��ս������
    void Clear();

private:
    // ������Ŀ�
    std::vector<std::string> m_enableBlock;
    std::vector<std::string> m_disableBlock;

    // ������
    std::string ProcessLine(const std::string& line);

    // �ж���������
    CommandType GetCommandType(const std::string& line);
};