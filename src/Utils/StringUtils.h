// StringUtils.h
#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

class StringUtils {
public:
    // 分割字符串
    static std::vector<std::string> Split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;

        while (std::getline(ss, token, delimiter)) {
            if (!token.empty()) {
                tokens.push_back(token);
            }
        }

        return tokens;
    }

    // 去除首尾空白
    static std::string Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            return "";
        }

        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }

    // 转换为大写
    static std::string ToUpper(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    // 转换为小写
    static std::string ToLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    // 替换字符串
    static std::string Replace(const std::string& str, const std::string& from, const std::string& to) {
        std::string result = str;
        size_t pos = 0;

        while ((pos = result.find(from, pos)) != std::string::npos) {
            result.replace(pos, from.length(), to);
            pos += to.length();
        }

        return result;
    }

    // 检查是否以指定字符串开始
    static bool StartsWith(const std::string& str, const std::string& prefix) {
        return str.size() >= prefix.size() &&
            str.compare(0, prefix.size(), prefix) == 0;
    }

    // 检查是否以指定字符串结束
    static bool EndsWith(const std::string& str, const std::string& suffix) {
        return str.size() >= suffix.size() &&
            str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    // 解析十六进制字符串
    static uint64_t ParseHex(const std::string& str) {
        std::string hex = str;

        // 移除0x前缀
        if (StartsWith(ToLower(hex), "0x")) {
            hex = hex.substr(2);
        }

        return std::stoull(hex, nullptr, 16);
    }

    // 格式化字节为十六进制字符串
    static std::string FormatBytes(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) ss << " ";
            ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                << static_cast<int>(bytes[i]);
        }

        return ss.str();
    }
};