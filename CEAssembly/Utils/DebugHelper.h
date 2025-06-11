// DebugHelper.h - 调试辅助类
#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <Windows.h>

// 调试级别
enum class DebugLevel {
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    Trace = 5
};

class DebugHelper {
private:
    static DebugLevel s_level;
    static bool s_consoleOutput;
    static bool s_fileOutput;
    static std::ofstream s_logFile;
public:
    static DebugLevel GetLevel() { return s_level; }
    // 初始化调试系统
    static void Initialize(DebugLevel level = DebugLevel::Debug, bool console = true, bool file = true) {
        s_level = level;
        s_consoleOutput = console;
        s_fileOutput = file;

        if (s_fileOutput) {
            // 生成带时间戳的日志文件名
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << "CEAssembly_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".log";
            s_logFile.open(ss.str(), std::ios::out | std::ios::app);
        }

        // 在控制台启用颜色
        if (s_consoleOutput) {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD mode;
            GetConsoleMode(hConsole, &mode);
            SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    // 关闭调试系统
    static void Shutdown() {
        if (s_logFile.is_open()) {
            s_logFile.close();
        }
    }

    // 日志输出
    static void Log(DebugLevel level, const std::string& message, const std::string& function = "", int line = 0) {
        if (level > s_level) return;

        // 获取时间戳
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&time_t), "%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";

        // 添加级别标签
        switch (level) {
        case DebugLevel::Error:   ss << "[ERROR] "; break;
        case DebugLevel::Warning: ss << "[WARN ] "; break;
        case DebugLevel::Info:    ss << "[INFO ] "; break;
        case DebugLevel::Debug:   ss << "[DEBUG] "; break;
        case DebugLevel::Trace:   ss << "[TRACE] "; break;
        }

        // 添加函数名和行号
        if (!function.empty()) {
            ss << "[" << function;
            if (line > 0) {
                ss << ":" << line;
            }
            ss << "] ";
        }

        ss << message;

        // 输出到控制台
        if (s_consoleOutput) {
            // 设置颜色
            switch (level) {
            case DebugLevel::Error:   std::cout << "\033[31m"; break; // 红色
            case DebugLevel::Warning: std::cout << "\033[33m"; break; // 黄色
            case DebugLevel::Info:    std::cout << "\033[32m"; break; // 绿色
            case DebugLevel::Debug:   std::cout << "\033[36m"; break; // 青色
            case DebugLevel::Trace:   std::cout << "\033[90m"; break; // 灰色
            }
            std::cout << ss.str() << "\033[0m" << std::endl;
        }

        // 输出到文件
        if (s_fileOutput && s_logFile.is_open()) {
            s_logFile << ss.str() << std::endl;
            s_logFile.flush();
        }
    }

    // 输出十六进制数据
    static void LogHex(DebugLevel level, const std::string& prefix, const uint8_t* data, size_t size, const std::string& function = "", int line = 0) {
        if (level > s_level) return;

        std::stringstream ss;
        ss << prefix << " (size=" << size << "):\n";

        for (size_t i = 0; i < size; i += 16) {
            ss << std::hex << std::setw(8) << std::setfill('0') << i << ": ";

            // 十六进制
            for (size_t j = i; j < i + 16 && j < size; ++j) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[j] << " ";
            }

            // 填充空格
            for (size_t j = size; j < i + 16; ++j) {
                ss << "   ";
            }

            ss << " | ";

            // ASCII
            for (size_t j = i; j < i + 16 && j < size; ++j) {
                char c = (char)data[j];
                ss << (isprint(c) ? c : '.');
            }

            if (i + 16 < size) ss << "\n";
        }

        Log(level, ss.str(), function, line);
    }
};

//// 静态成员初始化
//DebugLevel DebugHelper::s_level = DebugLevel::Info;
//bool DebugHelper::s_consoleOutput = true;
//bool DebugHelper::s_fileOutput = false;
//std::ofstream DebugHelper::s_logFile;

// 便捷宏定义
#define DEBUG_INIT(level) DebugHelper::Initialize(level)
#define DEBUG_SHUTDOWN() DebugHelper::Shutdown()

#define LOG_ERROR(msg) DebugHelper::Log(DebugLevel::Error, msg, __FUNCTION__, __LINE__)
#define LOG_WARN(msg) DebugHelper::Log(DebugLevel::Warning, msg, __FUNCTION__, __LINE__)
#define LOG_INFO(msg) DebugHelper::Log(DebugLevel::Info, msg, __FUNCTION__, __LINE__)
#define LOG_DEBUG(msg) DebugHelper::Log(DebugLevel::Debug, msg, __FUNCTION__, __LINE__)
#define LOG_TRACE(msg) DebugHelper::Log(DebugLevel::Trace, msg, __FUNCTION__, __LINE__)

#define LOG_HEX(level, prefix, data, size) DebugHelper::LogHex(level, prefix, data, size, __FUNCTION__, __LINE__)

// 格式化输出宏
#define LOG_ERROR_F(...) do { char buf[1024]; sprintf_s(buf, __VA_ARGS__); LOG_ERROR(buf); } while(0)
#define LOG_WARN_F(...) do { char buf[1024]; sprintf_s(buf, __VA_ARGS__); LOG_WARN(buf); } while(0)
#define LOG_INFO_F(...) do { char buf[1024]; sprintf_s(buf, __VA_ARGS__); LOG_INFO(buf); } while(0)
#define LOG_DEBUG_F(...) do { char buf[1024]; sprintf_s(buf, __VA_ARGS__); LOG_DEBUG(buf); } while(0)
#define LOG_TRACE_F(...) do { char buf[1024]; sprintf_s(buf, __VA_ARGS__); LOG_TRACE(buf); } while(0)