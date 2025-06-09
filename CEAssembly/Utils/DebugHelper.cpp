#include "DebugHelper.h"
DebugLevel DebugHelper::s_level = DebugLevel::Info;
bool DebugHelper::s_consoleOutput = true;
bool DebugHelper::s_fileOutput = false;
std::ofstream DebugHelper::s_logFile;