#include <iostream>
#include <fstream>
#include <sstream>
#include "CEAssembly.h"  // 使用统一包含文件
#include "DebugHelper.h"   

int main() {
    DEBUG_INIT(DebugLevel::Trace);
    // 示例脚本
    std::string scriptContent = R"(
[ENABLE]
aobscanmodule(INJECT,Notepad.exe,4A 8B 14 10 48 8B 43 10)
alloc(newmem,$1000,INJECT)
label(code)
label(return)

newmem:

code:
  mov rdx,[rax+r10]
  mov rax,[rbx+10]
  jmp return

INJECT:
  jmp newmem
  nop 3
return:

registersymbol(INJECT)

[DISABLE]
INJECT:
  db 4A 8B 14 10 48 8B 43 10

unregistersymbol(INJECT)
dealloc(newmem)
)";

    // 新的使用方式
    std::cout << "=== 新的API使用示例 ===" << std::endl;

    // 简单示例
    CEAssemblyEngine engine;
    if (engine.AttachToProcess("notepad.exe")) {
        auto script = engine.CreateScript("RemoteHack");
        script->Load(scriptContent);
        script->Enable();
        std::cout << "\n按任意键禁用脚本..." << std::endl;
        std::cin.get();
        std::cout << "禁用脚本..." << std::endl;
        if (script->Disable()) {
            std::cout << "脚本已禁用!" << std::endl;
        }
        else {
            std::cout << "禁用失败: " << script->GetLastError() << std::endl;
        }

    }
    DEBUG_SHUTDOWN();
}