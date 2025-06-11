#include <iostream>
#include <fstream>
#include <sstream>
#include "CEAssembly/CEAssembly.h"
#include "CEAssembly/Utils/DebugHelper.h"

int main() {
    DEBUG_INIT(DebugLevel::Trace);

    // Original CE script - @f jumps to next label (not necessarily @@)
    std::string scriptContent = R"(
[ENABLE]

aobscanmodule(INJECT,Notepad.exe,41 81 F2 69 6E 65 49) // should be unique
alloc(newmem,$1000,INJECT)

label(code)
label(return)

newmem:
mov rax,#123
code:
  xor r10d,49656E69
  jmp return

INJECT:
  jmp newmem
  nop 2
return:
registersymbol(INJECT)

[DISABLE]

INJECT:
  db 41 81 F2 69 6E 65 49

unregistersymbol(INJECT)
dealloc(newmem)
)";

    // 创建引擎
    CEAssemblyEngine engine;

    // 连接到进程
    if (engine.AttachToProcess("Notepad.exe")) {
        std::cout << "成功连接到 Notepad.exe (PID: " << engine.GetTargetPID() << ")" << std::endl;
        // 创建脚本
        auto script = engine.CreateScript("RemoteHack");

        // 加载脚本
        if (script->Load(scriptContent)) {
            std::cout << "✓ 脚本加载成功" << std::endl;

            // 显示符号表信息
            auto symbolMgr = engine.GetSymbolManager();
            std::cout << "\n准备启用脚本..." << std::endl;

            // 启用脚本
            if (script->Enable()) {
                std::cout << "✓ 脚本启用成功！" << std::endl;
                std::cout << "\n脚本执行流程：" << std::endl;
                std::cout << "\n按任意键禁用脚本..." << std::endl;
                std::cin.get();

                std::cout << "正在禁用脚本..." << std::endl;
                if (script->Disable()) {
                    std::cout << "✓ 脚本已成功禁用!" << std::endl;
                }
                else {
                    std::cout << "✗ 禁用失败: " << script->GetLastError() << std::endl;
                }
            }
            else {
                std::cout << "✗ 脚本启用失败: " << script->GetLastError() << std::endl;
                std::cout << "\n常见问题检查：" << std::endl;
                std::cout << "1. 确保游戏在运行" << std::endl;
                std::cout << "2. 确保模式匹配正确" << std::endl;
                std::cout << "3. 检查权限设置" << std::endl;
            }
        }
        else {
            std::cout << "✗ 脚本加载失败: " << script->GetLastError() << std::endl;
        }

        // 断开连接
        engine.DetachFromProcess();
        std::cout << "已断开与进程的连接" << std::endl;
    }
    else {
        std::cout << "✗ 无法连接到 Notepad.exe: " << engine.GetLastError() << std::endl;
        std::cout << "\n解决方案：" << std::endl;
        std::cout << "1. 启动游戏 (Notepad.exe)" << std::endl;
        std::cout << "2. 以管理员身份运行此程序" << std::endl;
        std::cout << "3. 检查防病毒软件是否阻止" << std::endl;

        // 显示当前运行的进程列表
        std::cout << "\n当前运行的进程：" << std::endl;
        ListProcesses();
    }

    DEBUG_SHUTDOWN();

    std::cout << "\n程序结束，按任意键退出..." << std::endl;
    std::cin.get();

    return 0;
}