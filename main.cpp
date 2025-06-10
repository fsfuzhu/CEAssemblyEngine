#include <iostream>
#include <fstream>
#include <sstream>
#include "CEAssembly/CEAssembly.h"
#include "CEAssembly/Utils/DebugHelper.h"

int main() {
    DEBUG_INIT(DebugLevel::Trace);

    // 按照用户详细说明的脚本示例
    std::string scriptContent = R"(
[ENABLE]

aobscanmodule(INJECT,Notepad.exe,4A 8B 14 10 48 8B 43 10) // should be unique
alloc(newmem,$1000,INJECT)

label(code)
label(return)

newmem:
  mov rax,10          // 应该变成 mov rax,0x10
  mov rbx,#10         // 应该变成 mov rbx,10 (十进制)
  mov rcx,$10         // 应该变成 mov rcx,0x10
  mov rdx,0x10        // 应该保持 mov rdx,0x10
  
  // 测试包含A-F的十六进制
  xor r10d,49656E69   // 应该变成 xor r10d,0x49656E69
  mov eax,DEADBEEF    // 应该变成 mov eax,0xDEADBEEF
  
  // 测试运算符中的数字
  mov rax,[rbx+10]    // 应该变成 mov rax,[rbx+0x10]
  lea rdx,[rcx-20]    // 应该变成 lea rdx,[rcx-0x20]
  add rax,30          // 应该变成 add rax,0x30
  
  // 测试其他指令
  push 40             // 应该变成 push 0x40
  sub rsp,50          // 应该变成 sub rsp,0x50
  
  mov r8,r9           // 寄存器不应该被改变
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

    // 创建引擎
    CEAssemblyEngine engine;

    // 连接到进程
    if (engine.AttachToProcess("notepad.exe")) {
        std::cout << "成功连接到 notepad.exe (PID: " << engine.GetTargetPID() << ")" << std::endl;

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
                std::cout << "1. 确保记事本在运行" << std::endl;
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
        std::cout << "✗ 无法连接到 notepad.exe: " << engine.GetLastError() << std::endl;
        std::cout << "\n解决方案：" << std::endl;
        std::cout << "1. 启动记事本 (notepad.exe)" << std::endl;
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