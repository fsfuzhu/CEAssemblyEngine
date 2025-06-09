#include <iostream>
#include <fstream>
#include <sstream>
#include "CEAssembly.h"  // 使用统一包含文件
#include "DebugHelper.h"   

int main() {
    DEBUG_INIT(DebugLevel::Trace);

    // 按照用户详细说明的脚本示例
    std::string scriptContent = R"(
[ENABLE]
aobscanmodule(INJECT,Notepad.exe,4A 8B 14 10 48 8B 43 10)
alloc(newmem,$1000,INJECT)
label(code)
label(return)

newmem:
mov rax,#123

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

    std::cout << "=== 简化版API使用示例 ===\n";
    std::cout << "修复内容：\n";
    std::cout << "1. 移除复杂的跳转表逻辑\n";
    std::cout << "2. 按照CE脚本执行流程实现\n";
    std::cout << "3. 修复符号替换，避免送给Keystone\n";
    std::cout << "4. 优化内存分配，尝试低位地址\n";
    std::cout << "5. 实现延迟处理前向引用\n\n";

    std::cout << "预期执行流程：\n";
    std::cout << "1. INJECT = 0x7FF775692E0A (aobscan结果)\n";
    std::cout << "2. alloc(newmem,$1000,INJECT) -> 在INJECT附近申请\n";
    std::cout << "3. 如果距离在E9范围内 -> 使用E9跳转\n";
    std::cout << "4. 如果距离太远 -> 重新申请低位地址 + FF25跳转\n";
    std::cout << "5. newmem: mov rax,#123 -> 48 C7 C0 23 01 00 00 (7字节)\n";
    std::cout << "6. code: = 当前地址\n";
    std::cout << "7. INJECT: jmp newmem -> E9或FF25跳转\n";
    std::cout << "8. return: = INJECT + 跳转指令长度 + nop 3\n";
    std::cout << "9. 延迟处理: jmp return -> E9跳转到正确地址\n\n";

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
                std::cout << "INJECT (高地址) -> 跳转表 -> newmem (低地址) -> return (高地址)" << std::endl;
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