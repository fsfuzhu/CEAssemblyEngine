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
aobscanmodule(aobplayer,GTA5_Enhanced.exe,48 8B * 08 48 85 C0 0F 84 * * 00 00 F3 0F 10 80 ?? ?? 00 00 0F 2E 80 ?? ?? 00 00 0F 87 * * 00 00)
alloc(newmem,$1000,aobplayer)
label(code)
label(return)
label(health armor player location)
registersymbol(health armor player location)

newmem:
  push rdx
  mov [player],rax
  mov rdx,[rax+30]
  test rdx,rdx
  je @f
  lea rdx,[rdx+50]
  mov [location],rdx
@@:
  lea rdx,[rax+1815]
  cmp [health],1
  jne @f
  mov [rax+280],(float)500
@@:
  cmp [armor],1
  jne @f
  mov [rdx-0C],(float)100
code:
  movss xmm0,[rdx]
  pop rdx
  jmp return

newmem+200:
health:
dd 0
armor:
dd 0

newmem+400:
player:
dq 0
location:
dq 0

aobplayer+D:
  jmp newmem
  nop 3
return:
registersymbol(aobplayer)

[DISABLE]
aobplayer+D:
  db F3 0F 10 80 18 15 00 00
dealloc(newmem)
)";

    // 创建引擎
    CEAssemblyEngine engine;

    // 连接到进程
    if (engine.AttachToProcess("GTA5_Enhanced.exe")) {
        std::cout << "成功连接到 GTA5_Enhanced.exe (PID: " << engine.GetTargetPID() << ")" << std::endl;
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

                    // 验证代码是否恢复
                    uint8_t buffer[8];
                    uintptr_t aobPlayerAddr = 0;
                    if (engine.GetSymbolManager()->GetSymbolAddress("aobplayer", aobPlayerAddr)) {
                        aobPlayerAddr += 0xD; // aobplayer+D

                        if (engine.GetMemoryManager()->ReadMemory(aobPlayerAddr, buffer, 8)) {
                            std::cout << "恢复后的代码: ";
                            for (int i = 0; i < 8; i++) {
                                std::cout << std::hex << std::setw(2) << std::setfill('0')
                                    << (int)buffer[i] << " ";
                            }
                            std::cout << std::endl;

                            // 检查是否是原始代码
                            uint8_t expected[] = { 0xF3, 0x0F, 0x10, 0x80, 0x18, 0x15, 0x00, 0x00 };
                            bool restored = true;
                            for (int i = 0; i < 8; i++) {
                                if (buffer[i] != expected[i]) {
                                    restored = false;
                                    break;
                                }
                            }
                            std::cout << "代码恢复: " << (restored ? "成功" : "失败") << std::endl;
                        }
                    }

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
        std::cout << "✗ 无法连接到 GTA5_Enhanced.exe: " << engine.GetLastError() << std::endl;
        std::cout << "\n解决方案：" << std::endl;
        std::cout << "1. 启动游戏 (GTA5_Enhanced.exe)" << std::endl;
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