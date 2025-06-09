#include <iostream>
#include <fstream>
#include <sstream>
#include "CEAssembly.h"  // ʹ��ͳһ�����ļ�

// ��ȡ�ļ�����
std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return "";

        return 0;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    // ����CE�������ʵ��
    CEAssemblyEngine engine;

    // ʾ���ű�
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

    // �µ�ʹ�÷�ʽ
    std::cout << "=== �µ�APIʹ��ʾ�� ===" << std::endl;

    // ��ʾ��
    CEAssemblyEngine engine;
    if (engine.AttachToProcess("notepad.exe")) {
        auto script = engine.CreateScript("RemoteHack");
        script->Load(scriptContent);
        script->Enable();
        std::cout << "\n����������ýű�..." << std::endl;
        std::cin.get();
        std::cout << "���ýű�..." << std::endl;
        if (script->Disable()) {
            std::cout << "�ű��ѽ���!" << std::endl;
        }
        else {
            std::cout << "����ʧ��: " << script->GetLastError() << std::endl;
        }

    }

}