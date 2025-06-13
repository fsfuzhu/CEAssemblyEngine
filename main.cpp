#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include "CEAssembly/CEAssembly.h"
#include "CEAssembly/Utils/DebugHelper.h"

// Test result structure
struct TestResult {
    std::string name;
    bool passed;
    std::string error;
};

// Test suite class
class CEAssemblyTestSuite {
private:
    CEAssemblyEngine engine;
    std::vector<TestResult> results;
    std::string targetProcess;

public:
    CEAssemblyTestSuite(const std::string& processName) : targetProcess(processName) {}

    bool Initialize() {
        std::cout << "Initializing test suite for process: " << targetProcess << std::endl;
        if (!engine.AttachToProcess(targetProcess)) {
            std::cout << "Failed to attach to " << targetProcess << std::endl;
            std::cout << "Make sure the target process is running!" << std::endl;
            return false;
        }
        std::cout << "✓ Successfully attached to process (PID: " << engine.GetTargetPID() << ")" << std::endl;
        return true;
    }

    void RunAllTests() {
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "Running CE Assembly Engine Test Suite" << std::endl;
        std::cout << std::string(80, '=') << std::endl;

        // Basic syntax tests
        TestBasicInstructions();
        TestCENumberFormats();
        TestFloatConversion();
        TestAnonymousLabels();
        TestNegativeOffsets();
        TestDataDirectives();
        TestMemoryOperands();
        TestJumpInstructions();
        TestSSEInstructions();
        TestComplexScript();
        TestCapturedVariables();
        TestRIPRelativeAddressing();

        // Print summary
        PrintSummary();
    }

private:
    void TestBasicInstructions() {
        RunTest("Basic Instructions", R"(
[ENABLE]
alloc(test,$100)
label(data)

test:
  push rax
  push rbx
  mov rax,123
  mov rbx,rax
  add rax,rbx
  sub rax,10
  xor rbx,rbx
  inc rax
  dec rbx
  pop rbx
  pop rax
  ret

data:
  dq 0

[DISABLE]
dealloc(test)
)");
    }

    void TestCENumberFormats() {
        RunTest("CE Number Formats", R"(
[ENABLE]
alloc(numbertest,$100)

numbertest:
  // Decimal with # prefix
  mov rax,#100
  mov rbx,#255
  
  // Hex with $ prefix
  mov rcx,$FF
  mov rdx,$1234
  
  // Pure hex (CE style)
  mov rsi,DEADBEEF
  mov rdi,1234ABCD
  
  // Mixed in memory operands
  mov [rax+#16],rbx
  mov [rcx+$20],rdx
  mov [rsi+30],rdi
  ret

[DISABLE]
dealloc(numbertest)
)");
    }

    void TestFloatConversion() {
        RunTest("Float Conversion", R"(
[ENABLE]
alloc(floattest,$100)

floattest:
  // Float immediate values
  mov [rax],(float)100.0
  mov [rbx+8],(float)3.14159
  mov [rcx+10],(float)-273.15
  
  // SSE with floats
  movss xmm0,[rax]
  movss xmm1,[rbx+8]
  addss xmm0,xmm1
  movss [rdx],(float)42.0
  ret

[DISABLE]
dealloc(floattest)
)");
    }

    void TestAnonymousLabels() {
        RunTest("Anonymous Labels", R"(
[ENABLE]
alloc(anontest,$200)

anontest:
  xor rax,rax
  test rax,rax
  jnz @f
  
  // This executes when rax is 0
  mov rax,1
  jmp @f
  
@@:
  mov rbx,rax
  inc rbx
  cmp rbx,10
  jl @b      // Jump back to previous @@
  
@@:
  // Final section
  mov rcx,rbx
  ret

[DISABLE]
dealloc(anontest)
)");
    }

    void TestNegativeOffsets() {
        RunTest("Negative Offsets", R"(
[ENABLE]
alloc(negoffset,$100)

negoffset:
  lea rdx,[rax+1000]
  
  // Negative offsets
  mov [rdx-4],ebx
  mov [rdx-8],ecx
  mov [rdx-C],esi
  mov [rdx-10],edi
  
  // Mixed positive/negative
  mov rax,[rdx+10]
  mov rbx,[rdx-20]
  
  // Large negative offset
  mov [rdx-100],rax
  ret

[DISABLE]
dealloc(negoffset)
)");
    }

    void TestDataDirectives() {
        RunTest("Data Directives", R"(
[ENABLE]
alloc(datatest,$200)
label(bytes)
label(words)
label(dwords)
label(qwords)

datatest:
  lea rax,[bytes]
  lea rbx,[words]
  lea rcx,[dwords]
  lea rdx,[qwords]
  ret

bytes:
  db 01 02 03 04 05 06 07 08
  db FF FE FD FC FB FA F9 F8

words:
  dw 1234 5678 ABCD EF01

dwords:
  dd 12345678 DEADBEEF CAFEBABE

qwords:
  dq 123456789ABCDEF0
  dq FEDCBA9876543210

[DISABLE]
dealloc(datatest)
)");
    }

    void TestMemoryOperands() {
        RunTest("Memory Operands", R"(
[ENABLE]
alloc(memtest,$200)

memtest:
  // Various addressing modes
  mov rax,[rbx]
  mov [rcx],rdx
  mov rax,[rbx+8]
  mov [rcx+rsi],rdx
  mov rax,[rbx+rsi*2]
  mov [rcx+rdx*4+10],rax
  mov eax,[rbx+rcx*8+100]
  
  // Different sizes
  mov al,[rbx]
  mov ax,[rcx+2]
  mov eax,[rdx+4]
  mov rax,[rsi+8]
  
  // With size specifiers
  mov byte ptr [rdi],10
  mov word ptr [rdi+2],1234
  mov dword ptr [rdi+4],12345678
  mov qword ptr [rdi+8],123456789ABCDEF0
  ret

[DISABLE]
dealloc(memtest)
)");
    }

    void TestJumpInstructions() {
        RunTest("Jump Instructions", R"(
[ENABLE]
alloc(jumptest,$300)
label(near_target)
label(loop_start)
label(loop_end)

jumptest:
  xor rcx,rcx
  
loop_start:
  inc rcx
  cmp rcx,5
  je near_target
  jl loop_start
  jg loop_end
  
near_target:
  mov rax,rcx
  test rax,rax
  jz loop_end
  jnz loop_end
  
  // Conditional jumps
  cmp rax,10
  ja loop_end
  jae loop_end
  jb loop_end
  jbe loop_end
  
loop_end:
  mov rbx,rcx
  ret

[DISABLE]
dealloc(jumptest)
)");
    }

    void TestSSEInstructions() {
        RunTest("SSE Instructions", R"(
[ENABLE]
alloc(ssetest,$200)
label(floatdata)

ssetest:
  // Load data
  movaps xmm0,[floatdata]
  movups xmm1,[floatdata+10]
  
  // Arithmetic
  addps xmm0,xmm1
  subps xmm0,xmm1
  mulps xmm0,xmm1
  divps xmm0,xmm1
  
  // Scalar operations
  movss xmm2,[rax]
  addss xmm2,xmm3
  sqrtss xmm4,xmm2
  
  // Comparisons
  comiss xmm0,xmm1
  ucomiss xmm2,xmm3
  
  // Shuffles
  shufps xmm0,xmm1,0
  ret

floatdata:
  dd (float)1.0 (float)2.0 (float)3.0 (float)4.0

[DISABLE]
dealloc(ssetest)
)");
    }

    void TestComplexScript() {
        RunTest("Complex Multi-Section Script", R"(
[ENABLE]
aobscanmodule(INJECT,notepad.exe,48 8B 05 * * * * 48 85 C0)
alloc(newmem,$1000,INJECT)
alloc(data,$100)
label(code)
label(return)
label(exit)
registersymbol(data)

newmem:
  push rax
  push rbx
  call code
  test rax,rax
  jz exit
  mov [data],rax
  jmp exit

code:
  mov rax,[data]
  test rax,rax
  jz @f
  inc rax
  ret
@@:
  mov rax,#100
  ret

exit:
  pop rbx
  pop rax
  jmp return

data:
  dq 0

INJECT:
  jmp newmem
  nop 2
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  db 48 8B 05

unregistersymbol(INJECT)
unregistersymbol(data)
dealloc(newmem)
dealloc(data)
)");
    }

    void TestCapturedVariables() {
        RunTest("Captured Variables (Pattern Scanning)", R"(
[ENABLE]
// Pattern with captured variables
aobscanmodule(pattern,notepad.exe,48 8B s1.2 48 8B s2.2)
alloc(captured,$100)

captured:
  // Use captured offsets
  mov rax,[rbx+s1]
  mov rdx,[rcx+s2]
  ret

[DISABLE]
dealloc(captured)
)");
    }

    void TestRIPRelativeAddressing() {
        RunTest("RIP-Relative Addressing", R"(
[ENABLE]
alloc(riptest,$200)
label(mydata)
label(target)
registersymbol(mydata)

riptest:
  // RIP-relative access
  mov rax,[mydata]
  mov [mydata],rbx
  lea rcx,[mydata]
  
  // Conditional RIP-relative jump
  test rax,rax
  jz target
  
  mov rdx,[mydata]
  ret

target:
  xor rdx,rdx
  ret

mydata:
  dq 123456789ABCDEF0

[DISABLE]
unregistersymbol(mydata)
dealloc(riptest)
)");
    }

    void RunTest(const std::string& testName, const std::string& scriptContent) {
        TestResult result;
        result.name = testName;
        result.passed = false;

        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "Test: " << testName << std::endl;
        std::cout << std::string(60, '-') << std::endl;

        auto script = engine.CreateScript(testName);

        if (!script->Load(scriptContent)) {
            result.error = "Failed to load script: " + script->GetLastError();
            std::cout << "✗ " << result.error << std::endl;
            results.push_back(result);
            return;
        }

        std::cout << "✓ Script loaded successfully" << std::endl;

        if (!script->Enable()) {
            result.error = "Failed to enable script: " + script->GetLastError();
            std::cout << "✗ " << result.error << std::endl;

            // Try to provide more specific error info
            std::string lastEngineError = engine.GetLastError();
            if (!lastEngineError.empty()) {
                std::cout << "  Engine error: " << lastEngineError << std::endl;
            }

            results.push_back(result);
            return;
        }

        std::cout << "✓ Script enabled successfully" << std::endl;

        // Test disable
        if (!script->Disable()) {
            result.error = "Failed to disable script: " + script->GetLastError();
            std::cout << "✗ " << result.error << std::endl;
            results.push_back(result);
            return;
        }

        std::cout << "✓ Script disabled successfully" << std::endl;

        result.passed = true;
        results.push_back(result);
    }

    void PrintSummary() {
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "Test Summary" << std::endl;
        std::cout << std::string(80, '=') << std::endl;

        int passed = 0;
        int failed = 0;

        for (const auto& result : results) {
            if (result.passed) {
                std::cout << "✓ ";
                passed++;
            }
            else {
                std::cout << "✗ ";
                failed++;
            }

            std::cout << std::setw(40) << std::left << result.name;

            if (!result.passed) {
                std::cout << " - " << result.error;
            }

            std::cout << std::endl;
        }

        std::cout << std::string(80, '-') << std::endl;
        std::cout << "Total Tests: " << results.size() << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;

        double successRate = (results.size() > 0) ?
            (static_cast<double>(passed) / results.size() * 100.0) : 0.0;

        std::cout << "Success Rate: " << std::fixed << std::setprecision(1)
            << successRate << "%" << std::endl;
        std::cout << std::string(80, '=') << std::endl;
    }
};

// Interactive test menu
void ShowInteractiveMenu() {
    std::cout << "\nCE Assembly Engine - Interactive Test Menu" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "1. Run all tests" << std::endl;
    std::cout << "2. Test custom script from file" << std::endl;
    std::cout << "3. Test custom script (inline)" << std::endl;
    std::cout << "4. List running processes" << std::endl;
    std::cout << "5. Exit" << std::endl;
    std::cout << "\nChoice: ";
}

int main() {
    // Initialize debug system
    DEBUG_INIT(DebugLevel::Info);  // Change to Debug or Trace for more details

    std::cout << "CE Assembly Engine - Comprehensive Test Suite" << std::endl;
    std::cout << "=============================================" << std::endl;

    // Default target process
    std::string targetProcess = "notepad.exe";

    // Check command line arguments
    if (GetCommandLineA() && strstr(GetCommandLineA(), "--process=")) {
        char* processStart = strstr(GetCommandLineA(), "--process=") + 10;
        char processName[256] = { 0 };
        sscanf_s(processStart, "%255s", processName, 256);
        targetProcess = processName;
    }

    // Interactive menu loop
    bool running = true;
    while (running) {
        ShowInteractiveMenu();

        int choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear newline

        switch (choice) {
        case 1: {
            // Run all tests
            std::cout << "\nTarget process (default: " << targetProcess << "): ";
            std::string input;
            std::getline(std::cin, input);
            if (!input.empty()) {
                targetProcess = input;
            }

            CEAssemblyTestSuite suite(targetProcess);
            if (suite.Initialize()) {
                suite.RunAllTests();
            }
            break;
        }

        case 2: {
            // Test custom script from file
            std::cout << "Enter script file path: ";
            std::string filePath;
            std::getline(std::cin, filePath);

            std::ifstream file(filePath);
            if (!file.is_open()) {
                std::cout << "Failed to open file: " << filePath << std::endl;
                break;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();

            CEAssemblyEngine engine;
            if (engine.AttachToProcess(targetProcess)) {
                auto script = engine.CreateScript("CustomScript");
                if (script->Load(buffer.str())) {
                    std::cout << "Script loaded successfully" << std::endl;

                    if (script->Enable()) {
                        std::cout << "Script enabled! Press Enter to disable..." << std::endl;
                        std::cin.get();
                        script->Disable();
                    }
                    else {
                        std::cout << "Failed to enable script: " << script->GetLastError() << std::endl;
                    }
                }
                else {
                    std::cout << "Failed to load script: " << script->GetLastError() << std::endl;
                }
            }
            break;
        }

        case 3: {
            // Test custom script inline
            std::cout << "Enter script (type 'END' on a new line to finish):" << std::endl;
            std::string scriptContent;
            std::string line;

            while (std::getline(std::cin, line)) {
                if (line == "END") break;
                scriptContent += line + "\n";
            }

            CEAssemblyEngine engine;
            if (engine.AttachToProcess(targetProcess)) {
                auto script = engine.CreateScript("InlineScript");
                if (script->Load(scriptContent)) {
                    std::cout << "Script loaded successfully" << std::endl;

                    if (script->Enable()) {
                        std::cout << "Script enabled! Press Enter to disable..." << std::endl;
                        std::cin.get();
                        script->Disable();
                    }
                    else {
                        std::cout << "Failed to enable script: " << script->GetLastError() << std::endl;
                    }
                }
                else {
                    std::cout << "Failed to load script: " << script->GetLastError() << std::endl;
                }
            }
            break;
        }

        case 4: {
            // List processes
            CEAssembly::ListProcesses();
            break;
        }

        case 5: {
            running = false;
            break;
        }

        default:
            std::cout << "Invalid choice!" << std::endl;
        }
    }

    // Cleanup
    DEBUG_SHUTDOWN();

    std::cout << "\nTest suite completed. Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}