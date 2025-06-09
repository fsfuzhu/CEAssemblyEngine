# CE Assembly Engine - Cheat Engine 自动汇编引擎

一个完全兼容 Cheat Engine 自动汇编语法的 C++ 引擎，支持高级通配符和动态符号管理。

## 特性

- ✅ 完整支持 CE 自动汇编语法
- ✅ 支持 `aobscanmodule`、`alloc`、`label`、`registersymbol` 等所有 CE 命令
- ✅ 高级通配符支持：`*`（两字节）、`?`（单字节）、`s1.2`（变量捕获）
- ✅ 动态符号注册和解析
- ✅ 智能内存分配（在目标地址附近分配以支持短跳转）
- ✅ **跨进程修改支持**（可以修改其他进程）
- ✅ 进程枚举和自动附加
- ✅ 集成 Keystone 汇编引擎
- ✅ 可选集成 AsmJit 进行高级代码生成

## 编译要求

- Visual Studio 2019 或更高版本
- CMake 3.16 或更高版本
- Windows SDK
- Keystone Engine（已包含在项目中）
- AsmJit（可选）

## 构建步骤

```bash
# 创建构建目录
mkdir build
cd build

# 生成项目文件
cmake ..

# 编译
cmake --build . --config Release
```

## 使用示例

### 基本使用 - 本进程

```cpp
// 使用统一包含文件，避免包含顺序问题
#include "CEAssembly.h"

// 创建引擎实例
CEAssemblyEngine engine;

// CE 脚本内容
std::string scriptContent = R"(
[ENABLE]
aobscanmodule(INJECT,Game.exe,48 8B 05 ?? ?? ?? ?? 48 83 C0 08)
alloc(newmem,$1000,INJECT)

newmem:
  mov rax, [rax+10]
  ret

INJECT:
  call newmem
  nop 3

[DISABLE]
INJECT:
  db 48 8B 05 ?? ?? ?? ?? 48 83 C0 08
dealloc(newmem)
)";

// 1. 创建脚本对象
auto script = engine.CreateScript("MyCheat");

// 2. 加载脚本内容
if (!script->Load(scriptContent)) {
    std::cout << "加载失败: " << script->GetLastError() << std::endl;
    return;
}

// 3. 启用脚本（执行[ENABLE]部分）
if (script->Enable()) {
    std::cout << "脚本已启用!" << std::endl;
}

// 4. 禁用脚本（执行[DISABLE]部分）
if (script->Disable()) {
    std::cout << "脚本已禁用!" << std::endl;
}
```

### 跨进程修改

```cpp
#include "CEAssembly.h"

CEAssemblyEngine engine;

// 方法1：通过进程名附加
if (engine.AttachToProcess("Game.exe")) {
    std::cout << "成功附加到 Game.exe" << std::endl;
    
    // 创建并执行脚本
    auto script = engine.CreateScript("RemoteCheat");
    script->Load(scriptContent);
    script->Enable();
    
    // 完成后分离
    engine.DetachFromProcess();
}

// 方法2：通过PID附加
DWORD pid = ProcessManager::FindProcessByName("Game.exe");
if (engine.AttachToProcess(pid)) {
    // ... 执行脚本 ...
}

// 方法3：枚举所有进程
auto processes = ProcessManager::EnumerateProcesses();
for (const auto& proc : processes) {
    std::cout << proc.name << " (PID: " << proc.pid << ")" << std::endl;
}
```

### 从文件加载脚本

```cpp
// 创建脚本并从文件加载
auto script = engine.CreateScript();
if (script->LoadFromFile("cheats/godmode.cea")) {
    script->Enable();  // 启用
    // ...
    script->Disable(); // 禁用
}
```

### 管理多个脚本

```cpp
CEAssemblyEngine engine;

// 创建多个脚本
auto godMode = engine.CreateScript("GodMode");
auto infiniteAmmo = engine.CreateScript("InfiniteAmmo");
auto speedHack = engine.CreateScript("SpeedHack");

// 加载脚本内容
godMode->Load(godModeScript);
infiniteAmmo->Load(infiniteAmmoScript);
speedHack->Load(speedHackScript);

// 独立控制每个脚本
godMode->Enable();      // 只启用无敌模式
infiniteAmmo->Enable(); // 启用无限弹药

// 检查状态
if (godMode->IsEnabled()) {
    std::cout << "无敌模式已激活" << std::endl;
}

// 禁用特定脚本
godMode->Disable();
```

### 使用变量捕获

```cpp
std::string script = R"(
[ENABLE]
// s1.4 将捕获4个字节并赋值给变量 s1
aobscanmodule(playerBase,Game.exe,48 8B 05 s1.4 48 83 C0 08)
alloc(godMode,$100,playerBase)

godMode:
  mov rax, s1      // 使用捕获的地址
  mov dword [rax], #9999  // 设置生命值
  ret

playerBase:
  call godMode
)";
```

## 集成 AsmJit（可选）

如果需要更高级的动态代码生成功能，可以集成 AsmJit：

### 1. 安装 AsmJit

```bash
git clone https://github.com/asmjit/asmjit.git
cd asmjit
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### 2. 修改 CMakeLists.txt

```cmake
# 添加 AsmJit
find_package(asmjit REQUIRED)
target_link_libraries(${PROJECT_NAME} asmjit::asmjit)
```

### 3. 使用 AsmJit 生成复杂代码

```cpp
#include <asmjit/asmjit.h>

bool CEAssemblyEngine::GenerateComplexCode(uintptr_t address) {
    using namespace asmjit;
    
    JitRuntime rt;
    CodeHolder code;
    code.init(rt.environment());
    
    x86::Assembler a(&code);
    
    // 生成动态跳转表
    Label jumpTable = a.newLabel();
    Label case1 = a.newLabel();
    Label case2 = a.newLabel();
    
    // 主代码
    a.mov(x86::rax, x86::qword_ptr(x86::rcx));
    a.cmp(x86::rax, 1);
    a.je(case1);
    a.cmp(x86::rax, 2);
    a.je(case2);
    
    // 处理情况
    a.bind(case1);
    a.mov(x86::rax, 100);
    a.ret();
    
    a.bind(case2);
    a.mov(x86::rax, 200);
    a.ret();
    
    // 获取生成的代码
    CodeBuffer& buffer = code.sectionById(0)->buffer();
    WriteProcessMemory(GetCurrentProcess(), 
                      reinterpret_cast<LPVOID>(address),
                      buffer.data(), 
                      buffer.size(), 
                      nullptr);
    
    return true;
}
```

## 高级功能

### 跨进程修改

引擎完全支持跨进程内存修改，类似于 Cheat Engine：

```cpp
// 附加到目标进程
CEAssemblyEngine engine;

// 方式1：通过进程名
if (engine.AttachToProcess("Game.exe")) {
    // 执行修改...
    engine.DetachFromProcess();
}

// 方式2：通过PID
DWORD pid = 1234;
if (engine.AttachToProcess(pid)) {
    // 执行修改...
}

// 枚举所有进程
auto processes = ProcessManager::EnumerateProcesses();
for (const auto& proc : processes) {
    std::cout << proc.name << " (PID: " << proc.pid << ")" << std::endl;
}
```

**注意事项**：
- 需要管理员权限才能修改其他进程
- 自动处理 32 位和 64 位进程
- 支持远程内存分配和代码注入
- 所有 CE 脚本功能都支持跨进程

### 自定义通配符

引擎支持自定义通配符语法：

- `*` - 匹配任意两个字节（等同于 `??`）
- `?` - 匹配任意一个字节
- `s1.2` - 捕获2个字节到变量 s1
- `s2.4` - 捕获4个字节到变量 s2
- `s3.8` - 捕获8个字节到变量 s3

### 符号管理

```cpp
// 手动注册符号
engine.GetSymbolManager()->RegisterSymbol("mySymbol", 0x12345678);

// 获取符号地址
uintptr_t addr;
if (engine.GetSymbolManager()->GetSymbolAddress("mySymbol", addr)) {
    std::cout << "Symbol address: " << std::hex << addr << std::endl;
}
```

### 错误处理

```cpp
if (!engine.ExecuteScript(script)) {
    std::string error = engine.GetLastError();
    
    // 详细错误信息
    if (error.find("Pattern not found") != std::string::npos) {
        std::cout << "特征码未找到，请检查目标进程" << std::endl;
    } else if (error.find("Failed to allocate") != std::string::npos) {
        std::cout << "内存分配失败" << std::endl;
    }
}
```

## 注意事项

1. **权限要求**：
   - 修改本进程不需要特殊权限
   - 跨进程修改需要管理员权限
   - 建议以管理员身份运行程序

2. **地址空间**：x64 程序的跳转限制为 ±2GB，引擎会自动在目标附近分配内存

3. **符号作用域**：符号在脚本执行期间有效，可以通过 `registersymbol` 持久化

4. **进程架构**：
   - x64 引擎可以修改 x64 和 x86 进程
   - x86 引擎只能修改 x86 进程
   - 引擎会自动检测目标进程架构

## 扩展开发

### 添加新的 CE 命令

```cpp
// 在 CEAssemblyEngine.cpp 中添加
bool CEAssemblyEngine::ProcessCustomCommand(const std::string& line) {
    ParsedCommand cmd = m_parser->ParseLine(line);
    
    if (cmd.type == CommandType::CUSTOM) {
        // 实现自定义命令逻辑
        return true;
    }
    
    return false;
}
```

### 支持新的通配符格式

```cpp
// 在 PatternScanner.cpp 中扩展
if (token.find('~') != std::string::npos) {
    // 处理新的通配符格式，如 ~4 表示跳过4个字节
    size_t skipBytes = std::stoi(token.substr(1));
    for (size_t i = 0; i < skipBytes; ++i) {
        pb.isWildcard = true;
        result.push_back(pb);
    }
}
```

## 性能优化建议

1. **批量扫描**：对多个特征码使用单次扫描
2. **缓存结果**：缓存常用的扫描结果
3. **并行处理**：使用多线程进行特征码扫描

## 常见问题

### 编译错误："no operator matches these operands"

如果遇到 `PatchInfo` 类型不匹配的错误，请确保：

1. 使用统一包含文件 `CEAssembly.h`
2. 或按正确顺序包含：
   ```cpp
   #include "CEAssemblyEngine.h"  // 先包含（定义PatchInfo）
   #include "CEScript.h"           // 后包含（使用PatchInfo）
   ```

### 链接错误

确保已正确链接 Keystone 库：
- 将 `keystone.lib` 放在 `lib/` 目录
- 在项目设置中添加库路径和依赖项

## 许可证

本项目使用 MIT 许可证。Keystone Engine 使用其自己的许可证。