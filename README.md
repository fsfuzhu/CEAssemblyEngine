# CE汇编引擎代码重构说明

### 使用示例简化

```cpp
// 使用统一的命名空间
using namespace CEAssembly;

// 创建简单的游戏修改器
SimpleGameTrainer trainer;
if (trainer.AttachToGame("game.exe")) {
    if (trainer.LoadScriptFromFile("hack.cea")) {
        trainer.EnableHack();
        // ...
        trainer.DisableHack();
    }
    trainer.Detach();
}
```

## 文件结构

```
CEAssemblerEngine/
├── main.cpp
├── README.md
├── include/
│   └── keystone/                # Keystone 头文件
├── lib/                         # Keystone 静态 / 动态库
└── CEAssembly/                  # 代码核心目录
    ├── Core/
    │   ├── CEAssemblyEngine.h
    │   ├── CEAssemblyEngine.cpp
    │   ├── CEScript.h
    │   ├── CEScript.cpp
    │   ├── MemoryManager.h
    │   ├── MemoryManager.cpp
    │   └── PassManager.h/cpp    # 多遍处理管理器
    ├── Parser/
    │   ├── CEScriptParser.h
    │   └── CEScriptParser.cpp
    ├── Scanner/
    │   ├── PatternScanner.h
    │   └── PatternScanner.cpp
    ├── Symbol/
    │   ├── SymbolManager.h
    │   └── SymbolManager.cpp
    ├── Utils/
    │   ├── StringUtils.h
    │   ├── DebugHelper.h
    │   └── DebugHelper.cpp
    └── CEAssembly.h             # 对外统一包含文件
```

## 编译依赖

1. **Keystone Engine** - 汇编引擎
2. **Windows SDK** - Windows API
3. **C++17** - 标准库支持

## 使用建议

1. **使用统一包含文件**

   ```cpp
   #include "CEAssembly.h"
   ```

2. **使用命名空间**

   ```cpp
   using namespace CEAssembly;
   ```

3. **错误处理**

   ```cpp
   if (!engine.AttachToProcess("target.exe")) {
       std::cerr << "Error: " << engine.GetLastError() << std::endl;
   }
   ```

4. **资源管理**

   * 使用RAII原则
   * 析构函数自动清理资源
   * 使用智能指针管理脚本

## 性能优化

1. **内存分配策略**

   * 优先在目标地址附近分配（E9跳转）
   * 失败时尝试低位地址（FF25跳转）

2. **批量操作**

   * 减少跨进程调用次数
   * 缓存模块信息

3. **符号管理**

   * 使用哈希表快速查找
   * 支持前向引用
   * 多遍处理确保正确的地址计算

---

## 自动汇编脚本执行流程示例

下面以一个典型脚本为例，说明 `[ENABLE]` 和 `[DISABLE]` 两个阶段中各指令的执行顺序、符号/内存管理以及汇编代码写入流程。

```assembly
[ENABLE]
aobscanmodule(INJECT,Notepad.exe,4A 8B 14 10 48 8B 43 10) // should be unique
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
```

> 以下流程中的所有地址均为示例值，用于帮助理解。

### `[ENABLE]` 阶段 - 多遍处理流程

引擎使用 **PassManager** 进行多遍处理，确保正确计算地址和解析符号：

#### Pass 1: 预处理 (Preprocessing)
- 识别命令类型
- 处理 `#` 符号（CE十进制立即数）
- 标记需要符号解析的指令

#### Pass 2: 符号收集 (Symbol Collection)

1. **aobscanmodule**
   * 在模块 `Notepad.exe` 内搜索特征码 `4A 8B 14 10 48 8B 43 10`
   * 找到唯一匹配地址 `0x7FF7 7569 2E0A`
   * 注册符号 `INJECT = 0x7FF7 7569 2E0A`

2. **alloc**
   * 在 `INJECT` 附近申请 `0x1000` 字节可执行内存
   * 获得地址 `0x7FF7 7558 0000`
   * 注册符号 `newmem = 0x7FF7 7558 0000`

3. **label**
   * 声明符号 `code` 和 `return`（地址待定）

#### Pass 3: 两遍汇编 (Two-Pass Assembly)

**第一遍：计算大小和分配地址**

1. **newmem:** → 设置当前地址 = `0x7FF7 7558 0000`

2. **mov rax,#123**
   * 转换为 `mov rax,123`
   * Keystone 计算大小：10 字节
   * 地址：`0x7FF7 7558 0000`

3. **code:** → 更新符号 `code = 0x7FF7 7558 000A`

4. **mov rdx,[rax+r10]**
   * 计算大小：4 字节
   * 地址：`0x7FF7 7558 000A`

5. **mov rax,[rbx+10]**
   * 计算大小：4 字节
   * 地址：`0x7FF7 7558 000E`

6. **jmp return**
   * 计算大小：5 字节（预估）
   * 地址：`0x7FF7 7558 0012`

7. **INJECT:** → 设置当前地址 = `0x7FF7 7569 2E0A`

8. **jmp newmem**
   * 计算大小：5 字节
   * 地址：`0x7FF7 7569 2E0A`

9. **nop 3**
   * 计算大小：3 字节
   * 地址：`0x7FF7 7569 2E0F`

10. **return:** → 更新符号 `return = 0x7FF7 7569 2E12`

**第二遍：生成机器码**

所有符号地址已确定，生成最终机器码：
- `mov rax,123` → `48 B8 7B 00 00 00 00 00 00 00`
- `jmp return` → `E9 FB 4D 10 00`（现在可以计算正确偏移）
- 其他指令正常汇编

#### Pass 4: 代码写入 (Code Emission)

批量写入所有生成的机器码到目标进程。

### `[DISABLE]` 阶段

1. **INJECT:** → 定位到 `0x7FF7 7569 2E0A`

2. **db 4A 8B 14 10 48 8B 43 10**
   * 恢复原始字节

3. **unregistersymbol(INJECT)**
   * 移除全局符号

4. **dealloc(newmem)**
   * 释放分配的内存

---

## 关键特性

### CE语法兼容性

- **`#` 前缀**：十进制立即数（如 `#123` = 123）
- **`$` 前缀**：十六进制数（如 `$1000` = 0x1000）
- **`@@` 标签**：匿名标签
- **`@f/@b`**：向前/向后跳转到最近的标签
- **`(float)`**：浮点数转换

### 符号解析

- 支持前向引用（先使用后定义）
- 局部符号（脚本内）vs 全局符号（`registersymbol`）
- 多遍处理确保所有符号正确解析

### 内存管理

- 智能内存分配策略
- 自动选择 E9（近跳转）或 FF25（远跳转）
- 跟踪所有分配以便清理

---

### 已知问题和限制

1. **符号作用域**
   - 标签默认为局部符号
   - 使用 `registersymbol` 提升为全局

2. **性能考虑**
   - 多遍处理可能增加编译时间
   - 对于大型脚本建议分段处理

3. **调试支持**
   - 使用 `DEBUG_INIT(DebugLevel::Trace)` 查看详细日志
   - 日志级别：Error, Warning, Info, Debug, Trace

---

### TODO

* 自动处理 `s1.2`, `*` 与 `?` 通配符的捕获与替换
* 支持浮点立即数写入（如 `mov [rax+s2],(float)500`）
* 支持多脚本并发启停的依赖检测
* 优化多遍处理的迭代次数
* 添加脚本语法验证器