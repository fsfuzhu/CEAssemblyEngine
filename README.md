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
    │   └── MemoryManager.cpp
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

### `[ENABLE]` 阶段

1. **aobscanmodule**

   * 在模块 `Notepad.exe` 内搜索特征码 `4A 8B 14 10 48 8B 43 10`。
   * 找到唯一匹配地址 `0x7FF7 7569 2E0A`。
   * 将该地址注册为**局部符号** `INJECT`（仅当前脚本可见）。

2. **alloc**

   * 在 `INJECT` 附近申请 `0x1000` 字节可执行内存，得到地址 `0x7FF7 7558 0000`。
   * 注册**局部符号** `newmem` 指向该地址。

3. **label(code) / label(return)**

   * 在局部符号表中新建 `code` 和 `return`，初始地址为 `0`，稍后填充。

4. **newmem:**

   * 指明接下来汇编将写入 `newmem`（`0x7FF7 7558 0000`）。

5. **mov rax,#123**

   * 交给 Keystone 汇编，生成机器码 `48 B8 7B 00 00 00 00 00 00 00`（10 字节）。
   * 写入 `newmem`，当前写指针移至 `0x7FF7 7558 000A`。

6. **code:**

   * 把当前地址 `0x7FF7 7558 000A` 填入局部符号 `code`。

7. **mov rdx,\[rax+r10]** → `4A 8B 14 10`

   * 写入并将指针移至 `0x7FF7 7558 000E`。

8. **mov rax,\[rbx+10]** → `48 8B 43 10`

   * 写入并将指针移至 `0x7FF7 7558 0012`。

9. **jmp return**

   * 由于 `return` 位置尚未确定，先留下占位（稍后回填）。

10. **INJECT:**

    * 切换写指针到 `INJECT` (`0x7FF7 7569 2E0A`)。

11. **jmp newmem**

    * 生成近跳转 `E9 F1 D1 EE FF` 并写入。
    * 指针移至 `0x7FF7 7569 2E0F`。

12. **nop 3**

    * 写入 `90 90 90`（或 `0F 1F 00`）。
    * 指针移至 `0x7FF7 7569 2E12`。

13. **return:**

    * 将当前地址 `0x7FF7 7569 2E12` 记录为 `return`。
    * 回到 `jmp return` 的占位，计算位移并回填机器码。

14. **registersymbol(INJECT)**

    * 把 `INJECT` 从局部提升为**全局符号**，供其他脚本访问。

### `[DISABLE]` 阶段

1. **INJECT:**

   * 写指针定位到 `0x7FF7 7569 2E0A`。

2. **db 4A 8B 14 10 48 8B 43 10**

   * 恢复原始字节，移除跳转与 NOP。

3. **unregistersymbol(INJECT)**

   * 将 `INJECT` 从全局符号表移除。

4. **dealloc(newmem)**

   * 释放 `0x7FF7 7558 0000` 处的动态内存。

---

> 该示例展示了 **CEAssemblyEngine** 在脚本各阶段的核心工作流程，包括：
>
> * 特征码扫描 → 符号绑定
> * 动态内存申请 → 汇编写入
> * 跳转构建 → 回填占位
> * 符号注册 / 反注册
> * 资源回收

---

### TODO

* 自动处理 `s1.2`, `*` 与 `?` 通配符的捕获与替换
* 支持浮点立即数写入（如 `mov [rax+s2],(float)500`）
* 支持多脚本并发启停的依赖检测
