# DLL 注入器使用指南

## 什么是 DLL 注入器

DLL 注入器通过 `CreateRemoteThread` 将我们的 Hook DLL 注入到目标进程（Xsjzb.exe）中，然后在进程内部拦截 HID API 调用。

## 工作原理

```
hid_injector.exe 运行
  ↓
查找 Xsjzb.exe 进程
  ↓
分配远程内存
  ↓
写入 hid_hook.dll 路径
  ↓
创建远程线程调用 LoadLibraryW
  ↓
hid_hook.dll 被加载到 Xsjzb.exe
  ↓
DllMain 执行 → 安装 HID Hook
  ↓
所有 HID API 调用被拦截 ✅
```

## 编译项目

### 方法 1: 使用 CMake（推荐）

```powershell
cd D:\GitHub\hidproxy\injector

# 配置（32位，匹配目标进程）
cmake -B build -A Win32

# 编译
cmake --build build --config Release

# 输出在 build\bin\Release\
# - hid_injector.exe (注入器)
# - hid_hook.dll (Hook DLL)
```

### 方法 2: 不使用 Detours（简化版本）

如果没有 Detours 库，编译时会自动使用基础监控模式（仅记录日志，不完全 Hook）。

要启用完整 Hook，需要下载 Detours：

```powershell
# 克隆 Detours
git clone https://github.com/microsoft/Detours.git D:\GitHub\hidproxy\injector\detours

# 或使用 vcpkg
vcpkg install detours:x86-windows

# 然后将 detours.lib 复制到 injector\detours\ 目录
```

## 使用方法

### 1. 基本使用（目标进程已运行）

```powershell
# 1. 确保 Xsjzb.exe 正在运行
Start-Process "C:\Xsj_Soft\Xsjzb\Xsjzb.exe"

# 2. 以管理员权限运行注入器
cd D:\GitHub\hidproxy\injector\build\bin\Release
.\hid_injector.exe

# 3. 查看日志
notepad C:\Xsj_Soft\Xsjzb\hid_hook.log
```

### 2. 指定进程名和 DLL

```powershell
.\hid_injector.exe Xsjzb.exe hid_hook.dll
```

### 3. 使用 DebugView 实时查看

1. 下载 DebugView: https://docs.microsoft.com/sysinternals/downloads/debugview
2. 以管理员权限运行 DebugView
3. 勾选 Capture → Capture Global Win32
4. 运行注入器
5. 在应用中触发 HID 操作
6. 实时查看输出

## 预期输出

### 注入器控制台

```
========================================
  HID Hook DLL Injector
========================================

目标进程: Xsjzb.exe
注入 DLL: hid_hook.dll

DLL 完整路径: D:\GitHub\hidproxy\injector\build\bin\Release\hid_hook.dll

正在查找进程...
[成功] 找到进程 PID: 12345

正在注入 DLL...
创建远程线程...
等待注入完成...
[成功] DLL 已加载到地址: 0x63C90000

[成功] DLL 注入成功！

检查日志文件:
  - hid_hook.log
  - 或使用 DebugView 查看实时输出
```

### 日志文件内容

```
[2025-11-13 10:30:45.123] ========================================
[2025-11-13 10:30:45.124]   HID Hook DLL Loaded
[2025-11-13 10:30:45.125] ========================================
[2025-11-13 10:30:45.126] 目标进程: C:\Xsj_Soft\Xsjzb\Xsjzb.exe
[2025-11-13 10:30:45.127] DLL 基址: 0x10000000
[2025-11-13 10:30:45.128] 
[2025-11-13 10:30:45.129] 开始安装 HID Hook...
[2025-11-13 10:30:45.130] ✅ HID Hook 安装成功！
[2025-11-13 10:30:45.131] ========================================
[2025-11-13 10:30:46.234] 🎯 HidD_GetHidGuid - 获取 HID GUID
[2025-11-13 10:30:46.345] 🎯 HidD_GetAttributes - VID=0x1234, PID=0x5678, Version=0x0100
[2025-11-13 10:30:46.456] 🎯 HidD_GetFeature - 成功读取 64 字节
[2025-11-13 10:30:46.567]   数据: 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 ...
[2025-11-13 10:30:46.678] 🎯 HidD_SetFeature - 写入 64 字节
[2025-11-13 10:30:46.789]   数据: AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 ...
```

## 常见问题

### 1. "无法打开进程，错误代码: 5"
**原因**: 权限不足  
**解决**: 以管理员权限运行注入器

```powershell
# 右键 → 以管理员身份运行 PowerShell
cd D:\GitHub\hidproxy\injector\build\bin\Release
.\hid_injector.exe
```

### 2. "找不到进程: Xsjzb.exe"
**原因**: 目标进程未运行  
**解决**: 先启动应用程序

```powershell
Start-Process "C:\Xsj_Soft\Xsjzb\Xsjzb.exe"
Start-Sleep 2
.\hid_injector.exe
```

### 3. "LoadLibrary 返回 NULL"
**原因**: DLL 加载失败  
**可能原因**:
- DLL 架构不匹配（64位 DLL 注入到 32位进程）
- 缺少依赖库（hid.lib, setupapi.lib）
- DLL 路径错误

**解决**: 检查 DLL 是否为 32位：

```powershell
dumpbin /HEADERS hid_hook.dll | Select-String "machine"
# 应该显示: 14C machine (x86)
```

### 4. 没有看到 Hook 日志
**原因**: 应用程序尚未调用 HID API  
**解决**: 在应用中执行实际的 HID 设备操作（如读取加密狗）

## 高级用法

### 启动时注入（推荐）

```powershell
# 创建快捷方式，自动注入
$script = @'
Start-Process "C:\Xsj_Soft\Xsjzb\Xsjzb.exe"
Start-Sleep 2
Start-Process "D:\GitHub\hidproxy\injector\build\bin\Release\hid_injector.exe" -Verb RunAs
'@

$script | Out-File -FilePath "启动并注入.ps1" -Encoding UTF8
```

### 监控多个进程

修改 `injector/main.cpp`：

```cpp
const wchar_t* processes[] = {
    L"Xsjzb.exe",
    L"OtherApp.exe"
};

for (auto& proc : processes) {
    DWORD pid = FindProcessByName(proc);
    if (pid) InjectDLL(pid, dllPath);
}
```

## 对比代理 DLL 方案

| 特性 | DLL 注入器 | 代理 DLL |
|------|-----------|----------|
| 实现难度 | ⭐⭐ 简单 | ⭐⭐⭐⭐ 复杂 |
| 需要备份原 DLL | ❌ 不需要 | ✅ 需要 |
| 需要管理员权限 | ✅ 需要 | ❌ 不需要 |
| 支持系统 DLL | ✅ 支持 | ❌ Known DLLs 无效 |
| 可撤销性 | ⭐⭐⭐⭐⭐ 随时卸载 | ⭐⭐⭐ 需要还原文件 |
| 稳定性 | ⭐⭐⭐⭐ 良好 | ⭐⭐⭐⭐⭐ 优秀 |

## 下一步

1. **编译项目** - 生成注入器和 Hook DLL
2. **测试注入** - 注入到 Xsjzb.exe 并查看日志
3. **分析调用** - 查看 HID API 调用序列
4. **自定义 Hook** - 修改 `hid_hooks.cpp` 实现特定功能

需要我现在帮您编译这个项目吗？
