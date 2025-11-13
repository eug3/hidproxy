# HID.dll Proxy

一个用于拦截和转发 Windows HID.dll API 调用的代理 DLL 项目，附带 HID 设备枚举控制台工具。

## 项目简介

此项目包含两个组件：

1. **hid.dll (代理 DLL)**: 一个代理 DLL，可以替换系统的 hid.dll，拦截所有 HID API 调用。通过 #pragma comment 链接方式（而非 LoadLibrary）转发到系统原始 hid.dll。
2. **hid_console.exe (控制台程序)**: 一个使用系统 HID API 枚举和显示所有 HID 设备信息的工具。

## 功能特性

- 完整的 HID.dll API 代理（44个导出函数）
- 使用 .def 文件精确控制导出序号
- 代理 DLL 不使用 LoadLibrary，通过编译期链接转发
- 控制台工具显示详细的 HID 设备信息：
  - 设备路径
  - VendorID/ProductID/Version
  - 制造商、产品名、序列号
  - Usage Page/Usage
  - 报告长度（输入/输出/特性）

## 构建要求

- CMake 3.15 或更高版本
- Visual Studio 2019 或更高版本 (MSVC) 或 MinGW-w64
- Windows SDK (包含 hid.lib, setupapi.lib)

## 构建步骤

### 使用 CMake + Visual Studio (推荐)

```powershell
# 创建构建目录
mkdir build
cd build

# 配置项目 (x64)
cmake .. -G "Visual Studio 16 2019" -A x64

# 编译
cmake --build . --config Release
```

### 使用 CMake + MinGW

```powershell
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake .. -G "MinGW Makefiles"

# 编译
cmake --build . --config Release
```

## 使用方法

### 1. 运行 HID 设备枚举工具

编译完成后，直接运行控制台程序：

```powershell
.\build\bin\Release\hid_console.exe
```

或者在 Debug 模式：

```powershell
.\build\bin\Debug\hid_console.exe
```

输出示例：
```
HID Device Enumeration Tool
===========================

=== HID Device Enumeration ===

[0] Device Path: 
    \\?\hid#vid_046d&pid_c52b&mi_00#...
    VendorID:  0x046d
    ProductID: 0xc52b
    Version:   0x1200
    Manufacturer: Logitech
    Product: USB Receiver
    Usage Page: 0x0001
    Usage:      0x0006
    Input Report Length:   20 bytes
    Output Report Length:  7 bytes
    Feature Report Length: 7 bytes

...

Total devices found: 12
```

1. 备份原始的 `hid.dll` (通常在 `C:\Windows\System32\`)
2. 将原始 `hid.dll` 重命名为 `hid_original.dll`
3. 将编译好的代理 `hid.dll` 复制到系统目录
4. 将 `hid_original.dll` 放在与代理 DLL 相同的目录

**警告**: 替换系统 DLL 可能导致系统不稳定。建议仅用于测试和开发目的。

## 项目结构

```
hidproxy/
├── src/
│   ├── dllmain.cpp      # DLL 入口点
│   ├── hid_proxy.h      # HID API 代理头文件
│   ├── hid_proxy.cpp    # HID API 代理实现
│   └── hid.def          # 导出函数定义
├── CMakeLists.txt       # CMake 构建配置
└── README.md            # 项目说明
```

## API 支持

代理以下 HID.dll 导出函数：

- HidD_FlushQueue
- HidD_FreePreparsedData
- HidD_GetAttributes
- HidD_GetConfiguration
- HidD_GetFeature
- HidD_GetHidGuid
- HidD_GetIndexedString
- HidD_GetInputReport
- HidD_GetManufacturerString
- HidD_GetMsGenreDescriptor
- HidD_GetNumInputBuffers
- HidD_GetPhysicalDescriptor
- HidD_GetPreparsedData
- HidD_GetProductString
- HidD_GetSerialNumberString
- HidD_Hello
- HidD_SetConfiguration
- HidD_SetFeature
- HidD_SetNumInputBuffers
- HidD_SetOutputReport
- HidP_GetButtonCaps
- HidP_GetCaps
- HidP_GetData
- HidP_GetExtendedAttributes
- HidP_GetLinkCollectionNodes
- HidP_GetScaledUsageValue
- HidP_GetSpecificButtonCaps
- HidP_GetSpecificValueCaps
- HidP_GetUsageValue
- HidP_GetUsageValueArray
- HidP_GetUsages
- HidP_GetUsagesEx
- HidP_GetValueCaps
- HidP_InitializeReportForID
- HidP_MaxDataListLength
- HidP_MaxUsageListLength
- HidP_SetData
- HidP_SetScaledUsageValue
- HidP_SetUsageValue
- HidP_SetUsageValueArray
- HidP_SetUsages
- HidP_TranslateUsagesToI8042ScanCodes
- HidP_UnsetUsages
- HidP_UsageListDifference

## 自定义扩展

在 `hid_proxy.cpp` 中，每个代理函数都可以添加自定义逻辑：

```cpp
BOOLEAN WINAPI HidD_GetFeature(HANDLE HidDeviceObject, PVOID ReportBuffer, ULONG ReportBufferLength)
{
    // 添加前置处理逻辑
    // ...
    
    // 调用原始函数
    BOOLEAN result = g_OriginalHidD_GetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
    
    // 添加后置处理逻辑
    // ...
    
    return result;
}
```

## 许可证

MIT License

## 注意事项

- 此项目仅供学习和研究目的
- 修改系统 DLL 可能违反某些软件的使用条款
- 始终在测试环境中使用
- 确保有系统恢复方案

## 贡献

欢迎提交问题和拉取请求。
