# 虚拟缓存功能说明

## 概述

虚拟缓存功能支持在没有物理 HID 设备的情况下，生成完整的虚拟设备身份信息，包括 HID、UID 和 SerialNumberString。

## SerialNumberString 计算方法

SerialNumberString 是一个 16 位十六进制字符串，格式为：

```
SerialNumberString = HID (8位) + (HID XOR UID) (8位)
```

### 示例

假设：
- HID = 0x2DA34397
- UID = 0x4B5EAC73

计算过程：
1. SerialPart1 = HID = 0x2DA34397
2. SerialPart2 = HID XOR UID = 0x2DA34397 XOR 0x4B5EAC73 = 0x66FDEFE4
3. SerialNumberString = "2DA3439766FDEFE4"

### 反向计算

从 SerialNumberString 解析 HID 和 UID：

```
HID = SerialNumberString[0:8] (前8位)
UID = SerialNumberString[8:16] XOR HID (后8位异或HID)
```

## 虚拟缓存生成方式

### 方式1：随机生成（推荐）

调用 `GenerateVirtualSectorsFromIdentity(0, 0, year)` 或 `ConfigureVirtualDeviceIdentity(0, 0)`，参数为 0 时自动随机生成 HID 和 UID：

```cpp
// 随机生成虚拟设备身份
GenerateVirtualSectorsFromIdentity(0, 0, 0);  // year=0 使用当前年份
```

生成过程：
1. 使用高精度时间戳作为随机种子
2. 随机生成 HID 和 UID
3. 根据 HID 和 UID 计算 SerialNumberString
4. 生成校验和（基于 UID、HID 和年份）
5. 创建虚拟扇区数据
6. 存储到全局缓存 `g_hidCache`

### 方式2：指定 HID 和 UID

```cpp
// 指定 HID 和 UID
DWORD hid = 0x12345678;
DWORD uid = 0x87654321;
GenerateVirtualSectorsFromIdentity(hid, uid, 0);
```

### 方式3：从配置文件指定

在 `virtual_device.cfg` 文件中配置（支持多种格式）：

```ini
# 方式 1: 使用 Serial 参数（自动解析出 HID 和 UID）
Serial=2DA3439766FDEFE4

# 方式 2: 直接指定 HID 和 UID（16进制）
HID=0x2DA34397
UID=0x4B5EAC73

# 方式 3: UID 使用 10 进制（推荐用户输入）
UID=1264205939
HID=0x2DA34397

# 方式 4: 只指定 UID（10进制），HID 自动随机生成
UID=1264205939

# 方式 5: 只指定 HID，UID 自动随机生成
HID=0x2DA34397
```

**注意**：
- UID 支持 **10 进制**（无前缀）和 **16 进制**（0x 前缀）
- HID 支持 **16 进制**（0x 前缀）
- 如果只提供其中一个，另一个会自动随机生成
- Serial 参数优先级最高

## 缓存文件结构

生成的缓存文件包括：

1. **`<HID>_device.cfg`** - 设备配置文件
   ```ini
   VID=0x096E
   PID=0x0201
   Version=0x0100
   ProductString=USB DONGLE
   SerialNumberString=<计算得到的16位十六进制>
   HID=0x<HID值>
   UID=0x<UID值>
   FeatureReportLength=73
   InputReportLength=73
   OutputReportLength=73
   Usage=1
   UsagePage=1
   ```

2. **`mem_<UID>_sector0.dat`** - 扇区0数据（512字节）
   - 前4字节：UID（小端序）
   - 4-8字节：HID（小端序）
   - 其他：元数据

3. **`mem_<UID>_sector1.dat`** - 扇区1数据（512字节）
   - 包含校验和
   - 包含年检信息

## 使用场景

### 场景1：用户指定 10 进制 UID

这是最常用的场景，用户只需要输入容易记忆的 10 进制 UID 数值：

**步骤 1**：创建 `cache\virtual_device.cfg` 文件：
```ini
# 只需要输入 UID 的 10 进制值
UID=1264205939
```

**步骤 2**：运行程序，系统会自动：
- 随机生成 HID（如 0x2DA34397）
- 使用指定的 UID（1264205939 = 0x4B5EAC73）
- 计算 SerialNumberString（2DA3439766FDEFE4）
- 生成校验和
- 创建虚拟扇区数据

**日志输出示例**：
```
[VIRTUAL] Generated: HID HID=0x2DA34397 UID=0x4B5EAC73 (UID decimal: 1264205939)
[VIRTUAL] Generated sector data (HID=0x2DA34397 UID=0x4B5EAC73 Serial=2DA3439766FDEFE4 year=2025)
```

### 场景2：测试环境无物理设备

使用 launcher 生成虚拟缓存：

```powershell
.\hid_launcher.exe --generate-cache "用户名"
```

### 场景2：程序运行时动态生成

DLL 注入后自动检测，如果没有物理设备，会启用虚拟化模式，并根据配置文件或随机生成身份。

### 场景3：缓存复用

一旦生成缓存文件，下次运行时会自动加载，无需重新生成。

## 代码实现

### 核心函数

1. **`GenerateRandomHidUid(DWORD& hidOut, DWORD& uidOut)`**
   - 生成随机的 HID 和 UID

2. **`GenerateSerialFromHidUid(DWORD hid, DWORD uid)`**
   - 根据 HID 和 UID 计算 SerialNumberString

3. **`ParseSerialToHidUid(const wstring& serial, DWORD& hid, DWORD& uid)`**
   - 从 SerialNumberString 解析 HID 和 UID

4. **`GenerateVirtualSectorsFromIdentity(DWORD hid, DWORD uid, int year)`**
   - 生成完整的虚拟设备数据
   - 支持随机生成（参数为0）

## 校验和算法

校验和使用 MD5 哈希计算：

```
checksum = "0" + MD5("1" + UID + "12" + HID + year).upper()
```

详见 `README_CHECKSUM_ALGORITHM.md`

## 注意事项

1. **随机性**：使用 `QueryPerformanceCounter` 确保每次生成的 HID/UID 都不同
2. **一致性**：SerialNumberString 和 HID/UID 的计算必须保持一致
3. **缓存管理**：生成的缓存文件存储在 `cache\` 子目录
4. **配置优先级**：配置文件中的 Serial 参数优先于单独的 HID/UID 参数
