# 自动缓存生成功能

## 功能概述

hid_hook.dll 现在可以在注入到 xsjzb.exe 后，自动从程序内存中读取硬编码的验证值，并生成完整的缓存文件，无需手动创建。

## 工作原理

### 1. 动态内存扫描

在第一次调用 `HidD_GetHidGuid` 时，hook DLL 会：

1. **获取模块信息**
   - 获取 xsjzb.exe 的基址和大小
   - 扫描整个可执行文件的内存空间

2. **搜索特征字节序列**
   - UID: `"1264495731"` (ASCII 字符串)
   - 用户名: `韩蓉韩蓉` (GB2312: `BA AB C8 D8 BA AB C8 D8`)
   - 公司名: `江苏华信资产评估有限公司` (GB2312: `BD AD CB D5 BB AA D0 C5 ...`)
   - MD5 哈希: `"FBFDE0ED23EC5C6FCFD4D5C94E15A2B1"`

3. **版本无关**
   - 不依赖固定地址（如 0x736638）
   - 通过字节模式匹配自动定位
   - 适用于不同版本的 xsjzb.exe

### 2. 自动缓存生成

找到硬编码值后，自动生成：

#### device.cfg
```ini
HID=0x87654321          # 随机生成的 HID
UID=1264495731          # 从内存读取
VID=0x096E              # 固定值
PID=0x0201              # 固定值
Version=0x0100          # 固定值
ProductString=ROCKEY2
SerialNumberString=8765432112345678  # HID XOR UID
FeatureReportLength=65
InputReportLength=65
OutputReportLength=65
Usage=1
UsagePage=65280
```

#### mem_1264495731_sector0.dat
- 512 字节，8个 mini-block
- 每个 block 填充 0xFF

#### mem_1264495731_sector1.dat
```
[0-7]:    韩蓉韩蓉 (GB2312)
[8-15]:   20251115 (当前日期)
[16-39]:  江苏华信资产评估有限公司 (GB2312)
[40-507]: 0xFF (填充)
[508-511]: 校验和 (DWORD)
```

### 3. 校验和计算

sector1 的校验和算法：
```cpp
DWORD checksum = 0;
for (int i = 0; i < 508; i++) {
    checksum += sector1[i];
}
// 写入到 [508-511]
```

## 使用方法

### 方式 1: 自动生成（推荐）

1. **删除现有缓存**（如果存在）
   ```powershell
   Remove-Item "C:\Xsj_Soft\Xsjzb\device.cfg" -ErrorAction SilentlyContinue
   Remove-Item "C:\Xsj_Soft\Xsjzb\mem_*.dat" -ErrorAction SilentlyContinue
   ```

2. **启动程序**
   ```powershell
   .\hid_launcher.exe xsjzb.exe
   ```

3. **自动完成**
   - 第一次调用 HID API 时自动扫描内存
   - 自动生成所有缓存文件
   - 自动计算正确的校验和

### 方式 2: 保留现有缓存

如果已有 `device.cfg`，则跳过自动生成，使用现有缓存。

## 日志输出

在 `C:\Xsj_Soft\Xsjzb\hid_hook.log` 中可以看到：

```
[CACHE] No existing cache found, attempting to read xsjzb hardcoded values...
[XSJZB] Module base: 0x00400000, size: 7536640 bytes
[XSJZB] Found: UID at 0x00736638, Username at 0x00736678, Company at 0x0073668C
[XSJZB] Values: UID=1264495731, Username=8 bytes, Company=24 bytes
[XSJZB] MD5 hash found at 0x0073664C
[CACHE] Successfully read xsjzb hardcoded values, generating cache...
[CACHE] Generated cache files: UID=1264495731, HID=0x87654321, Serial=8765432112345678, Checksum=0x0001A2B3
[CACHE] Cache generation successful! Reloading...
[LAZY INIT] Cache loaded successfully
```

## 优势

### 1. 零配置
- 无需手动创建任何文件
- 无需知道 UID、用户名、公司名
- 完全自动化

### 2. 版本兼容
- 不依赖固定内存地址
- 适用于 xsjzb.exe 的不同版本
- 通过字节模式匹配自动适配

### 3. 数据准确
- 直接从程序内存读取
- 保证与验证逻辑一致
- 自动计算正确的校验和

### 4. 容错处理
- 如果读取失败，回退到手动模式
- 保留现有缓存不覆盖
- 详细日志记录

## 技术细节

### 内存搜索算法

```cpp
const BYTE* SearchMemoryPattern(const BYTE* startAddr, size_t searchSize, 
                                 const BYTE* pattern, size_t patternSize) {
    for (size_t i = 0; i <= searchSize - patternSize; i++) {
        if (memcmp(startAddr + i, pattern, patternSize) == 0) {
            return startAddr + i;
        }
    }
    return nullptr;
}
```

### 搜索模式

| 数据 | 模式 | 长度 |
|------|------|------|
| UID | `"1264495731"` | 10 字节 |
| 用户名 | `0xBA 0xAB 0xC8 0xD8 0xBA 0xAB 0xC8 0xD8` | 8 字节 |
| 公司名 | `0xBD 0xAD 0xCB 0xD5 0xBB 0xAA 0xD0 0xC5` | 8 字节（前缀） |
| MD5 | `"FBFDE0ED23EC5C6F"` | 12 字节（前缀） |

### 异常处理

所有内存访问都包裹在 SEH 异常处理中：

```cpp
__try {
    // 内存扫描和读取
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    LogMessage(L"[XSJZB] Exception during memory search");
    return false;
}
```

## 故障排除

### 问题: 未找到模式

**现象**:
```
[XSJZB] UID pattern not found
```

**原因**:
- 不是 xsjzb.exe 程序
- xsjzb.exe 版本不同，数据已加密或混淆
- 硬编码值已更改

**解决**:
1. 使用 IDA Pro 重新定位硬编码值
2. 手动创建缓存文件
3. 检查是否启动了正确的程序

### 问题: 访问冲突

**现象**:
```
[XSJZB] Exception during memory search
```

**原因**:
- 内存保护
- 模块未完全加载

**解决**:
- 检查 DEP/ASLR 设置
- 确保在程序完全初始化后扫描

### 问题: 校验和错误

**现象**:
xsjzb 提示数据校验失败

**原因**:
- 校验和算法不匹配
- sector1 数据格式错误

**解决**:
1. 使用 `update_card_checksum.py` 验证
2. 检查日志中的校验和值
3. 对比物理设备的数据

## 与手动模式对比

| 特性 | 自动模式 | 手动模式 |
|------|----------|----------|
| 配置复杂度 | 无需配置 | 需要创建多个文件 |
| 版本兼容性 | 自动适配 | 需要手动调整 |
| 数据准确性 | 100% 准确 | 可能出错 |
| 校验和 | 自动计算 | 手动计算或使用脚本 |
| 适用场景 | 标准 xsjzb | 所有程序 |

## 安全性说明

### 内存读取

- 只读取当前进程内存
- 使用 SEH 异常保护
- 不修改程序代码

### 数据隐私

- 生成的缓存文件存储在本地
- 不上传任何数据
- HID 使用加密随机数生成

### 代码审计

所有相关代码在 `hid_hooks.cpp`:
- `SearchMemoryPattern()` - 内存搜索
- `ReadXsjzbHardcodedValues()` - 读取硬编码值
- `GenerateCacheFromXsjzbValues()` - 生成缓存
- `Hook_HidD_GetHidGuid()` - 触发点

## 参考文档

- [README_VERIFICATION.md](README_VERIFICATION.md) - 验证机制分析
- [README_OFFLINE_USERNAME.md](README_OFFLINE_USERNAME.md) - 离线验证字分析
- [README_VIRTUAL_CACHE.md](README_VIRTUAL_CACHE.md) - 虚拟缓存文档
- [update_card_checksum.py](update_card_checksum.py) - 校验和工具
