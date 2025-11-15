# Xsjzb 验证机制分析

## 概述

通过 IDA Pro 逆向分析 xsjzb 可执行文件，发现了关键的验证机制。

## 验证函数

**函数**: `sub_7363F0` (地址: `0x7363F0–0x73662F`)

这是一个验证/初始化函数，按顺序检查多个关键值。

## 硬编码验证值

### 1. UID 验证

**位置**: `0x736638`  
**值**: `"1264495731"` (十进制)  
**十六进制**: `0x4B5EAC73`  
**用途**: 检查 HID 设备的 UID 是否匹配

**在代码中的使用**:
```c
sub_405284(v4, "1264495731");  // line 71 @ 0x73659d
```

### 2. 用户名 MD5 哈希验证

**位置**: `0x73664c`  
**值**: `"FBFDE0ED23EC5C6FCFD4D5C94E15A2B1"`  
**长度**: 33 字节（32 位哈希 + null 终止符）

**在代码中的使用**:
```c
sub_405284(v7, "FBFDE0ED23EC5C6FCFD4D5C94E15A2B1");  // line 76 @ 0x7365e4
```

## 用户名与哈希值的关系

### 用户名
- **中文**: `韩蓉韩蓉`
- **GB2312 编码**: `BA AB C8 D8 BA AB C8 D8`

### MD5 计算
```
MD5(GB2312("韩蓉韩蓉")) = FBFDE0ED23EC5C6FCFD4D5C94E15A2B1
```

### 验证步骤

1. 程序从 HID 设备读取 sector1 数据
2. 提取用户名字段（GB2312 编码）
3. 计算 MD5 哈希值
4. 与硬编码的 `FBFDE0ED23EC5C6FCFD4D5C94E15A2B1` 比较
5. 如果匹配，验证通过

## 验证流程

函数 `sub_7363F0` 的验证顺序：

```c
// 1. 初始化一些全局变量
word_15780D8 = 12545;
word_15780DA = 12801;
word_15780DC = 12289;
word_15780DE = 12289;

// 2. 分配和初始化某些数据结构
sub_406C04(16);
// ... 循环初始化 ...

// 3. 填充加密数据（32 字节的负数序列）
*(_BYTE *)*dword_15780D4 = -67;
*(_BYTE *)(*dword_15780D4 + 1) = -61;
// ... 总共 16 对字节 ...

// 4. 验证 UID
sub_405284(v4, "1264495731");

// 5. 调用其他验证函数
sub_7367BC();

// 6. 处理动态计算的值
sub_405284(v5, v13);
sub_1543EB0();
sub_405284(v6, v12);

// 7. 验证用户名 MD5 哈希
sub_405284(v7, "FBFDE0ED23EC5C6FCFD4D5C94E15A2B1");

// 8. 处理其他全局变量
sub_405284(v8, dword_736678);
sub_405284(v9, dword_73668C);
```

## 在虚拟缓存中的应用

### 生成匹配的缓存

使用 `hid_launcher.exe` 生成虚拟缓存时：

1. **输入正确的 UID**:
   ```
   Do you want to specify a UID? (Y/N): Y
   Please enter UID (decimal number): 1264495731
   ```

2. **输入正确的用户名**:
   ```
   Please enter software key (4 Chinese characters): 韩蓉韩蓉
   ```

### 配置文件方式

创建 `cache\virtual_device.cfg`:

```ini
# 指定 UID（十进制）
UID=1264495731

# 或使用十六进制
UID=0x4B5EAC73
```

然后在启动时输入用户名 `韩蓉韩蓉`。

### 生成的缓存文件

- **`765674391_device.cfg`**: 设备配置（HID 会随机生成）
- **`mem_1264495731_sector0.dat`**: 扇区 0 数据（包含 UID）
- **`mem_1264495731_sector1.dat`**: 扇区 1 数据（包含 GB2312 编码的"韩蓉韩蓉"）

## 程序验证逻辑

当 xsjzb 运行时：

1. 通过 HID API 读取设备信息
2. `hid_hook.dll` 劫持 API 调用，返回缓存数据
3. 程序读取到 UID = `1264495731`
4. 程序读取到用户名 = `韩蓉韩蓉` (GB2312)
5. 计算 MD5 = `FBFDE0ED23EC5C6FCFD4D5C94E15A2B1`
6. 与硬编码值比较 → 验证通过

## PowerShell 验证命令

### 转换用户名为 GB2312 十六进制
```powershell
$bytes = [System.Text.Encoding]::GetEncoding('gb2312').GetBytes('韩蓉韩蓉')
$bytes | ForEach-Object { '{0:X2}' -f $_ } | Join-String -Separator ' '
# 输出: BA AB C8 D8 BA AB C8 D8
```

### 计算 MD5 哈希
```powershell
$md5 = [System.Security.Cryptography.MD5]::Create()
$bytes = [System.Text.Encoding]::GetEncoding('gb2312').GetBytes('韩蓉韩蓉')
$hash = $md5.ComputeHash($bytes)
($hash | ForEach-Object { $_.ToString('X2') }) -join ''
# 输出: FBFDE0ED23EC5C6FCFD4D5C94E15A2B1
```

### 转换 UID 进制
```powershell
# 十进制转十六进制
[Convert]::ToString(1264495731, 16)
# 输出: 4b5eac73

# 十六进制转十进制
[Convert]::ToInt64('0x4B5EAC73', 16)
# 输出: 1264495731
```

## 技术细节

### GB2312 编码

- "韩" = `BA AB`
- "蓉" = `C8 D8`
- "韩蓉韩蓉" = `BA AB C8 D8 BA AB C8 D8`

### MD5 算法

- 输入: 8 字节 GB2312 编码
- 输出: 32 字节十六进制字符串（128 位哈希）
- 算法: 标准 MD5 哈希

### UID 存储格式

- 类型: 32 位无符号整数 (DWORD)
- 字节序: 小端序 (Little Endian)
- 存储位置: sector0 的前 4 字节

## 相关函数

- `sub_405284`: 字符串处理/验证函数
- `sub_7367BC`: 未知验证函数（在 UID 验证之后调用）
- `sub_1543EB0`: 未知处理函数
- `sub_406C04`: 数据结构初始化函数
- `sub_406A48`: 返回值用于循环计数

## 注意事项

1. **编码必须使用 GB2312**: 使用 UTF-8 或其他编码会导致哈希值不匹配
2. **UID 必须精确匹配**: `1264495731` (十进制) = `0x4B5EAC73` (十六进制)
3. **用户名大小写敏感**: "韩蓉" 与 "韩荣" 是不同的字符
4. **字符重复**: 必须是"韩蓉韩蓉"（重复两次），不是"韩蓉"

## 扩展应用

如果需要支持其他用户名，需要：

1. 修改 xsjzb 程序中的硬编码哈希值
2. 或在 hook 层面劫持验证函数，绕过检查
3. 或生成包含正确用户名的缓存文件

当前实现已支持方式 3，可以通过 launcher 输入任意用户名生成缓存，但 xsjzb 只接受"韩蓉韩蓉"这一特定值。
