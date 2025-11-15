# 虚拟缓存生成 - UID 输入说明

## 使用方式

### 方式 1：交互式命令行输入（推荐）

运行 `hid_launcher.exe` 时，如果没有物理设备和缓存文件，会提示生成虚拟缓存。

**交互流程**：

```
========================================
[WARNING] No USB device detected!
[WARNING] No existing cache found!
========================================

Would you like to generate a virtual cache? (Y/N): Y

Please enter software key (4 Chinese characters): 测试用户

[INFO] Software key: 测试用户

Do you want to specify a UID? (Y/N, press N to auto-generate): Y
Please enter UID (decimal number, e.g., 1264205939): 1264205939

[INFO] Using UID: 1264205939 (0x4B5EAC73)

[INFO] Generating cache...
[INFO] Using user-specified UID: 1264205939 (0x4B5EAC73)
[INFO] Generated random HID: 0x2DA34397
[OK] Virtual cache generated successfully!
```

### 方式 2：配置文件方式

创建 `cache\virtual_device.cfg` 文件：

```ini
# 指定 UID（10进制）
UID=1264205939

# 可选：指定年份
Year=2025
```

然后运行 launcher，会自动加载配置。

## UID 输入格式

### 控制台输入
- **10 进制数字**（推荐）：直接输入数字，如 `1264205939`
- 范围：1 ~ 4294967295 (0 ~ 0xFFFFFFFF)
- 输入 0 或按 N 跳过将自动随机生成

### 配置文件输入
```ini
# 10 进制（推荐）
UID=1264205939

# 或 16 进制（需要 0x 前缀）
UID=0x4B5EAC73
```

## 示例

### 示例 1：指定 UID
```
Do you want to specify a UID? (Y/N, press N to auto-generate): Y
Please enter UID (decimal number, e.g., 1264205939): 1234567890

[INFO] Using UID: 1234567890 (0x499602D2)
[INFO] Generated random HID: 0xABCD1234
```

### 示例 2：自动生成 UID
```
Do you want to specify a UID? (Y/N, press N to auto-generate): N

[INFO] UID will be auto-generated
[INFO] Generated random HID: 0x12345678
[INFO] Generated random UID: 2147483647 (0x7FFFFFFF)
```

## 生成的文件

执行后会在 `cache\` 目录生成以下文件：

1. **`<HID>_device.cfg`** - 设备配置文件
   ```ini
   VID=0x096E
   PID=0x0201
   Version=0x0100
   ProductString=USB DONGLE
   SerialNumberString=<16位十六进制>
   HID=0x<HID值>
   UID=0x<UID值>
   FeatureReportLength=73
   InputReportLength=73
   OutputReportLength=73
   Usage=1
   UsagePage=1
   ```

2. **`mem_<UID>_sector0.dat`** - 扇区0数据（512字节）

3. **`mem_<UID>_sector1.dat`** - 扇区1数据（512字节，含校验和）

## 常见问题

### Q: UID 输入什么值合适？
A: 可以使用任意 10 进制数字（1-4294967295），建议使用容易记忆的数字。

### Q: 必须输入 UID 吗？
A: 不是必须的。按 N 跳过即可自动随机生成。

### Q: HID 可以指定吗？
A: 当前版本 HID 会自动随机生成。如需指定，请使用配置文件方式。

### Q: 如何验证生成的 UID？
A: 查看生成的日志输出，或打开 `cache\<HID>_device.cfg` 文件查看 UID 值。

### Q: UID 输入错误怎么办？
A: 删除 `cache\` 目录中的所有文件，重新运行 launcher 生成。

## 技术细节

- **UID 存储格式**：32 位无符号整数 (DWORD)
- **十进制范围**：0 ~ 4,294,967,295
- **十六进制范围**：0x00000000 ~ 0xFFFFFFFF
- **SerialNumberString 计算**：基于 HID 和 UID 通过 XOR 运算生成
- **校验和算法**：MD5("1" + UID + "12" + HID + year)
