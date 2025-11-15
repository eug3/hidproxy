#include <windows.h>
#include <stdio.h>
#include <conio.h>  // for _getwch()
#include <fcntl.h>  // for _setmode
#include <io.h>     // for _fileno
#include <initguid.h>  // Must be before hidsdi.h to define GUID
#include <hidsdi.h>
#include <setupapi.h>
#include <wincrypt.h>  // for MD5
#include <time.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")  // for CryptAPI

// HID GUID
DEFINE_GUID(GUID_DEVINTERFACE_HID, 0x4D1E55B2L, 0xF16F, 0x11CF, 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30);

static const USHORT kTargetVendorId = 0x096E;
static const USHORT kTargetProductId = 0x0201;

// 生成校验和: "0" + MD5("1" + UID + "12" + HID + year).upper()
void GenerateChecksum(DWORD uid, DWORD hid, int year, char* outChecksum) {
    // 构建输入字符串: "1" + UID + "12" + HID + year
    char input[64];
    sprintf_s(input, sizeof(input), "1%u12%u%d", uid, hid, year);
    
    // 计算MD5
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hashLen = 16;
    
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) &&
        CryptHashData(hHash, (BYTE*)input, (DWORD)strlen(input), 0) &&
        CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        
        // 转换为大写十六进制: "0" + 32个hex字符
        char temp[35];  // 临时缓冲区: 33个字符 + '\0' + 1个额外安全字节
        temp[0] = '0';
        for (int i = 0; i < 16; i++) {
            sprintf_s(temp + 1 + i * 2, 3, "%02X", hash[i]);  // 总是写入3个字节的空间 (2个字符 + '\0')
        }
        temp[33] = '\0';
        
        // 复制到输出缓冲区
        memcpy(outChecksum, temp, 34);
    } else {
        // 如果加密失败,返回全0的校验和
        memcpy(outChecksum, "000000000000000000000000000000000", 34);
    }
    
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}

// 更新扇区1中的校验和和年检信息
void UpdateSector1Checksum(BYTE sector1[512], DWORD uid, DWORD hid, int year) {
    // 生成新校验和
    char checksum[34];
    GenerateChecksum(uid, hid, year, checksum);
    
    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // 查找校验和位置(搜索以"0"开头的33字符校验和)
    // 通常在扇区1的某个位置,需要定位
    for (int i = 0; i < 512 - 33; i++) {
        // 检查是否是旧校验和(以'0'开头,后面32个是十六进制字符)
        if (sector1[i] == '0') {
            bool isChecksum = true;
            for (int j = 1; j < 33; j++) {
                char c = sector1[i + j];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                    isChecksum = false;
                    break;
                }
            }
            
            if (isChecksum) {
                // 找到校验和位置,更新它
                memcpy(sector1 + i, checksum, 33);
                wprintf(L"[UPDATE] Checksum updated at offset %d: %S\n", i, checksum);
                break;
            }
        }
    }
    
    // 更新年检信息 - 搜索并替换年份字符串
    char yearStr[16];
    sprintf_s(yearStr, "%d", year);
    
    // 这里简化处理,实际应该定位具体的年检信息字段位置
    wprintf(L"[UPDATE] Year value: %d\n", year);
}

// 生成虚拟缓存(无需真实设备)
bool GenerateVirtualCache(const wchar_t* baseDir, const wchar_t* userName) {
    wprintf(L"\n========================================\n");
    wprintf(L"  Generating Virtual HID Cache\n");
    wprintf(L"========================================\n\n");

    wprintf(L"[DEBUG] Function entered: GenerateVirtualCache\n");
    wprintf(L"[DEBUG] baseDir parameter: '%s'\n", baseDir);
    wprintf(L"[DEBUG] userName parameter: '%s'\n", userName);

    // 创建 cache 子目录
    wchar_t cacheDir[MAX_PATH];
    swprintf_s(cacheDir, L"%scache\\", baseDir);
    
    wprintf(L"[INFO] Base directory: %s\n", baseDir);
    wprintf(L"[INFO] Cache directory: %s\n", cacheDir);
    
    if (!CreateDirectoryW(cacheDir, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            wprintf(L"[ERROR] Failed to create cache directory! Error code: %lu\n", err);
            return false;
        }
        wprintf(L"[INFO] Cache directory already exists\n");
    } else {
        wprintf(L"[INFO] Cache directory created successfully\n");
    }

    // 生成随机 HID 和 UID
    srand((unsigned int)time(NULL));
    DWORD deviceHid = ((DWORD)rand() << 16) | rand();
    DWORD deviceUid = ((DWORD)rand() << 16) | rand();

    // 计算 SerialNumber (HID + (HID_reversed XOR UID))
    BYTE* hidBytes = (BYTE*)&deviceHid;
    DWORD hidReversed = (hidBytes[3] << 24) | (hidBytes[2] << 16) | (hidBytes[1] << 8) | hidBytes[0];
    DWORD serialPart2 = hidReversed ^ deviceUid;

    wprintf(L"[INFO] HID: %u, UID: %u\n", deviceHid, deviceUid);

    // 准备 sector0: UID 的十进制字符串
    BYTE partition0[512] = {0};
    char uidStr[32];
    sprintf_s(uidStr, sizeof(uidStr), "%u", deviceUid);
    memcpy(partition0, uidStr, strlen(uidStr));

    // 准备 sector1: 使用模板格式 (参考真实设备数据)
    BYTE partition1[512] = {0};
    
    // 获取当前年份
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentYear = st.wYear;
    int nextYear = currentYear + 1;

    // 构建 sector1 模板 (用用户名 + 年检信息 + 占位符校验和)
    char sector1Template[512];
    int offset = 0;
    
    // 1. 转换用户名到 GB2312
    char userNameGB[100] = {0};
    WideCharToMultiByte(CP_ACP, 0, userName, -1, userNameGB, sizeof(userNameGB), NULL, NULL);
    
    // 2. 构建完整字符串 (先用占位符校验和)
    offset = sprintf_s(sector1Template, sizeof(sector1Template),
                      "%s  %d\xc4\xea\xb6\xc8\xd3\xda%d-01-01 12:00:00 %d\xc4\xea\xb6\xc8\xd3\xda%d-01-01 12:00:00  \xd2\xd1\xb1\xb8\xb0\xb8-\xd4\xda\xd3\xc3        000000000000000000000000000000000        \xb1\xb1\xbe\xa9\xb9\xdc\xb5\xc0\xbd\xa8\xc9\xe8\xb9\xc9\xb7\xdd\xd3\xd0\xcf\xde\xb9\xab\xcb\xbe",
                      userNameGB, currentYear, currentYear, nextYear, nextYear);
    
    // 3. 复制到 partition1
    if (offset > 0 && offset < 512) {
        memcpy(partition1, sector1Template, offset);
    }
    
    // 4. 使用和真实设备相同的方法更新校验和
    wprintf(L"\n[UPDATE] Generating checksum for virtual cache...\n");
    UpdateSector1Checksum(partition1, deviceUid, deviceHid, currentYear);

    // 保存缓存文件 (模仿真实设备的写入方式)
    wprintf(L"\n[SAVE] Writing cache files...\n");
    
    wchar_t configPath[MAX_PATH];
    FILE* fp = NULL;
    
    __try {
        // 1. <HID>_device.cfg
        swprintf_s(configPath, L"%s%u_device.cfg", cacheDir, deviceHid);
        wprintf(L"  [DEBUG] Creating: %s\n", configPath);
        
        fp = _wfopen(configPath, L"w");
        if (fp) {
            fprintf(fp, "VID=0x096E\n");
            fprintf(fp, "PID=0x0201\n");
            fprintf(fp, "Version=0x0100\n");
            fprintf(fp, "ProductString=USB DONGLE\n");
            fprintf(fp, "SerialNumberString=%08X%08X\n", deviceHid, serialPart2);
            fprintf(fp, "HID=0x%08X\n", deviceHid);
            fprintf(fp, "UID=0x%08X\n", deviceUid);
            fprintf(fp, "FeatureReportLength=73\n");
            fprintf(fp, "InputReportLength=73\n");
            fprintf(fp, "OutputReportLength=73\n");
            fprintf(fp, "Usage=1\n");
            fprintf(fp, "UsagePage=1\n");
            fclose(fp);
            fp = NULL;
            wprintf(L"  [OK] %u_device.cfg\n", deviceHid);
        } else {
            wprintf(L"  [ERROR] Failed to create %u_device.cfg (errno: %d, GetLastError: %lu)\n", 
                   deviceHid, errno, GetLastError());
        }

        // 2. mem_<UID>_sector0.dat
        swprintf_s(configPath, L"%smem_%u_sector0.dat", cacheDir, deviceUid);
        wprintf(L"  [DEBUG] Creating: %s\n", configPath);
        
        fp = _wfopen(configPath, L"wb");
        if (fp) {
            size_t written = fwrite(partition0, 1, 512, fp);
            fclose(fp);
            fp = NULL;
            wprintf(L"  [OK] mem_%u_sector0.dat (%zu bytes written)\n", deviceUid, written);
        } else {
            wprintf(L"  [ERROR] Failed to create mem_%u_sector0.dat (errno: %d, GetLastError: %lu)\n", 
                   deviceUid, errno, GetLastError());
        }

        // 3. mem_<UID>_sector1.dat
        swprintf_s(configPath, L"%smem_%u_sector1.dat", cacheDir, deviceUid);
        wprintf(L"  [DEBUG] Creating: %s\n", configPath);
        
        fp = _wfopen(configPath, L"wb");
        if (fp) {
            size_t written = fwrite(partition1, 1, 512, fp);
            fclose(fp);
            fp = NULL;
            wprintf(L"  [OK] mem_%u_sector1.dat (%zu bytes written)\n", deviceUid, written);
        } else {
            wprintf(L"  [ERROR] Failed to create mem_%u_sector1.dat (errno: %d, GetLastError: %lu)\n", 
                   deviceUid, errno, GetLastError());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        wprintf(L"  [EXCEPTION] Caught exception during file writing! Code: 0x%08X\n", GetExceptionCode());
        if (fp) fclose(fp);
        return false;
    }

    // 验证文件是否真的存在
    wprintf(L"\n[VERIFY] Checking if files actually exist on disk...\n");
    
    swprintf_s(configPath, L"%s%u_device.cfg", cacheDir, deviceHid);
    if (GetFileAttributesW(configPath) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"  [OK] %u_device.cfg exists\n", deviceHid);
    } else {
        wprintf(L"  [ERROR] %u_device.cfg NOT FOUND! (Error: %lu)\n", deviceHid, GetLastError());
    }
    
    swprintf_s(configPath, L"%smem_%u_sector0.dat", cacheDir, deviceUid);
    if (GetFileAttributesW(configPath) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"  [OK] mem_%u_sector0.dat exists\n", deviceUid);
    } else {
        wprintf(L"  [ERROR] mem_%u_sector0.dat NOT FOUND! (Error: %lu)\n", deviceUid, GetLastError());
    }
    
    swprintf_s(configPath, L"%smem_%u_sector1.dat", cacheDir, deviceUid);
    if (GetFileAttributesW(configPath) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"  [OK] mem_%u_sector1.dat exists\n", deviceUid);
    } else {
        wprintf(L"  [ERROR] mem_%u_sector1.dat NOT FOUND! (Error: %lu)\n", deviceUid, GetLastError());
    }

    wprintf(L"\n[SUCCESS] Virtual cache generated successfully!\n");
    wprintf(L"========================================\n\n");
    return true;
}

// 从真实HID设备生成缓存文件
bool GenerateCacheFromDevice(const wchar_t* baseDir) {
    wprintf(L"\n========================================\n");
    wprintf(L"  Pre-caching HID Device Data\n");
    wprintf(L"========================================\n\n");

    // 创建 cache 子目录
    wchar_t cacheDir[MAX_PATH];
    swprintf_s(cacheDir, L"%scache\\", baseDir);
    CreateDirectoryW(cacheDir, NULL);  // 如果已存在会失败,但不影响

    // 查找Rockey2设备
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_HID, NULL, NULL, 
                                             DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] Failed to enumerate HID devices\n");
        return false;
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DWORD deviceUid = 0, deviceHid = 0;
    
    SP_DEVICE_INTERFACE_DATA devInterfaceData = { sizeof(SP_DEVICE_INTERFACE_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_HID, i, &devInterfaceData); i++) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, NULL, 0, &requiredSize, NULL);
        
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData = 
            (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(requiredSize);
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        
        if (SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, detailData, 
                                             requiredSize, NULL, NULL)) {
            HANDLE hTemp = CreateFileW(detailData->DevicePath, GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            
            if (hTemp != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attrib = { sizeof(HIDD_ATTRIBUTES) };
                if (HidD_GetAttributes(hTemp, &attrib)) {
                    if (attrib.VendorID == kTargetVendorId && attrib.ProductID == kTargetProductId) {
                        wprintf(L"[FOUND] Rockey2 device: VID_%04X&PID_%04X\n", 
                               attrib.VendorID, attrib.ProductID);
                        hDevice = hTemp;
                        
                        // 读取序列号 - HID和UID从序列号解析
                        wchar_t serialNumber[256] = {0};
                        if (HidD_GetSerialNumberString(hDevice, serialNumber, sizeof(serialNumber))) {
                            // 序列号格式: 前8字符=HID(hex), 后8字符=HID_reversed XOR UID
                            // 例如: 2DA3439766FDEFE4
                            // HID = 0x2DA34397
                            // UID部分 = 0x66FDEFE4
                            
                            if (wcslen(serialNumber) >= 16) {
                                wchar_t hidPart[9] = {0};
                                wchar_t uidPartStr[9] = {0};
                                wcsncpy_s(hidPart, serialNumber, 8);
                                wcsncpy_s(uidPartStr, serialNumber + 8, 8);
                                
                                // 解析HID
                                deviceHid = wcstoul(hidPart, nullptr, 16);
                                
                                // 解析UID部分
                                DWORD uidPart = wcstoul(uidPartStr, nullptr, 16);
                                
                                // HID字节反转: 0x2DA34397 -> bytes[2D A3 43 97] -> reverse -> 0x9743A32D
                                BYTE hidBytes[4];
                                memcpy(hidBytes, &deviceHid, 4);
                                DWORD hidReversed = ((DWORD)hidBytes[3] << 24) |
                                                   ((DWORD)hidBytes[2] << 16) |
                                                   ((DWORD)hidBytes[1] << 8) |
                                                   ((DWORD)hidBytes[0]);
                                
                                // UID = uidPart XOR hidReversed
                                deviceUid = uidPart ^ hidReversed;
                                
                                wprintf(L"[INFO] Serial Number: %s\n", serialNumber);
                                wprintf(L"[INFO] Device UID: 0x%08X (%u)\n", deviceUid, deviceUid);
                                wprintf(L"[INFO] Device HID: 0x%08X (%u)\n", deviceHid, deviceHid);
                            } else {
                                wprintf(L"[WARN] Serial number too short: %s\n", serialNumber);
                            }
                        } else {
                            wprintf(L"[WARN] Failed to read serial number\n");
                        }
                        break;
                    }
                }
                if (hTemp != hDevice) CloseHandle(hTemp);
            }
        }
        free(detailData);
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        wprintf(L"[INFO] No Rockey2 device found - will run in offline mode if cache exists\n");
        return false;  // 让调用者检查缓存
    }
    
    wprintf(L"\n[CACHE] Reading device data (16 blocks)...\n");
    
    // 读取16个数据块
    BYTE partition0[8][64] = {0};
    BYTE partition1[8][64] = {0};
    
    for (int partition = 0; partition < 2; partition++) {
        for (int miniBlock = 0; miniBlock < 8; miniBlock++) {
            BYTE report[73] = {0};
            
            // Feature Report格式 (参考hid_ops.rs和main.rs):
            // Byte[0]: Report ID (0x00)
            // Byte[1]: Reserved (request) / Error code (response)
            // Byte[2]: Command (0x81=read, 0x82=write)
            // Byte[3]: Partition index (0-4)
            // Byte[4]: Mini-block index (0-7)
            // Byte[5-8]: UID (little-endian)
            // Byte[9-72]: Data payload (64 bytes)
            
            report[0] = 0x00;  // Report ID
            report[1] = 0x00;  // Reserved
            report[2] = 0x81;  // Read command
            report[3] = partition;     // Partition
            report[4] = miniBlock;     // Mini-block
            memcpy(report + 5, &deviceUid, 4);  // UID (little-endian)
            
            // 发送请求
            if (!HidD_SetFeature(hDevice, report, 73)) {
                wprintf(L"  [ERROR] SetFeature failed for P%d MB%d (Error: %lu)\n", 
                       partition, miniBlock, GetLastError());
                continue;
            }
            
            // 刷新队列 (关键步骤!)
            HidD_FlushQueue(hDevice);
            
            // 读取响应
            ZeroMemory(report, 73);
            if (!HidD_GetFeature(hDevice, report, 73)) {
                wprintf(L"  [ERROR] GetFeature failed for P%d MB%d (Error: %lu)\n", 
                       partition, miniBlock, GetLastError());
                continue;
            }
            
            // 检查响应错误码 (Byte[1])
            if (report[1] != 0) {
                wprintf(L"  [ERROR] Device returned error code 0x%02X for P%d MB%d\n", 
                       report[1], partition, miniBlock);
                continue;
            }
            
            // 复制数据 (Byte[9-72])
            if (partition == 0)
                memcpy(partition0[miniBlock], report + 9, 64);
            else
                memcpy(partition1[miniBlock], report + 9, 64);
                
            wprintf(L"  [%d/%d] Partition %d, Block %d - OK\n", 
                   partition * 8 + miniBlock + 1, 16, partition, miniBlock);
        }
    }
    
    CloseHandle(hDevice);
    
    // 更新扇区1的校验和和年检信息
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentYear = st.wYear;
    
    wprintf(L"\n[UPDATE] Updating sector1 checksum...\n");
    UpdateSector1Checksum((BYTE*)partition1, deviceUid, deviceHid, currentYear);
    
    // 保存缓存文件
    wprintf(L"\n[SAVE] Writing cache files...\n");
    
    // 1. <HID>_device.cfg
    wchar_t configPath[MAX_PATH];
    swprintf_s(configPath, L"%s%u_device.cfg", cacheDir, deviceHid);
    FILE* fp = _wfopen(configPath, L"w");
    if (fp) {
        // 计算序列号: HID + (HID_reversed XOR UID)
        // HID字节反转: [A B C D] -> [D C B A]
        BYTE* hidBytes = (BYTE*)&deviceHid;
        DWORD hidReversed = (hidBytes[3] << 24) | (hidBytes[2] << 16) | (hidBytes[1] << 8) | hidBytes[0];
        DWORD serialPart2 = hidReversed ^ deviceUid;
        
        fprintf(fp, "VID=0x096E\n");
        fprintf(fp, "PID=0x0201\n");
        fprintf(fp, "Version=0x0100\n");
        fprintf(fp, "ProductString=USB DONGLE\n");
        fprintf(fp, "SerialNumberString=%08X%08X\n", deviceHid, serialPart2);
        fprintf(fp, "HID=0x%08X\n", deviceHid);
        fprintf(fp, "UID=0x%08X\n", deviceUid);
        fprintf(fp, "FeatureReportLength=73\n");
        fprintf(fp, "InputReportLength=73\n");
        fprintf(fp, "OutputReportLength=73\n");
        fprintf(fp, "Usage=1\n");
        fprintf(fp, "UsagePage=1\n");
        fclose(fp);
        wprintf(L"  [OK] %s\n", configPath);
    } else {
        wprintf(L"  [ERROR] Failed to create %s\n", configPath);
    }
    
    // 2. mem_*_sector0.dat
    swprintf_s(configPath, L"%smem_%u_sector0.dat", cacheDir, deviceUid);
    fp = _wfopen(configPath, L"wb");
    if (fp) {
        fwrite(partition0, 1, 512, fp);
        fclose(fp);
        wprintf(L"  [OK] mem_%u_sector0.dat (512 bytes)\n", deviceUid);
    } else {
        wprintf(L"  [ERROR] Failed to create mem_%u_sector0.dat\n", deviceUid);
    }
    
    // 3. mem_*_sector1.dat
    swprintf_s(configPath, L"%smem_%u_sector1.dat", cacheDir, deviceUid);
    fp = _wfopen(configPath, L"wb");
    if (fp) {
        fwrite(partition1, 1, 512, fp);
        fclose(fp);
        wprintf(L"  [OK] mem_%u_sector1.dat (512 bytes)\n", deviceUid);
    } else {
        wprintf(L"  [ERROR] Failed to create mem_%u_sector1.dat\n", deviceUid);
    }
    
    wprintf(L"\n[SUCCESS] Cache generated successfully!\n");
    wprintf(L"========================================\n\n");
    return true;
}

// Windows 控制台程序入口点
int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"========================================\n");
    wprintf(L"  HID Hook Launcher (Console Mode)\n");
    wprintf(L"========================================\n\n");

    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        wprintf(L"[ERROR] Administrator privileges required!\n");
        wprintf(L"Please run this program as Administrator.\n\n");
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }

    wprintf(L"[OK] Running with administrator privileges\n\n");

    // 获取 launcher 所在目录
    wchar_t launcherPath[MAX_PATH];
    wchar_t launcherDir[MAX_PATH];
    GetModuleFileNameW(NULL, launcherPath, MAX_PATH);
    wcscpy_s(launcherDir, launcherPath);
    wchar_t* lastSlash = wcsrchr(launcherDir, L'\\');
    if (lastSlash) {
        *(lastSlash + 1) = L'\0';  // 保留反斜杠
    }

    // 解析命令行参数或使用默认值
    wchar_t targetExe[MAX_PATH] = L"Xsjzb.exe";  // 默认目标
    
    // 如果有命令行参数，使用第一个参数作为目标程序
    if (argc > 1) {
        wcscpy_s(targetExe, argv[1]);
        wprintf(L"[INFO] Target from command line: %s\n", targetExe);
    } else {
        wprintf(L"[INFO] Using default target: %s\n", targetExe);
    }
    
    // 构建完整路径
    wchar_t targetExePath[MAX_PATH];
    wchar_t hookDllPath[MAX_PATH];
    
    // 如果 targetExe 是绝对路径，直接使用；否则相对于 launcher 目录
    if (targetExe[1] == L':' || (targetExe[0] == L'\\' && targetExe[1] == L'\\')) {
        // 已经是绝对路径
        wcscpy_s(targetExePath, targetExe);
    } else {
        // 相对路径，组合 launcher 目录
        swprintf_s(targetExePath, L"%s%s", launcherDir, targetExe);
    }
    
    // DLL 总是在 launcher 同目录
    swprintf_s(hookDllPath, L"%shid_hook.dll", launcherDir);

    // 生成缓存（在注入DLL之前）
    wprintf(L"[CACHE] Checking cache status...\n");
    
    // 先检查是否已有缓存文件 (查找 cache 目录中的 *_device.cfg)
    wchar_t cacheDir[MAX_PATH];
    swprintf_s(cacheDir, L"%scache\\", launcherDir);
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, L"%s*_device.cfg", cacheDir);
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath, &findData);
    bool hasCacheFile = (hFind != INVALID_HANDLE_VALUE);
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
    }
    
    if (hasCacheFile) {
        wprintf(L"[OK] Existing cache found\n");
        wprintf(L"[OK] Will use existing cache for offline operation\n\n");
    } else {
        // 没有缓存,尝试从真实设备生成
        wprintf(L"[INFO] No cache found, trying to read from real device...\n");
        bool cacheGenerated = GenerateCacheFromDevice(launcherDir);
        
        if (cacheGenerated) {
            wprintf(L"[OK] Cache generated from real device\n\n");
        } else {
            // 没有真实设备也没有缓存,生成虚拟缓存
            wprintf(L"\n========================================\n");
            wprintf(L"[WARNING] No USB device detected!\n");
            wprintf(L"[WARNING] No existing cache found!\n");
            wprintf(L"========================================\n\n");
            wprintf(L"Would you like to generate a virtual cache? (Y/N): ");
            
            wchar_t choice = _getwch();
            wprintf(L"%c\n", choice);
            
            if (choice == L'Y' || choice == L'y') {
                wprintf(L"\nPlease enter software key (4 Chinese characters): ");
                
                wchar_t userName[32] = {0};
                
                // 设置控制台为 Unicode 模式
                _setmode(_fileno(stdin), _O_U16TEXT);
                _setmode(_fileno(stdout), _O_U16TEXT);
                
                // 读取 Unicode 输入
                if (fgetws(userName, _countof(userName), stdin) != NULL) {
                    // 恢复正常模式
                    _setmode(_fileno(stdin), _O_TEXT);
                    _setmode(_fileno(stdout), _O_TEXT);
                    
                    // 去除末尾的换行符
                    size_t len = wcslen(userName);
                    if (len > 0 && userName[len - 1] == L'\n') {
                        userName[len - 1] = L'\0';
                        len--;
                    }
                    
                    if (len > 0) {
                        wprintf(L"[INFO] Generating cache for: %s\n", userName);
                        wprintf(L"[DEBUG] Calling GenerateVirtualCache with launcherDir='%s'\n", launcherDir);
                        
                        if (GenerateVirtualCache(launcherDir, userName)) {
                            wprintf(L"[OK] Virtual cache generated successfully!\n\n");
                            // 缓存生成后不立即退出，继续检查目标程序
                        } else {
                            wprintf(L"\n[ERROR] Failed to generate virtual cache\n");
                            wprintf(L"Press any key to exit...\n");
                            _getwch();
                            return 1;
                        }
                    } else {
                        // 用户输入为空
                        wprintf(L"\n[WARNING] No user name provided, cache generation cancelled.\n");
                        wprintf(L"[INFO] Cannot run without cache. Exiting...\n\n");
                        wprintf(L"Press any key to exit...\n");
                        _getwch();
                        return 1;
                    }
                } else {
                    // 读取失败
                    wprintf(L"\n[ERROR] Failed to read input.\n");
                    wprintf(L"Press any key to exit...\n");
                    _getwch();
                    return 1;
                }
            } else {
                wprintf(L"[WARNING] Application may show 'device not found' error\n\n");
            }
        }
    }

    // 预加载系统DLL到当前进程（确保它们在内存中，减轻目标进程负担）
    wprintf(L"[PRELOAD] Loading system DLLs into memory...\n");
    HMODULE hHid = LoadLibraryW(L"hid.dll");
    HMODULE hSetupApi = LoadLibraryW(L"setupapi.dll");
    if (hHid && hSetupApi) {
        wprintf(L"[OK] System DLLs loaded (hid.dll, setupapi.dll)\n\n");
    } else {
        wprintf(L"[WARNING] Failed to preload system DLLs\n\n");
    }

    wprintf(L"\n[CHECK] Verifying files...\n");
    wprintf(L"  Target EXE: %s\n", targetExePath);
    wprintf(L"  Hook DLL:   %s\n\n", hookDllPath);

    // 检查文件是否存在
    if (GetFileAttributesW(targetExePath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[INFO] Target executable not found: %s\n", targetExe);
        wprintf(L"[OK] Cache has been prepared.\n");
        wprintf(L"[INFO] To run the application:\n");
        wprintf(L"  1. Copy '%s' to: %s\n", targetExe, launcherDir);
        wprintf(L"  2. Run this launcher again\n");
        wprintf(L"\nPress any key to exit...\n");
        _getwch();
        return 0;
    }
    wprintf(L"[OK] Target executable found\n");

    if (GetFileAttributesW(hookDllPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[ERROR] hid_hook.dll not found!\n");
        wprintf(L"  Path: %s\n\n", hookDllPath);
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }
    wprintf(L"[OK] hid_hook.dll found\n\n");

    wprintf(L"[STEP 1] Creating suspended process...\n");
    
    // 准备启动信息 - 正常显示窗口（适用于 GUI 应用）
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    // 创建挂起的进程（保持 GUI 窗口可见）
    if (!CreateProcessW(
        targetExePath,      // Application name (完整路径)
        NULL,               // Command line
        NULL,               // Process security attributes
        NULL,               // Thread security attributes
        FALSE,              // Inherit handles
        CREATE_SUSPENDED,   // 挂起状态创建（注入后恢复）
        NULL,               // Environment
        NULL,               // Current directory
        &si,                // Startup info
        &pi                 // Process information
    )) {
        wprintf(L"[ERROR] Failed to create target process!\n");
        wprintf(L"  Error code: %lu\n\n", GetLastError());
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }
    wprintf(L"[OK] Process created (PID: %lu, suspended)\n\n", pi.dwProcessId);

    // 在目标进程中分配内存
    size_t dllPathSize = (wcslen(hookDllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(
        pi.hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pRemotePath) {
        wprintf(L"[ERROR] Failed to allocate memory in target process!\n");
        wprintf(L"  Error code: %lu\n\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }
    wprintf(L"[STEP 2] Allocated %zu bytes at 0x%p\n", dllPathSize, pRemotePath);

    // 写入 DLL 路径
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemotePath, hookDllPath, dllPathSize, &bytesWritten)) {
        wprintf(L"[ERROR] Failed to write DLL path to target process!\n");
        wprintf(L"  Error code: %lu\n\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }
    wprintf(L"[STEP 3] Wrote DLL path (%zu bytes)\n", bytesWritten);

    // 获取 LoadLibraryW 地址
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!pLoadLibraryW) {
        wprintf(L"[ERROR] Failed to get LoadLibraryW address!\n\n");
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }
    wprintf(L"[STEP 4] Got LoadLibraryW at 0x%p\n", pLoadLibraryW);

    // 创建远程线程加载 DLL
    wprintf(L"[STEP 5] Creating remote thread to load DLL...\n");
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        pLoadLibraryW,
        pRemotePath,
        0,
        NULL
    );

    if (!hThread) {
        wprintf(L"[ERROR] Failed to create remote thread!\n");
        wprintf(L"  Error code: %lu\n\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        wprintf(L"Press any key to exit...\n");
        _getwch();
        return 1;
    }

    // 等待 LoadLibrary 完成
    wprintf(L"[STEP 6] Waiting for DLL to load...\n");
    WaitForSingleObject(hThread, INFINITE);

    // 获取 LoadLibrary 返回值
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);

    // 清理远程内存
    VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);

    if (exitCode == 0) {
        wprintf(L"[WARNING] DLL injection may have failed (LoadLibrary returned NULL)\n");
        wprintf(L"  This might cause the application to malfunction.\n\n");
    } else {
        wprintf(L"[OK] DLL loaded successfully at 0x%08lX\n\n", exitCode);
    }

    // 恢复主线程执行
    wprintf(L"[STEP 7] Resuming main thread...\n");
    ResumeThread(pi.hThread);
    wprintf(L"[OK] Target process is now running (PID: %lu)\n\n", pi.dwProcessId);

    // 关闭句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"========================================\n");
    wprintf(L"Injection complete!\n");
    wprintf(L"Target process is running (PID: %lu)\n", pi.dwProcessId);
    wprintf(L"Check hid_hook.log for detailed activity.\n");
    wprintf(L"========================================\n");
    return 0;
}
