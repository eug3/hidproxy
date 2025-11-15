#include "hid_hooks.h"
#include "logging.h"
#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <vector>
#include <string>

static const USHORT kTargetVendorId = 0x096E;
static const USHORT kTargetProductId = 0x0201;
static const USHORT kVirtualVersion = 0x0100;
//USB\VID_096E&PID_0201 飞天诚信(ftsafe) 飞天2无驱型 加密锁 rockey 2 ROCKEY2 R2
static bool g_hasPhysicalTargetDevice = false;
static bool g_virtualDeviceEnabled = false;
static bool g_virtualIdentityConfigured = false;
static DWORD g_virtualIdentityHid = 0;
static DWORD g_virtualIdentityUid = 0;
static bool g_virtualSectorAvailable[5] = { false, false, false, false, false };
static std::wstring g_cacheDirectory;

// 全局缓存数据
static CachedHidData g_hidCache = { 0 };
static bool g_cacheLoadAttempted = false;  // 延迟加载标志
static std::vector<HANDLE> g_hijackedHandles;  // 保存所有被劫持的句柄
static CRITICAL_SECTION g_hijackedHandlesCs;  // 保护句柄列表的临界区

// 初始化临界区(只调用一次)
static void InitHijackedHandles() {
    static bool initialized = false;
    if (!initialized) {
        InitializeCriticalSection(&g_hijackedHandlesCs);
        initialized = true;
    }
}

// 检查句柄是否被劫持
static bool IsHijackedHandle(HANDLE h) {
    EnterCriticalSection(&g_hijackedHandlesCs);
    bool found = std::find(g_hijackedHandles.begin(), g_hijackedHandles.end(), h) != g_hijackedHandles.end();
    LeaveCriticalSection(&g_hijackedHandlesCs);
    return found;
}

// 延迟加载缓存（线程安全）
static void EnsureCacheLoaded() {
    if (g_cacheLoadAttempted) {
        return;  // 已经尝试过加载了
    }
    
    // 使用静态局部变量实现一次性初始化
    static LONG initFlag = 0;
    if (InterlockedCompareExchange(&initFlag, 1, 0) == 0) {
        // 第一次调用时初始化日志
        InitializeLogging();
        
        // 记录进程信息
        wchar_t processPath[MAX_PATH];
        GetModuleFileNameW(NULL, processPath, MAX_PATH);
        wchar_t logMsg[512];
        swprintf_s(logMsg, 512, L"[INIT] Target Process: %s", processPath);
        LogMessage(logMsg);
        swprintf_s(logMsg, 512, L"[INIT] DLL Base: 0x%p", g_hModule);
        LogMessage(logMsg);
        
        LogMessage(L"[LAZY INIT] First HID API call - loading cache now...");
        
        // 加载缓存文件
        std::wstring cacheDir = GetCacheDirectory();
        WIN32_FIND_DATAW findData;
        wchar_t searchPath[MAX_PATH];
        swprintf_s(searchPath, L"%s*_device.cfg", cacheDir.c_str());
        
        HANDLE hFind = FindFirstFileW(searchPath, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            // 找到配置文件
            wchar_t configPath[MAX_PATH];
            swprintf_s(configPath, L"%s%s", cacheDir.c_str(), findData.cFileName);
            
            FILE* fp = _wfopen(configPath, L"r");
            if (fp) {
                char line[512];
                while (fgets(line, sizeof(line), fp)) {
                    if (strncmp(line, "HID=", 4) == 0) {
                        // 兼容十六进制 (0x...) 和十进制格式
                        const char* value = line + 4;
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            sscanf_s(value, "0x%X", &g_hidCache.cachedHid);
                        } else {
                            sscanf_s(value, "%u", &g_hidCache.cachedHid);
                        }
                    } else if (strncmp(line, "UID=", 4) == 0) {
                        // 兼容十六进制 (0x...) 和十进制格式
                        const char* value = line + 4;
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            sscanf_s(value, "0x%X", &g_hidCache.cachedUid);
                        } else {
                            sscanf_s(value, "%u", &g_hidCache.cachedUid);
                        }
                    } else if (strncmp(line, "VID=", 4) == 0 || strncmp(line, "VendorID=", 9) == 0) {
                        // 兼容 VID= 和 VendorID=, 以及十六进制和十进制
                        const char* value = (line[1] == 'I') ? (line + 4) : (line + 9);
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            sscanf_s(value, "0x%hX", &g_hidCache.vendorId);
                        } else {
                            sscanf_s(value, "%hu", &g_hidCache.vendorId);
                        }
                    } else if (strncmp(line, "PID=", 4) == 0 || strncmp(line, "ProductID=", 10) == 0) {
                        // 兼容 PID= 和 ProductID=, 以及十六进制和十进制
                        const char* value = (line[1] == 'I') ? (line + 4) : (line + 10);
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            sscanf_s(value, "0x%hX", &g_hidCache.productId);
                        } else {
                            sscanf_s(value, "%hu", &g_hidCache.productId);
                        }
                    } else if (strncmp(line, "Version=", 8) == 0 || strncmp(line, "VersionNumber=", 14) == 0) {
                        // 兼容 Version= 和 VersionNumber=, 以及十六进制和十进制
                        const char* value = (line[7] == '=') ? (line + 8) : (line + 14);
                        if (strncmp(value, "0x", 2) == 0 || strncmp(value, "0X", 2) == 0) {
                            sscanf_s(value, "0x%hX", &g_hidCache.versionNumber);
                        } else {
                            sscanf_s(value, "%hu", &g_hidCache.versionNumber);
                        }
                    } else if (strncmp(line, "ProductString=", 14) == 0) {
                        char productStr[256];
                        strncpy_s(productStr, sizeof(productStr), line + 14, _TRUNCATE);
                        // 去除行尾换行符
                        size_t len = strlen(productStr);
                        if (len > 0 && (productStr[len-1] == '\n' || productStr[len-1] == '\r')) {
                            productStr[len-1] = '\0';
                        }
                        if (len > 1 && (productStr[len-2] == '\n' || productStr[len-2] == '\r')) {
                            productStr[len-2] = '\0';
                        }
                        MultiByteToWideChar(CP_ACP, 0, productStr, -1, g_hidCache.productString, 256);
                    } else if (strncmp(line, "SerialNumberString=", 19) == 0) {
                        char serialStr[256];
                        strncpy_s(serialStr, sizeof(serialStr), line + 19, _TRUNCATE);
                        // 去除行尾换行符
                        size_t len = strlen(serialStr);
                        if (len > 0 && (serialStr[len-1] == '\n' || serialStr[len-1] == '\r')) {
                            serialStr[len-1] = '\0';
                        }
                        if (len > 1 && (serialStr[len-2] == '\n' || serialStr[len-2] == '\r')) {
                            serialStr[len-2] = '\0';
                        }
                        MultiByteToWideChar(CP_ACP, 0, serialStr, -1, g_hidCache.serialNumberString, 256);
                    } else if (strncmp(line, "FeatureReportLength=", 20) == 0) {
                        sscanf_s(line + 20, "%hu", &g_hidCache.featureReportLength);
                    } else if (strncmp(line, "InputReportLength=", 18) == 0) {
                        sscanf_s(line + 18, "%hu", &g_hidCache.inputReportLength);
                    } else if (strncmp(line, "OutputReportLength=", 19) == 0) {
                        sscanf_s(line + 19, "%hu", &g_hidCache.outputReportLength);
                    } else if (strncmp(line, "Usage=", 6) == 0) {
                        sscanf_s(line + 6, "%hu", &g_hidCache.usage);
                    } else if (strncmp(line, "UsagePage=", 10) == 0) {
                        sscanf_s(line + 10, "%hu", &g_hidCache.usagePage);
                    }
                }
                fclose(fp);
                
                // 加载数据块文件
                wchar_t dataPath[MAX_PATH];
                swprintf_s(dataPath, L"%smem_%u_sector0.dat", cacheDir.c_str(), g_hidCache.cachedUid);
                fp = _wfopen(dataPath, L"rb");
                if (fp) {
                    fread(g_hidCache.partition0, 1, 512, fp);
                    fclose(fp);
                }
                
                swprintf_s(dataPath, L"%smem_%u_sector1.dat", cacheDir.c_str(), g_hidCache.cachedUid);
                fp = _wfopen(dataPath, L"rb");
                if (fp) {
                    fread(g_hidCache.partition1, 1, 512, fp);
                    fclose(fp);
                }
                
                g_hidCache.isValid = true;
            }
            FindClose(hFind);
        }
        
        g_cacheLoadAttempted = true;
        LogMessage(g_hidCache.isValid ? 
                   L"[LAZY INIT] Cache loaded successfully" : 
                   L"[LAZY INIT] Cache load failed - using passthrough mode");
    }
}


const std::wstring& GetCacheDirectory() {
    if (!g_cacheDirectory.empty()) {
        return g_cacheDirectory;
    }
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(g_hModule, path, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(path, L'\\');
    if (lastSlash) {
        *(lastSlash + 1) = 0;
    }
    g_cacheDirectory = path;
    g_cacheDirectory += L"cache\\";  // 添加cache子目录
    return g_cacheDirectory;
}

std::wstring GetConfigFilePath() {
    std::wstring path = GetCacheDirectory();
    path += L"virtual_device.cfg";
    return path;
}

static std::wstring BuildSectorFilePath(DWORD uidValue, BYTE sector) {
    wchar_t buffer[MAX_PATH];
    swprintf_s(buffer, MAX_PATH, L"%smem_%u_sector%d.dat", GetCacheDirectory().c_str(), uidValue, sector);
    return buffer;
}

// UID 数据采集结构
struct UidDataCollector {
    BYTE uid[4];           // UID (小端序)
    BYTE sectors[5][512];  // 5个区的数据 (区0-4)
    bool sectorReceived[5][8]; // 每个区的8个块是否已接收
    bool hasUid;
    CRITICAL_SECTION cs;
    
    // 缓存相关
    BYTE pendingReadSector;  // 待读取的区
    BYTE pendingReadBlock;   // 待读取的块
    bool useCacheForNextRead; // 下一次读取是否使用缓存
    BYTE cachedData[512];    // 缓存的区数据
    bool hasCachedData;      // 是否有缓存数据
    BYTE requestUid[4];      // 最近请求的 UID
    bool hasRequestUid;
    
    UidDataCollector() : hasUid(false), useCacheForNextRead(false), hasCachedData(false),
                        pendingReadSector(0xFF), pendingReadBlock(0xFF), hasRequestUid(false) {
        memset(uid, 0, sizeof(uid));
        memset(sectors, 0, sizeof(sectors));
        memset(sectorReceived, 0, sizeof(sectorReceived));
        memset(cachedData, 0, sizeof(cachedData));
        memset(requestUid, 0, sizeof(requestUid));
        InitializeCriticalSection(&cs);
    }
    
    ~UidDataCollector() {
        DeleteCriticalSection(&cs);
    }
};

static UidDataCollector g_uidCollector;

struct VirtualFeatureContext {
    BYTE sector;
    BYTE block;
    bool usedCache;
};

static bool BuildVirtualFeatureReport(PVOID reportBuffer, ULONG reportLength, VirtualFeatureContext* context) {
    if (!reportBuffer || reportLength < 9) {
        return false;
    }
    BYTE localUid[4] = {};
    BYTE cachedBlock[64] = {};
    BYTE sector = 0;
    BYTE block = 0;
    bool usedCache = false;
    EnterCriticalSection(&g_uidCollector.cs);
    if (g_uidCollector.pendingReadSector != 0xFF) {
        sector = g_uidCollector.pendingReadSector;
    }
    if (g_uidCollector.pendingReadBlock != 0xFF && g_uidCollector.pendingReadBlock < 8) {
        block = g_uidCollector.pendingReadBlock;
    }
    if (g_uidCollector.hasUid) {
        memcpy(localUid, g_uidCollector.uid, sizeof(localUid));
    } else if (g_uidCollector.hasRequestUid) {
        memcpy(localUid, g_uidCollector.requestUid, sizeof(localUid));
    }
    if (g_uidCollector.hasCachedData && block < 8 && g_uidCollector.useCacheForNextRead) {
        memcpy(cachedBlock, &g_uidCollector.cachedData[block * 64], sizeof(cachedBlock));
        usedCache = true;
    }
    g_uidCollector.useCacheForNextRead = false;
    LeaveCriticalSection(&g_uidCollector.cs);

    BYTE* dst = static_cast<BYTE*>(reportBuffer);
    ZeroMemory(dst, reportLength);
    dst[0] = 0x00;
    dst[1] = 0x00;
    dst[2] = 0x81;
    dst[3] = sector;
    dst[4] = block;
    memcpy(&dst[5], localUid, sizeof(localUid));

    ULONG payloadOffset = 9;
    if (reportLength > payloadOffset) {
        ULONG payloadSize = min((ULONG)64, reportLength - payloadOffset);
        memcpy(&dst[payloadOffset], cachedBlock, payloadSize);
    }

    if (context) {
        context->sector = sector;
        context->block = block;
        context->usedCache = usedCache;
    }
    return true;
}

static bool CopyVirtualSectorToCache(BYTE sector) {
    if (sector >= 5) {
        return false;
    }
    bool copied = false;
    EnterCriticalSection(&g_uidCollector.cs);
    if (g_virtualIdentityConfigured && g_virtualSectorAvailable[sector]) {
        memcpy(g_uidCollector.cachedData, g_uidCollector.sectors[sector], sizeof(g_uidCollector.cachedData));
        g_uidCollector.hasCachedData = true;
        copied = true;
    }
    LeaveCriticalSection(&g_uidCollector.cs);
    return copied;
}

static bool ComputeMd5Hash(const BYTE* data, DWORD length, BYTE output[16]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }
    BOOL ok = CryptHashData(hHash, data, length, 0);
    DWORD hashLen = 16;
    if (ok) {
        ok = CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return ok == TRUE;
}

static std::string BytesToHexUpper(const BYTE* data, size_t length) {
    static const char* hex = "0123456789ABCDEF";
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(hex[(data[i] >> 4) & 0x0F]);
        result.push_back(hex[data[i] & 0x0F]);
    }
    return result;
}

static std::string GenerateVirtualChecksumString(DWORD uidValue, DWORD hidValue, int year) {
    std::string uidStr = std::to_string(static_cast<unsigned long>(uidValue));
    std::string hidStr = std::to_string(static_cast<unsigned long>(hidValue));
    std::string yearStr = std::to_string(year);
    std::string input = "1" + uidStr + "12" + hidStr + yearStr;
    BYTE hash[16] = {};
    if (!ComputeMd5Hash(reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()), hash)) {
        return "0" + std::string(32, '0');
    }
    std::string md5Hex = BytesToHexUpper(hash, 16);
    return "0" + md5Hex;
}

static bool DetectTargetHidDevice() {
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);
    HDEVINFO deviceInfo = SetupDiGetClassDevsW(&hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfo == INVALID_HANDLE_VALUE) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"[DEVICE] SetupDiGetClassDevs failed: %lu", GetLastError());
        LogMessage(msg);
        return false;
    }
    bool found = false;
    SP_DEVICE_INTERFACE_DATA interfaceData = {};
    interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    for (DWORD index = 0;; ++index) {
        if (!SetupDiEnumDeviceInterfaces(deviceInfo, NULL, &hidGuid, index, &interfaceData)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                wchar_t err[256];
                swprintf_s(err, 256, L"[DEVICE] SetupDiEnumDeviceInterfaces error: %lu", GetLastError());
                LogMessage(err);
            }
            break;
        }
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(deviceInfo, &interfaceData, NULL, 0, &requiredSize, NULL);
        if (requiredSize == 0) {
            continue;
        }
        std::vector<BYTE> detailBuffer(requiredSize);
        auto detailData = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(detailBuffer.data());
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(deviceInfo, &interfaceData, detailData, requiredSize, NULL, NULL)) {
            wchar_t err[256];
            swprintf_s(err, 256, L"[DEVICE] SetupDiGetDeviceInterfaceDetail failed: %lu", GetLastError());
            LogMessage(err);
            continue;
        }
        HANDLE deviceHandle = CreateFileW(detailData->DevicePath, GENERIC_READ | GENERIC_WRITE,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, NULL);
        if (deviceHandle == INVALID_HANDLE_VALUE) {
            continue;
        }
        HIDD_ATTRIBUTES attributes = {};
        attributes.Size = sizeof(HIDD_ATTRIBUTES);
        if (HidD_GetAttributes(deviceHandle, &attributes)) {
            if (attributes.VendorID == kTargetVendorId && attributes.ProductID == kTargetProductId) {
                found = true;
                CloseHandle(deviceHandle);
                break;
            }
        }
        CloseHandle(deviceHandle);
    }
    SetupDiDestroyDeviceInfoList(deviceInfo);
    wchar_t msg[256];
    if (found) {
        swprintf_s(msg, 256, L"[DEVICE] Physical target HID detected (VID_%04X&PID_%04X)",
                    kTargetVendorId, kTargetProductId);
    } else {
        swprintf_s(msg, 256, L"[DEVICE] No VID_%04X&PID_%04X device detected, virtualization enabled",
                    kTargetVendorId, kTargetProductId);
    }
    LogMessage(msg);
    return found;
}

void InitializeVirtualDeviceState() {
    g_hasPhysicalTargetDevice = DetectTargetHidDevice();
    g_virtualDeviceEnabled = !g_hasPhysicalTargetDevice;
}

bool IsVirtualDeviceActive() {
    return g_virtualDeviceEnabled;
}

void ConfigureVirtualDeviceIdentity(DWORD hidValue, DWORD uidValue) {
    EnterCriticalSection(&g_uidCollector.cs);
    g_uidCollector.uid[0] = static_cast<BYTE>(uidValue & 0xFF);
    g_uidCollector.uid[1] = static_cast<BYTE>((uidValue >> 8) & 0xFF);
    g_uidCollector.uid[2] = static_cast<BYTE>((uidValue >> 16) & 0xFF);
    g_uidCollector.uid[3] = static_cast<BYTE>((uidValue >> 24) & 0xFF);
    memcpy(g_uidCollector.requestUid, g_uidCollector.uid, sizeof(g_uidCollector.uid));
    g_uidCollector.hasUid = true;
    g_uidCollector.hasRequestUid = true;
    LeaveCriticalSection(&g_uidCollector.cs);

    g_virtualIdentityConfigured = true;
    g_virtualIdentityHid = hidValue;
    g_virtualIdentityUid = uidValue;

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[VIRTUAL] HID identity configured: HID=0x%08X UID=0x%08X",
              hidValue, uidValue);
    LogMessage(msg);
}

static void WriteAsciiToBuffer(BYTE* buffer, size_t bufferSize, const std::string& text) {
    if (!buffer || bufferSize == 0) {
        return;
    }
    size_t bytesToCopy = text.size() < bufferSize ? text.size() : bufferSize;
    memcpy(buffer, text.data(), bytesToCopy);
}

void GenerateVirtualSectorsFromIdentity(DWORD hidValue, DWORD uidValue, int year) {
    std::string uidDec = std::to_string(static_cast<unsigned long>(uidValue));
    std::string hidDec = std::to_string(static_cast<unsigned long>(hidValue));
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentYear = year != 0 ? year : st.wYear;
    std::string checksum = GenerateVirtualChecksumString(uidValue, hidValue, currentYear);

    EnterCriticalSection(&g_uidCollector.cs);
    ZeroMemory(g_uidCollector.sectors[0], sizeof(g_uidCollector.sectors[0]));
    ZeroMemory(g_uidCollector.sectors[1], sizeof(g_uidCollector.sectors[1]));

    // Sector 0 - metadata and UID/HID information
    memcpy(&g_uidCollector.sectors[0][0], &uidValue, sizeof(uidValue));
    memcpy(&g_uidCollector.sectors[0][4], &hidValue, sizeof(hidValue));
    WriteAsciiToBuffer(&g_uidCollector.sectors[0][16], 32, "UID:" + uidDec);
    WriteAsciiToBuffer(&g_uidCollector.sectors[0][48], 32, "HID:" + hidDec);

    // Sector 1 - checksum and status information
    WriteAsciiToBuffer(&g_uidCollector.sectors[1][0], 32, "VIRTUAL CARD");
    WriteAsciiToBuffer(&g_uidCollector.sectors[1][32], 32, "YEAR:" + std::to_string(currentYear));
    WriteAsciiToBuffer(&g_uidCollector.sectors[1][64], 64, "UID:" + uidDec);
    WriteAsciiToBuffer(&g_uidCollector.sectors[1][128], 64, "HID:" + hidDec);
    WriteAsciiToBuffer(&g_uidCollector.sectors[1][2 * 64], 64, checksum);

    for (int block = 0; block < 8; ++block) {
        g_uidCollector.sectorReceived[0][block] = true;
        g_uidCollector.sectorReceived[1][block] = true;
    }
    g_virtualSectorAvailable[0] = true;
    g_virtualSectorAvailable[1] = true;
    LeaveCriticalSection(&g_uidCollector.cs);

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[VIRTUAL] Generated sector data (year=%d)", currentYear);
    LogMessage(msg);
}

// 检查并加载缓存文件
bool LoadCacheIfExists(BYTE sector, const BYTE* uid) {
    if (!uid || sector > 4) {
        return false;
    }

    DWORD uidValue = static_cast<DWORD>(uid[0]) |
                     (static_cast<DWORD>(uid[1]) << 8) |
                     (static_cast<DWORD>(uid[2]) << 16) |
                     (static_cast<DWORD>(uid[3]) << 24);
    std::wstring filePath = BuildSectorFilePath(uidValue, sector);

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BYTE localBuffer[512] = {};
        DWORD bytesRead = 0;
        bool success = ReadFile(hFile, localBuffer, sizeof(localBuffer), &bytesRead, NULL);
        CloseHandle(hFile);
        if (success && bytesRead == sizeof(localBuffer)) {
            EnterCriticalSection(&g_uidCollector.cs);
            memcpy(g_uidCollector.cachedData, localBuffer, sizeof(localBuffer));
            g_uidCollector.hasCachedData = true;
            LeaveCriticalSection(&g_uidCollector.cs);
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHE] Loaded sector %d from cache: %s", sector, filePath.c_str());
            LogMessage(msg);
            return true;
        }
    }

    if (g_virtualDeviceEnabled && g_virtualIdentityConfigured) {
        if (CopyVirtualSectorToCache(sector)) {
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[VIRTUAL] Using synthesized data for sector %d", sector);
            LogMessage(msg);
            return true;
        }
    }
    return false;
}

// 处理 UID 数据
void ProcessUidData(const BYTE* data, ULONG length) {
    if (!data || length < 9) return;
    
    // 检查是否是读命令响应: 00 00 81 [区] [块] [数据...]
    if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x81) {
        BYTE sector = data[3];
        BYTE block = data[4];
        
        wchar_t debugMsg[256];
        swprintf_s(debugMsg, 256, L"[DEBUG] Read response: Sector=%d, Block=%d, Length=%u", sector, block, length);
        LogMessage(debugMsg);
        
        // 只处理区 0-4
        if (sector > 4) {
            swprintf_s(debugMsg, 256, L"[DEBUG] Skipping sector %d (>4)", sector);
            LogMessage(debugMsg);
            return;
        }
        
        EnterCriticalSection(&g_uidCollector.cs);
        
        // 提取 UID (小端序) 从偏移 5 开始的 4 字节
        if (!g_uidCollector.hasUid && length >= 9) {
            memcpy(g_uidCollector.uid, &data[5], 4);
            g_uidCollector.hasUid = true;
            
            wchar_t msg[128];
            swprintf_s(msg, 128, L"[UID] Extracted: %02X %02X %02X %02X (Little Endian)",
                      g_uidCollector.uid[0], g_uidCollector.uid[1],
                      g_uidCollector.uid[2], g_uidCollector.uid[3]);
            LogMessage(msg);
        }
        
        // 存储块数据 (实际数据从偏移 9 开始，跳过 5字节头 + 4字节UID)
        if (block < 8 && length >= 9) { // 至少要有头部和UID
            // 实际数据从偏移 9 开始，最多 64 字节
            ULONG dataOffset = 9;
            ULONG dataSize = min(64, length - dataOffset);
            
            memcpy(&g_uidCollector.sectors[sector][block * 64], &data[dataOffset], dataSize);
            g_uidCollector.sectorReceived[sector][block] = true;
            
            wchar_t msg[128];
            swprintf_s(msg, 128, L"[UID] Sector %d Block %d received (%u bytes data)", sector, block, dataSize);
            LogMessage(msg);
            
            // 检查当前区是否完成
            bool currentSectorComplete = true;
            for (int b = 0; b < 8; b++) {
                if (!g_uidCollector.sectorReceived[sector][b]) {
                    currentSectorComplete = false;
                    break;
                }
            }
            
            // 如果当前区完成，保存文件
            if (currentSectorComplete && g_uidCollector.hasUid) {
                wchar_t processPath[MAX_PATH];
                GetModuleFileNameW(NULL, processPath, MAX_PATH);
                
                // 获取进程所在目录
                wchar_t* lastSlash = wcsrchr(processPath, L'\\');
                if (lastSlash) {
                    *(lastSlash + 1) = 0;
                }
                
                // 将 UID 转换为十进制数字 (小端序转大端序)
                DWORD uidDecimal = (g_uidCollector.uid[3] << 24) |
                                   (g_uidCollector.uid[2] << 16) |
                                   (g_uidCollector.uid[1] << 8) |
                                   g_uidCollector.uid[0];
                
                // 使用 UID 十进制 + 区号作为文件名
                wchar_t filePath[MAX_PATH];
                swprintf_s(filePath, MAX_PATH, L"%smem_%u_sector%d.dat", processPath, uidDecimal, sector);
                
                LogMessage(L"[INFO] Sector complete! Saving file...");
                
                HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL,
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    // 写入当前区的数据 (512 字节)
                    WriteFile(hFile, g_uidCollector.sectors[sector], 512, &written, NULL);
                    CloseHandle(hFile);
                    
                    wchar_t msg[512];
                    swprintf_s(msg, 512, L"[SUCCESS] Sector %d saved: %s (%d bytes)", sector, filePath, written);
                    LogMessage(msg);
                } else {
                    wchar_t msg[256];
                    swprintf_s(msg, 256, L"[ERROR] Failed to create file for sector %d: %d", sector, GetLastError());
                    LogMessage(msg);
                }
            }
            
            // 检查是否所有数据都已接收
            bool allReceived = true;
            int totalReceived = 0;
            for (int s = 0; s < 5; s++) {
                for (int b = 0; b < 8; b++) {
                    if (!g_uidCollector.sectorReceived[s][b]) {
                        allReceived = false;
                    } else {
                        totalReceived++;
                    }
                }
            }
            
            // 进度日志
            swprintf_s(msg, 128, L"[PROGRESS] Received %d/40 blocks", totalReceived);
            LogMessage(msg);
            
            // 如果所有数据都已接收，生成文件
            if (allReceived && g_uidCollector.hasUid) {
                LogMessage(L"[INFO] All 40 blocks received! Creating file...");
                
                wchar_t processPath[MAX_PATH];
                GetModuleFileNameW(NULL, processPath, MAX_PATH);
                
                // 获取进程所在目录
                wchar_t* lastSlash = wcsrchr(processPath, L'\\');
                if (lastSlash) {
                    *(lastSlash + 1) = 0;
                }
                
                // 将 UID 转换为十进制数字 (小端序转大端序)
                DWORD uidDecimal = (g_uidCollector.uid[3] << 24) |
                                   (g_uidCollector.uid[2] << 16) |
                                   (g_uidCollector.uid[1] << 8) |
                                   g_uidCollector.uid[0];
                
                // 使用 UID 十进制作为文件名
                wchar_t filePath[MAX_PATH];
                swprintf_s(filePath, MAX_PATH, L"%shidmem_%u.dat", processPath, uidDecimal);
                
                HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL,
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    // 写入 5 个区的数据 (5 * 512 = 2560 字节)
                    WriteFile(hFile, g_uidCollector.sectors, sizeof(g_uidCollector.sectors), &written, NULL);
                    CloseHandle(hFile);
                    
                    wchar_t msg[512];
                    swprintf_s(msg, 512, L"[SUCCESS] mem_uid.dat created: %s (%d bytes)", filePath, written);
                    LogMessage(msg);
                    swprintf_s(msg, 512, L"[UID] %02X %02X %02X %02X",
                              g_uidCollector.uid[0], g_uidCollector.uid[1],
                              g_uidCollector.uid[2], g_uidCollector.uid[3]);
                    LogMessage(msg);
                } else {
                    wchar_t msg[256];
                    swprintf_s(msg, 256, L"[ERROR] Failed to create mem_uid.dat: %d", GetLastError());
                    LogMessage(msg);
                }
            }
        }
        
        LeaveCriticalSection(&g_uidCollector.cs);
    }
}

// Helper function to log hex dump
void LogHexDump(const wchar_t* label, const BYTE* data, ULONG length) {
    if (!data || length == 0) return;
    
    wchar_t line[256];
    swprintf_s(line, 256, L"  %s (%u bytes):", label, length);
    LogMessage(line);
    
    // Print in rows of 16 bytes
    for (ULONG i = 0; i < length; i += 16) {
        wchar_t hexLine[128] = L"    ";
        wchar_t asciiLine[20] = L"  ";
        
        // Hex part
        for (ULONG j = 0; j < 16 && (i + j) < length; j++) {
            wchar_t hex[8];
            swprintf_s(hex, 8, L"%02X ", data[i + j]);
            wcscat_s(hexLine, 128, hex);
            
            // ASCII part
            wchar_t ch = (data[i + j] >= 32 && data[i + j] <= 126) ? data[i + j] : L'.';
            wchar_t ascii[2] = { ch, 0 };
            wcscat_s(asciiLine, 20, ascii);
        }
        
        // Pad hex part if needed
        ULONG bytesInRow = min(16, length - i);
        for (ULONG j = bytesInRow; j < 16; j++) {
            wcscat_s(hexLine, 128, L"   ");
        }
        
        wcscat_s(hexLine, 128, asciiLine);
        LogMessage(hexLine);
    }
}

#ifdef USE_DETOURS
#include <detours.h>

// 原始函数指针（Detours 方式）
static VOID (WINAPI* Real_HidD_GetHidGuid)(LPGUID) = HidD_GetHidGuid;
static BOOLEAN (WINAPI* Real_HidD_GetAttributes)(HANDLE, PHIDD_ATTRIBUTES) = HidD_GetAttributes;
static BOOLEAN (WINAPI* Real_HidD_GetFeature)(HANDLE, PVOID, ULONG) = HidD_GetFeature;
static BOOLEAN (WINAPI* Real_HidD_SetFeature)(HANDLE, PVOID, ULONG) = HidD_SetFeature;
static BOOLEAN (WINAPI* Real_HidD_GetPreparsedData)(HANDLE, PHIDP_PREPARSED_DATA*) = HidD_GetPreparsedData;
static BOOLEAN (WINAPI* Real_HidD_FreePreparsedData)(PHIDP_PREPARSED_DATA) = HidD_FreePreparsedData;
static BOOLEAN (WINAPI* Real_HidD_FlushQueue)(HANDLE) = HidD_FlushQueue;
static NTSTATUS (WINAPI* Real_HidP_GetCaps)(PHIDP_PREPARSED_DATA, PHIDP_CAPS) = HidP_GetCaps;
static BOOLEAN (WINAPI* Real_HidD_GetProductString)(HANDLE, PVOID, ULONG) = HidD_GetProductString;
static BOOLEAN (WINAPI* Real_HidD_GetSerialNumberString)(HANDLE, PVOID, ULONG) = HidD_GetSerialNumberString;

// SetupDi API (用于设备枚举)
static BOOL (WINAPI* Real_SetupDiEnumDeviceInterfaces)(HDEVINFO, PSP_DEVINFO_DATA, CONST GUID*, DWORD, PSP_DEVICE_INTERFACE_DATA) = SetupDiEnumDeviceInterfaces;
static BOOL (WINAPI* Real_SetupDiGetDeviceInterfaceDetailW)(HDEVINFO, PSP_DEVICE_INTERFACE_DATA, PSP_DEVICE_INTERFACE_DETAIL_DATA_W, DWORD, PDWORD, PSP_DEVINFO_DATA) = SetupDiGetDeviceInterfaceDetailW;
static HANDLE (WINAPI* Real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;

// 虚拟设备注入状态（每次枚举会话）
static HDEVINFO g_lastDeviceInfoHandle = NULL;  // 当前枚举会话的句柄
static DWORD g_lastRealDeviceIndex = 0;  // 真实设备的最后索引
static bool g_virtualDeviceInjected = false;  // 是否已注入虚拟设备
static const DWORD VIRTUAL_DEVICE_INDEX_MARKER = 0xFFFFFFFF;  // 虚拟设备的特殊索引
#define VIRTUAL_DEVICE_PATH L"\\\\?\\HID#VID_096E&PID_0201#VIRTUAL_CACHE#{4d1e55b2-f16f-11cf-88cb-001111000030}"

// Hook 函数实现
VOID WINAPI Hook_HidD_GetHidGuid(LPGUID HidGuid) {
    LogHidCall(L"HidD_GetHidGuid", L"Called");
    Real_HidD_GetHidGuid(HidGuid);
}

BOOLEAN WINAPI Hook_HidD_GetAttributes(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes) {
    EnsureCacheLoaded();
    
    // 【策略】只劫持第一个真实设备,其他设备返回失败
    static bool firstDeviceHijacked = false;
    
    // 如果是虚拟句柄,总是返回虚拟设备信息
    if (HidDeviceObject == (HANDLE)0xCAFEBABE && g_hidCache.isValid && Attributes) {
        Attributes->Size = sizeof(HIDD_ATTRIBUTES);
        Attributes->VendorID = kTargetVendorId;      // 固定值 0x096E
        Attributes->ProductID = kTargetProductId;    // 固定值 0x0201
        Attributes->VersionNumber = 0x0100;          // 固定值 0x0100
        
        wchar_t details[256];
        swprintf_s(details, 256, L"VID=0x%04X, PID=0x%04X, Version=0x%04X [VIRTUAL HANDLE]",
                   Attributes->VendorID, Attributes->ProductID, Attributes->VersionNumber);
        LogHidCall(L"HidD_GetAttributes", details);
        return TRUE;
    }
    
    // 如果有缓存且第一个设备还没被劫持,劫持这个设备
    if (g_hidCache.isValid && !firstDeviceHijacked && Attributes) {
        firstDeviceHijacked = true;
        
        // 添加到劫持句柄列表
        InitHijackedHandles();
        EnterCriticalSection(&g_hijackedHandlesCs);
        g_hijackedHandles.push_back(HidDeviceObject);
        LeaveCriticalSection(&g_hijackedHandlesCs);
        
        Attributes->Size = sizeof(HIDD_ATTRIBUTES);
        Attributes->VendorID = kTargetVendorId;      // 固定值 0x096E
        Attributes->ProductID = kTargetProductId;    // 固定值 0x0201
        Attributes->VersionNumber = 0x0100;          // 固定值 0x0100
        
        wchar_t details[256];
        swprintf_s(details, 256, L"VID=0x%04X, PID=0x%04X, Version=0x%04X [FIRST DEVICE HIJACKED - Handle=0x%p]",
                   Attributes->VendorID, Attributes->ProductID, Attributes->VersionNumber, HidDeviceObject);
        LogHidCall(L"HidD_GetAttributes", details);
        
        return TRUE;
    }
    
    // 其他真实设备正常调用
    BOOLEAN result = Real_HidD_GetAttributes(HidDeviceObject, Attributes);
    
    // 如果是目标 VID/PID 的设备,也添加到劫持列表
    if (result && g_hidCache.isValid && Attributes &&
        Attributes->VendorID == kTargetVendorId &&
        Attributes->ProductID == kTargetProductId) {
        
        InitHijackedHandles();
        EnterCriticalSection(&g_hijackedHandlesCs);
        if (std::find(g_hijackedHandles.begin(), g_hijackedHandles.end(), HidDeviceObject) == g_hijackedHandles.end()) {
            g_hijackedHandles.push_back(HidDeviceObject);
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[HIJACK] Added handle 0x%p to hijack list (real device with matching VID/PID)", HidDeviceObject);
            LogMessage(msg);
        }
        LeaveCriticalSection(&g_hijackedHandlesCs);
    }
    
    if (result && Attributes) {
        wchar_t details[256];
        swprintf_s(details, 256, L"VID=0x%04X, PID=0x%04X, Version=0x%04X [REAL DEVICE]",
                 Attributes->VendorID, Attributes->ProductID, Attributes->VersionNumber);
        LogHidCall(L"HidD_GetAttributes", details);
    } else {
        LogHidCall(L"HidD_GetAttributes", L"Failed");
    }
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetFeature(HANDLE HidDeviceObject, PVOID ReportBuffer, ULONG ReportBufferLength) {
    EnsureCacheLoaded();
    
    BOOLEAN result = FALSE;
    bool usedCache = false;
    bool virtualized = false;
    
    // 如果有缓存,直接从缓存返回数据(不检查句柄)
    if (g_hidCache.isValid) {
        // 从缓存返回数据
        EnterCriticalSection(&g_uidCollector.cs);
        BYTE sector = g_uidCollector.pendingReadSector;
        BYTE block = g_uidCollector.pendingReadBlock;
        
        if (ReportBufferLength >= 73 && block < 8 && sector < 2) {
            BYTE* data = (BYTE*)ReportBuffer;
            ZeroMemory(data, ReportBufferLength);
            data[0] = 0x00;
            data[1] = 0x00;  // No error
            data[2] = 0x81;  // Read command
            data[3] = sector;
            data[4] = block;
            memcpy(&data[5], &g_hidCache.cachedUid, 4);
            
            // Copy data from cache
            if (sector == 0) {
                memcpy(&data[9], g_hidCache.partition0[block], 64);
            } else {
                memcpy(&data[9], g_hidCache.partition1[block], 64);
            }
            
            result = TRUE;
            usedCache = true;
            virtualized = true;
            
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHED DATA] GetFeature: Sector=%d, Block=%d, Handle=0x%p", 
                       sector, block, HidDeviceObject);
            LogMessage(msg);
        }
        LeaveCriticalSection(&g_uidCollector.cs);
    } else {
        result = Real_HidD_GetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
    }
    
    if (result && !virtualized) {
        // 检查是否需要使用缓存
        EnterCriticalSection(&g_uidCollector.cs);
        usedCache = g_uidCollector.useCacheForNextRead && g_uidCollector.hasCachedData;
        BYTE sector = g_uidCollector.pendingReadSector;
        BYTE block = g_uidCollector.pendingReadBlock;
        
        if (usedCache && ReportBufferLength >= 73 && block < 8) {
            BYTE* data = (BYTE*)ReportBuffer;
            ULONG dataOffset = 9;
            ULONG dataSize = min(64, ReportBufferLength - dataOffset);
            memcpy(&data[dataOffset], &g_uidCollector.cachedData[block * 64], dataSize);
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHE] Replaced data with cache: Sector %d, Block %d", sector, block);
            LogMessage(msg);
            g_uidCollector.useCacheForNextRead = false;
        }
        LeaveCriticalSection(&g_uidCollector.cs);
    } else if (g_virtualDeviceEnabled) {
        VirtualFeatureContext ctx{};
        if (BuildVirtualFeatureReport(ReportBuffer, ReportBufferLength, &ctx)) {
            result = TRUE;
            usedCache = ctx.usedCache;
            virtualized = true;
        }
    }
    
    if (result) {
        wchar_t details[512];
        if (virtualized) {
            swprintf_s(details, 512, L"Success: %u bytes (VIRTUAL%s)", ReportBufferLength,
                       usedCache ? L" CACHE" : L"");
        } else {
            swprintf_s(details, 512, L"Success: %u bytes%s", ReportBufferLength,
                       usedCache ? L" (FROM CACHE)" : L"");
        }
        LogHidCall(L"HidD_GetFeature", details);
        if (ReportBufferLength > 0) {
            const wchar_t* label;
            if (virtualized) {
                label = usedCache ? L"Data generated (virtual cache)" : L"Data generated (virtual placeholder)";
            } else {
                label = usedCache ? L"Data received (cached)" : L"Data received";
            }
            LogHexDump(label, (BYTE*)ReportBuffer, ReportBufferLength);
            if (!usedCache && !virtualized) {
                ProcessUidData((BYTE*)ReportBuffer, ReportBufferLength);
            }
        }
    } else {
        wchar_t details[128];
        swprintf_s(details, 128, L"Failed, error: %d", GetLastError());
        LogHidCall(L"HidD_GetFeature", details);
    }
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_SetFeature(HANDLE HidDeviceObject, PVOID ReportBuffer, ULONG ReportBufferLength) {
    EnsureCacheLoaded();
    
    wchar_t details[512];
    swprintf_s(details, 512, L"Write: %u bytes", ReportBufferLength);
    LogHidCall(L"HidD_SetFeature", details);
    
    // 检查是否是虚拟句柄或被劫持的真实句柄
    bool isVirtualHandle = (HidDeviceObject == (HANDLE)0xCAFEBABE);
    bool isHijackedHandle = IsHijackedHandle(HidDeviceObject);
    
    // 调试: 记录句柄信息和劫持列表
    EnterCriticalSection(&g_hijackedHandlesCs);
    size_t hijackedCount = g_hijackedHandles.size();
    wchar_t handleList[512] = L"";
    for (size_t i = 0; i < hijackedCount && i < 10; i++) {
        wchar_t tmp[32];
        swprintf_s(tmp, 32, L"0x%p ", g_hijackedHandles[i]);
        wcscat_s(handleList, 512, tmp);
    }
    LeaveCriticalSection(&g_hijackedHandlesCs);
    
    wchar_t handleInfo[768];
    swprintf_s(handleInfo, 768, L"[DEBUG SetFeature] Handle=0x%p, Virtual=%d, Match=%d, CacheValid=%d, HijackedCount=%zu, List=[%s]", 
               HidDeviceObject, isVirtualHandle ? 1 : 0, 
               isHijackedHandle ? 1 : 0, g_hidCache.isValid ? 1 : 0, 
               hijackedCount, handleList);
    LogMessage(handleInfo);
    
    // Output full hex dump
    if (ReportBufferLength > 0) {
        LogHexDump(L"Data sending", (BYTE*)ReportBuffer, ReportBufferLength);
        
        // 检查是否是读命令: 00 00 81 [区] [块] ...
        BYTE* data = (BYTE*)ReportBuffer;
        if (ReportBufferLength >= 9 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x81) {
            BYTE sector = data[3];
            BYTE block = data[4];
            BYTE uid[4];
            memcpy(uid, &data[5], 4);
            
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHE] Write request detected: Sector=%d, Block=%d, UID=%02X %02X %02X %02X",
                      sector, block, uid[0], uid[1], uid[2], uid[3]);
            LogMessage(msg);
            
            // 记录待读取的区块
            EnterCriticalSection(&g_uidCollector.cs);
            g_uidCollector.pendingReadSector = sector;
            g_uidCollector.pendingReadBlock = block;
            memcpy(g_uidCollector.requestUid, uid, sizeof(uid));
            g_uidCollector.hasRequestUid = true;
            if (!g_uidCollector.hasUid) {
                memcpy(g_uidCollector.uid, uid, sizeof(uid));
                g_uidCollector.hasUid = true;
            }
            
            // 尝试加载缓存
            if (LoadCacheIfExists(sector, uid)) {
                g_uidCollector.useCacheForNextRead = true;
                LogMessage(L"[CACHE] Will use cached data for next read");
            } else {
                g_uidCollector.useCacheForNextRead = false;
                g_uidCollector.hasCachedData = false;
                LogMessage(L"[CACHE] No cache found, will use real device data");
            }
            LeaveCriticalSection(&g_uidCollector.cs);
        }
    }
    
    BOOLEAN result;
    
    // 如果有缓存,直接成功(不检查句柄)
    if (g_hidCache.isValid) {
        result = TRUE;
        LogMessage(L"[CACHE] HidD_SetFeature acknowledged (using cache)");
    } else {
        result = Real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
        
        if (!result) {
            if (g_virtualDeviceEnabled) {
                result = TRUE;
                LogMessage(L"[VIRTUAL] HidD_SetFeature acknowledged without physical device");
            } else {
                wchar_t errMsg[128];
                swprintf_s(errMsg, 128, L"  SetFeature failed, error: %d", GetLastError());
                LogMessage(errMsg);
            }
        }
    }
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_FlushQueue(HANDLE HidDeviceObject) {
    EnsureCacheLoaded();
    
    // 如果有缓存,直接成功(不检查句柄)
    if (g_hidCache.isValid) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"FlushQueue success - Handle=0x%p (using cache)", HidDeviceObject);
        LogHidCall(L"HidD_FlushQueue", msg);
        return TRUE;
    }
    
    BOOLEAN result = Real_HidD_FlushQueue(HidDeviceObject);
    if (!result && g_virtualDeviceEnabled) {
        LogHidCall(L"HidD_FlushQueue", L"Virtual success");
        return TRUE;
    }
    LogHidCall(L"HidD_FlushQueue", result ? L"Success" : L"Failed");
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetPreparsedData(HANDLE HidDeviceObject, PHIDP_PREPARSED_DATA* PreparsedData) {
    EnsureCacheLoaded();
    
    // 虚拟句柄：返回一个假的PreparsedData指针
    if (HidDeviceObject == (HANDLE)0xCAFEBABE && g_hidCache.isValid) {
        if (PreparsedData) {
            // 返回一个非NULL的假指针（用于HidP_GetCaps）
            *PreparsedData = (PHIDP_PREPARSED_DATA)0xDEADBEEF;
        }
        LogHidCall(L"HidD_GetPreparsedData", L"Virtual handle - returning fake pointer");
        return TRUE;
    }
    
    LogHidCall(L"HidD_GetPreparsedData", L"Called");
    return Real_HidD_GetPreparsedData(HidDeviceObject, PreparsedData);
}

BOOLEAN WINAPI Hook_HidD_FreePreparsedData(PHIDP_PREPARSED_DATA PreparsedData) {
    LogHidCall(L"HidD_FreePreparsedData", L"Called");
    return Real_HidD_FreePreparsedData(PreparsedData);
}

NTSTATUS WINAPI Hook_HidP_GetCaps(PHIDP_PREPARSED_DATA PreparsedData, PHIDP_CAPS Capabilities) {
    EnsureCacheLoaded();
    
    // 检查是否是虚拟的PreparsedData指针
    bool isVirtualData = (PreparsedData == (PHIDP_PREPARSED_DATA)0xDEADBEEF);
    
    if ((isVirtualData || g_hidCache.isValid) && Capabilities) {
        // 返回缓存的Capabilities
        ZeroMemory(Capabilities, sizeof(HIDP_CAPS));
        Capabilities->Usage = g_hidCache.usage;
        Capabilities->UsagePage = g_hidCache.usagePage;
        Capabilities->InputReportByteLength = g_hidCache.inputReportLength;
        Capabilities->OutputReportByteLength = g_hidCache.outputReportLength;
        Capabilities->FeatureReportByteLength = g_hidCache.featureReportLength;
        
        wchar_t details[256];
        swprintf_s(details, 256, L"Usage=0x%04X, UsagePage=0x%04X, Feature=%d bytes [CACHED]",
                 Capabilities->Usage, Capabilities->UsagePage, Capabilities->FeatureReportByteLength);
        LogHidCall(L"HidP_GetCaps", details);
        return HIDP_STATUS_SUCCESS;
    }
    
    NTSTATUS result = Real_HidP_GetCaps(PreparsedData, Capabilities);
    LogHidCall(L"HidP_GetCaps", result == HIDP_STATUS_SUCCESS ? L"Success" : L"Failed");
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetProductString(HANDLE HidDeviceObject, PVOID Buffer, ULONG BufferLength) {
    EnsureCacheLoaded();
    
    // 检查虚拟句柄或有缓存
    bool isVirtualHandle = (HidDeviceObject == (HANDLE)0xCAFEBABE);
    
    if ((isVirtualHandle || g_hidCache.isValid) && g_hidCache.isValid && Buffer && BufferLength > 0) {
        // 返回缓存的产品字符串
        size_t len = wcslen(g_hidCache.productString);
        size_t copyLen = (len + 1) * sizeof(wchar_t);
        if (copyLen > BufferLength) copyLen = BufferLength;
        
        memcpy(Buffer, g_hidCache.productString, copyLen);
        ((wchar_t*)Buffer)[BufferLength / sizeof(wchar_t) - 1] = L'\0';
        
        wchar_t details[256];
        swprintf_s(details, 256, L"Product: %s [CACHED]", g_hidCache.productString);
        LogHidCall(L"HidD_GetProductString", details);
        return TRUE;
    }
    
    BOOLEAN result = Real_HidD_GetProductString(HidDeviceObject, Buffer, BufferLength);
    LogHidCall(L"HidD_GetProductString", result ? L"Success" : L"Failed");
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetSerialNumberString(HANDLE HidDeviceObject, PVOID Buffer, ULONG BufferLength) {
    EnsureCacheLoaded();
    
    // 检查虚拟句柄或有缓存
    bool isVirtualHandle = (HidDeviceObject == (HANDLE)0xCAFEBABE);
    
    if ((isVirtualHandle || g_hidCache.isValid) && g_hidCache.isValid && Buffer && BufferLength > 0) {
        // 返回缓存的序列号字符串
        size_t len = wcslen(g_hidCache.serialNumberString);
        size_t copyLen = (len + 1) * sizeof(wchar_t);
        if (copyLen > BufferLength) copyLen = BufferLength;
        
        memcpy(Buffer, g_hidCache.serialNumberString, copyLen);
        ((wchar_t*)Buffer)[BufferLength / sizeof(wchar_t) - 1] = L'\0';
        
        wchar_t details[256];
        swprintf_s(details, 256, L"Serial: %s [CACHED]", g_hidCache.serialNumberString);
        LogHidCall(L"HidD_GetSerialNumberString", details);
        return TRUE;
    }
    
    BOOLEAN result = Real_HidD_GetSerialNumberString(HidDeviceObject, Buffer, BufferLength);
    LogHidCall(L"HidD_GetSerialNumberString", result ? L"Success" : L"Failed");
    return result;
}

// ==================== 设备枚举 Hook ====================

BOOL WINAPI Hook_SetupDiEnumDeviceInterfaces(
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    CONST GUID* InterfaceClassGuid,
    DWORD MemberIndex,
    PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
) {
    EnsureCacheLoaded();
    
    // 检测新的枚举会话
    if (DeviceInfoSet != g_lastDeviceInfoHandle || MemberIndex == 0) {
        g_lastDeviceInfoHandle = DeviceInfoSet;
        g_lastRealDeviceIndex = 0;
        g_virtualDeviceInjected = false;
        LogMessage(L"[ENUM] New device enumeration session started");
    }
    
    // 先调用真实 API
    BOOL result = Real_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);
    
    if (result) {
        // 真实设备存在
        g_lastRealDeviceIndex = MemberIndex;
        wchar_t msg[256];
        swprintf_s(msg, 256, L"[ENUM] Real device found at index %lu", MemberIndex);
        LogMessage(msg);
        return TRUE;
    }
    
    // result == FALSE：没有更多真实设备
    DWORD error = GetLastError();
    
    // 【禁用虚拟设备注入】因为已经劫持了第一个真实设备
    // 如果启用了第一个设备劫持,就不需要再注入虚拟设备了
    EnterCriticalSection(&g_hijackedHandlesCs);
    bool hasHijackedHandles = !g_hijackedHandles.empty();
    LeaveCriticalSection(&g_hijackedHandlesCs);
    if (error == ERROR_NO_MORE_ITEMS && g_hidCache.isValid && !g_virtualDeviceInjected && !hasHijackedHandles) {
        // 仅在没有劫持真实设备时才注入虚拟设备(当前已禁用)
        // 注入虚拟设备!
        g_virtualDeviceInjected = true;
        
        // 填充 DeviceInterfaceData
        if (DeviceInterfaceData) {
            DeviceInterfaceData->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
            DeviceInterfaceData->InterfaceClassGuid = *InterfaceClassGuid;
            DeviceInterfaceData->Flags = SPINT_ACTIVE | SPINT_DEFAULT;
            DeviceInterfaceData->Reserved = VIRTUAL_DEVICE_INDEX_MARKER;  // 标记为虚拟设备
        }
        
        wchar_t msg[256];
        swprintf_s(msg, 256, L"[ENUM] INJECTED virtual device at index %lu (after %lu real devices)", 
                   MemberIndex, g_lastRealDeviceIndex + 1);
        LogMessage(msg);
        
        SetLastError(ERROR_SUCCESS);
        return TRUE;  // 告诉应用程序：还有一个设备！
    }
    
    // 否则返回原始错误
    SetLastError(error);
    return FALSE;
}

BOOL WINAPI Hook_SetupDiGetDeviceInterfaceDetailW(
    HDEVINFO DeviceInfoSet,
    PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W DeviceInterfaceDetailData,
    DWORD DeviceInterfaceDetailDataSize,
    PDWORD RequiredSize,
    PSP_DEVINFO_DATA DeviceInfoData
) {
    EnsureCacheLoaded();
    
    // 检查是否是虚拟设备（通过 Reserved 字段判断）
    bool isVirtualDevice = (DeviceInterfaceData && DeviceInterfaceData->Reserved == VIRTUAL_DEVICE_INDEX_MARKER);
    
    if (isVirtualDevice && g_hidCache.isValid) {
        // 计算需要的大小
        DWORD pathLen = (DWORD)wcslen(VIRTUAL_DEVICE_PATH);
        DWORD requiredSize = offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath) + (pathLen + 1) * sizeof(WCHAR);
        
        if (RequiredSize) {
            *RequiredSize = requiredSize;
        }
        
        // 如果缓冲区足够，填充数据
        if (DeviceInterfaceDetailData && DeviceInterfaceDetailDataSize >= requiredSize) {
            DeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
            wcscpy_s(DeviceInterfaceDetailData->DevicePath, pathLen + 1, VIRTUAL_DEVICE_PATH);
            
            if (DeviceInfoData) {
                DeviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
            }
            
            LogMessage(L"[ENUM] Returned virtual device path: " VIRTUAL_DEVICE_PATH);
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
        
        // 缓冲区不够
        if (!DeviceInterfaceDetailData) {
            // 第一次调用（查询大小）
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }
    
    // 真实设备或缓存不可用，调用真实 API
    return Real_SetupDiGetDeviceInterfaceDetailW(DeviceInfoSet, DeviceInterfaceData, 
                                                   DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize,
                                                   RequiredSize, DeviceInfoData);
}

HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    EnsureCacheLoaded();
    
    // 调试: 记录所有 HID 设备打开
    if (lpFileName && wcsstr(lpFileName, L"hid#")) {
        wchar_t msg[768];
        swprintf_s(msg, 768, L"[CREATEFILE DEBUG] Path: %s", lpFileName);
        LogMessage(msg);
    }
    
    // 检查是否是我们的虚拟设备路径
    if (lpFileName && wcsstr(lpFileName, L"VID_096E&PID_0201") && wcsstr(lpFileName, L"VIRTUAL_CACHE")) {
        if (g_hidCache.isValid) {
            // 创建一个虚拟句柄（使用特殊值）
            HANDLE virtualHandle = (HANDLE)0xCAFEBABE;  // 魔数标记
            
            wchar_t msg[512];
            swprintf_s(msg, 512, L"[CREATEFILE] Virtual device opened: %s -> Handle 0x%p", lpFileName, virtualHandle);
            LogMessage(msg);
            
            SetLastError(ERROR_SUCCESS);
            return virtualHandle;
        }
    }
    
    // 真实文件/设备 - 先调用真实 API
    HANDLE hDevice = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, 
                                       lpSecurityAttributes, dwCreationDisposition, 
                                       dwFlagsAndAttributes, hTemplateFile);
    
    // 如果成功打开,且是目标 VID/PID 的 HID 设备路径,添加到劫持列表
    if (hDevice != INVALID_HANDLE_VALUE && g_hidCache.isValid && lpFileName) {
        // 检查是否是目标设备路径 (VID_096E&PID_0201)
        if (wcsstr(lpFileName, L"hid#") && 
            wcsstr(lpFileName, L"vid_096e") && 
            wcsstr(lpFileName, L"pid_0201")) {
            
            InitHijackedHandles();
            EnterCriticalSection(&g_hijackedHandlesCs);
            if (std::find(g_hijackedHandles.begin(), g_hijackedHandles.end(), hDevice) == g_hijackedHandles.end()) {
                g_hijackedHandles.push_back(hDevice);
                wchar_t msg[512];
                swprintf_s(msg, 512, L"[CREATEFILE] Target device opened, added handle 0x%p to hijack list (Path: %s)", 
                          hDevice, lpFileName);
                LogMessage(msg);
            }
            LeaveCriticalSection(&g_hijackedHandlesCs);
        }
    }
    
    return hDevice;
}

// 修改 HidD_GetAttributes 以支持虚拟句柄
// 安装 Hook
bool InstallHidHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    DetourAttach(&(PVOID&)Real_HidD_GetHidGuid, Hook_HidD_GetHidGuid);
    DetourAttach(&(PVOID&)Real_HidD_GetAttributes, Hook_HidD_GetAttributes);
    DetourAttach(&(PVOID&)Real_HidD_GetFeature, Hook_HidD_GetFeature);
    DetourAttach(&(PVOID&)Real_HidD_SetFeature, Hook_HidD_SetFeature);
    DetourAttach(&(PVOID&)Real_HidD_FlushQueue, Hook_HidD_FlushQueue);
    DetourAttach(&(PVOID&)Real_HidD_GetPreparsedData, Hook_HidD_GetPreparsedData);
    DetourAttach(&(PVOID&)Real_HidD_FreePreparsedData, Hook_HidD_FreePreparsedData);
    DetourAttach(&(PVOID&)Real_HidP_GetCaps, Hook_HidP_GetCaps);
    DetourAttach(&(PVOID&)Real_HidD_GetProductString, Hook_HidD_GetProductString);
    DetourAttach(&(PVOID&)Real_HidD_GetSerialNumberString, Hook_HidD_GetSerialNumberString);
    
    // 设备枚举 API
    DetourAttach(&(PVOID&)Real_SetupDiEnumDeviceInterfaces, Hook_SetupDiEnumDeviceInterfaces);
    DetourAttach(&(PVOID&)Real_SetupDiGetDeviceInterfaceDetailW, Hook_SetupDiGetDeviceInterfaceDetailW);
    DetourAttach(&(PVOID&)Real_CreateFileW, Hook_CreateFileW);
    
    LONG error = DetourTransactionCommit();
    return (error == NO_ERROR);
}

// 卸载 Hook
void UninstallHidHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    DetourDetach(&(PVOID&)Real_HidD_GetHidGuid, Hook_HidD_GetHidGuid);
    DetourDetach(&(PVOID&)Real_HidD_GetAttributes, Hook_HidD_GetAttributes);
    DetourDetach(&(PVOID&)Real_HidD_GetFeature, Hook_HidD_GetFeature);
    DetourDetach(&(PVOID&)Real_HidD_SetFeature, Hook_HidD_SetFeature);
    DetourDetach(&(PVOID&)Real_HidD_FlushQueue, Hook_HidD_FlushQueue);
    DetourDetach(&(PVOID&)Real_HidD_GetPreparsedData, Hook_HidD_GetPreparsedData);
    DetourDetach(&(PVOID&)Real_HidD_FreePreparsedData, Hook_HidD_FreePreparsedData);
    DetourDetach(&(PVOID&)Real_HidP_GetCaps, Hook_HidP_GetCaps);
    DetourDetach(&(PVOID&)Real_HidD_GetProductString, Hook_HidD_GetProductString);
    DetourDetach(&(PVOID&)Real_HidD_GetSerialNumberString, Hook_HidD_GetSerialNumberString);
    
    // 设备枚举 API
    DetourDetach(&(PVOID&)Real_SetupDiEnumDeviceInterfaces, Hook_SetupDiEnumDeviceInterfaces);
    DetourDetach(&(PVOID&)Real_SetupDiGetDeviceInterfaceDetailW, Hook_SetupDiGetDeviceInterfaceDetailW);
    DetourDetach(&(PVOID&)Real_CreateFileW, Hook_CreateFileW);
    
    DetourTransactionCommit();
}

#else // 不使用 Detours，使用简单的 IAT Hook

// IAT Hook implementation (simplified, logging only)
bool InstallHidHooks() {
    LogMessage(L"[WARNING] Detours not enabled, using basic monitoring mode");
    LogMessage(L"[INFO] Download Detours library for full Hook functionality");
    
    // Can implement simple IAT Hook or just monitoring here
    // For simplified example, just return success without actual Hook
    return true;
}

void UninstallHidHooks() {
    // Cleanup IAT Hook (if any)
}

#endif
