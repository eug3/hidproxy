#include "hid_hooks.h"
#include "logging.h"
#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <wincrypt.h>
#include <psapi.h>
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

// xsjzb内存数据地址(动态读取)
static const BYTE* g_xsjzbUidAddr = nullptr;
static const BYTE* g_xsjzbUsernameAddr = nullptr;
static const BYTE* g_xsjzbCompanyAddr = nullptr;
static bool g_xsjzbDataLocated = false;

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

// 延迟初始化（线程安全）- 仅初始化日志,不加载磁盘缓存
static void EnsureCacheLoaded() {
    if (g_cacheLoadAttempted) {
        return;  // 已经尝试过初始化了
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
        
        LogMessage(L"[INIT] Memory-based cache mode - waiting for HidD_GetHidGuid to initialize");
        
        g_cacheLoadAttempted = true;
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

// 反转 DWORD 的字节序
static DWORD ReverseDwordBytes(DWORD value) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0xFF000000) >> 24);
}

// 从 SerialNumberString 解析出 HID 和 UID
// SerialNumberString 格式: HID(8位16进制) + (HID XOR UID)(8位16进制)
static bool ParseSerialToHidUid(const std::wstring& serialStr, DWORD& hidOut, DWORD& uidOut) {
    if (serialStr.length() < 16) {
        return false;
    }
    
    // 提取前8位作为 HID
    std::wstring hidPart = serialStr.substr(0, 8);
    std::wstring uidSeedPart = serialStr.substr(8, 8);
    
    wchar_t* endPtr = nullptr;
    DWORD hidValue = wcstoul(hidPart.c_str(), &endPtr, 16);
    if (endPtr == nullptr || endPtr == hidPart.c_str()) {
        return false;
    }
    
    DWORD uidSeed = wcstoul(uidSeedPart.c_str(), &endPtr, 16);
    if (endPtr == nullptr || endPtr == uidSeedPart.c_str()) {
        return false;
    }
    
    // 计算 UID: uidSeed XOR HID
    hidOut = hidValue;
    uidOut = uidSeed ^ hidValue;
    return true;
}

// 根据 HID 和 UID 生成 SerialNumberString
// 格式: HID(8位16进制) + (HID XOR UID)(8位16进制)
static std::wstring GenerateSerialFromHidUid(DWORD hidValue, DWORD uidValue) {
    DWORD serialPart2 = hidValue ^ uidValue;
    
    wchar_t buffer[17];
    swprintf_s(buffer, 17, L"%08X%08X", hidValue, serialPart2);
    return std::wstring(buffer);
}

// 生成随机的 HID 和 UID
static void GenerateRandomHidUid(DWORD& hidOut, DWORD& uidOut) {
    // 使用高精度时间作为随机种子
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    srand(static_cast<unsigned int>(counter.QuadPart ^ GetCurrentProcessId()));
    
    hidOut = ((DWORD)rand() << 16) | rand();
    uidOut = ((DWORD)rand() << 16) | rand();
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
    // 智能生成缺失的值
    bool hidGenerated = false;
    bool uidGenerated = false;
    
    if (hidValue == 0 && uidValue == 0) {
        // 都未提供，随机生成两者
        GenerateRandomHidUid(hidValue, uidValue);
        hidGenerated = true;
        uidGenerated = true;
    } else if (hidValue == 0) {
        // 只提供了 UID，随机生成 HID
        DWORD tempUid;
        GenerateRandomHidUid(hidValue, tempUid);
        hidGenerated = true;
    } else if (uidValue == 0) {
        // 只提供了 HID，随机生成 UID
        DWORD tempHid;
        GenerateRandomHidUid(tempHid, uidValue);
        uidGenerated = true;
    }
    
    if (hidGenerated || uidGenerated) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"[VIRTUAL] Generated: %s%s%sHID=0x%08X UID=0x%08X (UID decimal: %u)",
                  hidGenerated ? L"HID " : L"",
                  (hidGenerated && uidGenerated) ? L"and " : L"",
                  uidGenerated ? L"UID " : L"",
                  hidValue, uidValue, uidValue);
        LogMessage(msg);
    }
    
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
    
    // 生成并存储 SerialNumberString
    std::wstring serialNumber = GenerateSerialFromHidUid(hidValue, uidValue);
    g_hidCache.cachedHid = hidValue;
    g_hidCache.cachedUid = uidValue;
    wcscpy_s(g_hidCache.serialNumberString, 256, serialNumber.c_str());

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[VIRTUAL] HID identity configured: HID=0x%08X UID=0x%08X Serial=%s",
              hidValue, uidValue, serialNumber.c_str());
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
    // 智能生成缺失的值
    bool hidGenerated = false;
    bool uidGenerated = false;
    
    if (hidValue == 0 && uidValue == 0) {
        // 都未提供，随机生成两者
        GenerateRandomHidUid(hidValue, uidValue);
        hidGenerated = true;
        uidGenerated = true;
    } else if (hidValue == 0) {
        // 只提供了 UID，随机生成 HID
        DWORD tempUid;
        GenerateRandomHidUid(hidValue, tempUid);
        hidGenerated = true;
    } else if (uidValue == 0) {
        // 只提供了 HID，随机生成 UID
        DWORD tempHid;
        GenerateRandomHidUid(tempHid, uidValue);
        uidGenerated = true;
    }
    
    if (hidGenerated || uidGenerated) {
        wchar_t msg[256];
        swprintf_s(msg, 256, L"[VIRTUAL] Generated: %s%s%sHID=0x%08X UID=0x%08X (UID decimal: %u)",
                  hidGenerated ? L"HID " : L"",
                  (hidGenerated && uidGenerated) ? L"and " : L"",
                  uidGenerated ? L"UID " : L"",
                  hidValue, uidValue, uidValue);
        LogMessage(msg);
    }
    
    std::string uidDec = std::to_string(static_cast<unsigned long>(uidValue));
    std::string hidDec = std::to_string(static_cast<unsigned long>(hidValue));
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentYear = year != 0 ? year : st.wYear;
    std::string checksum = GenerateVirtualChecksumString(uidValue, hidValue, currentYear);
    
    // 生成 SerialNumberString
    std::wstring serialNumber = GenerateSerialFromHidUid(hidValue, uidValue);

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
    
    // 存储到全局缓存
    g_hidCache.cachedHid = hidValue;
    g_hidCache.cachedUid = uidValue;
    wcscpy_s(g_hidCache.serialNumberString, 256, serialNumber.c_str());

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[VIRTUAL] Generated sector data (HID=0x%08X UID=0x%08X Serial=%s year=%d)", 
               hidValue, uidValue, serialNumber.c_str(), currentYear);
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

// 在内存中搜索字节序列
static const BYTE* SearchMemoryPattern(const BYTE* startAddr, size_t searchSize, const BYTE* pattern, size_t patternSize) {
    for (size_t i = 0; i <= searchSize - patternSize; i++) {
        if (memcmp(startAddr + i, pattern, patternSize) == 0) {
            return startAddr + i;
        }
    }
    return nullptr;
}

// 搜索函数特征码（基于 IDA 反编译的 sub_7363F0 函数）
static const BYTE* FindValidationFunction(const BYTE* baseAddr, size_t moduleSize) {
    // sub_7363F0 函数的特征字节序列（函数开头和关键指令）
    // 从 IDA 反编译看到的特征：
    // - 函数开头设置版本标志: word_15780D8 = 12545 (0x3101)
    // - mov word ptr [...], 3101h
    // - mov word ptr [...], 3201h (12801)
    // - mov word ptr [...], 3001h (12289)
    
    // 特征模式1: 连续设置3个 word 值
    const BYTE pattern1[] = {
        0xC7, 0x05,              // mov dword ptr [addr], imm32
        // ... 地址 ...
        0x01, 0x31, 0x00, 0x00,  // 0x3101 (12545)
    };
    
   
   
    
 

    const BYTE hashRefPattern[] = {
        'F', 'B', 'F', 'D', 'E', '0', 'E', 'D', '2', '3', 'E', 'C', '5', 'C', '6', 'F',
        'C', 'F', 'D', '4', 'D', '5', 'C', '9', '4', 'E', '1', '5', 'A', '2', 'B', '1'
    };
    
    // 先找 MD5 哈希字符串（这是最独特的标识）
    const BYTE* hashStringAddr = SearchMemoryPattern(baseAddr, moduleSize, hashRefPattern, sizeof(hashRefPattern));
    
    if (!hashStringAddr) {
        return nullptr;
    }
    
    // 在整个模块中搜索引用这个 MD5 字符串地址的代码
    // 指令通常是 push offset hashStringAddr 或 mov edx, offset hashStringAddr
    // 这会在代码段中形成一个 DWORD 指向数据地址
    DWORD hashStringOffset = (DWORD)(hashStringAddr - baseAddr);
    
    // 搜索代码段中对此地址的引用
    for (size_t i = 0; i < moduleSize - 4; i++) {
        DWORD* pAddr = (DWORD*)(baseAddr + i);
        if (*pAddr == (DWORD)hashStringAddr) {
            // 找到引用，向前回溯找函数开头
            // 函数开头通常是: push ebp; mov ebp, esp 或类似的序幕
            const BYTE* refAddr = baseAddr + i;
            
            // 向前搜索最多 512 字节找函数开头
            for (size_t j = 0; j < 512 && (refAddr - j) > baseAddr; j++) {
                const BYTE* funcStart = refAddr - j;
                
                // 常见函数序幕模式
                if ((funcStart[0] == 0x55 && funcStart[1] == 0x8B && funcStart[2] == 0xEC) || // push ebp; mov ebp, esp
                    (funcStart[0] == 0x8B && funcStart[1] == 0xFF) ||  // mov edi, edi (hotpatch)
                    (funcStart[0] == 0x6A && funcStart[2] == 0x68)) {  // push ...; push ...
                    
                    return funcStart;
                }
            }
        }
    }
    
    return nullptr;
}

// 从验证函数中提取字符串地址引用
static const BYTE* ExtractStringReference(const BYTE* funcAddr, size_t maxFuncSize, const BYTE* baseAddr, size_t moduleSize) {
    // 在函数代码中搜索 push offset string 或 mov edx, offset string 指令
    // 这些会引用数据段中的字符串地址
    
    for (size_t i = 0; i < maxFuncSize - 5; i++) {
        const BYTE* instr = funcAddr + i;
        
        // push offset addr (68 xx xx xx xx)
        if (instr[0] == 0x68) {
            DWORD addr = *(DWORD*)(instr + 1);
            // 检查地址是否在模块范围内
            if (addr >= (DWORD)baseAddr && addr < (DWORD)(baseAddr + moduleSize)) {
                return (const BYTE*)addr;
            }
        }
        
        // mov edx, offset addr (BA xx xx xx xx)
        if (instr[0] == 0xBA) {
            DWORD addr = *(DWORD*)(instr + 1);
            if (addr >= (DWORD)baseAddr && addr < (DWORD)(baseAddr + moduleSize)) {
                return (const BYTE*)addr;
            }
        }
        
        // mov eax, offset addr (B8 xx xx xx xx)
        if (instr[0] == 0xB8) {
            DWORD addr = *(DWORD*)(instr + 1);
            if (addr >= (DWORD)baseAddr && addr < (DWORD)(baseAddr + moduleSize)) {
                return (const BYTE*)addr;
            }
        }
    }
    
    return nullptr;
}

// 安全内存读取辅助函数(使用SEH保护)
static bool SafeMemoryRead(const void* addr, void* buffer, size_t size) {
    __try {
        memcpy(buffer, addr, size);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 安全内存比较辅助函数(使用SEH保护)
static bool SafeMemoryCompare(const void* addr1, const void* addr2, size_t size) {
    __try {
        return memcmp(addr1, addr2, size) == 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 定位 xsjzb 内存中的验证数据地址（不读取内容）
static bool LocateXsjzbValidationData() {
    if (g_xsjzbDataLocated) {
        return true;  // 已经定位过了
    }
    
    // 获取当前进程的可执行文件基址
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        LogMessage(L"[XSJZB] Failed to get module handle");
        return false;
    }
    
    // 获取模块信息
    MODULEINFO modInfo = {0};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        LogMessage(L"[XSJZB] Failed to get module information");
        return false;
    }
    
    const BYTE* baseAddr = (const BYTE*)modInfo.lpBaseOfDll;
    size_t moduleSize = modInfo.SizeOfImage;
    
    wchar_t msg[512];
    swprintf_s(msg, 512, L"[XSJZB] Module: base=0x%p, size=%zu bytes", baseAddr, moduleSize);
    LogMessage(msg);
        
        // 第一步：定位验证函数 sub_7363F0
        LogMessage(L"[XSJZB] Searching for validation function...");
        const BYTE* validationFunc = FindValidationFunction(baseAddr, moduleSize);
        
        if (!validationFunc) {
            LogMessage(L"[XSJZB] Validation function not found, falling back to pattern search");
            
            // 回退到直接搜索 MD5 哈希字符串
            const BYTE hashPattern[] = {
                'F', 'B', 'F', 'D', 'E', '0', 'E', 'D', '2', '3', 'E', 'C', '5', 'C', '6', 'F'
            };
            const BYTE* hashAddr = SearchMemoryPattern(baseAddr, moduleSize, hashPattern, sizeof(hashPattern));
            
            if (!hashAddr) {
                LogMessage(L"[XSJZB] MD5 hash not found");
                return false;
            }
            
            swprintf_s(msg, 512, L"[XSJZB] Found MD5 hash at 0x%p", hashAddr);
            LogMessage(msg);
            
            // 在哈希前后搜索 UID、用户名、公司名
            // UID 通常在 MD5 前面不远处
            const BYTE* searchStart = (hashAddr > baseAddr + 256) ? (hashAddr - 256) : baseAddr;
            size_t searchSize = 512;
            
            const BYTE* uidAddr = nullptr;
            const BYTE* usernameAddr = nullptr;
            const BYTE* companyAddr = nullptr;
            
            // 搜索 UID（10位数字）
            for (size_t i = 0; i < searchSize - 10; i++) {
                const BYTE* p = searchStart + i;
                bool isUid = true;
                BYTE testBuf[11];
                if (!SafeMemoryRead(p, testBuf, 11)) {
                    continue;
                }
                for (int j = 0; j < 10; j++) {
                    if (testBuf[j] < '0' || testBuf[j] > '9') {
                        isUid = false;
                        break;
                    }
                }
                if (isUid && (testBuf[10] < '0' || testBuf[10] > '9')) {
                    uidAddr = p;
                    break;
                }
            }
            
            // 搜索用户名（重复双字模式）
            for (size_t i = 0; i < searchSize - 8; i++) {
                const BYTE* p = searchStart + i;
                BYTE testBuf[8];
                if (!SafeMemoryRead(p, testBuf, 8)) {
                    continue;
                }
                if (testBuf[0] >= 0xA1 && testBuf[0] <= 0xFE && testBuf[1] >= 0xA1 && testBuf[1] <= 0xFE &&
                    testBuf[0] == testBuf[4] && testBuf[1] == testBuf[5] && testBuf[2] == testBuf[6] && testBuf[3] == testBuf[7]) {
                    usernameAddr = p;
                    break;
                }
            }
            
            // 搜索公司名（"公司"关键词）
            const BYTE companyKeyword[] = {0xB9, 0xAB, 0xCB, 0xBE}; // "公司"
            for (size_t i = 0; i < searchSize - 24; i++) {
                const BYTE* p = searchStart + i;
                // 检查是否包含"公司"且前面有足够的 GB2312 字符
                bool hasCompanyKeyword = false;
                for (size_t j = 0; j < 20; j += 2) {
                    if (SafeMemoryCompare(p + j, companyKeyword, 4)) {
                        hasCompanyKeyword = true;
                        break;
                    }
                }
                if (hasCompanyKeyword) {
                    companyAddr = p;
                    break;
                }
            }
            
            if (uidAddr && usernameAddr && companyAddr) {
                // 保存地址
                g_xsjzbUidAddr = uidAddr;
                g_xsjzbUsernameAddr = usernameAddr;
                g_xsjzbCompanyAddr = companyAddr;
                g_xsjzbDataLocated = true;
                
                // 读取当前值用于日志
                char uidStr[16] = {0};
                if (SafeMemoryRead(uidAddr, uidStr, 10)) {
                    DWORD currentUid = atol(uidStr);
                    swprintf_s(msg, 512, L"[XSJZB] ✓ Located via fallback: UID=%u at 0x%p", currentUid, uidAddr);
                    LogMessage(msg);
                }
                
                LogMessage(L"[XSJZB] Memory addresses located (fallback) - will read dynamically when needed");
                return true;
            }
            
            return false;
        }
        
        // 找到了验证函数
        swprintf_s(msg, 512, L"[XSJZB] ✓ Found validation function at 0x%p", validationFunc);
        LogMessage(msg);
        
        // 第二步：在函数中查找字符串引用（最多分析 1KB 的函数代码）
        std::vector<const BYTE*> stringRefs;
        size_t maxFuncSize = 1024;
        
        for (size_t i = 0; i < maxFuncSize && (validationFunc + i) < (baseAddr + moduleSize); i++) {
            const BYTE* instr = validationFunc + i;
            
            // push offset addr (68 xx xx xx xx)
            if (instr[0] == 0x68) {
                DWORD addr = *(DWORD*)(instr + 1);
                if (addr >= (DWORD)baseAddr && addr < (DWORD)(baseAddr + moduleSize)) {
                    stringRefs.push_back((const BYTE*)addr);
                }
            }
            
            // mov reg, offset addr
            if ((instr[0] == 0xBA || instr[0] == 0xB8 || instr[0] == 0xB9) && 
                i + 5 < maxFuncSize) {
                DWORD addr = *(DWORD*)(instr + 1);
                if (addr >= (DWORD)baseAddr && addr < (DWORD)(baseAddr + moduleSize)) {
                    stringRefs.push_back((const BYTE*)addr);
                }
            }
        }
        
        swprintf_s(msg, 512, L"[XSJZB] Found %zu string references in function", stringRefs.size());
        LogMessage(msg);
        
        const BYTE* uidAddr = nullptr;
        const BYTE* usernameAddr = nullptr;
        const BYTE* companyAddr = nullptr;
        
        // 第三步：分析每个引用，识别数据类型
        for (auto ref : stringRefs) {
            BYTE testBuf[32];
            if (!SafeMemoryRead(ref, testBuf, 32)) {
                continue;
            }
            
            // 检查是否是 UID（10位数字）
            bool isUid = true;
            for (int i = 0; i < 10; i++) {
                if (testBuf[i] < '0' || testBuf[i] > '9') {
                    isUid = false;
                    break;
                }
            }
            if (isUid && (testBuf[10] == 0 || testBuf[10] < '0' || testBuf[10] > '9')) {
                uidAddr = ref;
                continue;
            }
            
            // 检查是否是 MD5 哈希（32个十六进制字符）
            bool isHash = true;
            for (int i = 0; i < 32; i++) {
                char c = testBuf[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                    isHash = false;
                    break;
                }
            }
            if (isHash) {
                continue; // 跳过哈希
            }
            
            // 检查是否是重复双字用户名模式
            if (testBuf[0] >= 0xA1 && testBuf[0] <= 0xFE && testBuf[1] >= 0xA1 && testBuf[1] <= 0xFE &&
                testBuf[0] == testBuf[4] && testBuf[1] == testBuf[5] && testBuf[2] == testBuf[6] && testBuf[3] == testBuf[7]) {
                usernameAddr = ref;
                continue;
            }
            
            // 检查是否是公司名（包含"公司"关键词）
            const BYTE companyKeyword[] = {0xB9, 0xAB, 0xCB, 0xBE}; // "公司"
            for (int i = 0; i < 24; i += 2) {
                if (SafeMemoryCompare(ref + i, companyKeyword, 4)) {
                    companyAddr = ref;
                    break;
                }
            }
        }
        
        // 验证结果
        if (!uidAddr || !usernameAddr || !companyAddr) {
            LogMessage(L"[XSJZB] Could not identify all required data in function references");
            return false;
        }
        
        // 保存地址供后续使用
        g_xsjzbUidAddr = uidAddr;
        g_xsjzbUsernameAddr = usernameAddr;
        g_xsjzbCompanyAddr = companyAddr;
        g_xsjzbDataLocated = true;
        
        // 读取当前值用于日志
        char uidStr[16] = {0};
        char userBuf[8] = {0};
        
        if (SafeMemoryRead(uidAddr, uidStr, 10) && SafeMemoryRead(usernameAddr, userBuf, 8)) {
            DWORD currentUid = atol(uidStr);
            swprintf_s(msg, 512, L"[XSJZB] ✓ Located UID=%u at 0x%p", currentUid, uidAddr);
            LogMessage(msg);
            swprintf_s(msg, 512, L"[XSJZB] ✓ Located Username at 0x%p: %02X %02X %02X %02X %02X %02X %02X %02X",
                       usernameAddr, (BYTE)userBuf[0], (BYTE)userBuf[1], (BYTE)userBuf[2], (BYTE)userBuf[3],
                       (BYTE)userBuf[4], (BYTE)userBuf[5], (BYTE)userBuf[6], (BYTE)userBuf[7]);
            LogMessage(msg);
            swprintf_s(msg, 512, L"[XSJZB] ✓ Located Company at 0x%p", companyAddr);
            LogMessage(msg);
        }
        
        LogMessage(L"[XSJZB] Memory addresses located - will read dynamically when needed");
        return true;
}

// 从已定位的内存地址动态读取当前验证数据
static bool ReadCurrentXsjzbData(DWORD& uidOut, std::string& usernameOut, std::string& companyOut) {
    if (!g_xsjzbDataLocated) {
        return false;
    }
    
    char uidStr[16] = {0};
    char userBuf[8] = {0};
    char compBuf[24] = {0};
    
    if (!SafeMemoryRead(g_xsjzbUidAddr, uidStr, 10) ||
        !SafeMemoryRead(g_xsjzbUsernameAddr, userBuf, 8) ||
        !SafeMemoryRead(g_xsjzbCompanyAddr, compBuf, 24)) {
        LogMessage(L"[XSJZB] Failed to read current data from memory");
        return false;
    }
    
    uidOut = atol(uidStr);
    usernameOut.assign(userBuf, 8);
    companyOut.assign(compBuf, 24);
    
    wchar_t msg[256];
    swprintf_s(msg, 256, L"[XSJZB] Current UID=%u", uidOut);
    LogMessage(msg);
    
    return true;
}

// 计算 sector1 的校验和
static DWORD CalculateSector1Checksum(const BYTE* sector1Data) {
    DWORD sum = 0;
    // 前 508 字节参与校验和计算
    for (int i = 0; i < 508; i++) {
        sum += sector1Data[i];
    }
    return sum;
}

// 动态生成 Sector 0 (基于当前内存数据)
static bool GenerateDynamicSector0(BYTE* sector0, DWORD uid) {
    // Sector0: UID的十进制字符串,其余填充0x00
    memset(sector0, 0x00, 512);
    
    char uidStr[32];
    sprintf_s(uidStr, sizeof(uidStr), "%u", uid);
    memcpy(sector0, uidStr, strlen(uidStr));
    
    return true;
}

// 动态生成 Sector 1 (基于当前内存数据)
static bool GenerateDynamicSector1(BYTE* sector1) {
    if (!g_xsjzbDataLocated) {
        return false;
    }
    
    DWORD uid;
    std::string username, company;
    if (!ReadCurrentXsjzbData(uid, username, company)) {
        return false;
    }
    
    // 清零
    memset(sector1, 0x00, 512);
    
    // 获取当前年份
    SYSTEMTIME st;
    GetLocalTime(&st);
    int currentYear = st.wYear;
    int nextYear = currentYear + 1;
    
    // 构建 sector1 模板(与launcher一致)
    // 格式: 用户名 + 年检信息模板
    char sector1Template[512];
    int offset = sprintf_s(sector1Template, sizeof(sector1Template),
                          "%s  %d\xc4\xea\xb6\xc8\xd3\xda%d-01-01 12:00:00 %d\xc4\xea\xb6\xc8\xd3\xda%d-01-01 12:00:00 \xd2\xd1\xb1\xb8\xb0\xb8-\xd4\xda\xd3\xc3        000000000000000000000000000000000        %s",
                          username.c_str(), currentYear, currentYear, nextYear, nextYear, company.c_str());
    
    if (offset > 0 && offset < 512) {
        memcpy(sector1, sector1Template, offset);
    }
    
    // 注意: 校验和会在launcher的UpdateSector1Checksum中计算
    // 这里我们简化,不计算校验和(因为xsjzb可能不检查)
    
    return true;
}

// 生成并保存缓存文件
static bool GenerateCacheFromXsjzbValues(DWORD uid, const std::string& username, const std::string& company) {
    // 随机生成 HID (使用加密安全的随机数)
    HCRYPTPROV hProv = 0;
    DWORD hid = 0;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&hid);
        CryptReleaseContext(hProv, 0);
        hid |= 0x80000000; // 确保最高位为 1
    } else {
        hid = 0x87654321; // 回退默认值
    }
    
    // 准备 sector0 和 sector1
    BYTE sector0[512] = {0};
    BYTE sector1[512] = {0};
    
    // sector0: 8个 mini-block, 每个64字节
    for (int i = 0; i < 8; i++) {
        memset(sector0 + i * 64, 0xFF, 64);
    }
    
    // sector1 结构:
    // [0-7]: 用户名 (GB2312, 最多8字节)
    // [8-15]: 年检日期 ("20241115", 8字节)
    // [16-39]: 公司名 (GB2312, 最多24字节)
    // [40-507]: 填充 0xFF
    // [508-511]: 校验和 (DWORD, little-endian)
    
    // 复制用户名
    if (username.size() > 0) {
        size_t copyLen = (username.size() > 8) ? 8 : username.size();
        memcpy(sector1, username.c_str(), copyLen);
    }
    
    // 写入年检日期
    SYSTEMTIME st;
    GetLocalTime(&st);
    char dateStr[9];
    sprintf_s(dateStr, "%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
    memcpy(sector1 + 8, dateStr, 8);
    
    // 复制公司名
    if (company.size() > 0) {
        size_t copyLen = (company.size() > 24) ? 24 : company.size();
        memcpy(sector1 + 16, company.c_str(), copyLen);
    }
    
    // 填充剩余部分
    memset(sector1 + 40, 0xFF, 468);
    
    // 计算并写入校验和
    DWORD checksum = CalculateSector1Checksum(sector1);
    memcpy(sector1 + 508, &checksum, 4);
    
    // 获取缓存目录
    const std::wstring& cacheDir = GetCacheDirectory();
    
    // 保存 device.cfg
    wchar_t configPath[MAX_PATH];
    swprintf_s(configPath, L"%sdevice.cfg", cacheDir.c_str());
    FILE* fp = _wfopen(configPath, L"wt, ccs=UTF-8");
    if (!fp) {
        LogMessage(L"[CACHE] Failed to create device.cfg");
        return false;
    }
    
    std::wstring serial = GenerateSerialFromHidUid(hid, uid);
    fprintf(fp, "HID=0x%08X\n", hid);
    fprintf(fp, "UID=%u\n", uid);
    fprintf(fp, "VID=0x096E\n");
    fprintf(fp, "PID=0x0201\n");
    fprintf(fp, "Version=0x0100\n");
    fprintf(fp, "ProductString=ROCKEY2\n");
    fwprintf(fp, L"SerialNumberString=%s\n", serial.c_str());
    fprintf(fp, "FeatureReportLength=65\n");
    fprintf(fp, "InputReportLength=65\n");
    fprintf(fp, "OutputReportLength=65\n");
    fprintf(fp, "Usage=1\n");
    fprintf(fp, "UsagePage=65280\n");
    fclose(fp);
    
    // 保存 sector0
    swprintf_s(configPath, L"%smem_%u_sector0.dat", cacheDir.c_str(), uid);
    fp = _wfopen(configPath, L"wb");
    if (fp) {
        fwrite(sector0, 1, 512, fp);
        fclose(fp);
    }
    
    // 保存 sector1
    swprintf_s(configPath, L"%smem_%u_sector1.dat", cacheDir.c_str(), uid);
    fp = _wfopen(configPath, L"wb");
    if (fp) {
        fwrite(sector1, 1, 512, fp);
        fclose(fp);
    }
    
    wchar_t msg[512];
    swprintf_s(msg, 512, L"[CACHE] Generated cache files: UID=%u, HID=0x%08X, Serial=%s, Checksum=0x%08X",
               uid, hid, serial.c_str(), checksum);
    LogMessage(msg);
    
    return true;
}

// Hook 函数实现
VOID WINAPI Hook_HidD_GetHidGuid(LPGUID HidGuid) {
    static bool dataLocateAttempted = false;
    
    LogHidCall(L"HidD_GetHidGuid", L"Called");
    
    // 第一次调用时尝试定位 xsjzb 内存数据
    if (!dataLocateAttempted) {
        dataLocateAttempted = true;
        
        LogMessage(L"[XSJZB] Attempting to locate validation data in memory...");
        
        if (LocateXsjzbValidationData()) {
            LogMessage(L"[XSJZB] Validation data located successfully - using dynamic memory access");
            
            // 读取当前的 UID/用户名/公司名，生成虚拟设备缓存数据
            DWORD currentUid = 0;
            std::string username, company;
            if (ReadCurrentXsjzbData(currentUid, username, company)) {
                // 生成随机 HID
                HCRYPTPROV hProv = 0;
                DWORD hid = 0;
                if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                    CryptGenRandom(hProv, sizeof(DWORD), (BYTE*)&hid);
                    CryptReleaseContext(hProv, 0);
                    hid |= 0x80000000; // 确保最高位为 1
                } else {
                    hid = 0x87654321; // 回退默认值
                }
                
                // 填充 g_hidCache 结构
                g_hidCache.vendorId = kTargetVendorId;     // 0x096E
                g_hidCache.productId = kTargetProductId;   // 0x0201
                g_hidCache.versionNumber = 0x0100;
                g_hidCache.cachedUid = currentUid;
                g_hidCache.cachedHid = hid;
                
                // 生成序列号
                std::wstring serialNumber = GenerateSerialFromHidUid(hid, currentUid);
                wcscpy_s(g_hidCache.serialNumberString, serialNumber.c_str());
                
                // 产品字符串（模拟真实的 Rockey2 USB 加密锁）
                wcscpy_s(g_hidCache.productString, L"USB DONGLE");
                
                // 设置 HID Capabilities
                g_hidCache.usage = 0x0000;
                g_hidCache.usagePage = 0x0000;
                g_hidCache.inputReportLength = 0;
                g_hidCache.outputReportLength = 0;
                g_hidCache.featureReportLength = 73;
                
                // 生成 sector 数据到 partition
                BYTE sector0[512], sector1[512];
                GenerateDynamicSector0(sector0, currentUid);
                GenerateDynamicSector1(sector1);
                
                // 复制到 partition（8个64字节块）
                memcpy(g_hidCache.partition0, sector0, 512);
                memcpy(g_hidCache.partition1, sector1, 512);
                
                g_hidCache.isValid = true;
                
                wchar_t msg[256];
                swprintf_s(msg, 256, L"[CACHE] Generated virtual device data: UID=%u, HID=0x%08X, Serial=%s",
                           currentUid, hid, serialNumber.c_str());
                LogMessage(msg);
            }
        } else {
            LogMessage(L"[XSJZB] Failed to locate validation data (wrong version or not xsjzb.exe?)");
        }
    }
    
    Real_HidD_GetHidGuid(HidGuid);
}

BOOLEAN WINAPI Hook_HidD_GetAttributes(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes) {
    EnsureCacheLoaded();
    
    // 检查是否已定位 xsjzb 数据或有缓存
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    
    // 如果是虚拟句柄,总是返回虚拟设备信息
    if (HidDeviceObject == (HANDLE)0xCAFEBABE && canEmulate && Attributes) {
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
    
    // 检查这个句柄是否已经在劫持列表中
    InitHijackedHandles();
    EnterCriticalSection(&g_hijackedHandlesCs);
    bool alreadyHijacked = std::find(g_hijackedHandles.begin(), g_hijackedHandles.end(), HidDeviceObject) != g_hijackedHandles.end();
    bool hasAnyHijacked = !g_hijackedHandles.empty();
    LeaveCriticalSection(&g_hijackedHandlesCs);
    
    // 如果可以模拟且还没劫持任何设备,劫持当前这个设备
    if (canEmulate && !hasAnyHijacked && Attributes) {
        // 添加到劫持句柄列表
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
    if (result && canEmulate && Attributes &&
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
    
    // 不记录普通真实设备的属性（太多了）
    // 只在上面记录了劫持设备和虚拟设备
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetFeature(HANDLE HidDeviceObject, PVOID ReportBuffer, ULONG ReportBufferLength) {
    EnsureCacheLoaded();
    
    BOOLEAN result = FALSE;
    bool usedCache = false;
    bool virtualized = false;
    
    // 检查是否可以模拟设备（缓存模式或动态内存模式）
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    if (canEmulate) {
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
            
            // 如果定位了xsjzb数据,使用动态生成的sector数据
            if (g_xsjzbDataLocated) {
                BYTE dynamicSector[512];
                bool generated = false;
                
                // 读取当前UID
                DWORD currentUid = 0;
                std::string username, company;
                if (ReadCurrentXsjzbData(currentUid, username, company)) {
                    if (sector == 0) {
                        generated = GenerateDynamicSector0(dynamicSector, currentUid);
                    } else if (sector == 1) {
                        generated = GenerateDynamicSector1(dynamicSector);
                    }
                }
                
                if (generated) {
                    // 复制对应的64字节block
                    memcpy(&data[9], &dynamicSector[block * 64], 64);
                    
                    result = TRUE;
                    usedCache = true;
                    virtualized = true;
                    
                    wchar_t msg[256];
                    swprintf_s(msg, 256, L"[DYNAMIC DATA] GetFeature: Sector=%d, Block=%d (from xsjzb memory)", 
                               sector, block);
                    LogMessage(msg);
                    LeaveCriticalSection(&g_uidCollector.cs);
                    goto log_and_return;
                }
            }
            
            // 回退到缓存数据
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

log_and_return:
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
    
    // 检查是否可以模拟设备
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    if (canEmulate) {
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
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    if (HidDeviceObject == (HANDLE)0xCAFEBABE && canEmulate) {
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
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    
    if ((isVirtualHandle || canEmulate) && g_hidCache.isValid && Buffer && BufferLength > 0) {
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
        // 如果定位了xsjzb数据,使用动态UID生成序列号
        if (g_xsjzbDataLocated) {
            DWORD currentUid = 0;
            std::string username, company;
            if (ReadCurrentXsjzbData(currentUid, username, company)) {
                // 使用缓存的HID和当前UID生成序列号
                std::wstring dynamicSerial = GenerateSerialFromHidUid(g_hidCache.cachedHid, currentUid);
                
                size_t len = dynamicSerial.length();
                size_t copyLen = (len + 1) * sizeof(wchar_t);
                if (copyLen > BufferLength) copyLen = BufferLength;
                
                memcpy(Buffer, dynamicSerial.c_str(), copyLen);
                ((wchar_t*)Buffer)[BufferLength / sizeof(wchar_t) - 1] = L'\0';
                
                wchar_t details[256];
                swprintf_s(details, 256, L"Serial: %s [DYNAMIC from UID=%u]", dynamicSerial.c_str(), currentUid);
                LogHidCall(L"HidD_GetSerialNumberString", details);
                return TRUE;
            }
        }
        
        // 回退到缓存的序列号字符串
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
        
        // 清空劫持列表,允许新会话重新劫持设备
        InitHijackedHandles();
        EnterCriticalSection(&g_hijackedHandlesCs);
        g_hijackedHandles.clear();
        LeaveCriticalSection(&g_hijackedHandlesCs);
        
        LogMessage(L"[ENUM] New device enumeration session started");
    }
    
    // 先调用真实 API
    BOOL result = Real_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);
    
    if (result) {
        // 真实设备存在
        g_lastRealDeviceIndex = MemberIndex;
        // 不记录每个真实设备（太多了）
        return TRUE;
    }
    
    // result == FALSE：没有更多真实设备
    DWORD error = GetLastError();
    
    // 【策略】优先劫持第一个真实设备，只有在没有劫持任何设备时才注入虚拟设备
    EnterCriticalSection(&g_hijackedHandlesCs);
    bool hasHijackedHandles = !g_hijackedHandles.empty();
    LeaveCriticalSection(&g_hijackedHandlesCs);
    
    // 检查是否可以模拟（缓存或动态内存）
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    
    // 仅在没有劫持真实设备时才注入虚拟设备
    if (error == ERROR_NO_MORE_ITEMS && canEmulate && !g_virtualDeviceInjected && !hasHijackedHandles) {
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
        return TRUE;
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
    
    // 虚拟设备检查 - 支持缓存模式或动态模式
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    if (isVirtualDevice && canEmulate) {
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
    
    // 只记录关键的设备打开（劫持/虚拟设备）
    // 不记录所有真实设备打开，避免日志过多
    
    // 检查是否是我们的虚拟设备路径
    bool canEmulate = g_xsjzbDataLocated || g_hidCache.isValid;
    if (lpFileName && wcsstr(lpFileName, L"VID_096E&PID_0201") && wcsstr(lpFileName, L"VIRTUAL_CACHE")) {
        if (canEmulate) {
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
    if (hDevice != INVALID_HANDLE_VALUE && canEmulate && lpFileName) {
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
