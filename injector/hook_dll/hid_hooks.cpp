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

// Hook 函数实现
VOID WINAPI Hook_HidD_GetHidGuid(LPGUID HidGuid) {
    LogHidCall(L"HidD_GetHidGuid", L"Called");
    Real_HidD_GetHidGuid(HidGuid);
}

BOOLEAN WINAPI Hook_HidD_GetAttributes(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes) {
    BOOLEAN result = Real_HidD_GetAttributes(HidDeviceObject, Attributes);
    bool virtualResponse = false;
    
    if (!result && g_virtualDeviceEnabled && Attributes) {
        ZeroMemory(Attributes, sizeof(HIDD_ATTRIBUTES));
        Attributes->Size = sizeof(HIDD_ATTRIBUTES);
        Attributes->VendorID = kTargetVendorId;
        Attributes->ProductID = kTargetProductId;
        Attributes->VersionNumber = kVirtualVersion;
        result = TRUE;
        virtualResponse = true;
    }
    
    if (result && Attributes) {
        wchar_t details[256];
        swprintf_s(details, 256,
                 virtualResponse ?
                 L"VID=0x%04X, PID=0x%04X, Version=0x%04X (virtual)" :
                 L"VID=0x%04X, PID=0x%04X, Version=0x%04X",
                 Attributes->VendorID,
                 Attributes->ProductID,
                 Attributes->VersionNumber);
        LogHidCall(L"HidD_GetAttributes", details);
    } else {
        LogHidCall(L"HidD_GetAttributes", L"Failed");
    }
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetFeature(HANDLE HidDeviceObject, PVOID ReportBuffer, ULONG ReportBufferLength) {
    BOOLEAN result = Real_HidD_GetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
    bool usedCache = false;
    bool virtualized = false;
    
    if (result) {
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
    wchar_t details[512];
    swprintf_s(details, 512, L"Write: %u bytes", ReportBufferLength);
    LogHidCall(L"HidD_SetFeature", details);
    
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
    
    BOOLEAN result = Real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
    
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
    
    return result;
}

BOOLEAN WINAPI Hook_HidD_FlushQueue(HANDLE HidDeviceObject) {
    BOOLEAN result = Real_HidD_FlushQueue(HidDeviceObject);
    if (!result && g_virtualDeviceEnabled) {
        LogHidCall(L"HidD_FlushQueue", L"Virtual success");
        return TRUE;
    }
    LogHidCall(L"HidD_FlushQueue", result ? L"Success" : L"Failed");
    return result;
}

BOOLEAN WINAPI Hook_HidD_GetPreparsedData(HANDLE HidDeviceObject, PHIDP_PREPARSED_DATA* PreparsedData) {
    LogHidCall(L"HidD_GetPreparsedData", L"Called");
    return Real_HidD_GetPreparsedData(HidDeviceObject, PreparsedData);
}

BOOLEAN WINAPI Hook_HidD_FreePreparsedData(PHIDP_PREPARSED_DATA PreparsedData) {
    LogHidCall(L"HidD_FreePreparsedData", L"Called");
    return Real_HidD_FreePreparsedData(PreparsedData);
}

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
