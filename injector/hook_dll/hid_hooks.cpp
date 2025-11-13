#include "hid_hooks.h"
#include "logging.h"
#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <stdio.h>

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
    
    UidDataCollector() : hasUid(false), useCacheForNextRead(false), hasCachedData(false),
                        pendingReadSector(0xFF), pendingReadBlock(0xFF) {
        memset(uid, 0, sizeof(uid));
        memset(sectors, 0, sizeof(sectors));
        memset(sectorReceived, 0, sizeof(sectorReceived));
        memset(cachedData, 0, sizeof(cachedData));
        InitializeCriticalSection(&cs);
    }
    
    ~UidDataCollector() {
        DeleteCriticalSection(&cs);
    }
};

static UidDataCollector g_uidCollector;

// 检查并加载缓存文件
bool LoadCacheIfExists(BYTE sector, const BYTE* uid) {
    wchar_t processPath[MAX_PATH];
    GetModuleFileNameW(NULL, processPath, MAX_PATH);
    
    wchar_t* lastSlash = wcsrchr(processPath, L'\\');
    if (lastSlash) {
        *(lastSlash + 1) = 0;
    }
    
    // 将 UID 转换为十进制
    DWORD uidDecimal = (uid[3] << 24) | (uid[2] << 16) | (uid[1] << 8) | uid[0];
    
    wchar_t filePath[MAX_PATH];
    swprintf_s(filePath, MAX_PATH, L"%smem_%u_sector%d.dat", processPath, uidDecimal, sector);
    
    // 检查文件是否存在
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesRead;
        bool success = ReadFile(hFile, g_uidCollector.cachedData, 512, &bytesRead, NULL);
        CloseHandle(hFile);
        
        if (success && bytesRead == 512) {
            g_uidCollector.hasCachedData = true;
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHE] Loaded sector %d from cache: %s", sector, filePath);
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

// Hook 函数实现
VOID WINAPI Hook_HidD_GetHidGuid(LPGUID HidGuid) {
    LogHidCall(L"HidD_GetHidGuid", L"Called");
    Real_HidD_GetHidGuid(HidGuid);
}

BOOLEAN WINAPI Hook_HidD_GetAttributes(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes) {
    BOOLEAN result = Real_HidD_GetAttributes(HidDeviceObject, Attributes);
    
    if (result && Attributes) {
        wchar_t details[256];
        swprintf_s(details, 256, 
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
    
    if (result) {
        // 检查是否需要使用缓存
        EnterCriticalSection(&g_uidCollector.cs);
        bool useCache = g_uidCollector.useCacheForNextRead && g_uidCollector.hasCachedData;
        BYTE sector = g_uidCollector.pendingReadSector;
        BYTE block = g_uidCollector.pendingReadBlock;
        
        if (useCache && ReportBufferLength >= 73) {
            // 保持头部 (5字节) + UID (4字节) ，替换剩余数据
            BYTE* data = (BYTE*)ReportBuffer;
            ULONG dataOffset = 9;
            ULONG dataSize = min(64, ReportBufferLength - dataOffset);
            
            // 从缓存中获取对应块的数据
            memcpy(&data[dataOffset], &g_uidCollector.cachedData[block * 64], dataSize);
            
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[CACHE] Replaced data with cache: Sector %d, Block %d", sector, block);
            LogMessage(msg);
            
            // 重置缓存标志
            g_uidCollector.useCacheForNextRead = false;
        }
        LeaveCriticalSection(&g_uidCollector.cs);
        
        wchar_t details[512];
        swprintf_s(details, 512, L"Success: %u bytes%s", ReportBufferLength, useCache ? L" (FROM CACHE)" : L"");
        LogHidCall(L"HidD_GetFeature", details);
        
        // Output full hex dump
        if (ReportBufferLength > 0) {
            LogHexDump(useCache ? L"Data received (cached)" : L"Data received", (BYTE*)ReportBuffer, ReportBufferLength);
            
            // 处理 UID 数据 (只在非缓存时)
            if (!useCache) {
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
        wchar_t errMsg[128];
        swprintf_s(errMsg, 128, L"  SetFeature failed, error: %d", GetLastError());
        LogMessage(errMsg);
    }
    
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
