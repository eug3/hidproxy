#pragma once
#include <windows.h>
#include <string>

extern HMODULE g_hModule;

// 缓存数据结构 - 完整的设备响应缓存
struct CachedHidData {
    // 数据块缓存
    BYTE partition0[8][64];  // 分区 0: 8 个 mini-block
    BYTE partition1[8][64];  // 分区 1: 8 个 mini-block
    
    // 设备属性缓存
    DWORD cachedUid;         // 缓存的 UID
    DWORD cachedHid;         // 缓存的 HID
    USHORT vendorId;         // VID
    USHORT productId;        // PID
    USHORT versionNumber;    // Version
    
    // 字符串缓存
    WCHAR productString[256];      // 产品名称
    WCHAR serialNumberString[256]; // 序列号
    
    // PreparsedData 和 Capabilities 缓存
    USHORT inputReportLength;
    USHORT outputReportLength;
    USHORT featureReportLength;
    USHORT usage;
    USHORT usagePage;
    
    bool isValid;            // 缓存是否有效
};

// HID Hook 管理
bool InstallHidHooks();
void UninstallHidHooks();
void InitializeVirtualDeviceState();
bool IsVirtualDeviceActive();
void ConfigureVirtualDeviceIdentity(DWORD hidValue, DWORD uidValue);
void GenerateVirtualSectorsFromIdentity(DWORD hidValue, DWORD uidValue, int year);
const std::wstring& GetCacheDirectory();
std::wstring GetConfigFilePath();
std::wstring BuildSectorFilePath(DWORD uidValue, BYTE sector);

// 日志函数
void LogMessage(const wchar_t* message);
void LogHidCall(const wchar_t* functionName, const wchar_t* details);
void LogHexDump(const wchar_t* label, const BYTE* data, ULONG length);

// UID 数据采集
void ProcessUidData(const BYTE* data, ULONG length);
