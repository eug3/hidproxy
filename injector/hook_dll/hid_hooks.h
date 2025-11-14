#pragma once
#include <windows.h>
#include <string>

extern HMODULE g_hModule;

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
