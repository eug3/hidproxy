#pragma once
#include <windows.h>

// HID Hook 管理
bool InstallHidHooks();
void UninstallHidHooks();

// 日志函数
void LogMessage(const wchar_t* message);
void LogHidCall(const wchar_t* functionName, const wchar_t* details);
void LogHexDump(const wchar_t* label, const BYTE* data, ULONG length);

// UID 数据采集
void ProcessUidData(const BYTE* data, ULONG length);
