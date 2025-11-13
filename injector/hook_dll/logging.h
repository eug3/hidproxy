#pragma once
#include <windows.h>

// 日志管理
void InitializeLogging();
void ShutdownLogging();
void LogMessage(const wchar_t* message);
void LogHidCall(const wchar_t* functionName, const wchar_t* details);
