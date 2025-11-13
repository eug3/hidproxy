#include "logging.h"
#include <stdio.h>
#include <time.h>

static FILE* g_logFile = NULL;
static CRITICAL_SECTION g_logLock;

void InitializeLogging() {
    InitializeCriticalSection(&g_logLock);
    
    // Create log file (append mode)
    wchar_t logPath[MAX_PATH];
    GetModuleFileNameW(NULL, logPath, MAX_PATH);
    
    // Change process path to log path
    wchar_t* pFileName = wcsrchr(logPath, L'\\');
    if (pFileName) {
        wcscpy(pFileName + 1, L"hid_hook.log");
    }
    
    _wfopen_s(&g_logFile, logPath, L"a");
    
    if (g_logFile) {
        fwprintf(g_logFile, L"\n");
    }
}

void ShutdownLogging() {
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }
    DeleteCriticalSection(&g_logLock);
}

void LogMessage(const wchar_t* message) {
    EnterCriticalSection(&g_logLock);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // Write to file
    if (g_logFile) {
        fwprintf(g_logFile, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                message);
        fflush(g_logFile);
    }
    
    // Output to DebugView
    wchar_t debugMsg[1024];
    swprintf(debugMsg, 1024, L"[HID Hook] %s", message);
    OutputDebugStringW(debugMsg);
    
    LeaveCriticalSection(&g_logLock);
}

void LogHidCall(const wchar_t* functionName, const wchar_t* details) {
    wchar_t message[512];
    swprintf_s(message, 512, L"[HID] %s - %s", functionName, details);
    LogMessage(message);
}
