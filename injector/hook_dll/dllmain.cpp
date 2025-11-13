#include <windows.h>
#include <stdio.h>
#include "hid_hooks.h"
#include "logging.h"

HMODULE g_hModule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) {
    switch (ul_reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_hModule = hModule;
        
        // Initialize logging
        InitializeLogging();
        LogMessage(L"========================================");
        LogMessage(L"  HID Hook DLL Loaded");
        LogMessage(L"========================================");
        
        // Get process information
        wchar_t processPath[MAX_PATH];
        GetModuleFileNameW(NULL, processPath, MAX_PATH);
        
        wchar_t logMsg[512];
        swprintf_s(logMsg, 512, L"Target Process: %s", processPath);
        LogMessage(logMsg);
        
        swprintf_s(logMsg, 512, L"DLL Base: 0x%p", hModule);
        LogMessage(logMsg);
        
        // Install HID Hooks
        LogMessage(L"Installing HID Hooks...");
        if (InstallHidHooks()) {
            LogMessage(L"[OK] HID Hooks installed successfully");
        } else {
            LogMessage(L"[ERROR] Failed to install HID Hooks");
        }
        
        LogMessage(L"========================================");
        break;

    case DLL_PROCESS_DETACH:
        LogMessage(L"========================================");
        LogMessage(L"  HID Hook DLL Unloading");
        LogMessage(L"========================================");
        
        // Uninstall Hooks
        UninstallHidHooks();
        LogMessage(L"[OK] HID Hooks uninstalled");
        
        // 关闭日志
        ShutdownLogging();
        break;
    }
    return TRUE;
}
