// Include winsock2.h BEFORE windows.h to avoid conflicts
#include "network_hooks.h"  // This includes winsock2.h
#include <windows.h>
#include <stdio.h>
#include <string>
#include <cwctype>
#include <wchar.h>
#include "hid_hooks.h"
#include "logging.h"

HMODULE g_hModule = NULL;

static std::wstring Trim(const std::wstring& input) {
    size_t start = 0;
    while (start < input.size() && iswspace(input[start])) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && iswspace(input[end - 1])) {
        --end;
    }
    return input.substr(start, end - start);
}

static std::wstring ToLower(const std::wstring& input) {
    std::wstring result = input;
    for (auto& ch : result) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return result;
}

static DWORD ReverseDwordBytes(DWORD value) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0xFF000000) >> 24);
}

static bool ParseHexString(const std::wstring& text, DWORD& output) {
    if (text.empty()) {
        return false;
    }
    wchar_t* endPtr = nullptr;
    output = wcstoul(text.c_str(), &endPtr, 16);
    return (endPtr != nullptr && endPtr != text.c_str());
}

static bool ParseSerialString(const std::wstring& serialInput, DWORD& hidOut, DWORD& uidOut) {
    std::wstring serial = Trim(serialInput);
    if (serial.rfind(L"0x", 0) == 0 || serial.rfind(L"0X", 0) == 0) {
        serial = serial.substr(2);
    }
    if (serial.length() < 16) {
        return false;
    }
    std::wstring hidPart = serial.substr(0, 8);
    std::wstring uidSeedPart = serial.substr(8, 8);

    DWORD hidValue = 0;
    DWORD uidSeed = 0;
    if (!ParseHexString(hidPart, hidValue) || !ParseHexString(uidSeedPart, uidSeed)) {
        return false;
    }

    DWORD hidReversed = ReverseDwordBytes(hidValue);
    hidOut = hidValue;
    uidOut = uidSeed ^ hidReversed;
    return true;
}

static bool LoadVirtualIdentityConfig(const std::wstring& directory, DWORD& hidOut, DWORD& uidOut, int& yearOut) {
    std::wstring configPath = directory;
    configPath += L"virtual_device.cfg";
    yearOut = 0;

    FILE* file = nullptr;
    if (_wfopen_s(&file, configPath.c_str(), L"rt, ccs=UTF-8") != 0 || !file) {
        wchar_t msg[512];
        swprintf_s(msg, 512, L"[VIRTUAL] Config file not found: %s", configPath.c_str());
        LogMessage(msg);
        return false;
    }

    std::wstring serialValue;
    std::wstring hidValueStr;
    std::wstring uidValueStr;
    std::wstring yearValueStr;

    wchar_t line[512];
    while (fgetws(line, _countof(line), file)) {
        std::wstring current(line);
        while (!current.empty() && (current.back() == L'\n' || current.back() == L'\r')) {
            current.pop_back();
        }
        auto trimmed = Trim(current);
        if (trimmed.empty() || trimmed[0] == L'#' || trimmed[0] == L';') {
            continue;
        }
        size_t equalPos = trimmed.find(L'=');
        if (equalPos == std::wstring::npos) {
            continue;
        }
        auto key = ToLower(Trim(trimmed.substr(0, equalPos)));
        auto value = Trim(trimmed.substr(equalPos + 1));
        if (key == L"serial") {
            serialValue = value;
        } else if (key == L"hid") {
            hidValueStr = value;
        } else if (key == L"uid") {
            uidValueStr = value;
        } else if (key == L"year") {
            yearValueStr = value;
        }
    }
    fclose(file);

    bool hidReady = false;
    bool uidReady = false;
    DWORD hidValue = 0;
    DWORD uidValue = 0;

    if (!serialValue.empty()) {
        if (ParseSerialString(serialValue, hidValue, uidValue)) {
            hidReady = true;
            uidReady = true;
        } else {
            wchar_t warn[512];
            swprintf_s(warn, 512, L"[VIRTUAL] Failed to parse serial: %s", serialValue.c_str());
            LogMessage(warn);
        }
    }

    if (!hidValueStr.empty()) {
        DWORD parsed = 0;
        if (ParseHexString(hidValueStr, parsed)) {
            hidValue = parsed;
            hidReady = true;
        } else {
            wchar_t warn[512];
            swprintf_s(warn, 512, L"[VIRTUAL] Invalid HID entry: %s", hidValueStr.c_str());
            LogMessage(warn);
        }
    }

    if (!uidValueStr.empty()) {
        DWORD parsed = 0;
        if (ParseHexString(uidValueStr, parsed)) {
            uidValue = parsed;
            uidReady = true;
        } else {
            wchar_t warn[512];
            swprintf_s(warn, 512, L"[VIRTUAL] Invalid UID entry: %s", uidValueStr.c_str());
            LogMessage(warn);
        }
    }

    int parsedYear = 0;
    if (!yearValueStr.empty()) {
        parsedYear = _wtoi(yearValueStr.c_str());
    }
    if (parsedYear <= 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        parsedYear = st.wYear;
    }

    if (hidReady && uidReady) {
        hidOut = hidValue;
        uidOut = uidValue;
        yearOut = parsedYear;
        wchar_t msg[512];
        swprintf_s(msg, 512, L"[VIRTUAL] Loaded HID=0x%08X UID=0x%08X YEAR=%d from %s",
                   hidValue, uidValue, parsedYear, configPath.c_str());
        LogMessage(msg);
        return true;
    }

    wchar_t msg[512];
    swprintf_s(msg, 512, L"[VIRTUAL] Config missing HID/UID data: %s", configPath.c_str());
    LogMessage(msg);
    return false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) {
    switch (ul_reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        g_hModule = hModule;
        
        // 最小化初始化：仅安装Hook
        // 日志在第一次Hook调用时才初始化
        // 缓存在第一次HID API调用时才加载
        
        // Install HID Hooks
        if (!InstallHidHooks()) {
            return FALSE;  // Hook安装失败，拒绝加载
        }

        // Install network hooks
        if (!InstallNetworkHooks()) {
            UninstallHidHooks();
            return FALSE;
        }
        
        break;
    }

    case DLL_PROCESS_DETACH:
        // Uninstall Hooks
        UninstallNetworkHooks();
        UninstallHidHooks();
        
        // 关闭日志（如果已初始化）
        ShutdownLogging();
        break;
    }
    return TRUE;
}
