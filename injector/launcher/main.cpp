#include <windows.h>
#include <stdio.h>
#include <conio.h>

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"========================================\n");
    wprintf(L"  HID Hook Launcher (Admin Mode)\n");
    wprintf(L"========================================\n\n");

    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        wprintf(L"[ERROR] This launcher requires administrator privileges.\n");
        wprintf(L"        Please run as administrator.\n\n");
        wprintf(L"Press any key to exit...\n");
        _getch();
        return 1;
    }

    wprintf(L"[OK] Running with administrator privileges\n\n");

    // 配置路径
    const wchar_t* targetExe = L"C:\\Xsj_Soft\\Xsjzb\\Xsjzb.exe";
    const wchar_t* hookDll = L"hid_hook.dll";

    // 允许命令行参数覆盖
    if (argc >= 2) {
        targetExe = argv[1];
    }
    if (argc >= 3) {
        hookDll = argv[2];
    }

    wprintf(L"Target Application: %s\n", targetExe);
    wprintf(L"Hook DLL: %s\n\n", hookDll);

    // 检查文件是否存在
    if (GetFileAttributesW(targetExe) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[ERROR] Target application not found: %s\n", targetExe);
        return 1;
    }

    // 获取 DLL 完整路径
    wchar_t dllPath[MAX_PATH];
    GetFullPathNameW(hookDll, MAX_PATH, dllPath, NULL);

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[ERROR] Hook DLL not found: %s\n", dllPath);
        return 1;
    }

    wprintf(L"Hook DLL Full Path: %s\n\n", dllPath);

    // 准备启动信息
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    // 创建挂起的进程
    wprintf(L"Creating process (suspended)...\n");
    
    if (!CreateProcessW(
        targetExe,          // Application name
        NULL,               // Command line
        NULL,               // Process security attributes
        NULL,               // Thread security attributes
        FALSE,              // Inherit handles
        CREATE_SUSPENDED,   // Creation flags - 挂起状态创建
        NULL,               // Environment
        NULL,               // Current directory
        &si,                // Startup info
        &pi                 // Process information
    )) {
        wprintf(L"[ERROR] Failed to create process: %d\n", GetLastError());
        return 1;
    }

    wprintf(L"[OK] Process created (PID: %d)\n", pi.dwProcessId);

    // 在目标进程中分配内存
    wprintf(L"Allocating memory in target process...\n");
    
    size_t dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(
        pi.hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pRemotePath) {
        wprintf(L"[ERROR] Failed to allocate memory in target process\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // 写入 DLL 路径
    wprintf(L"Writing DLL path to target process...\n");
    
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemotePath, dllPath, dllPathSize, &bytesWritten)) {
        wprintf(L"[ERROR] Failed to write to target process memory\n");
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // 获取 LoadLibraryW 地址
    wprintf(L"Getting LoadLibraryW address...\n");
    
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    if (!pLoadLibraryW) {
        wprintf(L"[ERROR] Failed to get LoadLibraryW address\n");
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // 创建远程线程加载 DLL
    wprintf(L"Creating remote thread to load DLL...\n");
    
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        pLoadLibraryW,
        pRemotePath,
        0,
        NULL
    );

    if (!hThread) {
        wprintf(L"[ERROR] Failed to create remote thread: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // 等待 LoadLibrary 完成
    wprintf(L"Waiting for DLL injection...\n");
    WaitForSingleObject(hThread, INFINITE);

    // 获取 LoadLibrary 返回值
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        wprintf(L"[WARNING] LoadLibrary returned NULL, DLL may not be loaded\n");
    } else {
        wprintf(L"[OK] DLL loaded at address: 0x%08X\n", exitCode);
    }

    CloseHandle(hThread);

    // 清理远程内存
    VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);

    // 恢复主线程执行
    wprintf(L"\nResuming main thread...\n");
    ResumeThread(pi.hThread);

    wprintf(L"\n========================================\n");
    wprintf(L"[SUCCESS] Application started with HID Hook!\n");
    wprintf(L"========================================\n\n");

    wprintf(L"Process Information:\n");
    wprintf(L"  PID: %d\n", pi.dwProcessId);
    wprintf(L"  Thread ID: %d\n", pi.dwThreadId);
    wprintf(L"\nLog File:\n");
    wprintf(L"  C:\\Xsj_Soft\\Xsjzb\\hid_hook.log\n");
    wprintf(L"\nDebugView:\n");
    wprintf(L"  Run DebugView as Administrator to see real-time output\n");
    wprintf(L"  Filter: [HID Hook]\n");

    // 关闭句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"\nLauncher will exit in 3 seconds...\n");
    Sleep(3000);

    return 0;
}
