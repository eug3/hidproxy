@echo off
echo ================================================
echo Testing HID Device Hijacking
echo ================================================
echo.

REM Clear old log
if exist "C:\Xsj_Soft\Xsjzb\hid_hook.log" del "C:\Xsj_Soft\Xsjzb\hid_hook.log"

echo [1] Launching Xsjzb.exe with HID hook...
cd /d "D:\GitHub\hidproxy\injector\build\bin\Release"
start "" "hid_launcher.exe" "C:\Xsj_Soft\Xsjzb\Xsjzb.exe"

timeout /t 3 >nul

echo.
echo [2] Checking log for hijacked HidD_GetAttributes calls...
echo.
findstr /C:"HIJACKED" "C:\Xsj_Soft\Xsjzb\hid_hook.log"

echo.
echo [3] Full HidD_GetAttributes log:
echo.
findstr /C:"HidD_GetAttributes" "C:\Xsj_Soft\Xsjzb\hid_hook.log"

echo.
echo ================================================
echo Test complete! Check above for [HIJACKED] tags
echo ================================================
pause
