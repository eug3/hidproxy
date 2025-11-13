# HID Hook Launcher Script
# Automatically launches target application with HID Hook DLL injected
# Requires Administrator privileges

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  HID Hook Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script requires administrator privileges." -ForegroundColor Red
    Write-Host "        Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] Running with administrator privileges" -ForegroundColor Green
Write-Host ""

# Configuration
$launcherExe = ".\build\bin\Release\hid_launcher.exe"
$targetApp = "C:\Xsj_Soft\Xsjzb\Xsjzb.exe"

# Check if launcher exists
if (-not (Test-Path $launcherExe)) {
    Write-Host "[ERROR] Launcher not found: $launcherExe" -ForegroundColor Red
    Write-Host "        Please build the project first:" -ForegroundColor Yellow
    Write-Host "        cd build" -ForegroundColor Gray
    Write-Host "        cmake --build . --config Release" -ForegroundColor Gray
    Write-Host ""
    pause
    exit 1
}

Write-Host "Launcher: $launcherExe" -ForegroundColor Gray
Write-Host "Target:   $targetApp" -ForegroundColor Gray
Write-Host ""

# Check if target application is already running
$existingProcess = Get-Process -Name "Xsjzb" -ErrorAction SilentlyContinue
if ($existingProcess) {
    Write-Host "[WARNING] Target application is already running (PID: $($existingProcess.Id))" -ForegroundColor Yellow
    $response = Read-Host "Do you want to close it first? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Stop-Process -Name "Xsjzb" -Force
        Start-Sleep -Seconds 1
        Write-Host "[OK] Process terminated" -ForegroundColor Green
    }
    Write-Host ""
}

# Launch with HID Hook
Write-Host "Launching application with HID Hook..." -ForegroundColor Cyan
& $launcherExe $targetApp

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Launch Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Check the log file:" -ForegroundColor Gray
Write-Host "  C:\Xsj_Soft\Xsjzb\hid_hook.log" -ForegroundColor Yellow
Write-Host ""
Write-Host "Or use DebugView to monitor real-time output:" -ForegroundColor Gray
Write-Host "  https://docs.microsoft.com/sysinternals/downloads/debugview" -ForegroundColor Gray
Write-Host ""
