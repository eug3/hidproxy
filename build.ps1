# build.ps1 - Quick Build Script for HID Proxy Project
param(
    [string]$Config = "Release"
)

Write-Host "=== HID Proxy Build Script ===" -ForegroundColor Cyan
Write-Host "Configuration: $Config" -ForegroundColor Yellow
Write-Host ""

# 进入 injector 目录编译
Push-Location "injector\build"

try {
    # 编译 injector 项目
    Write-Host "Building injector project..." -ForegroundColor Green
    cmake --build . --config $Config --target hid_hook --target hid_launcher
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
    
    Pop-Location
    
    # 创建根目录的 build\bin 目录
    $buildBinDir = "build\bin\$Config"
    if (-not (Test-Path $buildBinDir)) {
        Write-Host "Creating output directory: $buildBinDir" -ForegroundColor Green
        New-Item -ItemType Directory -Path $buildBinDir -Force | Out-Null
    }
    
    # 复制文件到根目录 build
    Write-Host "Copying files to $buildBinDir..." -ForegroundColor Green
    Copy-Item "injector\build\bin\$Config\hid_hook.dll" -Destination "$buildBinDir\" -Force
    Copy-Item "injector\build\bin\$Config\hid_launcher.exe" -Destination "$buildBinDir\" -Force
    
    Write-Host ""
    Write-Host "Build succeeded!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output files:" -ForegroundColor Cyan
    Write-Host "  - DLL:      $buildBinDir\hid_hook.dll" -ForegroundColor Yellow
    Write-Host "  - Launcher: $buildBinDir\hid_launcher.exe" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To deploy:" -ForegroundColor Cyan
    Write-Host "  Copy-Item '$buildBinDir\hid_hook.dll' -Destination 'C:\Xsj_Soft\Xsjzb\' -Force" -ForegroundColor Gray
    
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
} finally {
    if ((Get-Location).Path -ne $PSScriptRoot) {
        Pop-Location
    }
}
