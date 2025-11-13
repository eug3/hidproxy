# build.ps1 - Quick Build Script for HID Proxy Project
param(
    [string]$Config = "Release",
    [string]$Generator = "Visual Studio 17 2022",
    [string]$Arch = "x64"
)

Write-Host "=== HID Proxy Build Script ===" -ForegroundColor Cyan
Write-Host "Configuration: $Config" -ForegroundColor Yellow
Write-Host "Generator: $Generator" -ForegroundColor Yellow
Write-Host "Architecture: $Arch" -ForegroundColor Yellow
Write-Host ""

# 创建 build 目录
if (-not (Test-Path "build")) {
    Write-Host "Creating build directory..." -ForegroundColor Green
    New-Item -ItemType Directory -Path "build" | Out-Null
}

# 进入 build 目录
Push-Location "build"

try {
    # 配置 CMake
    Write-Host "Configuring CMake..." -ForegroundColor Green
    cmake .. -G "$Generator" -A $Arch
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "CMake configuration failed!" -ForegroundColor Red
        exit 1
    }
    
    # 编译
    Write-Host ""
    Write-Host "Building project..." -ForegroundColor Green
    cmake --build . --config $Config
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "Build succeeded!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output files:" -ForegroundColor Cyan
    Write-Host "  - DLL:     bin\$Config\hid.dll" -ForegroundColor Yellow
    Write-Host "  - Console: bin\$Config\hid_console.exe" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To run the console application:" -ForegroundColor Cyan
    Write-Host "  .\bin\$Config\hid_console.exe" -ForegroundColor Yellow
    
} finally {
    Pop-Location
}
