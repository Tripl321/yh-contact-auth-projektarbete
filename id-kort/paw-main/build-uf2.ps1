<#
.SYNOPSIS
    Builds PAW firmware and creates UF2 file for drag-and-drop flashing
.DESCRIPTION
    This PowerShell script compiles the paw-main.ino firmware and generates
    a UF2 file that can be dragged onto the RPI-RP2 drive for flashing.
    
    Requires:
    - Arduino IDE with arduino-pico core installed
    - OR PlatformIO

.EXAMPLE
    .\build-uf2.ps1
    
.EXAMPLE
    .\build-uf2.ps1 -Method PlatformIO
#>

param(
    [string]$Method = "Arduino",
    [string]$OutputPath = ".\build",
    [switch]$OpenFolder
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "PAW Firmware Builder (UF2)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$uf2File = Join-Path $OutputPath "paw-main.uf2"
$hexFile = Join-Path $OutputPath "paw-main.hex"

if ($Method -eq "PlatformIO") {
    Write-Host "Building with PlatformIO..." -ForegroundColor Yellow
    
    # Check if pio is available
    if (-not (Get-Command pio -ErrorAction SilentlyContinue)) {
        Write-Host "PlatformIO not found! Installing..." -ForegroundColor Yellow
        pip install platformio
    }
    
    # Build
    Push-Location (Get-Location)
    cd id-kort\paw-main
    
    try {
        pio run --target upload 2>&1 | Tee-Object -Variable buildOutput
        
        # Find the UF2 file
        $uf2Files = Get-ChildItem -Path .pio\build\* -Filter "*.uf2" -Recurse -ErrorAction SilentlyContinue
        if ($uf2Files.Count -gt 0) {
            $latestUf2 = $uf2Files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Copy-Item $latestUf2.FullName $uf2File -Force
            Write-Host "UF2 file created: $uf2File" -ForegroundColor Green
        } else {
            Write-Host "No UF2 file found in PlatformIO build" -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "PlatformIO build failed: $_" -ForegroundColor Red
        exit 1
    }
    
    Pop-Location
    
} elseif ($Method -eq "Arduino") {
    Write-Host "Building with Arduino CLI..." -ForegroundColor Yellow
    
    # Check if arduino-cli is available
    if (-not (Get-Command arduino-cli -ErrorAction SilentlyContinue)) {
        Write-Host "Arduino CLI not found!" -ForegroundColor Red
        Write-Host "Download from: https://arduino.github.io/arduino-cli/latest/installation/" -ForegroundColor Yellow
        exit 1
    }
    
    # Build
    arduino-cli compile \
        --fqbn arduino-pico:rp2040:feather_rp2350 \
        --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
        --output-dir $OutputPath \
        id-kort\paw-main\paw-main.ino
    
    # Find UF2 or HEX file
    $uf2Files = Get-ChildItem -Path $OutputPath -Filter "*.uf2" -Recurse -ErrorAction SilentlyContinue
    $hexFiles = Get-ChildItem -Path $OutputPath -Filter "*.hex" -Recurse -ErrorAction SilentlyContinue
    
    if ($uf2Files.Count -gt 0) {
        $latestUf2 = $uf2Files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Copy-Item $latestUf2.FullName $uf2File -Force
        Write-Host "UF2 file created: $uf2File" -ForegroundColor Green
    } elseif ($hexFiles.Count -gt 0) {
        Write-Host "HEX file found but not UF2. Manual conversion needed." -ForegroundColor Yellow
        # Would need elf2uf2 from pico-sdk
        exit 1
    } else {
        Write-Host "No build output found" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Invalid method. Use 'Arduino' or 'PlatformIO'" -ForegroundColor Red
    exit 1
}

# Success
Write-Host "" 
Write-Host "============================================" -ForegroundColor Green
Write-Host "Build successful!" -ForegroundColor Green
Write-Host "UF2 file: $uf2File" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "To flash:" -ForegroundColor Cyan
Write-Host "1. Press and hold BOOTSEL button on Feather" -ForegroundColor Cyan
Write-Host "2. Connect USB cable" -ForegroundColor Cyan
Write-Host "3. Release BOOTSEL (RPI-RP2 drive appears)" -ForegroundColor Cyan
Write-Host "4. Drag and drop $((Get-Item $uf2File).Name) to RPI-RP2" -ForegroundColor Cyan
Write-Host "5. Device will auto-reboot with new firmware" -ForegroundColor Cyan
Write-Host ""

if ($OpenFolder) {
    Invoke-Item $OutputPath
}
