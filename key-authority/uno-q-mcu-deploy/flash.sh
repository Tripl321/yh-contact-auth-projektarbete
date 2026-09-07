#!/usr/bin/env bash
#
# SHALLOT — UNO Q MCU Flash Script
#
# Safety:
#   - Dynamically finds UNO Q USB device
#   - Requires EXPLICIT user confirmation before flashing
#   - Verifies device identity (board name contains "UNO Q")
#   - Verifies boot banner at 115200 baud after flashing
#   - NEVER runs in CI (aborts immediately)
#   - NEVER auto-flashes without confirmation
#
# Usage:
#   ./flash.sh              # Interactive: find device, confirm, flash, verify
#   ./flash.sh help         # Show this help
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================
# Configuration
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$PROJECT_DIR")"

BUILD_DIR="$SCRIPT_DIR/build"
HEX_FILE="$BUILD_DIR/uno-q-key-authority-mcu.hex"

FQBN="arduino:zephyr:unoq"
BAUD_RATE=115200
BOOT_BANNER="SHALLOT — UNO Q Key Authority"
DEVICE_NAME_PATTERN="UNO Q"

# ============================================================
# CI Guard - NEVER FLASH IN CI
# ============================================================
IS_CI=false
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITLAB_CI:-}" ]]; then
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}✗ FLASH ABORTED: Running in CI environment${NC}"
    echo -e "${RED}============================================${NC}"
    echo ""
    echo "Flashing is NEVER allowed in CI for security reasons."
    echo "Build with: ./build.sh"
    echo "Flash manually on development hardware only."
    exit 1
fi

# ============================================================
# Functions
# ============================================================
usage() {
    echo "Usage: $0 [help]"
    echo ""
    echo "Interactive script that:"
    echo "  1. Finds UNO Q device dynamically"
    echo "  2. Requires explicit user confirmation"
    echo "  3. Flashes firmware"
    echo "  4. Verifies boot banner at $BAUD_RATE baud"
    echo ""
    echo "NEVER runs in CI environment."
}

find_unoq_device() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Searching for UNO Q device...${NC}"
    echo ""
    
    # Get list of serial ports
    DEVICES=()
    
    # macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        while IFS= read -r line; do
            DEVICES+=("$line")
        done < <(ls /dev/cu.usbmodem* 2>/dev/null)
    # Linux
    elif [[ "$OSTYPE" == "linux"* ]]; then
        while IFS= read -r line; do
            DEVICES+=("$line")
        done < <(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null)
    fi
    
    if [[ ${#DEVICES[@]} -eq 0 ]]; then
        echo -e "${RED}✗ No serial devices found${NC}"
        echo "Please connect UNO Q and try again."
        exit 1
    fi
    
    echo "Found devices:"
    local count=0
    local unoq_index=-1
    for dev in "${DEVICES[@]}"; do
        count=$((count + 1))
        echo "  $count. $dev"
        
        # Try to detect UNO Q by checking board info via arduino-cli
        if command -v arduino-cli >/dev/null 2>&1; then
            BOARD_INFO=$(arduino-cli board list --format json 2>/dev/null | grep -A5 "$dev" | grep -i "UNO Q" || true)
            if [[ -n "$BOARD_INFO" ]]; then
                unoq_index=$count
                echo "     ^^^ UNO Q detected"
            fi
        fi
    done
    
    echo ""
    
    if [[ $unoq_index -gt 0 ]]; then
        # UNO Q found, but still ask for confirmation
        echo -e "Auto-detected UNO Q at position $unoq_index"
        echo -e "${YELLOW}Please confirm this is the correct device:${NC}"
        read -p "  Use device ${DEVICES[$((unoq_index-1))]}? [y/N/abort] " -n 1 -r
        echo ""
        case $REPLY in
            [Yy])
                echo "${DEVICES[$((unoq_index-1))]}"
                return 0
                ;;
            [Aa]|[Bb])
                echo -e "${RED}Aborted by user${NC}"
                exit 0
                ;;
            *)
                echo "Using manual selection..."
                ;;
        esac
    fi
    
    # Manual selection
    read -p "Select device number (1-$count) or 'abort': " -n 2 -r
    echo ""
    
    if [[ "$REPLY" =~ ^[0-9]+$ ]] && [[ $REPLY -ge 1 ]] && [[ $REPLY -le $count ]]; then
        echo "${DEVICES[$((REPLY-1))]}"
        return 0
    elif [[ "$REPLY" =~ ^[Aa][Bb]?$ ]]; then
        echo -e "${RED}Aborted by user${NC}"
        exit 0
    else
        echo -e "${RED}Invalid selection${NC}"
        exit 1
    fi
}

verify_hex_exists() {
    if [[ ! -f "$HEX_FILE" ]]; then
        echo -e "${RED}✗ HEX file not found: $HEX_FILE${NC}"
        echo ""
        echo "Build first with: ./build.sh"
        exit 1
    fi
    echo -e "${GREEN}✓ HEX file found: $HEX_FILE${NC}"
}

confirm_flash() {
    local device="$1"
    echo ""
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}⚠️  FLASH WARNING ⚠️${NC}"
    echo -e "${RED}============================================${NC}"
    echo ""
    echo "You are about to FLASH firmware to:"
    echo "  Device: $device"
    echo "  Target: UNO Q MCU (STM32U585)"
    echo "  HEX:    $HEX_FILE"
    echo "  FQBN:   $FQBN"
    echo ""
    echo "This will:"
    echo "  ✓ Overwrite existing firmware"
    echo "  ✓ Require physical button press for key operations"
    echo "  ✓ Use hardware TRNG for key generation"
    echo ""
    echo -e "${RED}This action cannot be undone!${NC}"
    echo ""
    read -p "Type 'FLASH' to confirm, or any other key to abort: " -n 10 -r
    echo ""
    
    if [[ "$REPLY" != "FLASH" ]]; then
        echo -e "${GREEN}✓ Flash aborted by user${NC}"
        exit 0
    fi
}

flash_firmware() {
    local device="$1"
    
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Flashing firmware...${NC}"
    echo ""
    
    echo "arduino-cli upload -p $device -b $FQBN --input-file $HEX_FILE"
    echo ""
    
    arduino-cli upload \
        -p "$device" \
        -b "$FQBN" \
        -i "$HEX_FILE" 2>&1
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗ Flash failed${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}✓ Flash successful!${NC}"
    echo -e "${GREEN}============================================${NC}"
}

verify_boot() {
    local device="$1"
    echo ""
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Verifying boot banner at $BAUD_RATE baud...${NC}"
    echo ""
    
    # Wait for device to reconnect
    echo -e "${YELLOW}Waiting for device to reconnect after flash...${NC}"
    sleep 5
    
    # Try to read boot banner
    if command -v screen >/dev/null 2>&1; then
        # Use screen for reliable serial communication
        BOOT_OUTPUT=$(timeout 10 screen -S verify_boot "$device" $BAUD_RATE 2>/dev/null | grep "$BOOT_BANNER" || true)
    else
        # Fallback to Python
        BOOT_OUTPUT=$(timeout 10 python3 -c "
import serial, time, sys
try:
    with serial.Serial('$device', $BAUD_RATE, timeout=3) as s:
        time.sleep(3)
        data = s.read_all()
        sys.stdout.write(data.decode('utf-8', errors='replace'))
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null | grep "$BOOT_BANNER" || true)
    fi
    
    if [[ -n "$BOOT_OUTPUT" ]]; then
        echo -e "${GREEN}✓ Boot banner verified:${NC}"
        echo "  $BOOT_OUTPUT"
        return 0
    else
        echo -e "${RED}⚠️  Boot banner not detected${NC}"
        echo "  This may be normal if the device is still rebooting."
        echo "  Manual verification recommended."
        return 1
    fi
}

# ============================================================
# Main
# ============================================================

if [[ "$#" -gt 0 && ("$1" = "help" || "$1" = "--help" || "$1" = "-h") ]]; then
    usage
    exit 0
fi

# Step 1: Verify HEX file exists
verify_hex_exists

# Step 2: Find UNO Q device
DEVICE=$(find_unoq_device)
if [[ $? -ne 0 ]]; then
    exit 1
fi

# Step 3: Confirm flash
confirm_flash "$DEVICE"

# Step 4: Flash firmware
flash_firmware "$DEVICE"

# Step 5: Verify boot
verify_boot "$DEVICE"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Deployment complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Verify device identity with: ./verify-device.sh"
echo "  2. Run provisioning test: NP-01"
echo ""
