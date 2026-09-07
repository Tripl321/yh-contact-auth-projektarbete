#!/usr/bin/env bash
#
# SHALLOT — UNO Q Device Identity Verification
#
# Safety:
#   - Verifies device identity before provisioning
#   - Checks boot banner at 115200 baud
#   - Aborts on uncertain device identity
#   - Configurable expected identity patterns
#
# Usage:
#   ./verify-device.sh              # Auto-detect and verify
#   ./verify-device.sh /dev/cu.usbmodemXXXX  # Verify specific device
#   ./verify-device.sh help         # Show this help
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
BAUD_RATE=115200
EXPECTED_BANNER="SHALLOT — UNO Q Key Authority"
UNINITIALIZED_STATE="Key state: UNINITIALIZED"

# ============================================================
# Functions
# ============================================================
usage() {
    echo "Usage: $0 [device] [help]"
    echo ""
    echo "Verify UNO Q device identity before provisioning."
    echo ""
    echo "Options:"
    echo "  device    Serial port to verify (e.g., /dev/cu.usbmodemXXXX)"
    echo "  help     Show this help message"
    echo ""
    echo "Aborts with exit code 1 on identity mismatch or error."
}

find_unoq_devices() {
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
    
    echo "${DEVICES[@]}"
}

verify_device() {
    local device="$1"
    
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Verifying device: $device${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Try to read from device
    if command -v screen >/dev/null 2>&1; then
        # Use screen for reliable connection
        echo -e "${YELLOW}Connecting at $BAUD_RATE baud...${NC}"
        VERIFY_OUTPUT=$(timeout 5 screen -S verify_device "$device" $BAUD_RATE 2>/dev/null || true)
    else
        # Fallback to Python
        echo -e "${YELLOW}Connecting at $BAUD_RATE baud (Python fallback)...${NC}"
        VERIFY_OUTPUT=$(timeout 5 python3 -c "
import serial, time, sys
try:
    with serial.Serial('$device', $BAUD_RATE, timeout=3) as s:
        time.sleep(2)
        data = s.read_all()
        sys.stdout.write(data.decode('utf-8', errors='replace'))
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null || true)
    fi
    
    if [[ -z "$VERIFY_OUTPUT" ]]; then
        echo -e "${RED}✗ No data received from device${NC}"
        echo "  Check:"
        echo "    - Device is connected"
        echo "    - Correct baud rate ($BAUD_RATE)"
        echo "    - Device is powered on"
        return 1
    fi
    
    echo "Device output:"
    echo "$VERIFY_OUTPUT"
    echo ""
    
    # Check for expected banner
    if echo "$VERIFY_OUTPUT" | grep -q "$EXPECTED_BANNER"; then
        echo -e "${GREEN}✓ Device identity verified: UNO Q MCU${NC}"
    else
        echo -e "${RED}✗ Uncertain device identity${NC}"
        echo "  Expected: '$EXPECTED_BANNER'"
        echo "  Got: '$(echo $VERIFY_OUTPUT | head -n 1)'"
        return 1
    fi
    
    # Check for UNINITIALIZED state (optional but recommended)
    if echo "$VERIFY_OUTPUT" | grep -q "$UNINITIALIZED_STATE"; then
        echo -e "${GREEN}✓ Device state: UNINITIALIZED (expected)${NC}"
    else
        echo -e "${YELLOW}⚠️  Device not in UNINITIALIZED state${NC}"
        echo "  This may be normal after provisioning."
    fi
    
    return 0
}

# ============================================================
# Main
# ============================================================

if [[ "$#" -gt 0 && ("$1" = "help" || "$1" = "--help" || "$1" = "-h") ]]; then
    usage
    exit 0
elif [[ "$#" -gt 0 ]]; then
    # Device specified
    DEVICE="$1"
    if verify_device "$DEVICE"; then
        echo ""
        echo -e "${GREEN}============================================${NC}"
        echo -e "${GREEN}✓ Device verification PASSED${NC}"
        echo -e "${GREEN}============================================${NC}"
        exit 0
    else
        echo ""
        echo -e "${RED}============================================${NC}"
        echo -e "${RED}✗ Device verification FAILED${NC}"
        echo -e "${RED}============================================${NC}"
        exit 1
    fi
else
    # Auto-detect devices
    DEVICES=($(find_unoq_devices))
    
    if [[ ${#DEVICES[@]} -eq 0 ]]; then
        echo -e "${RED}✗ No serial devices found${NC}"
        exit 1
    fi
    
    echo "Found devices:"
    for i in "${!DEVICES[@]}"; do
        echo "  $((i+1)). ${DEVICES[$i]}"
    done
    echo ""
    
    read -p "Select device to verify (1-${#DEVICES[@]}): " -n 1 -r
    echo ""
    
    if [[ "$REPLY" =~ ^[0-9]+$ ]] && [[ $REPLY -ge 1 ]] && [[ $REPLY -le ${#DEVICES[@]} ]]; then
        SELECTED_INDEX=$((REPLY-1))
        DEVICE="${DEVICES[$SELECTED_INDEX]}"
    else
        echo -e "${RED}Invalid selection${NC}"
        exit 1
    fi
    
    if verify_device "$DEVICE"; then
        echo ""
        echo -e "${GREEN}============================================${NC}"
        echo -e "${GREEN}✓ Device verification PASSED${NC}"
        echo -e "${GREEN}============================================${NC}"
        exit 0
    else
        echo ""
        echo -e "${RED}============================================${NC}"
        echo -e "${RED}✗ Device verification FAILED${NC}"
        echo -e "${RED}============================================${NC}"
        exit 1
    fi
fi
