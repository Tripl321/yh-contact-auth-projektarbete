#!/bin/bash

# PAW Firmware Builder (UF2)
# Builds paw-main.ino and creates UF2 file for drag-and-drop flashing
#
# Usage:
#   ./build-uf2.sh              # Build with Arduino CLI
#   ./build-uf2.sh pio          # Build with PlatformIO
#   ./build-uf2.sh clean        # Clean build
#
# Requirements:
#   - Arduino CLI with arduino-pico core
#   - OR PlatformIO

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_UF2="$BUILD_DIR/paw-main.uf2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}PAW Firmware Builder (UF2)${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Check command
if [ $# -eq 0 ] || [ "$1" = "arduino" ]; then
    METHOD="arduino"
elif [ "$1" = "pio" ]; then
    METHOD="platformio"
elif [ "$1" = "clean" ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    exit 0
else
    echo "Usage: $0 [arduino|pio|clean]"
    exit 1
fi

if [ "$METHOD" = "platformio" ]; then
    echo -e "${YELLOW}Building with PlatformIO...${NC}"
    
    # Check for pio
    if ! command -v pio &> /dev/null; then
        echo -e "${RED}PlatformIO not found!${NC}"
        echo "Install with: pip install platformio"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
    
    # Build
    if ! pio run --target upload; then
        echo -e "${RED}PlatformIO build failed${NC}"
        exit 1
    fi
    
    # Find UF2 file
    UF2_FILE=$(find .pio/build -name "*.uf2" 2>/dev/null | head -n 1)
    if [ -n "$UF2_FILE" ]; then
        cp "$UF2_FILE" "$OUTPUT_UF2"
        echo -e "${GREEN}UF2 file created: $OUTPUT_UF2${NC}"
    else
        echo -e "${RED}No UF2 file found in PlatformIO build${NC}"
        exit 1
    fi

elif [ "$METHOD" = "arduino" ]; then
    echo -e "${YELLOW}Building with Arduino CLI...${NC}"
    
    # Check for arduino-cli
    if ! command -v arduino-cli &> /dev/null; then
        echo -e "${RED}Arduino CLI not found!${NC}"
        echo "Download from: https://arduino.github.io/arduino-cli/latest/installation/"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
    
    # Build
    echo "Building for Adafruit Feather RP2350..."
    arduino-cli compile \
        --fqbn rp2040:rp2040:generic_rp2350 \
        --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
        --output-dir "$BUILD_DIR" \
        paw-main.ino
    
    # Find UF2 or HEX file
    UF2_FILE=$(find "$BUILD_DIR" -name "*.uf2" 2>/dev/null | head -n 1)
    HEX_FILE=$(find "$BUILD_DIR" -name "*.hex" 2>/dev/null | head -n 1)
    
    if [ -n "$UF2_FILE" ]; then
        cp "$UF2_FILE" "$OUTPUT_UF2"
        echo -e "${GREEN}UF2 file created: $OUTPUT_UF2${NC}"
    elif [ -n "$HEX_FILE" ]; then
        echo -e "${YELLOW}HEX file found but not UF2. Manual conversion needed.${NC}"
        echo "Install pico-sdk and use elf2uf2 tool"
        exit 1
    else
        echo -e "${RED}No build output found${NC}"
        exit 1
    fi
fi

# Clean up - keep only the final UF2 file
rm -f "$BUILD_DIR"/*.bin "$BUILD_DIR"/*.elf "$BUILD_DIR"/*.map "$BUILD_DIR"/*.ino.uf2

# Success
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Build successful!${NC}"
echo -e "${GREEN}UF2 file: $OUTPUT_UF2${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${CYAN}To flash:${NC}"
echo "  1. Press and hold BOOTSEL button on Feather"
echo "  2. Connect USB cable"
echo "  3. Release BOOTSEL (RPI-RP2 drive appears)"
echo "  4. Drag and drop $(basename "$OUTPUT_UF2") to RPI-RP2"
echo "  5. Device will auto-reboot with new firmware"
echo ""

# Open folder (optional, works on macOS)
if [ "$OSTYPE" = "darwin" ] && command -v open &> /dev/null; then
    read -p "Open build folder? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open "$BUILD_DIR"
    fi
fi
