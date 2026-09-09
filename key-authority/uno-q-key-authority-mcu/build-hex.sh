#!/bin/bash

# MAMA BEAR MCU Firmware Builder (HEX)
# Builds uno-q-key-authority-mcu.ino and creates HEX file for flashing
#
# Usage:
#   ./build-hex.sh              # Build with Arduino CLI
#   ./build-hex.sh clean        # Clean build
#
# Requirements:
#   - Arduino CLI with Arduino IDE packages
#   - Uno Q board support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_HEX="$BUILD_DIR/uno-q-key-authority-mcu.hex"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}MAMA BEAR MCU Firmware Builder (HEX)${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Check command
if [ $# -eq 0 ]; then
    METHOD="arduino"
elif [ "$1" = "clean" ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    exit 0
else
    echo "Usage: $0 [clean]"
    exit 1
fi

if [ "$METHOD" = "arduino" ]; then
    echo -e "${YELLOW}Building with Arduino CLI...${NC}"
    
    # Check for arduino-cli
    if ! command -v arduino-cli &> /dev/null; then
        echo -e "${RED}Arduino CLI not found!${NC}"
        echo "Download from: https://arduino.github.io/arduino-cli/latest/installation/"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
    
    # Build for Arduino UNO Q
    echo "Building for Arduino UNO Q (STM32U585)..."
    arduino-cli compile \
        --fqbn arduino:zephyr:unoq \
        --library "$SCRIPT_DIR/../../libraries/ShallotLoRa" \
        --output-dir "$BUILD_DIR" \
        uno-q-key-authority-mcu.ino
    
    # Find HEX file
    HEX_FILE=$(find "$BUILD_DIR" -name "*.hex" 2>/dev/null | head -n 1)
    
    if [ -n "$HEX_FILE" ]; then
        cp "$HEX_FILE" "$OUTPUT_HEX"
        echo -e "${GREEN}HEX file created: $OUTPUT_HEX${NC}"
    else
        echo -e "${RED}No HEX file found in build${NC}"
        exit 1
    fi
fi

# Clean up - keep only the final HEX file
rm -f "$BUILD_DIR"/*.bin "$BUILD_DIR"/*.elf "$BUILD_DIR"/*.map "$BUILD_DIR"/*.ino.hex

# Success
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Build successful!${NC}"
echo -e "${GREEN}HEX file: $OUTPUT_HEX${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${CYAN}To flash:${NC}"
echo "  Use Arduino IDE or arduino-cli to upload to UNO Q"
echo "  arduino-cli upload -p /dev/cu.usbmodemXXXX -b arduino:zephyr:unoq $OUTPUT_HEX"
echo ""

# Open folder (optional, works on macOS)
if [ "$OSTYPE" = "darwin" ] && command -v open &> /dev/null; then
    read -p "Open build folder? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open "$BUILD_DIR"
    fi
fi
