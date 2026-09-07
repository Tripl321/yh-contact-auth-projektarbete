#!/usr/bin/env bash
#
# SHALLOT — UNO Q MCU Build Script
#
# Safety:
#   - Reproducible builds for arduino:zephyr:unoq
#   - Uses prj.conf and existing libraries
#   - CI-safe: builds but NEVER flashes
#   - Verifies toolchain and dependencies
#
# Usage:
#   ./build.sh              # Build with defaults
#   ./build.sh clean        # Clean build artifacts
#   ./build.sh help         # Show this help
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
OUTPUT_HEX="$BUILD_DIR/uno-q-key-authority-mcu.hex"
OUTPUT_ELF="$BUILD_DIR/uno-q-key-authority-mcu.elf"

FQBN="arduino:zephyr:unoq"
SKETCH_PATH="$REPO_ROOT/key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino"
LIBRARY_PATH="$REPO_ROOT/libraries/ShallotLoRa"
PRJ_CONF="$REPO_ROOT/key-authority/uno-q-key-authority-mcu/prj.conf"

# ============================================================
# CI Detection - NEVER flash in CI
# ============================================================
IS_CI=false
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITLAB_CI:-}" ]]; then
    IS_CI=true
fi

# ============================================================
# Functions
# ============================================================
usage() {
    echo "Usage: $0 [clean|help]"
    echo ""
    echo "Commands:"
    echo "  clean    Remove build artifacts"
    echo "  help     Show this help message"
    echo ""
    echo "Default: Build MCU firmware for $FQBN"
}

clean_build() {
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
    echo -e "${GREEN}✓ Build directory cleaned${NC}"
    exit 0
}

check_dependencies() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Checking dependencies...${NC}"
    echo ""
    
    # Check arduino-cli
    if ! command -v arduino-cli >/dev/null 2>&1; then
        echo -e "${RED}✗ arduino-cli not found${NC}"
        echo "  Install from: https://arduino.github.io/arduino-cli/latest/installation/"
        exit 1
    fi
    echo -e "${GREEN}✓ arduino-cli found${NC}"
    
    # Check Zephyr board platform
    if ! arduino-cli core list | grep -q "arduino:zephyr"; then
        echo -e "${RED}✗ arduino:zephyr platform not installed${NC}"
        echo "  Install with: arduino-cli core install arduino:zephyr"
        exit 1
    fi
    echo -e "${GREEN}✓ arduino:zephyr platform installed${NC}"
    
    # Check prj.conf exists
    if [[ ! -f "$PRJ_CONF" ]]; then
        echo -e "${RED}✗ prj.conf not found at $PRJ_CONF${NC}"
        echo "  This file is required for hardware TRNG configuration"
        exit 1
    fi
    echo -e "${GREEN}✓ prj.conf found${NC}"
    
    # Check sketch exists
    if [[ ! -f "$SKETCH_PATH" ]]; then
        echo -e "${RED}✗ Sketch not found at $SKETCH_PATH${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Sketch found${NC}"
    
    # Check library exists
    if [[ ! -d "$LIBRARY_PATH" ]]; then
        echo -e "${RED}✗ Library not found at $LIBRARY_PATH${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Library found${NC}"
    
    echo ""
}

build_firmware() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Building UNO Q MCU Firmware${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    echo "FQBN:      $FQBN"
    echo "Sketch:    $SKETCH_PATH"
    echo "Library:   $LIBRARY_PATH"
    echo "prj.conf:  $PRJ_CONF"
    echo "Output:    $BUILD_DIR/"
    echo ""
    
    mkdir -p "$BUILD_DIR"
    
    # Build command
    echo -e "${YELLOW}Running arduino-cli compile...${NC}"
    
    arduino-cli compile \
        --fqbn "$FQBN" \
        --library "$LIBRARY_PATH" \
        --build-property "build.path=$BUILD_DIR" \
        --output-dir "$BUILD_DIR" \
        "$SKETCH_PATH" 2>&1 | grep -v "Downloading" || true
    
    # Check if build succeeded
    if [[ ! -f "$OUTPUT_HEX" && ! -f "$OUTPUT_ELF" ]]; then
        echo -e "${RED}✗ Build failed - no output files found${NC}"
        exit 1
    fi
    
    # Get file sizes
    HEX_SIZE=$(stat -f%z "$OUTPUT_HEX" 2>/dev/null || stat -c%s "$OUTPUT_HEX")
    ELF_SIZE=$(stat -f%z "$OUTPUT_ELF" 2>/dev/null || stat -c%s "$OUTPUT_ELF")
    
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}Build successful!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo "Output files:"
    echo "  HEX: $OUTPUT_HEX ($HEX_SIZE bytes)"
    echo "  ELF: $OUTPUT_ELF ($ELF_SIZE bytes)"
    echo ""
    echo "To flash (manual step, NOT in CI):"
    echo "  ./flash.sh"
    echo ""
}

# ============================================================
# Main
# ============================================================

# CI guard - build is allowed, flash is not
if [[ "$#" -eq 0 ]]; then
    check_dependencies
    build_firmware
elif [[ "$1" = "clean" ]]; then
    clean_build
elif [[ "$1" = "help" || "$1" = "--help" || "$1" = "-h" ]]; then
    usage
else
    echo -e "${RED}Unknown argument: $1${NC}"
    usage
    exit 1
fi
