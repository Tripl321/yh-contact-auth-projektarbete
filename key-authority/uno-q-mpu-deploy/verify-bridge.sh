#!/usr/bin/env bash
#
# SHALLOT — Bridge/RPC Verification Script
#
# Verifies that Arduino Bridge and MPU service are running correctly
#
# Safety:
#   - Verifies Bridge socket exists and is accessible
#   - Verifies MPU service is running
#   - Aborts on any verification failure
#   - Configurable paths
#
# Usage:
#   ./verify-bridge.sh              # Full verification
#   ./verify-bridge.sh quick        # Quick check only
#   ./verify-bridge.sh help         # Show this help
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
BRIDGE_SOCKET="/var/run/arduino-router.sock"
SERVICE_NAME="shallot-mpu.service"
PYTHON_MIN_VERSION="3.7"

# ============================================================
# Functions
# ============================================================
usage() {
    echo "Usage: $0 [quick|help]"
    echo ""
    echo "Verify Bridge/RPC installation on UNO Q MPU."
    echo ""
    echo "Options:"
    echo "  quick    Quick verification (socket + service only)"
    echo "  help    Show this help message"
    echo ""
    echo "Aborts with exit code 1 on any failure."
}

verify_python() {
    echo -e "${CYAN}Verifying Python...${NC}"
    
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}✗ Python 3 not found${NC}"
        return 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
    if [[ "$PYTHON_VERSION" < "$PYTHON_MIN_VERSION" ]]; then
        echo -e "${RED}✗ Python $PYTHON_MIN_VERSION+ required (found: $PYTHON_VERSION)${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Python 3.$PYTHON_VERSION${NC}"
    return 0
}

verify_python_packages() {
    echo -e "${CYAN}Verifying Python packages...${NC}"
    
    local missing=0
    
    # Check each required package
    for pkg in pyserial msgpack; do
        if python3 -c "import $pkg" 2>/dev/null; then
            echo -e "${GREEN}✓ $pkg${NC}"
        else
            echo -e "${RED}✗ $pkg missing${NC}"
            missing=$((missing + 1))
        fi
    done
    
    if [[ $missing -gt 0 ]]; then
        echo ""
        echo "Install missing packages with:"
        echo "  pip3 install pyserial msgpack"
        return 1
    fi
    
    return 0
}

verify_bridge_socket() {
    echo -e "${CYAN}Verifying Bridge socket...${NC}"
    
    # Check socket exists
    if [[ ! -S "$BRIDGE_SOCKET" ]]; then
        echo -e "${RED}✗ Bridge socket not found: $BRIDGE_SOCKET${NC}"
        echo "  Arduino Bridge may not be running."
        echo "  Start with: ArduinoBridge &"
        return 1
    fi
    echo -e "${GREEN}✓ Socket exists: $BRIDGE_SOCKET${NC}"
    
    # Test socket connectivity
    echo -e "${YELLOW}Testing socket connectivity...${NC}"
    if python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('$BRIDGE_SOCKET')
    s.close()
    print('OK')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>&1 | grep -q "OK"; then
        echo -e "${GREEN}✓ Socket is accessible${NC}"
    else
        echo -e "${RED}✗ Socket is not accessible${NC}"
        return 1
    fi
    
    return 0
}

verify_bridge_process() {
    echo -e "${CYAN}Verifying Arduino Bridge process...${NC}"
    
    if pgrep -x ArduinoBridge >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Arduino Bridge process running${NC}"
        return 0
    else
        echo -e "${RED}✗ Arduino Bridge process not running${NC}"
        echo "  Start with: ArduinoBridge &"
        return 1
    fi
}

verify_service() {
    echo -e "${CYAN}Verifying MPU service...${NC}"
    
    # Check if service is enabled
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Service enabled: $SERVICE_NAME${NC}"
    else
        echo -e "${RED}✗ Service not enabled: $SERVICE_NAME${NC}"
        return 1
    fi
    
    # Check if service is active
    if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Service active: $SERVICE_NAME${NC}"
    else
        echo -e "${RED}✗ Service not active: $SERVICE_NAME${NC}"
        echo "  Start with: sudo systemctl start $SERVICE_NAME"
        return 1
    fi
    
    return 0
}

verify_script() {
    echo -e "${CYAN}Verifying MPU script...${NC}"
    
    local script_path="/home/user/shallot/key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py"
    
    if [[ -f "$script_path" ]]; then
        echo -e "${GREEN}✓ MPU script found: $script_path${NC}"
        return 0
    else
        echo -e "${RED}✗ MPU script not found: $script_path${NC}"
        echo "  Install with: ./install.sh"
        return 1
    fi
}

verify_config() {
    echo -e "${CYAN}Verifying configuration...${NC}"
    
    local config_path="/etc/shallot/shallot-mpu.conf"
    
    if [[ -f "$config_path" ]]; then
        echo -e "${GREEN}✓ Configuration found: $config_path${NC}"
        
        # Check for required settings
        if grep -q "AUDIT_LOG_DIR" "$config_path"; then
            echo -e "${GREEN}✓ AUDIT_LOG_DIR configured${NC}"
        else
            echo -e "${YELLOW}⚠️  AUDIT_LOG_DIR not in config${NC}"
        fi
        
        if grep -q "BRIDGE_SOCKET_PATH" "$config_path"; then
            echo -e "${GREEN}✓ BRIDGE_SOCKET_PATH configured${NC}"
        else
            echo -e "${YELLOW}⚠️  BRIDGE_SOCKET_PATH not in config${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}✗ Configuration not found: $config_path${NC}"
        return 1
    fi
}

verify_audit_dir() {
    echo -e "${CYAN}Verifying audit directory...${NC}"
    
    local audit_dir="/home/user/shallot/audit"
    
    if [[ -d "$audit_dir" ]]; then
        echo -e "${GREEN}✓ Audit directory exists: $audit_dir${NC}"
        
        # Check for log file
        if [[ -f "$audit_dir/provisioning_log.jsonl" ]]; then
            echo -e "${GREEN}✓ Audit log file exists${NC}"
        else
            echo -e "${YELLOW}⚠️  Audit log file not found (will be created on first use)${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}✗ Audit directory not found: $audit_dir${NC}"
        return 1
    fi
}

# ============================================================
# Main
# ============================================================

QUICK_MODE=false
if [[ "$#" -gt 0 && "$1" = "quick" ]]; then
    QUICK_MODE=true
elif [[ "$#" -gt 0 && ("$1" = "help" || "$1" = "--help" || "$1" = "-h") ]]; then
    usage
    exit 0
fi

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} SHALLOT — Bridge/RPC Verification${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

local failed=0

# Always verify Python
if ! verify_python; then
    failed=$((failed + 1))
fi

echo ""

# Quick mode: only socket and service
if [[ "$QUICK_MODE" = true ]]; then
    echo -e "${YELLOW}Quick mode: socket + service only${NC}"
    echo ""
    
    if ! verify_bridge_socket; then
        failed=$((failed + 1))
    fi
    
    if ! verify_service; then
        failed=$((failed + 1))
    fi
else
    # Full verification
    if ! verify_bridge_process; then
        failed=$((failed + 1))
    fi
    
    if ! verify_bridge_socket; then
        failed=$((failed + 1))
    fi
    
    if ! verify_python_packages; then
        failed=$((failed + 1))
    fi
    
    if ! verify_script; then
        failed=$((failed + 1))
    fi
    
    if ! verify_config; then
        failed=$((failed + 1))
    fi
    
    if ! verify_audit_dir; then
        failed=$((failed + 1))
    fi
    
    if ! verify_service; then
        failed=$((failed + 1))
    fi
fi

echo ""
echo -e "${CYAN}============================================================${NC}"

if [[ $failed -eq 0 ]]; then
    echo -e "${GREEN}✓ All verifications PASSED${NC}"
    echo -e "${GREEN}============================================================${NC}"
    exit 0
else
    echo -e "${RED}✗ $failed verification(s) FAILED${NC}"
    echo -e "${RED}============================================================${NC}"
    echo ""
    echo "Please fix the issues above and retry."
    exit 1
fi
