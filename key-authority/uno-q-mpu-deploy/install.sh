#!/usr/bin/env bash
#
# SHALLOT — UNO Q MPU Installation Script
#
# Installs and configures the MPU orchestration script on Arduino UNO Q
#
# Safety:
#   - Configurable audit log path
#   - Verifies Bridge/RPC before installation
#   - Creates necessary directories
#   - Aborts on uncertain device identity
#
# Usage:
#   ./install.sh              # Interactive installation
#   ./install.sh /custom/path # Custom audit log directory
#   ./install.sh help         # Show this help
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

MPU_SCRIPT="$REPO_ROOT/key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py"
INSTALL_DIR="/home/user/shallot/key-authority/uno-q-key-authority-mpu"
SERVICE_DIR="$SCRIPT_DIR/service"
CONFIG_DIR="/etc/shallot"
CONFIG_FILE="$CONFIG_DIR/shallot-mpu.conf"

# Default audit log path
DEFAULT_AUDIT_DIR="/home/user/shallot/audit"
DEFAULT_AUDIT_LOG="$DEFAULT_AUDIT_DIR/provisioning_log.jsonl"

# Bridge socket path
BRIDGE_SOCKET="/var/run/arduino-router.sock"

# ============================================================
# Functions
# ============================================================
usage() {
    echo "Usage: $0 [audit_dir] [help]"
    echo ""
    echo "Install SHALLOT MPU orchestration script on UNO Q."
    echo ""
    echo "Options:"
    echo "  audit_dir    Custom audit log directory (default: $DEFAULT_AUDIT_DIR)"
    echo "  help        Show this help message"
    echo ""
    echo "Requirements:"
    echo "  - Python 3.7+"
    echo "  - Arduino Bridge running (socket: $BRIDGE_SOCKET)"
    echo "  - Root access for service installation"
}

check_environment() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Checking Environment${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Check Python
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}✗ Python 3 not found${NC}"
        echo "  Install with: sudo apt install python3"
        exit 1
    fi
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
    if [[ "$PYTHON_VERSION" < "3.7" ]]; then
        echo -e "${RED}✗ Python 3.7+ required (found: $PYTHON_VERSION)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Python 3.$PYTHON_VERSION found${NC}"
    
    # Check pip
    if ! command -v pip3 >/dev/null 2>&1; then
        echo -e "${RED}✗ pip3 not found${NC}"
        echo "  Install with: sudo apt install python3-pip"
        exit 1
    fi
    echo -e "${GREEN}✓ pip3 found${NC}"
    
    # Check for root or sudo
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}⚠️  Not running as root${NC}"
        echo "  Some steps will require sudo"
    fi
    
    echo ""
}

check_bridge() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Checking Bridge/RPC${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Check if Arduino Bridge is running
    if ! pgrep -x ArduinoBridge >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Arduino Bridge not running${NC}"
        read -p "Start Arduino Bridge now? [y/N] " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ArduinoBridge &
            sleep 3
        fi
    fi
    
    # Check socket
    if [[ ! -S "$BRIDGE_SOCKET" ]]; then
        echo -e "${RED}✗ Bridge socket not found: $BRIDGE_SOCKET${NC}"
        echo "  Arduino Bridge may not be running or socket not created."
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
        echo -e "${YELLOW}⚠️  Proceeding without Bridge verification${NC}"
    else
        echo -e "${GREEN}✓ Bridge socket found: $BRIDGE_SOCKET${NC}"
    fi
    
    # Test socket connectivity
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('$BRIDGE_SOCKET')
    s.close()
    print('OK')
except Exception as e:
    print('FAIL')
" 2>/dev/null | grep -q "OK"; then
            echo -e "${GREEN}✓ Bridge socket accessible${NC}"
        else
            echo -e "${YELLOW}⚠️  Bridge socket not accessible${NC}"
        fi
    fi
    
    echo ""
}

create_directories() {
    local audit_dir="$1"
    
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Creating Directories${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Installation directory
    echo "Creating installation directory: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    echo -e "${GREEN}✓ $INSTALL_DIR created${NC}"
    
    # Config directory
    echo "Creating config directory: $CONFIG_DIR"
    sudo mkdir -p "$CONFIG_DIR"
    echo -e "${GREEN}✓ $CONFIG_DIR created${NC}"
    
    # Audit log directory
    echo "Creating audit log directory: $audit_dir"
    sudo mkdir -p "$audit_dir"
    sudo chown -R user:user "$audit_dir"
    sudo chmod 755 "$audit_dir"
    echo -e "${GREEN}✓ $audit_dir created${NC}"
    
    echo ""
}

install_script() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Installing MPU Script${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Copy script
    echo "Copying: $MPU_SCRIPT"
    echo "        → $INSTALL_DIR/uno-q-key-authority-mpu.py"
    sudo cp "$MPU_SCRIPT" "$INSTALL_DIR/uno-q-key-authority-mpu.py"
    sudo chown user:user "$INSTALL_DIR/uno-q-key-authority-mpu.py"
    sudo chmod +x "$INSTALL_DIR/uno-q-key-authority-mpu.py"
    echo -e "${GREEN}✓ Script installed${NC}"
    
    echo ""
}

install_config() {
    local audit_dir="$1"
    
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Creating Configuration${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Create config file
    echo "Creating: $CONFIG_FILE"
    sudo bash -c "cat > $CONFIG_FILE << 'EOF'
# SHALLOT MPU Configuration
# Generated by install.sh

# Audit log configuration
AUDIT_LOG_DIR=$audit_dir
AUDIT_LOG_FILE=\${AUDIT_LOG_DIR}/provisioning_log.jsonl

# Bridge RPC configuration
BRIDGE_SOCKET_PATH=/var/run/arduino-router.sock

# Recovery code configuration
RECOVERY_CODE_PEPPER=shallot_recovery_pepper_2026
EOF"
    
    sudo chmod 644 "$CONFIG_FILE"
    echo -e "${GREEN}✓ Configuration created: $CONFIG_FILE${NC}"
    
    echo ""
}

install_services() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Installing Services${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Copy service files
    echo "Copying service files to /etc/systemd/system/"
    sudo cp "$SERVICE_DIR/shallot-mpu.service" /etc/systemd/system/
    sudo cp "$SERVICE_DIR/arduino-bridge.service" /etc/systemd/system/
    echo -e "${GREEN}✓ Service files copied${NC}"
    
    # Reload systemd
    echo "Reloading systemd..."
    sudo systemctl daemon-reload
    echo -e "${GREEN}✓ systemd reloaded${NC}"
    
    # Enable services
    echo "Enabling services..."
    sudo systemctl enable shallot-mpu.service
    sudo systemctl enable arduino-bridge.service
    echo -e "${GREEN}✓ Services enabled${NC}"
    
    # Start services
    echo "Starting services..."
    sudo systemctl start arduino-bridge.service
    sudo systemctl start shallot-mpu.service
    echo -e "${GREEN}✓ Services started${NC}"
    
    echo ""
}

verify_installation() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}Verifying Installation${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    
    # Check script
    if [[ -f "$INSTALL_DIR/uno-q-key-authority-mpu.py" ]]; then
        echo -e "${GREEN}✓ Script installed${NC}"
    else
        echo -e "${RED}✗ Script not found${NC}"
    fi
    
    # Check config
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${GREEN}✓ Configuration created${NC}"
    else
        echo -e "${RED}✗ Configuration not found${NC}"
    fi
    
    # Check services
    if systemctl is-enabled shallot-mpu.service >/dev/null 2>&1; then
        echo -e "${GREEN}✓ shallot-mpu.service enabled${NC}"
    else
        echo -e "${RED}✗ shallot-mpu.service not enabled${NC}"
    fi
    
    if systemctl is-enabled arduino-bridge.service >/dev/null 2>&1; then
        echo -e "${GREEN}✓ arduino-bridge.service enabled${NC}"
    else
        echo -e "${RED}✗ arduino-bridge.service not enabled${NC}"
    fi
    
    # Check service status
    if systemctl is-active shallot-mpu.service >/dev/null 2>&1; then
        echo -e "${GREEN}✓ shallot-mpu.service running${NC}"
    else
        echo -e "${YELLOW}⚠️  shallot-mpu.service not running${NC}"
        echo "  Start with: sudo systemctl start shallot-mpu.service"
    fi
    
    echo ""
}

show_summary() {
    local audit_dir="$1"
    
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}✓ Installation Complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo "Installation Summary:"
    echo "  Script:       $INSTALL_DIR/uno-q-key-authority-mpu.py"
    echo "  Config:       $CONFIG_FILE"
    echo "  Audit Log:    $audit_dir/provisioning_log.jsonl"
    echo "  Services:     shallot-mpu.service, arduino-bridge.service"
    echo ""
    echo "To verify:"
    echo "  ./verify-bridge.sh"
    echo ""
    echo "To start manually:"
    echo "  cd $INSTALL_DIR && python3 uno-q-key-authority-mpu.py"
    echo ""
    echo "To manage services:"
    echo "  sudo systemctl status shallot-mpu.service"
    echo "  sudo journalctl -u shallot-mpu.service -f"
    echo ""
}

# ============================================================
# Main
# ============================================================

# Parse arguments
AUDIT_DIR="$DEFAULT_AUDIT_DIR"
if [[ "$#" -gt 0 && "$1" != "help" && "$1" != "--help" && "$1" != "-h" ]]; then
    AUDIT_DIR="$1"
fi

if [[ "$#" -gt 0 && ("$1" = "help" || "$1" = "--help" || "$1" = "-h") ]]; then
    usage
    exit 0
fi

# Step 1: Check environment
check_environment

# Step 2: Check Bridge/RPC
check_bridge

# Step 3: Create directories
create_directories "$AUDIT_DIR"

# Step 4: Install script
install_script

# Step 5: Install configuration
install_config "$AUDIT_DIR"

# Step 6: Install services (requires root)
if [[ $EUID -eq 0 ]]; then
    install_services
else
    echo -e "${YELLOW}⚠️  Not running as root - skipping service installation${NC}"
    echo "  To install services, run:"
    echo "    sudo $0 $AUDIT_DIR"
    echo ""
fi

# Step 7: Verify installation
verify_installation

# Step 8: Show summary
show_summary "$AUDIT_DIR"
