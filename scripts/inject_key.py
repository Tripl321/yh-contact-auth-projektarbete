#!/usr/bin/env python3
"""
SHALLOT — UNO Q Key Authority Orchestration Script

This script orchestrates key generation and distribution using the Arduino UNO Q
as the single source of truth. It communicates with the UNO Q's STM32U585 MCU via
Bridge RPC to trigger key operations without ever handling key material.

Requirements:
- Arduino UNO Q with proper key authority firmware
- USB connections between host/Mama Bear MPU and target devices (PLC/PAW) via USB hub
  (UART via D0/D1 is DEPRECATED as of 2026-09-04 - do not use)
- For Bridge RPC: UNO Q connected to host computer via USB (optional for monitoring)

Usage:
  python3 inject_key.py [--monitor]
    --monitor: Monitor UNO Q status via Bridge RPC (requires USB connection)

Security:
- This script NEVER generates or handles key material
- All key operations happen on UNO Q's STM32U585 using hardware TRNG
- Key distribution requires USB connections and operator confirmation (button on Mama Bear)
- Script only provides orchestration and status monitoring
"""

import sys
import time
import serial
from typing import Optional, Dict, Any

# Configuration for monitoring UNO Q via Bridge RPC
BRIDGE_BAUD = 115200
UNOQ_SERIAL_PORT = None  # Will be auto-detected or specified

# USB connections for key distribution (all devices via USB hub)
# DEPRECATED: UART_BAUD and D0/D1 wiring - use USB CDC at 115200 baud instead
UART_BAUD = 115200  # Kept for backwards compat, now maps to USB CDC baud
USB_BAUD = 115200


def print_header():
    print("=" * 60)
    print("SHALLOT — UNO Q Key Authority Orchestration")
    print("=" * 60)
    print()


def print_airgapped_workflow():
    print("AIR-GAPPED WORKFLOW (USB - UART DEPRECATED 2026-09-04):")
    print("-" * 40)
    print("1. Connect all devices via USB hub to host/Mama Bear MPU")
    print("   - UNO Q via USB-C")
    print("   - PLC (Pico 2W) via USB")
    print("   - PAW (Feather RP2350) via USB")
    print("2. Power on all devices")
    print("3. On UNO Q: Press button to generate key (hardware TRNG)")
    print("4. For each target device:")
    print("   a. Ensure USB connection is active")
    print("   b. On UNO Q: Press distribution button for that target")
    print("   c. UNO Q distributes key via USB with physical confirmation")
    print("5. Verify both devices show matching fingerprints")
    print("   NOTE: UART (D0/D1) is no longer used. Use USB only.")
    print()


def print_monitor_workflow():
    print("MONITORED WORKFLOW (requires UNO Q USB connection):")
    print("-" * 55)
    print("1. Connect all devices via USB hub to host computer")
    print("   - UNO Q via USB-C")
    print("   - PLC via USB")
    print("   - PAW via USB")
    print("2. Power on all devices")
    print("3. This script monitors UNO Q status and guides operator")
    print("4. All key operations still happen on UNO Q with physical confirmation")
    print("5. Distribution via USB (UART deprecated)")
    print()


def find_unoq_port() -> Optional[str]:
    """Attempt to find UNO Q serial port automatically."""
    # Common port patterns for different operating systems
    import os
    if os.name == 'nt':  # Windows
        patterns = ['COM*']
    else:  # macOS/Linux
        patterns = ['/dev/cu.usbmodem*', '/dev/ttyACM*', '/dev/ttyUSB*']
    
    for pattern in patterns:
        import glob
        ports = glob.glob(pattern)
        for port in ports:
            # UNO Q typically identifies with specific vendor/product IDs
            # For now, we'll return the first available port
            # In production, you'd want more specific detection
            return port
    return None


def monitor_unoq_status():
    """Monitor UNO Q status via Bridge RPC."""
    port = find_unoq_port()
    if not port:
        print("UNO Q serial port not found. Please specify manually.")
        print("Available ports:")
        try:
            import serial.tools.list_ports
            ports = serial.tools.list_ports.comports()
            for p in ports:
                print(f"  {p.device}")
        except ImportError:
            print("  (install pyserial[list-ports] to see available ports)")
        return
    
    print(f"Connecting to UNO Q on {port}...")
    
    try:
        # For Bridge RPC monitoring, we need to connect via the bridge socket
        # This is a simplified version - actual Bridge RPC requires Arduino RouterBridge
        ser = serial.Serial(port, BRIDGE_BAUD, timeout=1.0)
        time.sleep(2)  # Allow connection to establish
        
        print("UNO Q Monitor Mode")
        print("-" * 20)
        print("Waiting for UNO Q status messages...")
        print("Press Ctrl+C to exit")
        print()
        
        while True:
            if ser.in_waiting:
                line = ser.readline().decode('utf-8', errors='replace').strip()
                if line:
                    print(f"[UNO Q] {line}")
                    
                    # Look for key status indicators
                    if "Key generated successfully" in line:
                        print("✓ Key generation complete on UNO Q")
                    elif "distributed successfully" in line:
                        print("✓ Key distribution complete")
                    elif "fingerprint" in line.lower():
                        print("✓ Key fingerprint available")
                    elif "ERROR" in line.upper():
                        print("✗ Error detected on UNO Q")
            else:
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Monitor error: {e}")
    finally:
        if 'ser' in locals():
            ser.close()


def main():
    print_header()
    
    monitor_mode = '--monitor' in sys.argv or '-m' in sys.argv
    
    if monitor_mode:
        print_monitor_workflow()
        monitor_unoq_status()
    else:
        print_airgapped_workflow()
        
        print("IMPORTANT SECURITY NOTES:")
        print("-" * 30)
        print("• UNO Q is the ONLY device that generates keys")
        print("• Keys are generated using STM32U585 hardware TRNG")
        print("• This script NEVER handles key material")
        print("• Distribution requires physical button press on UNO Q")
        print("• Key material never leaves secure domain until USB distribution")
        print("• USB is now used for distribution (UART deprecated 2026-09-04)")
        print()
        
        print("To monitor UNO Q status via USB connection:")
        print(f"  {sys.argv[0]} --monitor")
        print()
        
        print("For completely air-gapped operation:")
        print("  1. Follow the workflow above without connecting to host computer")
        print("  2. Use UNO Q's physical buttons for all operations")
        print("  3. Verify key fingerprints match on all devices")
        print()


if __name__ == "__main__":
    main()
