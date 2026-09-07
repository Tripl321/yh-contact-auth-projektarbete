#!/usr/bin/env python3
"""
SHALLOT — USB CDC Relay Test

Bridge-initiated USB CDC path: MCU provides a non-secret handshake frame
(0xA1) via Bridge RPC, this script relays it to PLC/PAW via /dev/ttyACM*,
reads the READY (0xA2) response, and reports the result back to MCU.

No key material is involved. No AES keys are sent through Linux.

Usage (on UNO Q MPU via SSH):
    python3 usb_cdc_relay_test.py plc           # Test PLC only
    python3 usb_cdc_relay_test.py paw           # Test PAW only
    python3 usb_cdc_relay_test.py both           # Test PLC then PAW
    python3 usb_cdc_relay_test.py plc --epoch 42 # Custom epoch
"""

import sys
import os
import time
import struct
import subprocess
import re

# =============================================================
# Configuration
# =============================================================

DEVICE_PORTS = {
    1: "/dev/serial/by-id/usb-Raspberry_Pi_Pico_2W_AD501B5D51AD1DFA-if00",
    2: "/dev/serial/by-id/usb-Adafruit_Feather_RP2350_HSTX_48F1F06C7460AE5E-if00",
}

TARGET_NAMES = {1: "PLC", 2: "PAW"}

SHALLOT_MSG_HANDSHAKE = 0xA1
SHALLOT_MSG_READY     = 0xA2
SHALLOT_KD_HANDSHAKE_LEN = 7
SHALLOT_KD_READY_LEN     = 9
SHALLOT_TARGET_PLC = 0x01
SHALLOT_TARGET_PAW = 0x02

DEFAULT_EPOCH = 1
DEFAULT_TIMEOUT = 8
BAUD_RATE = 115200

# =============================================================
# Bridge RPC via arduino-router-cli
# =============================================================

def bridge_call(method, *args, timeout=5):
    """Call a Bridge RPC method via arduino-router-cli."""
    cmd = ["timeout", str(timeout), "arduino-router-cli", method] + [str(a) for a in args]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        output = result.stdout + result.stderr
        match = re.search(r'Got RPC response:\s+"?(.*?)"?\s*$', output, re.MULTILINE)
        if match:
            return match.group(1)
        if "panic:" in output:
            return "rpc_ok_cli_panic"
        return None
    except Exception as e:
        print(f"[BRIDGE] RPC call '{method}' failed: {e}")
        return None

# =============================================================
# USB CDC Relay
# =============================================================

def verify_device_identity(port_path):
    """Read USB sysfs attributes to verify device identity."""
    try:
        real = os.path.realpath(port_path)
        dev_name = os.path.basename(real)
        sys_path = f"/sys/class/tty/{dev_name}/device/.."
        vid = pid = prod = serialnum = ""
        try:
            with open(os.path.join(sys_path, "idVendor")) as f: vid = f.read().strip()
            with open(os.path.join(sys_path, "idProduct")) as f: pid = f.read().strip()
            with open(os.path.join(sys_path, "product")) as f: prod = f.read().strip()
            with open(os.path.join(sys_path, "serial")) as f: serialnum = f.read().strip()
        except:
            pass
        return {"vid": vid, "pid": pid, "product": prod, "serial": serialnum}
    except Exception:
        return {"vid": "", "pid": "", "product": "", "serial": ""}

def relay_test(target_id, epoch=DEFAULT_EPOCH, timeout=DEFAULT_TIMEOUT):
    """Send non-secret handshake to target via /dev/ttyACM, return result dict."""

    target_name = TARGET_NAMES.get(target_id, f"0x{target_id:02X}")
    port = DEVICE_PORTS.get(target_id)

    print(f"\n{'='*50}")
    print(f"[RELAY] Testing {target_name} (target={target_id}, epoch={epoch})")
    print(f"{'='*50}")

    if not port:
        return {"success": False, "error": "no_port_mapping"}

    if not os.path.exists(port):
        print(f"[RELAY] Port not found: {port}")
        print(f"[RELAY] Device {target_name} is likely DISCONNECTED")
        return {"success": False, "error": "port_not_found (disconnected)"}

    dev_info = verify_device_identity(port)
    print(f"[RELAY] Device identity: VID={dev_info['vid']} PID={dev_info['pid']}"
          f" Product='{dev_info['product']}' Serial='{dev_info['serial']}'")

    if dev_info['vid'] and dev_info['pid']:
        if target_id == SHALLOT_TARGET_PLC:
            expected_vid, expected_pid = "2e8a", "f00f"
        elif target_id == SHALLOT_TARGET_PAW:
            expected_vid, expected_pid = "239a", "814f"
        else:
            expected_vid = expected_pid = None

        if expected_vid and dev_info['vid'].lower() != expected_vid:
            print(f"[RELAY] WRONG DEVICE: expected VID={expected_vid}, got {dev_info['vid']}")
            return {"success": False, "error": f"wrong_vid:{dev_info['vid']}"}
        if expected_pid and dev_info['pid'].lower() != expected_pid:
            print(f"[RELAY] WRONG DEVICE: expected PID={expected_pid}, got {dev_info['pid']}")
            return {"success": False, "error": f"wrong_pid:{dev_info['pid']}"}

    print(f"[RELAY] Device identity verified for {target_name}")

    # Get non-secret payload from MCU via Bridge RPC
    print(f"[RELAY] Requesting test payload from MCU via Bridge RPC...")
    payload_hex = bridge_call("get_relay_test_payload", target_id, epoch)

    if not payload_hex or payload_hex == "rpc_ok_cli_panic":
        print(f"[RELAY] ERROR: MCU returned no payload")
        return {"success": False, "error": "mcu_no_payload"}

    payload_hex = payload_hex.strip().strip('"').strip("'")
    print(f"[RELAY] MCU provided payload: {payload_hex}")

    try:
        payload_bytes = bytes.fromhex(payload_hex)
    except ValueError:
        print(f"[RELAY] ERROR: Invalid hex payload: {payload_hex}")
        return {"success": False, "error": "invalid_hex_payload"}

    if len(payload_bytes) != SHALLOT_KD_HANDSHAKE_LEN:
        print(f"[RELAY] ERROR: Wrong payload length: {len(payload_bytes)}")
        return {"success": False, "error": "wrong_payload_length"}

    if payload_bytes[0] != SHALLOT_MSG_HANDSHAKE:
        print(f"[RELAY] ERROR: Wrong message type: 0x{payload_bytes[0]:02X}")
        return {"success": False, "error": "wrong_msg_type"}

    pkt_target = payload_bytes[1]
    pkt_epoch = struct.unpack('>I', payload_bytes[2:6])[0]
    pkt_seq = payload_bytes[6]
    print(f"[RELAY] Payload decoded: target=0x{pkt_target:02X} epoch={pkt_epoch} seq={pkt_seq}")

    if pkt_target != target_id:
        print(f"[RELAY] ERROR: Payload target mismatch")
        return {"success": False, "error": "payload_target_mismatch"}

    # Open serial port
    print(f"[RELAY] Opening port: {port}")
    try:
        import serial
        ser = serial.Serial(port, BAUD_RATE, timeout=timeout)
        # Wait for device to boot/settle (PAW has e-Paper init that takes time)
        time.sleep(3.0)
        # Drain all boot/debug text
        drained = ser.in_waiting
        if drained > 0:
            ser.read(ser.in_waiting)
        time.sleep(0.5)
        # Second drain for any late debug text
        if ser.in_waiting > 0:
            ser.read(ser.in_waiting)
        time.sleep(0.2)
    except FileNotFoundError:
        return {"success": False, "error": "port_not_found"}
    except PermissionError:
        return {"success": False, "error": "permission_denied"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Send handshake frame with retry loop
    # USB CDC on RP2350 can lose the first byte of a write unpredictably.
    # Workaround: retry sending until a READY response is received.
    print(f"[RELAY] Sending handshake ({len(payload_bytes)} bytes, with retries)...")
    max_retries = 5
    ready_frame = None
    all_data = b''
    try:
        for attempt in range(max_retries):
            if attempt > 0:
                print(f"[RELAY] Retry {attempt}/{max_retries}...")
                # Drain any debug text from previous attempt
                if ser.in_waiting > 0:
                    ser.read(ser.in_waiting)
                time.sleep(0.3)

            # Send frame
            ser.write(payload_bytes)
            ser.flush()

            # Read response: scan for 0xA2 tag, skipping debug text
            deadline = time.time() + 2.0  # 2 second per-attempt timeout
            while time.time() < deadline:
                chunk = ser.read(64)
                if chunk:
                    all_data += chunk
                    for i in range(len(all_data)):
                        if all_data[i] == SHALLOT_MSG_READY:
                            if len(all_data) - i >= SHALLOT_KD_READY_LEN:
                                ready_frame = all_data[i:i+SHALLOT_KD_READY_LEN]
                                break
                    if ready_frame:
                        break
            if ready_frame:
                break
    except Exception as e:
        ser.close()
        return {"success": False, "error": f"write_failed:{e}"}

    ser.close()

    if ready_frame is None:
        if len(all_data) == 0:
            print(f"[RELAY] TIMEOUT: No response from {target_name}")
            return {"success": False, "error": "timeout_no_response"}
        else:
            print(f"[RELAY] No 0xA2 tag found in {len(all_data)} bytes")
            print(f"[RELAY] Raw data: {all_data.hex()}")
            print(f"[RELAY] As text: {all_data.decode('utf-8', errors='replace')[:200]}")
            return {"success": False, "error": "no_ready_tag_found"}

    response = ready_frame
    print(f"[RELAY] READY frame found (skipped {len(all_data) - len(response)} debug bytes)")
    print(f"[RELAY] Raw frame: {response.hex()} ({len(response)} bytes)")

    msg_type = response[0]
    device_id = response[1:5]
    echoed_epoch = struct.unpack('>I', response[5:9])[0]
    device_id_hex = device_id.hex()

    print(f"[RELAY] READY received:")
    print(f"  Device ID: {device_id_hex}")
    print(f"  Echoed epoch: {echoed_epoch}")

    if echoed_epoch != epoch:
        print(f"[RELAY] EPOCH MISMATCH: sent {epoch}, got {echoed_epoch}")
        return {"success": False, "error": f"epoch_mismatch:{echoed_epoch}",
                "device_id": device_id_hex, "echoed_epoch": echoed_epoch}

    if target_id == SHALLOT_TARGET_PLC:
        expected_id = bytes([0x50, 0x4C, 0x43, 0x01]).hex()
    elif target_id == SHALLOT_TARGET_PAW:
        expected_id = bytes([0x50, 0x41, 0x57, 0x01]).hex()
    else:
        expected_id = None

    if expected_id and device_id_hex != expected_id:
        print(f"[RELAY] DEVICE ID MISMATCH: expected {expected_id}, got {device_id_hex}")
        return {"success": False, "error": f"device_id_mismatch:{device_id_hex}",
                "device_id": device_id_hex, "echoed_epoch": echoed_epoch}

    print(f"[RELAY] SUCCESS: {target_name} responded correctly!")
    print(f"  Target binding: OK")
    print(f"  Epoch echo: OK ({echoed_epoch})")
    print(f"  Device ID: OK ({device_id_hex})")

    return {
        "success": True,
        "device_id": device_id_hex,
        "echoed_epoch": echoed_epoch
    }

def report_to_mcu(target_id, result):
    """Report relay result back to MCU via Bridge RPC."""
    print(f"\n[RELAY] Reporting result to MCU via Bridge RPC...")

    success = result.get("success", False)
    device_id_hex = result.get("device_id", "")
    echoed_epoch = result.get("echoed_epoch", 0)
    error = result.get("error", "") if not success else ""

    ret = bridge_call("set_relay_test_result", target_id,
                      "true" if success else "false",
                      device_id_hex, echoed_epoch, error)

    if ret is not None:
        print(f"[RELAY] MCU acknowledged result")
    else:
        print(f"[RELAY] WARNING: MCU did not acknowledge")

    stored = bridge_call("get_relay_test_result", target_id)
    print(f"[RELAY] MCU stored result: {stored}")

# =============================================================
# Main
# =============================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target_arg = sys.argv[1].lower()
    epoch = DEFAULT_EPOCH

    for i, a in enumerate(sys.argv[2:], 2):
        if a == "--epoch" and i + 1 < len(sys.argv):
            try:
                epoch = int(sys.argv[i + 1])
            except ValueError:
                print(f"Invalid epoch: {sys.argv[i + 1]}")
                sys.exit(1)

    if target_arg == "status":
        for tid, name in TARGET_NAMES.items():
            result = bridge_call("get_relay_test_result", tid)
            print(f"{name}: {result}")
        return

    if target_arg == "plc":
        targets = [SHALLOT_TARGET_PLC]
    elif target_arg == "paw":
        targets = [SHALLOT_TARGET_PAW]
    elif target_arg == "both":
        targets = [SHALLOT_TARGET_PLC, SHALLOT_TARGET_PAW]
    else:
        print(f"Unknown target: {target_arg}")
        print(__doc__)
        sys.exit(1)

    for target_id in targets:
        result = relay_test(target_id, epoch=epoch)
        report_to_mcu(target_id, result)

    print(f"\n{'='*50}")
    print("SUMMARY")
    print(f"{'='*50}")
    for target_id in targets:
        name = TARGET_NAMES[target_id]
        port = DEVICE_PORTS[target_id]
        exists = os.path.exists(port)
        status = 'found' if exists else 'MISSING'
        print(f"  {name}: port={status}, test=run")

if __name__ == "__main__":
    main()
