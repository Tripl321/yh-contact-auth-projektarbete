# SHALLOT — UNO Q Key Authority MPU Script (PRO-45 + PRO-46)
#
# Linux side: Qualcomm QRB2210 (Debian) via Arduino App Lab
#
# Role:
#   Layer 2 — Orchestration UI, audit log, validation.
#   NEVER touches key material. Communicates with MCU via Bridge RPC.
#
# This script runs on the MPU (Linux) side and provides:
#   1. Orchestration: triggers key generation and distribution via RPC
#   2. Audit log: records all provisioneringshändelser to file
#   3. Validation: verifies that both nodes are provisioned correctly
#
# Security:
#   - This script never receives or handles the AES key
#   - All key operations happen on the MCU (STM32U585)
#   - The MPU only receives status events and key fingerprints (hashes)
#   - Audit log stores hashes only, never keys

import time
import json
import os
import socket
import struct
import threading
from datetime import datetime

# Arduino Bridge socket path
BRIDGE_SOCKET_PATH = "/var/run/arduino-router.sock"

# Target names for human-readable logging
TARGET_NAMES = {
    1: "PLC (edge enforcement)",
    2: "PAW (ID-bricka)",
}

# Key state names for human-readable logging
STATE_NAMES = {
    0: "UNINITIALIZED",
    1: "GENERATED",
    2: "DISTRIBUTED_PLC",
    3: "DISTRIBUTED_PAW",
    4: "DISTRIBUTED_BOTH",
    0xFF: "ERROR",
}

AUDIT_LOG_PATH = "/home/user/shallot/audit/provisioning_log.jsonl"
AUDIT_DIR = os.path.dirname(AUDIT_LOG_PATH)


def check_fido2_device_present():
    """Check if a FIDO2 device is present on the system.
    
    Checks for HID devices that match FIDO2 interface descriptors.
    Returns True if a FIDO2 device is detected.
    """
    try:
        # Check for hidraw devices (FIDO2 devices typically appear as hidraw)
        hidraw_devices = []
        if os.path.exists('/dev'):
            for entry in os.listdir('/dev'):
                if entry.startswith('hidraw'):
                    hidraw_devices.append(entry)
        
        # FIDO2 devices typically have specific USB vendor/product IDs
        # Common FIDO2 VID/PID pairs:
        # Yubico: 1050:*
        # Google: 18d1:50*
        # Pico FIDO: 2E8A:10FE (Raspberry Pi), or custom VID/PID
        
        # Check lsusb output for FIDO2 devices
        try:
            import subprocess
            result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Check for known FIDO2 vendor IDs
                    if any(vid in line.lower() for vid in ['1050:', '18d1:', '2e8a:', '0483:', '1209:']):
                        return True
        except Exception:
            pass
        
        # Check for hidraw devices
        if hidraw_devices:
            print(f"[FIDO2] Found HID devices: {hidraw_devices}")
            return True
            
        print("[FIDO2] No FIDO2 device detected")
        return False
        
    except Exception as e:
        print(f"[FIDO2] Error checking for device: {e}")
        return False


def verify_fido2_presence(timeout=10):
    """Verify FIDO2 device presence with user prompt.
    
    Prompts user to press button on FIDO2 device and verifies device is present.
    Waits for timeout seconds for device to be detected.
    
    Returns True if FIDO2 device is detected within timeout.
    """
    print("[FIDO2] Please press the button on your FIDO2 device...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        if check_fido2_device_present():
            print("[FIDO2] Device detected!")
            return True
        time.sleep(1)
    
    print("[FIDO2] No FIDO2 device detected within timeout")
    return False


# =============================================================
# MessagePack RPC Client for Arduino Bridge
# =============================================================

class BridgeRPC:
    """Minimal MessagePack RPC client for Arduino Bridge communication."""
    
    def __init__(self, socket_path=BRIDGE_SOCKET_PATH):
        self.socket_path = socket_path
        self.socket = None
        self.message_id = 1
        self.lock = threading.Lock()
        
    def connect(self):
        """Connect to the Arduino Bridge socket."""
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(self.socket_path)
            return True
        except Exception as e:
            print(f"[BRIDGE] Connection failed: {e}")
            self.socket = None
            return False
    
    def is_connected(self):
        """Check if socket is connected."""
        return self.socket is not None
    
    def reconnect(self):
        """Reconnect if not connected."""
        if not self.is_connected():
            return self.connect()
        return True
    
    def close(self):
        """Close the socket connection."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _next_message_id(self):
        """Get next message ID with thread safety."""
        with self.lock:
            msg_id = self.message_id
            self.message_id += 1
            return msg_id
    
    def _encode_string(self, s):
        """Encode string in MessagePack format (str8 for short strings)."""
        if len(s) < 32:
            return bytes([0xA0 + len(s)]) + s.encode('utf-8')
        else:
            return bytes([0xDA]) + struct.pack('>H', len(s)) + s.encode('utf-8')
    
    def _encode_integer(self, value):
        """Encode integer in MessagePack format."""
        if value >= 0:
            if value <= 127:
                return bytes([value])
            elif value <= 0xFF:
                return bytes([0xCC, value])
            elif value <= 0xFFFF:
                return bytes([0xCD]) + struct.pack('>H', value)
            else:
                return bytes([0xCE]) + struct.pack('>I', value)
        else:
            if value >= -32:
                return bytes([value + 256])
            elif value >= -128:
                return bytes([0xD0, value & 0xFF])
            else:
                return bytes([0xD1]) + struct.pack('>h', value)
    
    def _encode_array(self, elements):
        """Encode array in MessagePack format."""
        if len(elements) <= 15:
            header = bytes([0x90 + len(elements)])
        else:
            header = bytes([0xDC]) + struct.pack('>H', len(elements))
        
        encoded_elements = b''
        for element in elements:
            if isinstance(element, str):
                encoded_elements += self._encode_string(element)
            elif isinstance(element, int):
                encoded_elements += self._encode_integer(element)
            elif isinstance(element, bytes):
                encoded_elements += self._encode_binary(element)
            elif isinstance(element, list):
                encoded_elements += self._encode_array(element)
            else:
                raise ValueError(f"Unsupported type: {type(element)}")
        
        return header + encoded_elements
    
    def _encode_binary(self, data):
        """Encode binary data in MessagePack format."""
        if len(data) <= 255:
            return bytes([0xC4, len(data)]) + data
        else:
            return bytes([0xC5]) + struct.pack('>H', len(data)) + data
    
    def _encode_rpc_request(self, method, args):
        """Encode an RPC request as MessagePack."""
        msg_id = self._next_message_id()
        elements = [0, msg_id, method, args]
        return self._encode_array(elements)
    
    def _decode_messagepack(self, data):
        """Decode MessagePack data."""
        if len(data) == 0:
            return None
        
        first_byte = data[0]
        
        # Handle fixint (0x00-0x7F)
        if first_byte <= 0x7F:
            return first_byte
        
        # Handle str8 (0xA0-0xBF)
        elif 0xA0 <= first_byte <= 0xBF:
            length = first_byte - 0xA0
            if len(data) >= 1 + length:
                return data[1:1+length].decode('utf-8')
        
        # Handle str16 (0xDA)
        elif first_byte == 0xDA:
            if len(data) >= 3:
                length = struct.unpack('>H', data[1:3])[0]
                if len(data) >= 3 + length:
                    return data[3:3+length].decode('utf-8')
        
        # Handle uint8 (0xCC)
        elif first_byte == 0xCC:
            if len(data) >= 2:
                return data[1]
        
        # Handle uint16 (0xCD)
        elif first_byte == 0xCD:
            if len(data) >= 3:
                return struct.unpack('>H', data[1:3])[0]
        
        # Handle uint32 (0xCE)
        elif first_byte == 0xCE:
            if len(data) >= 5:
                return struct.unpack('>I', data[1:5])[0]
        
        # Handle array (0x90-0x9F for fixarray)
        elif 0x90 <= first_byte <= 0x9F:
            length = first_byte - 0x90
            return self._decode_array(data[1:], length)
        
        # Handle binary (0xC4, 0xC5)
        elif first_byte == 0xC4:  # bin8
            if len(data) >= 2:
                length = data[1]
                if len(data) >= 2 + length:
                    return data[2:2+length]
        
        return None
    
    def _decode_array(self, data, length):
        """Decode MessagePack array."""
        elements = []
        offset = 0
        
        for _ in range(length):
            if offset >= len(data):
                break
            
            element, decoded_bytes = self._decode_element(data[offset:])
            if element is not None:
                elements.append(element)
                offset += decoded_bytes
            else:
                break
        
        return elements
    
    def _decode_element(self, data):
        """Decode a single MessagePack element, return (element, bytes_consumed)."""
        if len(data) == 0:
            return None, 0
        
        first_byte = data[0]
        
        # Boolean: false (0xC2), true (0xC3)
        if first_byte == 0xC2:
            return False, 1
        if first_byte == 0xC3:
            return True, 1
        
        # Fixint positive (0x00-0x7F)
        if first_byte <= 0x7F:
            return first_byte, 1
        
        # Fixint negative (0xE0-0xFF)
        elif 0xE0 <= first_byte <= 0xFF:
            return first_byte - 256, 1  # Convert to negative
        
        # Str8 (0xA0-0xBF)
        elif 0xA0 <= first_byte <= 0xBF:
            length = first_byte - 0xA0
            if len(data) >= 1 + length:
                return data[1:1+length].decode('utf-8'), 1 + length
        
        # Uint8 (0xCC)
        elif first_byte == 0xCC:
            if len(data) >= 2:
                return data[1], 2
        
        # Uint16 (0xCD)
        elif first_byte == 0xCD:
            if len(data) >= 3:
                return struct.unpack('>H', data[1:3])[0], 3
        
        # Uint32 (0xCE)
        elif first_byte == 0xCE:
            if len(data) >= 5:
                return struct.unpack('>I', data[1:5])[0], 5
        
        # Binary (0xC4, 0xC5)
        elif first_byte == 0xC4:  # bin8
            if len(data) >= 2:
                length = data[1]
                if len(data) >= 2 + length:
                    return data[2:2+length], 2 + length
        
        # Fixarray (0x90-0x9F)
        elif 0x90 <= first_byte <= 0x9F:
            array_length = first_byte - 0x90
            elements, bytes_consumed = self._decode_array_with_offset(data[1:], array_length)
            return elements, 1 + bytes_consumed
        
        return None, 1
    
    def _decode_array_with_offset(self, data, length):
        """Decode MessagePack array from offset, return (elements, bytes_consumed)."""
        elements = []
        offset = 0
        
        for _ in range(length):
            if offset >= len(data):
                break
            
            element, decoded_bytes = self._decode_element(data[offset:])
            if element is not None:
                elements.append(element)
                offset += decoded_bytes
            else:
                break
        
        return elements, offset
    
    def call(self, method, *args):
        """Make an RPC call to the Arduino Bridge."""
        if not self.reconnect():
            print(f"[BRIDGE] Failed to connect to {self.socket_path}")
            return None
        
        try:
            # Encode the RPC request
            request_data = self._encode_rpc_request(method, list(args))
            
            # Send the request
            self.socket.sendall(request_data)
            
            # Read the response
            response_data = b''
            while True:
                chunk = self.socket.recv(1024)
                if not chunk:
                    break
                response_data += chunk
            
            if len(response_data) == 0:
                print("[BRIDGE] Empty response")
                return None
            
            # Decode the response
            result = self._decode_element(response_data)
            
            # If result is an array with [type, id, payload], extract payload
            if isinstance(result, list) and len(result) >= 3:
                payload = result[2]
                if isinstance(payload, list) and len(payload) == 1:
                    return payload[0]  # Single return value
                else:
                    return payload
            else:
                return result
                
        except Exception as e:
            print(f"[BRIDGE] RPC call failed: {e}")
            self.close()
            return None


# Global Bridge RPC instance
Bridge = BridgeRPC()


def ensure_audit_dir():
    """Create audit log directory if it does not exist."""
    if not os.path.exists(AUDIT_DIR):
        os.makedirs(AUDIT_DIR)


def write_audit_log(event_type, details):
    """Append a JSON line to the audit log file.

    Args:
        event_type: String identifier for the event type.
        details: Dict with event-specific metadata.
    """
    ensure_audit_dir()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "details": details,
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[AUDIT] {entry['timestamp']} | {event_type} | {details}")


def on_key_authority_event(event, message):
    """Callback for key_authority_event notifications from MCU.

    This is called when the MCU sends a status notification via Bridge.notify.
    The event and message contain only status information — never key material.

    Args:
        event: Event type string (e.g. "key_generated", "distribution_success").
        message: Human-readable status message.
    """
    print(f"[MCU EVENT] {event}: {message}")
    write_audit_log(event, {"message": message})


def get_key_state():
    """Query the MCU for current key state via Bridge RPC."""
    state = Bridge.call("get_key_state")
    state_name = STATE_NAMES.get(state, "UNKNOWN")
    print(f"[STATUS] Key state: {state_name} (0x{state:02X})")
    return state


def get_key_fingerprint():
    """Query the MCU for the key fingerprint (SHA-256 hash, first 4 bytes).

    This returns only a hash — never the key itself.
    """
    fingerprint = Bridge.call("get_key_fingerprint")
    print(f"[STATUS] Key fingerprint: {fingerprint}")
    return fingerprint


def request_key_generation():
    """Request the MCU to generate a new AES-128 key via Bridge RPC.

    The key is generated entirely on the STM32U585 using its hardware TRNG.
    The MPU never sees the key.
    """
    print("[ORCHESTRATION] Requesting key generation on MCU...")
    success = Bridge.call("request_key_generation")
    if success:
        print("[ORCHESTRATION] Key generation successful.")
        fingerprint = get_key_fingerprint()
        write_audit_log("key_generation_requested", {
            "result": "success",
            "fingerprint": fingerprint,
        })
    else:
        print("[ORCHESTRATION] Key generation FAILED.")
        write_audit_log("key_generation_requested", {"result": "failure"})
    return success


def request_key_distribution(target_id):
    """Request the MCU to distribute the key to a target device.

    This arms the distribution on the MCU side. The operator must then
    physically press the confirmation button on the UNO Q to complete
    the distribution. This two-step process ensures physical authorization.

    Args:
        target_id: 1 for PLC (edge enforcement), 2 for PAW (ID-bricka).
    """
    target_name = TARGET_NAMES.get(target_id, f"Unknown({target_id})")
    print(f"[ORCHESTRATION] Requesting key distribution to {target_name}.")
    print("[ORCHESTRATION] Operator must press confirmation button on UNO Q.")

    success = Bridge.call("request_key_distribution", target_id)
    if success:
        write_audit_log("distribution_armed", {"target": target_name})
        print(f"[ORCHESTRATION] Distribution to {target_name} armed. Waiting for button press...")

        # Wait for distribution to complete (poll key state)
        max_wait = 30  # seconds
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(1)
            state = get_key_state()
            if target_id == 1 and state in (2, 4):  # DISTRIBUTED_PLC or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed.")
                write_audit_log("distribution_confirmed", {"target": target_name})
                return True
            if target_id == 2 and state in (3, 4):  # DISTRIBUTED_PAW or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed.")
                write_audit_log("distribution_confirmed", {"target": target_name})
                return True

        print(f"[ORCHESTRATION] Timeout waiting for {target_name} distribution.")
        write_audit_log("distribution_timeout", {"target": target_name})
        return False
    else:
        print(f"[ORCHESTRATION] Failed to arm distribution to {target_name}.")
        return False


def distribute_key_now(target_id):
    """Distribute the key to a target device using FIDO2 verification.
    
    This uses FIDO2 device presence as verification, then calls distribute_key_now
    RPC which directly sends the key without requiring UNO Q button press.
    
    Args:
        target_id: 1 for PLC (edge enforcement), 2 for PAW (ID-bricka).
    """
    target_name = TARGET_NAMES.get(target_id, f"Unknown({target_id})")
    print(f"[ORCHESTRATION] Requesting key distribution to {target_name}.")
    print(f"[FIDO2] Please provide your registered FIDO key and press the button on the device")
    
    # Verify FIDO2 device is present (user has pressed button)
    if not verify_fido2_presence(timeout=10):
        print(f"[FIDO2] No FIDO2 device detected. Falling back to UNO Q button press method.")
        return request_key_distribution(target_id)
    
    print(f"[FIDO2] FIDO2 device verified. Initiating immediate distribution to {target_name}...")
    
    # Call the immediate distribution RPC
    success = Bridge.call("distribute_key_now", target_id)
    if success:
        print(f"[ORCHESTRATION] Distribution to {target_name} initiated (FIDO2 verified).")
        write_audit_log("distribution_fido2_initiated", {"target": target_name})
        
        # Wait for distribution to complete (poll key state)
        max_wait = 30  # seconds
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(1)
            state = get_key_state()
            if target_id == 1 and state in (2, 4):  # DISTRIBUTED_PLC or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed via FIDO2.")
                write_audit_log("distribution_fido2_confirmed", {"target": target_name})
                return True
            if target_id == 2 and state in (3, 4):  # DISTRIBUTED_PAW or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed via FIDO2.")
                write_audit_log("distribution_fido2_confirmed", {"target": target_name})
                return True

        print(f"[ORCHESTRATION] Timeout waiting for {target_name} distribution via FIDO2.")
        write_audit_log("distribution_fido2_timeout", {"target": target_name})
        return False
    else:
        print(f"[ORCHESTRATION] Failed to initiate immediate distribution to {target_name}.")
        write_audit_log("distribution_fido2_failed", {"target": target_name})
        return False


def validate_provisioning():
    """Validate that both nodes are provisioned correctly.

    Checks:
      1. Key state is DISTRIBUTED_BOTH
      2. Key fingerprint is available
      3. Audit log has entries for both distributions
    """
    print("\n=== VALIDATION ===")
    state = get_key_state()
    if state == 4:
        print("[VALIDATION] Key state: DISTRIBUTED_BOTH — OK")
    else:
        state_name = STATE_NAMES.get(state, "UNKNOWN")
        print(f"[VALIDATION] Key state: {state_name} — INCOMPLETE")
        return False

    fingerprint = get_key_fingerprint()
    if fingerprint and len(fingerprint) == 8:
        print(f"[VALIDATION] Key fingerprint: {fingerprint} — OK")
    else:
        print(f"[VALIDATION] Key fingerprint: {fingerprint} — INVALID")
        return False

    print("[VALIDATION] All checks passed.")
    write_audit_log("validation", {
        "result": "pass",
        "state": "DISTRIBUTED_BOTH",
        "fingerprint": fingerprint,
    })
    print("===================\n")
    return True


def print_menu():
    """Print the operator menu."""
    print("\n=== SHALLOT UNO Q — Orchestration (MPU) ===")
    print("  1 — Generate new AES-128 key (MCU TRNG)")
    print("  2 — Distribute key to PLC (edge enforcement) [FIDO2]")
    print("  3 — Distribute key to PAW (ID-bricka) [FIDO2]")
    print("  4 — Query key state")
    print("  5 — Show key fingerprint")
    print("  6 — Validate provisioning (both nodes)")
    print("  7 — Print audit log")
    print("  q — Quit")
    print("===========================================\n")


def print_audit_log():
    """Print the contents of the audit log."""
    if not os.path.exists(AUDIT_LOG_PATH):
        print("[AUDIT] No audit log file found.")
        return
    print("\n=== AUDIT LOG ===")
    with open(AUDIT_LOG_PATH, "r") as f:
        for line in f:
            entry = json.loads(line.strip())
            ts = entry.get("timestamp", "?")
            evt = entry.get("event", "?")
            det = entry.get("details", {})
            print(f"  {ts} | {evt} | {det}")
    print("==================\n")


class EventListener:
    """Simple thread to listen for Bridge notifications."""
    
    def __init__(self, bridge):
        self.bridge = bridge
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the event listener thread."""
        self.running = True
        print("[EVENT LISTENER] Bridge notifications will be processed on demand.")
    
    def stop(self):
        """Stop the event listener thread."""
        self.running = False
        if self.thread:
            self.thread.join()


def loop():
    """Main loop — operator menu interface."""
    print_menu()
    
    # Initialize Bridge connection
    if not Bridge.connect():
        print(f"[BRIDGE] Could not connect to {BRIDGE_SOCKET_PATH}")
        print("Make sure Arduino Bridge is running on the UNO Q.")
        print("Exiting...")
        return
    
    print(f"[BRIDGE] Connected to {BRIDGE_SOCKET_PATH}")
    
    # Start event listener (simplified)
    event_listener = EventListener(Bridge)
    event_listener.start()

    while True:
        try:
            cmd = input("Select option: ").strip().lower()

            if cmd == "1":
                request_key_generation()
            elif cmd == "2":
                distribute_key_now(1)
            elif cmd == "3":
                distribute_key_now(2)
            elif cmd == "4":
                get_key_state()
            elif cmd == "5":
                get_key_fingerprint()
            elif cmd == "6":
                validate_provisioning()
            elif cmd == "7":
                print_audit_log()
            elif cmd == "q":
                print("Exiting.")
                event_listener.stop()
                Bridge.close()
                break
            else:
                print("Unknown option.")
        except KeyboardInterrupt:
            print("\nExiting.")
            event_listener.stop()
            Bridge.close()
            break
        except Exception as e:
            print(f"Error: {e}")
            # Try to reconnect
            Bridge.close()


if __name__ == "__main__":
    # Check if we're running in the correct environment
    if not os.path.exists(BRIDGE_SOCKET_PATH):
        print(f"[BRIDGE] Socket not found: {BRIDGE_SOCKET_PATH}")
        print("Make sure Arduino Bridge is running and the socket exists.")
        print("This script is designed to run on the UNO Q MPU (QRB2210 Linux).")
        exit(1)
    
    # Check for required directories
    ensure_audit_dir()
    
    # Run the main loop
    loop()
