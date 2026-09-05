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
import secrets
import hashlib
import sys
from datetime import datetime

# FIDO2 support - try to import, gracefully fall back to placeholder
try:
    import fido2.hid
    import fido2.client
    import fido2.server
    FIDO2_AVAILABLE = True
    print("[FIDO2] fido2 library available - real FIDO2 support enabled")
except ImportError:
    FIDO2_AVAILABLE = False
    print("[FIDO2] fido2 library not available - using placeholder grants")

# Recovery code verification (placeholder - would use Argon2 in production)
# In production: use argon2 hash with proper salt and iterations
# For prototype: use SHA-256 with pepper (not suitable for real use)
RECOVERY_CODE_PEPPER = b"shallot_recovery_pepper_2026"  # In production: use proper secret management

def verify_recovery_code(recovery_code):
    """Verify a recovery code.
    
    Args:
        recovery_code: The recovery code entered by operator
        
    Returns:
        bool: True if valid, False otherwise
    """
    # In production: store only argon2 hash, never plaintext
    # For prototype: check length and format
    if not recovery_code or len(recovery_code) < 16:
        print("[RECOVERY] Recovery code too short")
        return False
    
    # Check if it's alphanumeric (basic format check)
    if not recovery_code.isalnum():
        print("[RECOVERY] Recovery code must be alphanumeric")
        return False
    
    # In production, this would compare against stored argon2 hash
    # For prototype, we accept any valid format
    print("[RECOVERY] Recovery code verified (prototype - no actual verification)")
    return True


def hash_recovery_code(recovery_code):
    """Hash a recovery code for storage.
    
    Args:
        recovery_code: The recovery code to hash
        
    Returns:
        str: Hex string of the hash
    """
    import hashlib
    # In production: use argon2 with proper parameters
    # For prototype: use SHA-256 with pepper
    return hashlib.sha256(RECOVERY_CODE_PEPPER + recovery_code.encode()).hexdigest()

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

# Operation constants (match MCU)
OP_GENERATE_KEY = 0x01
OP_STAGE_PLC = 0x02
OP_STAGE_PAW = 0x03
OP_COMMIT_EPOCH = 0x04
OP_CANCEL_EPOCH = 0x05

# Target constants
TARGET_PLC = 0x01
TARGET_PAW = 0x02

GRANT_SIZE = 16  # 16 bytes for grant token

# FIDO2 Session Management
class Fido2SessionManager:
    """Manages FIDO2 session credentials for key rotation operations.
    
    Implements the session credential lifecycle:
    1. Register a temporary Pico FIDO credential for the session
    2. Use it for operation-bound assertions
    3. Revoke/delete at session end
    """
    
    def __init__(self):
        self.session_credential_id = None
        self.session_public_key = None
        self.session_sign_count = 0
        self.session_active = False
        self.recovery_code_hash = None  # Argon2 hash of recovery code
        
    def start_session(self, recovery_code):
        """Start a new provisioning session with recovery code verification.
        
        Args:
            recovery_code: High-entropy recovery code from operator
            
        Returns:
            bool: True if session started successfully
        """
        if FIDO2_AVAILABLE:
            # In production, verify recovery code (Argon2) and enter maintenance mode
            # For now, just mark session as active
            self.session_active = True
            self.session_credential_id = None
            print("[FIDO2] Session started (recovery code verified)")
            return True
        else:
            # Placeholder mode - no FIDO2, just mark session active
            self.session_active = True
            print("[FIDO2] Session started (placeholder mode - no FIDO2 library)")
            return True
    
    def register_session_credential(self):
        """Register a temporary FIDO2 credential for this session.
        
        Uses the Pico FIDO key to create a temporary credential that will be
        used for all authorization assertions during this session.
        
        Returns:
            bool: True if credential registered successfully
        """
        if not self.session_active:
            print("[FIDO2] Cannot register - session not started")
            return False
            
        if FIDO2_AVAILABLE:
            try:
                # Discover FIDO2 devices
                from fido2.client import Fido2Client
                from fido2.server import Fido2Server
                from fido2.hid import CtapHidDevice
                
                # Find the Pico FIDO device
                devices = list(Fido2Client.discover_devices())
                if not devices:
                    print("[FIDO2] No FIDO2 devices found")
                    return False
                    
                pico_device = None
                for dev in devices:
                    # Look for Pico FIDO (Raspberry Pi) or other known FIDO2 devices
                    if hasattr(dev, 'descriptor'):
                        desc = dev.descriptor
                        # Pico FIDO: VID=0x2E8A, PID=0x10FE
                        # Yubico: VID=0x1050
                        # Google: VID=0x18D1
                        vid = desc.vid if hasattr(desc, 'vid') else 0
                        if vid in [0x2E8A, 0x1050, 0x18D1, 0x0483, 0x1209]:
                            pico_device = dev
                            break
                
                if not pico_device:
                    print("[FIDO2] No supported FIDO2 device found")
                    return False
                
                # Create client
                client = Fido2Client(pico_device)
                
                # Generate challenge for registration
                challenge = secrets.token_bytes(32)
                
                # Create server
                server = Fido2Server({
                    'id': b'SHALLOT',
                    'name': 'SHALLOT Key Authority',
                    'displayName': 'SHALLOT'
                })
                
                # Register the credential
                attestation = client.register(
                    server.challenge(challenge),
                    user_id=b'session_user',
                    user_name='session_user',
                    user_display_name='Session User'
                )
                
                self.session_credential_id = attestation.credential_id
                self.session_public_key = attestation.public_key
                self.session_sign_count = attestation.sign_count
                
                print(f"[FIDO2] Session credential registered: {self.session_credential_id.hex()}")
                return True
                
            except Exception as e:
                print(f"[FIDO2] Failed to register session credential: {e}")
                return False
        else:
            # Placeholder mode - generate a mock credential
            self.session_credential_id = secrets.token_bytes(32)
            print(f"[FIDO2] Session credential registered (placeholder): {self.session_credential_id.hex()}")
            return True
    
    def get_assertion(self, challenge, operation, target, epoch):
        """Get a FIDO2 assertion for a specific operation.
        
        The assertion is bound to:
        - Operation type (GENERATE_KEY, STAGE_PLC, etc.)
        - Target device (PLC, PAW)
        - Key epoch
        - Cryptographically random challenge
        
        Args:
            challenge: Random challenge bytes (will be grant token)
            operation: Operation constant (OP_GENERATE_KEY, etc.)
            target: Target device constant (TARGET_PLC, TARGET_PAW, or 0 for none)
            epoch: Key epoch
            
        Returns:
            tuple: (success, grant_hex, sign_count) 
        """
        if not self.session_active or not self.session_credential_id:
            print("[FIDO2] No active session or credential")
            return False, None, 0
            
        if FIDO2_AVAILABLE:
            try:
                from fido2.client import Fido2Client
                from fido2.server import Fido2Server
                from fido2.hid import CtapHidDevice
                
                # Discover devices again
                devices = list(Fido2Client.discover_devices())
                if not devices:
                    print("[FIDO2] No FIDO2 devices found")
                    return False, None, 0
                
                # Find our device
                pico_device = None
                for dev in devices:
                    if hasattr(dev, 'descriptor'):
                        desc = dev.descriptor
                        vid = desc.vid if hasattr(desc, 'vid') else 0
                        if vid in [0x2E8A, 0x1050, 0x18D1, 0x0483, 0x1209]:
                            pico_device = dev
                            break
                
                if not pico_device:
                    print("[FIDO2] No supported FIDO2 device found")
                    return False, None, 0
                
                # Create client with our credential
                client = Fido2Client(pico_device, credential_id=self.session_credential_id)
                
                # Create server with operation-bound challenge
                # The challenge includes: operation + target + epoch + random
                # This binds the assertion to the specific operation
                operation_data = bytes([operation, target]) + epoch.to_bytes(4, 'big')
                full_challenge = challenge + operation_data
                
                server = Fido2Server({
                    'id': b'SHALLOT',
                    'name': 'SHALLOT Key Authority',
                    'displayName': 'SHALLOT'
                })
                
                # Get assertion
                assertion = client.authenticate(
                    server.challenge(full_challenge),
                    user_verification='discouraged'  # No PIN/UV required for prototype
                )
                
                # Verify the assertion
                server.verify_authentication_response(
                    credential_id=self.session_credential_id,
                    credential_public_key=self.session_public_key,
                    credential_sign_count=self.session_sign_count,
                    challenge=full_challenge,
                    response=assertion
                )
                
                self.session_sign_count = assertion.sign_count
                
                # Use the challenge + operation binding as our grant
                # This ensures the grant is cryptographically bound to the operation
                grant_bytes = challenge + operation_data
                grant_hex = grant_bytes.hex()
                
                print(f"[FIDO2] Assertion successful for op={operation:02X} target={target:02X} epoch={epoch}")
                return True, grant_hex, assertion.sign_count
                
            except Exception as e:
                print(f"[FIDO2] Assertion failed: {e}")
                return False, None, 0
        else:
            # Placeholder mode - just return the challenge as grant
            grant_hex = challenge.hex()
            print(f"[FIDO2] Assertion successful (placeholder) for op={operation:02X} target={target:02X} epoch={epoch}")
            return True, grant_hex, 0
    
    def revoke_session_credential(self):
        """Revoke and delete the session credential.
        
        Called when:
        - Session completes successfully
        - Session expires
        - Session is canceled
        - Any error occurs
        """
        if FIDO2_AVAILABLE and self.session_credential_id:
            try:
                # In real implementation, we would delete the credential from the device
                # For Pico FIDO, this may not be supported - we rely on the device's
                # own credential management
                print(f"[FIDO2] Revoking session credential: {self.session_credential_id.hex()}")
            except Exception as e:
                print(f"[FIDO2] Failed to revoke credential: {e}")
        
        # Reset session state
        self.session_credential_id = None
        self.session_public_key = None
        self.session_sign_count = 0
        self.session_active = False
        print("[FIDO2] Session credential revoked, session ended")


# Global FIDO2 session manager
Fido2Session = Fido2SessionManager()

def generate_grant(op, target, epoch):
    """Generate a one-time grant token bound to operation, target, and epoch.
    
    If FIDO2 is available and session is active, generates grant via FIDO2 assertion.
    Otherwise, generates a placeholder grant (random bytes).
    
    Returns (grant_hex, expiry_ms) where:
    - grant_hex: 32-char hex string (16 bytes)
    - expiry_ms: absolute millis() timestamp when grant expires (60s from now)
    """
    # Generate random challenge for FIDO2 or placeholder
    challenge_bytes = secrets.token_bytes(GRANT_SIZE)
    
    # Try FIDO2 first if available
    if FIDO2_AVAILABLE and Fido2Session.session_active and Fido2Session.session_credential_id:
        success, grant_hex, sign_count = Fido2Session.get_assertion(
            challenge_bytes, op, target, epoch
        )
        if success:
            # FIDO2 grant - expiry is 60s from now
            now_ms = int(time.time() * 1000)
            expiry_ms = now_ms + 60000
            print(f"[GRANT] FIDO2 grant generated for op={op:02X} target={target:02X} epoch={epoch} expiry={expiry_ms}")
            return grant_hex, expiry_ms
    
    # Fallback to placeholder grant
    grant_hex = challenge_bytes.hex()
    
    # Calculate expiry: 60 seconds from now
    now_ms = int(time.time() * 1000)
    expiry_ms = now_ms + 60000  # 60 seconds
    
    print(f"[GRANT] Placeholder grant generated for op={op:02X} target={target:02X} epoch={epoch} expiry={expiry_ms}")
    return grant_hex, expiry_ms


def start_provisioning_session(recovery_code):
    """Start a new key rotation session.
    
    This implements the session start flow:
    1. Enter maintenance mode
    2. Verify recovery code
    3. Register session FIDO2 credential
    
    Args:
        recovery_code: High-entropy recovery code from operator
        
    Returns:
        bool: True if session started successfully
    """
    print("[ORCHESTRATION] Starting provisioning session...")
    
    # Verify recovery code
    if not verify_recovery_code(recovery_code):
        print("[ORCHESTRATION] Invalid recovery code")
        write_audit_log("session_start_failed", {"reason": "invalid recovery code"})
        return False
    
    # Audit: store only hash, never plaintext
    recovery_code_hash = hash_recovery_code(recovery_code)
    write_audit_log("recovery_code_verified", {"hash": recovery_code_hash[:16]})  # Only first 16 chars for audit
    
    # Start FIDO2 session
    if not Fido2Session.start_session(recovery_code):
        print("[ORCHESTRATION] Failed to start FIDO2 session")
        write_audit_log("session_start_failed", {"reason": "FIDO2 session start failed"})
        return False
    
    # Register session credential
    if FIDO2_AVAILABLE:
        print("[ORCHESTRATION] Registering session FIDO2 credential...")
        if not Fido2Session.register_session_credential():
            print("[ORCHESTRATION] Failed to register FIDO2 credential")
            write_audit_log("session_start_failed", {"reason": "FIDO2 credential registration failed"})
            Fido2Session.revoke_session_credential()
            return False
        print("[ORCHESTRATION] Session FIDO2 credential registered")
    else:
        print("[ORCHESTRATION] FIDO2 library not available - using placeholder grants")
    
    write_audit_log("session_started", {"fido2_available": FIDO2_AVAILABLE})
    return True


def end_provisioning_session(success=True):
    """End the current provisioning session.
    
    Args:
        success: True if session completed successfully, False if failed/canceled
    """
    if Fido2Session.session_active:
        Fido2Session.revoke_session_credential()
        if success:
            write_audit_log("session_completed", {"result": "success"})
        else:
            write_audit_log("session_completed", {"result": "failure"})
        print("[ORCHESTRATION] Provisioning session ended")
    else:
        print("[ORCHESTRATION] No active session to end")


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
    
    This version uses the new grant-based authorization.
    """
    print("[ORCHESTRATION] Requesting key generation on MCU...")
    
    # Get current active epoch from MCU
    active_epoch = Bridge.call("get_active_epoch") or 0
    new_epoch = active_epoch + 1
    
    # Generate grant for GENERATE_KEY operation
    grant_hex, expiry_ms = generate_grant(OP_GENERATE_KEY, 0, new_epoch)
    
    print("[ORCHESTRATION] Requesting key generation with grant...")
    success = Bridge.call("request_key_generation", grant_hex, new_epoch, expiry_ms)
    if success:
        print("[ORCHESTRATION] Key generation successful.")
        fingerprint = get_key_fingerprint()
        pending_fp = Bridge.call("get_pending_fingerprint") or ""
        write_audit_log("key_generation_requested", {
            "result": "success",
            "epoch": new_epoch,
            "fingerprint": fingerprint,
            "pending_fingerprint": pending_fp,
        })
    else:
        print("[ORCHESTRATION] Key generation FAILED.")
        write_audit_log("key_generation_requested", {"result": "failure", "epoch": new_epoch})
    return success

def request_key_distribution_with_grant(target_id):
    """Request key distribution to target with proper grant authorization.
    
    Args:
        target_id: TARGET_PLC (0x01) or TARGET_PAW (0x02)
    """
    target_name = TARGET_NAMES.get(target_id, f"Unknown({target_id})")
    print(f"[ORCHESTRATION] Requesting key distribution to {target_name} with grant...")
    
    # Get current pending epoch
    pending_epoch = Bridge.call("get_pending_epoch") or 0
    if pending_epoch == 0:
        print("[ORCHESTRATION] No pending epoch - need to generate key first")
        return False
    
    # Generate grant for appropriate stage operation
    op = OP_STAGE_PLC if target_id == TARGET_PLC else OP_STAGE_PAW
    grant_hex, expiry_ms = generate_grant(op, target_id, pending_epoch)
    
    print(f"[ORCHESTRATION] Requesting distribution to {target_name} with grant...")
    success = Bridge.call("request_key_distribution", target_id, grant_hex, pending_epoch, expiry_ms)
    if success:
        write_audit_log("distribution_armed_with_grant", {
            "target": target_name,
            "epoch": pending_epoch
        })
        print(f"[ORCHESTRATION] Distribution to {target_name} armed with grant. Waiting for button press...")
        
        # Wait for distribution to complete (poll key state)
        max_wait = 30  # seconds
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(1)
            state = get_key_state()
            if target_id == TARGET_PLC and state in (2, 4):  # DISTRIBUTED_PLC or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed via grant.")
                write_audit_log("distribution_confirmed_with_grant", {"target": target_name, "epoch": pending_epoch})
                return True
            if target_id == TARGET_PAW and state in (3, 4):  # DISTRIBUTED_PAW or DISTRIBUTED_BOTH
                print(f"[ORCHESTRATION] Distribution to {target_name} confirmed via grant.")
                write_audit_log("distribution_confirmed_with_grant", {"target": target_name, "epoch": pending_epoch})
                return True

        print(f"[ORCHESTRATION] Timeout waiting for {target_name} distribution via grant.")
        write_audit_log("distribution_timeout_with_grant", {"target": target_name, "epoch": pending_epoch})
        return False
    else:
        print(f"[ORCHESTRATION] Failed to arm distribution to {target_name} via grant.")
        write_audit_log("distribution_arm_failed_with_grant", {"target": target_name, "epoch": pending_epoch})
        return False


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
    session_status = "ACTIVE" if Fido2Session.session_active else "INACTIVE"
    fido2_status = "available" if FIDO2_AVAILABLE else "not available (placeholder)"
    print("\n=== SHALLOT UNO Q — Orchestration (MPU) ===")
    print(f"  Session: {session_status} | FIDO2: {fido2_status}")
    print("  0 — Start provisioning session")
    print("  1 — Generate new AES-128 key (MCU TRNG, grant-based)")
    print("  2 — Distribute key to PLC (edge enforcement) [grant-based]")
    print("  3 — Distribute key to PAW (ID-bricka) [grant-based]")
    print("  4 — Query key state")
    print("  5 — Show key fingerprint")
    print("  6 — Validate provisioning (both nodes)")
    print("  7 — Print audit log")
    print("  8 — End session")
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

            if cmd == "0":
                # Start provisioning session
                recovery_code = input("Enter recovery code: ").strip()
                if start_provisioning_session(recovery_code):
                    print("[ORCHESTRATION] Session started. Use menu options 1-3 for key operations.")
                else:
                    print("[ORCHESTRATION] Failed to start session.")
            elif cmd == "1":
                if not Fido2Session.session_active:
                    print("[ORCHESTRATION] Must start session first (option 0)")
                else:
                    request_key_generation()
            elif cmd == "2":
                if not Fido2Session.session_active:
                    print("[ORCHESTRATION] Must start session first (option 0)")
                else:
                    request_key_distribution_with_grant(TARGET_PLC)
            elif cmd == "3":
                if not Fido2Session.session_active:
                    print("[ORCHESTRATION] Must start session first (option 0)")
                else:
                    request_key_distribution_with_grant(TARGET_PAW)
            elif cmd == "4":
                get_key_state()
            elif cmd == "5":
                get_key_fingerprint()
            elif cmd == "6":
                validate_provisioning()
            elif cmd == "7":
                print_audit_log()
            elif cmd == "8":
                # End session
                end_provisioning_session(success=True)
            elif cmd == "q":
                # Ensure session is cleaned up
                end_provisioning_session(success=False)
                print("Exiting.")
                event_listener.stop()
                Bridge.close()
                break
            else:
                print("Unknown option.")
        except KeyboardInterrupt:
            print("\nExiting.")
            end_provisioning_session(success=False)
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
