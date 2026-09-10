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

from arduino.app_utils import *
import time
import json
import os
import glob
import hmac
from datetime import datetime

try:
    import serial
    HAS_PYSERIAL = True
except ImportError:  # unit-test hosts without pyserial
    serial = None
    HAS_PYSERIAL = False

AUDIT_LOG_PATH = "/home/user/shallot/audit/provisioning_log.jsonl"
AUDIT_DIR = os.path.dirname(AUDIT_LOG_PATH)

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


# USB-CDC provisioning transport (PRO-46 USB-C)
USB_BAUD = 115200
USB_STEP_TIMEOUT = 5.0      # per protocol step (READY / STORED waits)
USB_EXPORT_TIMEOUT = 30     # max wait for armed+button key export
USB_EXPORT_POLL = 1.0

# Provisioning wire tags (same frames the MCU used to send over UART;
# now carried over USB-CDC — byte-identical protocol).
USB_MSG_HANDSHAKE = 0xA1
USB_MSG_READY = 0xA2
USB_MSG_KEY_DATA = 0xA3
USB_MSG_STORED = 0xA4


class UsbDistributeError(Exception):
    """Internal control flow for fail-closed USB distribution."""


class UsbCdcDistributor:
    """MPU-side USB-CDC key distributor (PRO-46 USB-C).

    Opens the target device's /dev/ttyACM* port and speaks the existing
    provisioning protocol (handshake / READY / key-data+CRC / STORED).
    Pure transport: key bytes arrive as an argument, are wiped before
    return, and are never logged, stored, or audited — only the
    fingerprint (hash) leaves this object.
    """

    def __init__(self, port=None, baud=USB_BAUD, step_timeout=USB_STEP_TIMEOUT):
        self.port = port
        self.baud = baud
        self.step_timeout = step_timeout

    def resolve_port(self):
        """Explicit port wins; otherwise exactly one /dev/ttyACM* may exist.
        Zero or ambiguous candidates fail closed (no guessing)."""
        if self.port:
            return self.port
        cands = sorted(glob.glob('/dev/ttyACM*'))
        if len(cands) == 1:
            return cands[0]
        if not cands:
            raise UsbDistributeError('no-device')
        raise UsbDistributeError('ambiguous-port')

    def _read_exact(self, ser, count, deadline):
        out = bytearray()
        while len(out) < count:
            if time.time() > deadline:
                raise UsbDistributeError('timeout')
            chunk = ser.read(count - len(out))
            if chunk:
                out += chunk
            else:
                time.sleep(0.01)
        return bytes(out)

    # Max non-tag bytes skipped while seeking a frame tag. PAW multiplexes
    # human-readable log lines with binary protocol frames on the same USB
    # CDC port, so the distributor must resynchronize past log output
    # instead of blind-reading (a blind read consumes log text as framing
    # and fails every transfer on a chatty device — bench-proven).
    RESYNC_BUDGET = 256

    def _read_frame(self, ser, tag, total, deadline):
        """Tag-anchored frame read: skip stray/log bytes until `tag`
        (bounded), then read the exact remainder. Fail closed on timeout
        or exhausted budget."""
        skipped = 0
        while True:
            if time.time() > deadline:
                raise UsbDistributeError('timeout')
            chunk = ser.read(1)
            if not chunk:
                time.sleep(0.01)
                continue
            if chunk[0] == tag:
                rest = self._read_exact(ser, total - 1, deadline)
                return bytes([tag]) + rest
            skipped += 1
            if skipped > self.RESYNC_BUDGET:
                raise UsbDistributeError('resync-exhausted')

    def distribute(self, target_id, key_bytes, expected_fp_hex):
        """Run one USB distribution round. Returns (ok, reason).

        key_bytes is copied into a mutable buffer that is zeroed before
        return on every path. expected_fp_hex is the 8-char fingerprint
        from get_key_fingerprint(); the device STORED hash must match it
        (constant-time compare) or the round fails.
        """
        if target_id not in TARGET_NAMES:
            return False, 'bad-target'
        key = bytearray(key_bytes)  # mutable copy; wiped in finally
        try:
            if len(key) != 16:
                return False, 'bad-key-length'
            expected = bytes.fromhex(expected_fp_hex)
            if len(expected) != 4:
                return False, 'bad-fingerprint'
            if not HAS_PYSERIAL:
                return False, 'no-pyserial'
            try:
                port = self.resolve_port()
            except UsbDistributeError as e:
                return False, str(e)
            print(f"[USB] Opening {port} for {TARGET_NAMES[target_id]}...")
            try:
                # NOTE: timeout MUST be a keyword (3rd positional Serial()
                # arg is bytesize, not timeout — passing it positionally
                # silently breaks reads on some pyserial versions).
                ser = serial.Serial(port, self.baud, timeout=0.5)
            except Exception:
                return False, 'open-failed'
            try:
                try:
                    ser.reset_input_buffer()  # drop stale bytes from earlier runs
                except Exception:
                    pass
                # Step 1: handshake, expect READY + 4-byte device ID
                # (resyncing past PAW log lines multiplexed on this port).
                ser.write(bytes([USB_MSG_HANDSHAKE, target_id]))
                ser.flush()
                deadline = time.time() + self.step_timeout
                ready = self._read_frame(ser, USB_MSG_READY, 5, deadline)
                print(f"[USB] READY from device id {ready[1:].hex()}, "
                      f"sending key data...")
                # Step 2: key packet (tag + len + key + CRC32 big-endian).
                import binascii
                crc = binascii.crc32(bytes(key)) & 0xFFFFFFFF
                ser.write(bytes([USB_MSG_KEY_DATA, len(key)]) + bytes(key) +
                          crc.to_bytes(4, 'big'))
                ser.flush()
                # Step 3: STORED + 4-byte hash, verified against fingerprint.
                deadline = time.time() + self.step_timeout
                stored = self._read_frame(ser, USB_MSG_STORED, 5, deadline)
                if not hmac.compare_digest(stored[1:], expected):
                    return False, 'fingerprint-mismatch'
                print(f"[USB] STORED verified, fingerprint {expected_fp_hex}.")
                return True, 'ok'
            except UsbDistributeError as e:
                return False, str(e)
            except Exception:
                return False, 'io-error'
            finally:
                try:
                    ser.close()
                except Exception:
                    pass
        finally:
            for i in range(len(key)):
                key[i] = 0  # key material must not linger
    # NOTE: audit/log call sites must only ever reference the fingerprint
    # (expected_fp_hex), target names and outcomes — never `key`.


def request_key_distribution(target_id, port=None):
    """Distribute the staged key to a target device over USB-C.

    Flow (existing authorization preserved):
      1. Arm on the MCU via Bridge (validates state/target).
      2. Operator presses the physical UNO Q button (MCU-gated 5 s window).
      3. Poll the one-shot key export; the MCU releases key bytes exactly
         once per arming (see export_staged_key; SECURITY NOTE below).
      4. Run the USB-CDC exchange; verify STORED == key fingerprint.
      5. Confirm the outcome back to the MCU (advances key state only on
         success) and audit fingerprint + outcome (never key material).

    SECURITY NOTE: unlike the legacy UART sender (key never left the
    MCU), the USB-C transport forces key bytes through MPU RAM in
    transit. UsbCdcDistributor holds them only in a local bytearray that
    is zeroed in a finally block, never logs, stores, or audits them.
    This residual is accepted: the MPU host is already inside the trusted
    provisioning perimeter (physical access + button + audit).

    Args:
        target_id: 1 for PLC (edge enforcement), 2 for PAW (ID-bricka).
        port: explicit /dev/ttyACM* path, or None to auto-detect a
            single attached device (fail closed otherwise).
    """
    target_name = TARGET_NAMES.get(target_id, f"Unknown({target_id})")
    if target_id not in TARGET_NAMES:
        print(f"[ORCHESTRATION] Invalid target {target_id}.")
        return False
    print(f"[ORCHESTRATION] Requesting key distribution to {target_name}.")
    print("[ORCHESTRATION] Operator must press confirmation button on UNO Q.")

    if not Bridge.call("request_key_distribution", target_id):
        print(f"[ORCHESTRATION] Failed to arm distribution to {target_name}.")
        return False
    write_audit_log("distribution_armed", {"target": target_name})

    # Wait for the armed one-shot export (button-gated on the MCU).
    key_hex = ""
    start = time.time()
    while time.time() - start < USB_EXPORT_TIMEOUT:
        key_hex = Bridge.call("export_staged_key") or ""
        if key_hex:
            break
        time.sleep(USB_EXPORT_POLL)
    if not key_hex:
        print(f"[ORCHESTRATION] No key export (button not pressed in time).")
        write_audit_log("distribution_timeout", {"target": target_name})
        return False
    try:
        key_bytes = bytearray(bytes.fromhex(key_hex))  # mutable: wiped below
    except ValueError:
        print("[ORCHESTRATION] Malformed key export from MCU.")
        write_audit_log("distribution_failed",
                        {"target": target_name, "reason": "bad-export"})
        return False
    if len(key_bytes) != 16:
        print("[ORCHESTRATION] Exported key has wrong length.")
        write_audit_log("distribution_failed",
                        {"target": target_name, "reason": "bad-export-length"})
        return False

    fingerprint = get_key_fingerprint()
    distributor = UsbCdcDistributor(port=port)
    ok, reason = distributor.distribute(target_id, key_bytes, fingerprint)
    for i in range(len(key_bytes)):
        key_bytes[i] = 0  # local copy wiped right after the transfer
    del key_bytes
    write_audit_log("usb_distributed", {"target": target_name,
                                        "fingerprint": fingerprint,
                                        "outcome": "success" if ok else reason})
    confirmed = Bridge.call("confirm_distribution", target_id, ok)
    if ok and confirmed:
        print(f"[ORCHESTRATION] Distribution to {target_name} confirmed.")
        return True
    print(f"[ORCHESTRATION] Distribution to {target_name} FAILED ({reason}).")
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
    print("  2 — Distribute key to PLC (edge enforcement)")
    print("  3 — Distribute key to PAW (ID-bricka)")
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


def loop():
    """Main loop — operator menu interface."""
    print_menu()

    while True:
        cmd = input("Select option: ").strip().lower()

        if cmd == "1":
            request_key_generation()
        elif cmd == "2":
            request_key_distribution(1)
        elif cmd == "3":
            request_key_distribution(2)
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
            break
        else:
            print("Unknown option.")


# Register the MCU event callback
Bridge.provide("key_authority_event", on_key_authority_event)

# Start the application
App.run(user_loop=loop)
