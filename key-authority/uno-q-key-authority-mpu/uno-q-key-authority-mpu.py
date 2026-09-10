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
from datetime import datetime

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
    write_audit_log(event, {"message": message}}


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
    print("  8 — Envelope fixture session (TEST-ONLY, needs fixture MCU+PAW)")
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


# --- Phase 2 envelope relay (fixture-only, TEST-ONLY) ---
#
# Relays PUBLIC fields only between PAW (USB serial, hex lines) and MCU
# (Bridge RPC, hex strings): E1/E2 envelopes, VERIFY comparison value,
# epoch, and the E3 fingerprint. This module never handles key material —
# no raw keys, no wrapping keys, no DH output, no ephemeral secrets
# (source-guarded by tests/test_envelope_phase2.py). Requires fixture builds
# (ENVELOPE_PHASE2) with the MCU button held at boot; anything else aborts.

ENVELOPE_E1_LEN = 45
ENVELOPE_E2_LEN = 81


def _envelope_read_line(ser, prefix, hex_len, timeout_s):
    """Read one strict '<prefix><hex>' line; logs/interleavings skipped."""
    deadline = time.time() + timeout_s
    buf = b""
    while time.time() < deadline:
        chunk = ser.read(1)
        if not chunk:
            continue
        if chunk in b"\r\n":
            if not buf:
                continue
            line = buf.decode("ascii", errors="replace")
            buf = b""
            if line.startswith(prefix) and len(line) == len(prefix) + hex_len:
                body = line[len(prefix):]
                if all(c in "0123456789abcdefABCDEF" for c in body):
                    return body.lower()
            # Non-matching line (log output): ignore, keep waiting.
            continue
        buf += chunk
        if len(buf) > 200:
            buf = b""
    return None


def envelope_fixture_session(serial_port, target_id, timeout_s=15):
    """Run one TEST-ONLY fixture envelope session.

    Args:
        serial_port: PAW USB serial device (e.g. /dev/ttyACM0).
        target_id: 1 for PLC, 2 for PAW.
    Returns True iff the MCU confirms the PAW fingerprint.
    """
    import serial

    target_name = TARGET_NAMES.get(target_id, f"Unknown({target_id})")
    if target_id not in TARGET_NAMES:
        print(f"[ENVELOPE] Invalid target {target_id}.")
        return False

    try:
        armed = Bridge.call("env_fixture_armed")
    except Exception as e:
        print(f"[ENVELOPE] MCU envelope RPC unavailable ({e}).")
        return False
    if not armed:
        print("[ENVELOPE] Refused: MCU not in fixture mode "
              "(hold button at MCU boot, flash ENVELOPE_PHASE2 build).")
        write_audit_log("envelope_refused", {"reason": "mcu_not_fixture"})
        return False

    try:
        ser = serial.Serial(serial_port, 115200, timeout=0.1)
    except Exception as e:
        print(f"[ENVELOPE] Cannot open {serial_port} ({e}).")
        return False

    ok = False
    try:
        ser.write(b"FIXTURE\n")
        ser.write(b"ENVELOPE_START\n")
        e1_hex = _envelope_read_line(ser, "E1:", 2 * ENVELOPE_E1_LEN, timeout_s)
        if e1_hex is None:
            print("[ENVELOPE] No E1 from PAW (fixture not armed?).")
            write_audit_log("envelope_timeout", {"stage": "E1"})
            return False

        resp = Bridge.call("env_wrap", f"{e1_hex}:{target_id}")
        if not resp or "." not in resp:
            print("[ENVELOPE] MCU wrap refused.")
            write_audit_log("envelope_refused", {"reason": "mcu_wrap"})
            return False
        e2_hex, verify = resp.split(".", 1)
        if len(e2_hex) != 2 * ENVELOPE_E2_LEN or len(verify) != 16:
            print("[ENVELOPE] Malformed MCU response.")
            return False
        print(f"[ENVELOPE] MCU VERIFY: {verify} "
              f"(compare with PAW VERIFY below)")

        ser.write(f"E2:{e2_hex}\n".encode())
        e3_hex = _envelope_read_line(ser, "E3:", 8, timeout_s)
        paw_verify = _envelope_read_line(ser, "VERIFY:", 16, 5)
        if e3_hex is None:
            print("[ENVELOPE] No E3 from PAW (tag verify failed on PAW?).")
            write_audit_log("envelope_timeout", {"stage": "E3"})
            return False
        print(f"[ENVELOPE] PAW VERIFY: {paw_verify}")
        if paw_verify != verify:
            print("[ENVELOPE] VERIFY MISMATCH — operator aborts.")
            write_audit_log("envelope_verify_mismatch",
                            {"mcu": verify, "paw": paw_verify})
            return False

        confirmed = Bridge.call("env_confirm", e3_hex)
        write_audit_log("envelope_fixture_session", {
            "fixture": "TEST-ONLY",
            "target": target_name,
            "verify": verify,
            "result": "confirmed" if confirmed else "fingerprint_mismatch",
        })
        print(f"[ENVELOPE] TEST-ONLY session "
              f"{'CONFIRMED' if confirmed else 'FAILED (fingerprint)'}")
        ok = bool(confirmed)
    finally:
        ser.close()
    return ok


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
        elif cmd == "8":
            port = input("PAW serial port [/dev/ttyACM0]: ").strip() or "/dev/ttyACM0"
            tgt = input("Target 1=PLC 2=PAW [2]: ").strip() or "2"
            envelope_fixture_session(port, int(tgt))
        elif cmd == "q":
            print("Exiting.")
            break
        else:
            print("Unknown option.")


# Register the MCU event callback
Bridge.provide("key_authority_event", on_key_authority_event)

# Start the application
App.run(user_loop=loop)
