#!/usr/bin/env python3
"""
SHALLOT — USB key injection helper
Injects a single shared 16-byte AES key into both PLC and PAW over USB,
then prints both fingerprints so you can verify they match before running
the LoRa challenge-response.

Usage:
  python3 inject_key.py [hexkey]
    [hexkey]  optional 32-char hex key; if omitted, a random one is generated.

Requires: pip3 install pyserial
"""
import sys
import re
import time
import secrets
import hashlib

import serial

PLC_PORT = "/dev/cu.usbmodem11101"
PAW_PORT = "/dev/cu.usbmodem101"
BAUD = 115200


def parse_hexkey(s):
    s = s.strip()
    if len(s) != 32:
        raise ValueError("hex key must be exactly 32 hex chars (16 bytes)")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("hex key contains non-hex characters")


def sha256_fingerprint(key: bytes) -> str:
    digest = hashlib.sha256(key).digest()
    return digest[:4].hex().upper()


def open_port(port, attempts=10):
    for i in range(attempts):
        try:
            s = serial.Serial(port, BAUD, timeout=1.0)
            s.reset_input_buffer()
            return s
        except Exception as e:
            time.sleep(0.5)
    raise RuntimeError(f"could not open {port}: {e}")


def inject(port, keyhex: str, wait_banner: str = None) -> str:
    s = open_port(port)
    try:
        # Optionally wait briefly for the setup banner to land the key in the
        # one-shot setup window; even if missed, loop-based injection accepts
        # the key afterwards, so always send regardless.
        if wait_banner:
            deadline = time.time() + 2.0
            buf = b""
            while time.time() < deadline:
                chunk = s.read(128)
                if chunk:
                    buf += chunk
                    if wait_banner.encode() in buf:
                        break
                time.sleep(0.05)
        line = ("K " + keyhex + "\n").encode()
        s.write(line)
        s.flush()
        # Wait for the '[USB-KEY] Key stored. Fingerprint:' acknowledgment
        deadline = time.time() + 15
        buf = b""
        fprint = None
        while time.time() < deadline:
            chunk = s.read(256)
            if chunk:
                buf += chunk
                text = buf.decode(errors="replace")
                # Fingerprint is 8 hex chars after the marker
                m = re.search(r"\[USB-KEY\] Key stored\. Fingerprint: ([0-9A-Fa-f]{8})", text)
                if m:
                    fprint = m.group(1).upper()
                    break
        return fprint
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    if len(sys.argv) > 1:
        keyhex = parse_hexkey(sys.argv[1]).hex()
    else:
        key = secrets.token_bytes(16)
        keyhex = key.hex()

    keybytes = bytes.fromhex(keyhex)
    print(f"Shared key: {keyhex}")
    print(f"Fingerprint (SHA256[:4]): {sha256_fingerprint(keybytes)}")
    print()

    print(f"Injecting into PLC ({PLC_PORT})...")
    plc_fp = inject(PLC_PORT, keyhex)
    print(f"  PLC fingerprint: {plc_fp}")

    print(f"Injecting into PAW ({PAW_PORT})...")
    paw_fp = inject(PAW_PORT, keyhex,
                    wait_banner="[USB-KEY] Waiting for key over USB...")
    print(f"  PAW fingerprint: {paw_fp}")

    print()
    if plc_fp and paw_fp and plc_fp == paw_fp:
        print("MATCH: both nodes hold the same key. Ready for LoRa test.")
    else:
        print("NOTE: fingerprints differ or missing — check that both nodes")
        print("      were powered and listening, then re-run.")


if __name__ == "__main__":
    main()
