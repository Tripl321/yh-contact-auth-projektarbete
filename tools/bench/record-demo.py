"""Scripted demo recording: DENIED + GRANTED (TEST-ONLY bench).

Runs on the bench host (serial ports are local there), via stdin pipe —
no files are written on the host:
  ssh <ssh-alias> "python3 -" < tools/bench/record-demo.py | \
    tee demo-recording-$(date -u +%Y%m%dT%H%M%SZ).txt

Mode as argument after '-': 'act1' = only Act 1 (DENIED), 'act2' = only
Act 2 (GRANTED), no argument = both acts. An act that matches the
expectation ends with an ASCII verdict (FAILED/AUTHENTICATED).

Flow (all with fixed test vectors, never secrets):
  0. Readiness: waits for loop lines from both (proof both are alive).
  1. Provisions DEN (test key) + delivers a signed empty test list.
  2. Act 1: PAW with WRONG key -> DENIED (fail closed), PAW FAILED.
     Watch the e-paper: should show FAILED (X + word).
  3. Act 2: PAW with RIGHT key -> AUTHENTICATED (code 0).
     Watch the e-paper: should show AUTHENTICATED (checkmark + word).
All output is the transcript. Exit 0 = every executed act as expected.

Requires: DEN with pinned TEST-ONLY trust root + PAW with panel drivers
(see flash-log-den-paw-20260923.md). Pyserial on the host, nothing else.
"""

import hashlib
import sys
import time
import zlib

import serial

RIGHT_KEY = bytes(range(16))
WRONG_KEY = bytes(range(16, 32))

# Signed empty list (TEST-ONLY): version(1)+issuer(16)+count(0)+sig(64).
# Valid only against a DEN build with the pinned TEST-ONLY trust root.
EMPTY_SIGNED_LIST = bytes.fromhex(
    "015348414c4c4f542d415554480000000000"
    "231c0719bf0780950b819d2c9dcfc30db9432e3535aef58b2d00f8e260e"
    "560361c135d4fe40a1ddbb220c513052f3911fe77aabf53f3eccb6ac2b"
    "af4bf4a810f"
)

BANNER_FAILED = (
    "████ .██. ███ █... ████ ███.",
    "█... █..█ .█. █... █... █..█",
    "███. ████ .█. █... ███. █..█",
    "█... █..█ .█. █... █... █..█",
    "█... █..█ ███ ████ ████ ███.",
)

BANNER_AUTHENTICATED = (
    ".██. █..█ █████ █..█ ████ █...█ █████ ███ .███ .██. █████ ████ ███.",
    "█..█ █..█ ..█.. █..█ █... ██..█ ..█.. .█. █... █..█ ..█.. █... █..█",
    "████ █..█ ..█.. ████ ███. █.█.█ ..█.. .█. █... ████ ..█.. ███. █..█",
    "█..█ █..█ ..█.. █..█ █... █..██ ..█.. .█. █... █..█ ..█.. █... █..█",
    "█..█ .██. ..█.. █..█ ████ █...█ ..█.. ███ .███ █..█ ..█.. ████ ███.",
)


def fp(key):
    return hashlib.sha256(bytes(key)).digest()[:4]


def read_exact(ser, n, deadline):
    out = bytearray()
    while len(out) < n:
        if deadline - time.monotonic() <= 0:
            raise RuntimeError("timeout")
        chunk = ser.read(n - len(out))
        if not chunk:
            raise RuntimeError("timeout")
        out += chunk
    return bytes(out)


def sync(ser, want, deadline):
    while True:
        if deadline - time.monotonic() <= 0:
            raise RuntimeError("timeout")
        chunk = ser.read(1)
        if not chunk:
            raise RuntimeError("timeout")
        if chunk[0] in want:
            return chunk[0]


def keydata(key):
    return bytes([0xA3, 16]) + bytes(key) + zlib.crc32(bytes(key)).to_bytes(4, "big")


def provision(ser, target_code, key, name):
    deadline = time.monotonic() + 12.0
    ser.write(bytes([0xA1, target_code]))
    sync(ser, (0xA2,), deadline)
    read_exact(ser, 4, deadline)
    ser.write(keydata(key))
    first = sync(ser, (0xA4, 0xA5), deadline)
    if first == 0xA5:
        raise RuntimeError("%s answered ERROR" % name)
    rest = read_exact(ser, 4, deadline)
    if bytes(rest) != fp(key):
        raise RuntimeError("%s fingerprint mismatch" % name)
    print("  %s provisioned fp=%s" % (name, fp(key).hex()), flush=True)


def wait_loop(ser, needle, tag, timeout=20.0):
    print("waiting for %s loop (max %d s)..." % (tag, timeout), flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = ser.readline()
        if raw and needle in raw:
            print("%s loop alive" % tag, flush=True)
            return
    raise RuntimeError("%s loop never seen" % tag)


def observe(den, paw, seconds, tag):
    granted = denied = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for label, ser in (("DEN", den), ("PAW", paw)):
            try:
                raw = ser.readline()
            except Exception as e:
                print("[%s] READ ERROR %s" % (label, e), flush=True)
                continue
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip()
            print("[%s] %s" % (label, line), flush=True)
            if "code 0" in line:
                granted += 1
            if "code 5" in line or "code 1" in line or "DEN denied" in line:
                denied += 1
    print("  [%s] code 0: %d, denied: %d" % (tag, granted, denied), flush=True)
    return granted, denied


def act1(den, paw):
    print("--- ACT 1: wrong key -> must be DENIED (fail closed) ---", flush=True)
    provision(paw, 0x02, WRONG_KEY, "PAW(wrong)")
    den.reset_input_buffer()
    paw.reset_input_buffer()
    time.sleep(4.0)  # let the first post-reprovision session pass
    print("  Watch the e-paper: should show FAILED.", flush=True)
    g, d = observe(den, paw, 14, "ACT1")
    ok = g == 0 and d >= 1
    print(
        "  ACT 1 VERDICT: %s" % ("DENIED (expected)" if ok else "DEVIATION!"),
        flush=True,
    )
    if ok:
        print("\n" + "\n".join(BANNER_FAILED) + "\n", flush=True)
    return ok


def act2(den, paw):
    print("--- ACT 2: right key -> must be GRANTED ---", flush=True)
    provision(paw, 0x02, RIGHT_KEY, "PAW(right)")
    den.reset_input_buffer()
    paw.reset_input_buffer()
    time.sleep(4.0)  # let the first post-reprovision session pass
    print("  Watch the e-paper: should show AUTHENTICATED.", flush=True)
    g, d = observe(den, paw, 14, "ACT2")
    ok = g >= 1
    print(
        "  ACT 2 VERDICT: %s" % ("GRANTED (expected)" if ok else "DEVIATION!"),
        flush=True,
    )
    if ok:
        print("\n" + "\n".join(BANNER_AUTHENTICATED) + "\n", flush=True)
    return ok


MODES = ("act1", "act2", "all")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode not in MODES:
        print("usage: python3 - [act1|act2]", file=sys.stderr)
        sys.exit(2)
    print(
        "=== SHALLOT DEMO RECORDING (TEST-ONLY bench, MVP: DENIED + GRANTED) ===",
        flush=True,
    )
    den = serial.Serial(
        port="/dev/ttyACM0", baudrate=115200, timeout=1.0, write_timeout=2.0
    )
    paw = serial.Serial(
        port="/dev/ttyACM1", baudrate=115200, timeout=1.0, write_timeout=2.0
    )
    wait_loop(den, b"[DEN]", "DEN")
    wait_loop(paw, b"PRO-84", "PAW")
    den.reset_input_buffer()
    paw.reset_input_buffer()

    print("--- Baseline: provision DEN + signed empty list ---", flush=True)
    provision(den, 0x01, RIGHT_KEY, "DEN")
    den.write(bytes([0xA6]) + EMPTY_SIGNED_LIST)
    print("  blocklist sent", flush=True)

    ok = {}
    if mode in ("all", "act1"):
        ok["act1"] = act1(den, paw)
    if mode in ("all", "act2"):
        ok["act2"] = act2(den, paw)

    parts = ["%s=%s" % (k, "OK" if v else "DEVIATION") for k, v in ok.items()]
    print("=== END: %s ===" % " ".join(parts), flush=True)
    den.close()
    paw.close()
    if not all(ok.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
