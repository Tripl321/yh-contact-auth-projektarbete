"""Manusstyrd demo-inspelning: NEKAD + ÅTKOMST (TEST-ONLY bänk).

Körs på bänkvärden (serieportar lokala där), via stdin-pipe — inga filer
skrivs på värden:
  ssh <ssh-alias> "python3 -" < tools/bench/record-demo.py | \
    tee demo-inspelning-$(date -u +%Y%m%dT%H%M%SZ).txt

Läge som argument efter '-': 'akt1' = endast Akt 1 (NEKAD), 'akt2' =
endast Akt 2 (ÅTKOMST), inget argument = båda akterna. En akt som matchar
förväntningen avslutas med ASCII-verdict (FAILED/AUTHENTICATED).

Flöde (allt med fasta testvektorer, aldrig hemligheter):
  0. Beredskap: väntar loop-rader från båda (bevis att båda lever).
  1. Provisionerar DEN (testnyckel) + levererar signerad tom testlista.
  2. Akt 1: PAW med FEL nyckel -> DENIED (fail closed), PAW FAILED.
     Titta på e-paper: ska visa FAILED (X + ord).
  3. Akt 2: PAW med RÄTT nyckel -> AUTHENTICATED (code 0).
     Titta på e-paper: ska visa AUTHENTICATED (bock + ord).
All output = transcriptet. Exit 0 = körda akter som förväntat.

Kräver: DEN med pinnad TEST-ONLY trust root + PAW med panel-drivers
(se flash-log-den-paw-20260923.md). Pyserial på värden, inget annat.
"""

import hashlib
import sys
import time
import zlib

import serial

RIGHT_KEY = bytes(range(16))
WRONG_KEY = bytes(range(16, 32))

# Tom signerad lista (TEST-ONLY): version(1)+issuer(16)+count(0)+sig(64).
# Gäller endast mot DEN-bygge med pinnad TEST-ONLY trust root.
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
        raise RuntimeError("%s svarade ERROR" % name)
    rest = read_exact(ser, 4, deadline)
    if bytes(rest) != fp(key):
        raise RuntimeError("%s fingerprint-matchning" % name)
    print("  %s provisionerad fp=%s" % (name, fp(key).hex()), flush=True)


def wait_loop(ser, needle, tag, timeout=20.0):
    print("väntar %s-loop (max %d s)..." % (tag, timeout), flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = ser.readline()
        if raw and needle in raw:
            print("%s-loop lever" % tag, flush=True)
            return
    raise RuntimeError("%s-loopen sågs aldrig" % tag)


def observe(den, paw, seconds, tag):
    granted = denied = 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for label, ser in (("DEN", den), ("PAW", paw)):
            try:
                raw = ser.readline()
            except Exception as e:
                print("[%s] LÄSFEL %s" % (label, e), flush=True)
                continue
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip()
            print("[%s] %s" % (label, line), flush=True)
            if "code 0" in line:
                granted += 1
            if "code 5" in line or "code 1" in line or "DEN denied" in line:
                denied += 1
    print("  [%s] code 0: %d, nekade: %d" % (tag, granted, denied), flush=True)
    return granted, denied


def akt1(den, paw):
    print("--- AKT 1: fel nyckel -> ska NEKAS (fail closed) ---", flush=True)
    provision(paw, 0x02, WRONG_KEY, "PAW(fel)")
    den.reset_input_buffer()
    paw.reset_input_buffer()
    time.sleep(4.0)  # låt första sessionen efter omprovisionering passera
    print("  Titta på e-paper: ska visa FAILED.", flush=True)
    g, d = observe(den, paw, 14, "AKT1")
    ok = g == 0 and d >= 1
    print(
        "  AKT 1 VERDIKT: %s" % ("NEKAD (förväntat)" if ok else "AVVIKELSE!"),
        flush=True,
    )
    if ok:
        print("\n" + "\n".join(BANNER_FAILED) + "\n", flush=True)
    return ok


def akt2(den, paw):
    print("--- AKT 2: rätt nyckel -> ska BEVILJAS ---", flush=True)
    provision(paw, 0x02, RIGHT_KEY, "PAW(rätt)")
    den.reset_input_buffer()
    paw.reset_input_buffer()
    time.sleep(4.0)  # låt första sessionen efter omprovisionering passera
    print("  Titta på e-paper: ska visa AUTHENTICATED.", flush=True)
    g, d = observe(den, paw, 14, "AKT2")
    ok = g >= 1
    print(
        "  AKT 2 VERDIKT: %s" % ("ÅTKOMST (förväntat)" if ok else "AVVIKELSE!"),
        flush=True,
    )
    if ok:
        print("\n" + "\n".join(BANNER_AUTHENTICATED) + "\n", flush=True)
    return ok


MODES = ("akt1", "akt2", "alla")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "alla"
    if mode not in MODES:
        print("användning: python3 - [akt1|akt2]", file=sys.stderr)
        sys.exit(2)
    print(
        "=== SHALLOT DEMO-INSPELNING (TEST-ONLY bänk, MVP: NEKAD + ÅTKOMST) ===",
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

    print("--- Baslinje: provisionera DEN + signerad tom lista ---", flush=True)
    provision(den, 0x01, RIGHT_KEY, "DEN")
    den.write(bytes([0xA6]) + EMPTY_SIGNED_LIST)
    print("  blocklista sänd", flush=True)

    ok = {}
    if mode in ("alla", "akt1"):
        ok["akt1"] = akt1(den, paw)
    if mode in ("alla", "akt2"):
        ok["akt2"] = akt2(den, paw)

    parts = ["%s=%s" % (k, "OK" if v else "AVVIKELSE") for k, v in ok.items()]
    print("=== SLUT: %s ===" % " ".join(parts), flush=True)
    den.close()
    paw.close()
    if not all(ok.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
