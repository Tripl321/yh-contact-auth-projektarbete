"""`shallot doctor` — miljökontroll utan hårdvarupåverkan.

Kontrollerar verktyg, repo-kataloger, serieportar (skrivfritt) och
flaggar osäkra build-konfigurationer. Exit 0 = allt OK, 1 = saknade
beroenden eller osäkra konfigurationer hittades.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

from shallot_cli import serial_adapters

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

REQUIRED_FILES = [
    "plc/den-main/den-main.ino",
    "id-kort/paw-main/paw-main.ino",
    "key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino",
    "libraries/DenUartProtocol/src/DenUartProtocol.h",
    "tests/test_pro87_uart.py",
]

FIRMWARE_GUARD_FILES = [
    "plc/den-main/den-main.ino",
    "id-kort/paw-main/paw-main.ino",
    "plc/edge-challenge-response/edge-challenge-response.ino",
]

#: Mönster som aldrig får förekomma ogardat i aktiv firmware.
#: Arkivet (id-kort/archive/) är historik och skannas inte.
DEVKEY_PATTERNS = ("DEN_DEV_KEY", "#warning", "DEVELOPMENT-ONLY", "MASTER_KEY")

_OPT_IN = "EDGE_ALLOW_DEV_KEY"
_OPEN = re.compile(r"^\s*#\s*(?:ifndef\s+%s\b|if\s+!defined\s*\(\s*%s\s*\))" % (_OPT_IN, _OPT_IN))
_IF = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b")
_ELSE = re.compile(r"^\s*#\s*(?:else|elif)\b")
_ENDIF = re.compile(r"^\s*#\s*endif\b")
_ERROR = re.compile(r"^\s*#\s*error\b")
_DEFINE = re.compile(r"^\s*#\s*define\s+%s\b" % _OPT_IN)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _has_fail_closed_opt_in(text: str) -> bool:
    """True endast vid ett verkligt fail-closed preprocessor-guard.

    Kräver `#ifndef EDGE_ALLOW_DEV_KEY` (eller `#if !defined(...)`) med
    `#error` före matchande `#endif`, på djup 0 och före ev. `#else` —
    dvs. utan flaggan stoppas bygget ovillkorligt. Guardet måste stå på
    toppnivå: ett guard nästlat i ett annat villkor utvärderas kanske
    aldrig och godkänns inte. En förekomst i kommentar/sträng räcker
    inte (direktiv måste stå vid radstart), och en egen `#define` av
    flaggan underkänner (opt-in måste komma från byggflaggan -D,
    annars är guardet teater).
    """
    lines = _BLOCK_COMMENT.sub("", text).splitlines()
    if any(_DEFINE.match(l) for l in lines):
        return False
    outer = 0  # global häckningsnivå — openern måste stå på toppnivå
    for i, line in enumerate(lines):
        if _OPEN.match(line) and outer == 0:
            depth = 0
            else_seen = False
            for later in lines[i + 1:]:
                if _IF.match(later):
                    depth += 1
                elif _ENDIF.match(later):
                    if depth == 0:
                        break  # guardet stängt utan #error
                    depth -= 1
                elif depth == 0 and _ELSE.match(later):
                    else_seen = True
                elif _ERROR.match(later):
                    if depth == 0 and not else_seen:
                        return True
        if _IF.match(line):
            outer += 1
        elif _ENDIF.match(line):
            outer = max(0, outer - 1)
    return False


def _tool_version(cmd: list[str]) -> str | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    first = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    return first[0][:100] if first else "ok (ingen versionssträng)"


def _find_upload_scripts() -> list[str]:
    """Skript som implicit kan ladda upp firmware (får aldrig köras av CLI:t)."""
    hits = []
    for pattern in ("*.sh", "*.ps1"):
        for path in sorted(REPO_ROOT.rglob(pattern)):
            if ".git/" in path.as_posix():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if "--target upload" in text or "upload_protocol" in text or \
                    ("pio run" in text and "upload" in text):
                hits.append(path.relative_to(REPO_ROOT).as_posix())
    return hits


def _firmware_devkey_guard() -> list[str]:
    """Firmware får inte innehålla hårdkodade utvecklingsnycklar.

    Edge-responserns TEST-ONLY-nyckel accepteras endast bakom ett
    verkligt fail-closed preprocessor-guard (utan flaggan stoppas
    bygget med #error); saknas guardet flaggas filen.
    """
    bad = []
    for rel in FIRMWARE_GUARD_FILES:
        try:
            text = (REPO_ROOT / rel).read_text(errors="replace")
        except OSError:
            continue
        if any(p in text for p in DEVKEY_PATTERNS):
            if _has_fail_closed_opt_in(text):
                continue  # verkligt guard-block finns — bänkbygge, OK
            bad.append(rel)
    return bad


def run() -> int:
    print("shallot doctor — skrivfri kontroll (rör ingen hårdvara)")
    problems = 0

    def check(name: str, ok: bool, detail: str = ""):
        nonlocal problems
        if not ok:
            problems += 1
        print("[%s] %-14s %s" % ("OK" if ok else "!!", name, detail or ("ok" if ok else "problem")))

    check("python", True, "version %s" % sys.version.split()[0])
    check("pytest", importlib.util.find_spec("pytest") is not None,
          "installerad" if importlib.util.find_spec("pytest") else "saknas: pip install pytest")
    check("pyserial", importlib.util.find_spec("serial") is not None,
          "installerad" if importlib.util.find_spec("serial") else "saknas: pip install pyserial")

    v = _tool_version(["arduino-cli", "version"])
    check("arduino-cli", v is not None, v or "saknas (behövs endast för firmwarebyggen)")
    v = _tool_version(["pio", "--version"])
    check("platformio", v is not None, v or "saknas (behövs endast för firmwarebyggen)")

    for rel in REQUIRED_FILES:
        exists = (REPO_ROOT / rel).exists()
        check(rel.split("/")[-1], exists, rel if exists else "saknas: %s" % rel)

    ports = serial_adapters.list_ports()
    if ports:
        for p in ports:
            print("[OK] port          %s (%s)" % (p["device"], p["description"]))
    else:
        print("[--] port          inga serieportar hittades (skrivfri sökning)")

    for hit in _find_upload_scripts():
        check("upload-skript", False, "%s kan ladda upp firmware — körs aldrig av CLI:t" % hit)
    for rel in _firmware_devkey_guard():
        check("dev-nyckel", False, "%s innehåller hårdkodad utvecklingsnyckel" % rel)

    print("LoRa: utanför aktiv MVP — kontrolleras inte av doctor.")
    if problems:
        print("%d problem hittades (se !! ovan)." % problems, file=sys.stderr)
        return 1
    print("Allt OK.")
    return 0
