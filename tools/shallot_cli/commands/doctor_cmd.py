"""`shallot doctor` — miljökontroll utan hårdvarupåverkan.

Kontrollerar verktyg, repo-kataloger, serieportar (skrivfritt) och
flaggar osäkra build-konfigurationer. Exit 0 = allt OK, 1 = saknade
beroenden eller osäkra konfigurationer hittades.
"""

from __future__ import annotations

import importlib.util
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
]


def _tool_version(cmd: list[str]) -> str | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
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
    """Firmware får inte innehålla hårdkodade utvecklingsnycklar."""
    bad = []
    for rel in FIRMWARE_GUARD_FILES:
        try:
            text = (REPO_ROOT / rel).read_text(errors="replace")
        except OSError:
            continue
        if "DEN_DEV_KEY" in text or "#warning" in text:
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
