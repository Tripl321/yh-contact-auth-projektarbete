"""`shallot build` — visar (aldrig kör) firmware-byggkommandon.

CLI:t bygger eller laddar aldrig upp firmware utan ett framtida
explicit ``--hardware``-läge. Befintliga skript som implicit laddar
upp (t.ex. ``build-uf2.sh pio`` → ``pio run --target upload``)
används aldrig här — endast rena ``compile``-kommandon visas.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

#: Mål -> (källfil, exakt compile-kommando som skulle köras).
TARGETS = {
    "den": (
        # DEN-hårdvara är Pico 2 W: rpipico2w-targetet driver onboard-LED
        # via CYW43 (initieras automatiskt, inget WiFi-bibliotek krävs).
        "plc/den-main/den-main.ino",
        [
            "arduino-cli",
            "compile",
            "--fqbn",
            "rp2040:rp2040:rpipico2w",
            "--output-dir",
            "build",
            "plc/den-main/den-main.ino",
        ],
    ),
    "paw": (
        "id-kort/paw-main/paw-main.ino",
        [
            "arduino-cli",
            "compile",
            "--fqbn",
            "rp2040:rp2040:adafruit_feather_rp2350_hstx",
            "--build-property",
            "build.extra_flags=-DARDUINO_USB_CDC_ONLY",
            "--output-dir",
            "build",
            "id-kort/paw-main/paw-main.ino",
        ],
    ),
    # MamaBear (UNO Q MCU, ArduinoCore-zephyr via Arduino IDE): inget
    # verifierat CLI-byggkommando finns dokumenterat — redovisa ärligt.
    "mamabear": (
        "key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino",
        None,
    ),
}


def _quote(cmd: list[str]) -> str:
    return " ".join(
        (
            c
            if c.replace("-", "")
            .replace("_", "")
            .replace(".", "")
            .replace("/", "")
            .isalnum()
            else "'%s'" % c
        )
        for c in cmd
    )


def run(target: str, dry_run: bool = False) -> int:
    if target not in TARGETS:
        print(
            "error: okänt mål %r (välj: %s)" % (target, "|".join(TARGETS)),
            file=sys.stderr,
        )
        return 2
    if not dry_run:
        print(
            "error: vägrar bygga — bygge kräver ett framtida explicit --hardware-läge. "
            "Inget byggdes eller laddades upp. Använd --dry-run för att se kommandot.",
            file=sys.stderr,
        )
        return 2
    src, cmd = TARGETS[target]
    if not (REPO_ROOT / src).exists():
        print("error: källfil saknas: %s" % src, file=sys.stderr)
        return 1
    print("mål     : %s" % target)
    print("källa   : %s" % src)
    if cmd is None:
        print("kommando: (inget verifierat CLI-byggkommando)")
        print(
            "notering: MamaBear byggs via Arduino IDE + ArduinoCore-zephyr "
            "(se key-authority/README.md). Inget kördes."
        )
    else:
        print("kommando: %s" % _quote(cmd))
        print(
            "notering: compile visar endast — uppladdning kräver framtida --hardware-läge. "
            "Inget kördes."
        )
    return 0
