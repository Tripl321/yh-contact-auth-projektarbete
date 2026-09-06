"""Component definitions: PAW, PLC, UNO Q.

Each component maps to a source .ino in the repo, a FQBN for the board,
a board-core to install, a human-readable board name (for port detection
fallback), and optional extra files to copy (e.g. prj.conf).
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Component:
    key: str            # short id used on the CLI: "paw", "plc", "unoq"
    name: str           # human-readable: "PAW (Adafruit Feather RP2350)"
    src_path: str       # path relative to repo root
    fqbn: str           # Fully Qualified Board Name for arduino-cli
    core: str           # core package to install (may include @version)
    board_name: str     # board name substring for port-detection fallback
    extras: List[str] = field(default_factory=list)  # extra files to copy with the sketch


COMPONENTS: List[Component] = [
    Component(
        key="paw",
        name="PAW (Adafruit Feather RP2350)",
        src_path="id-kort/paw-main/paw-main.ino",
        fqbn="rp2040:rp2040:adafruit_feather_rp2350_hstx",
        core="rp2040:rp2040",
        board_name="Feather RP2350",
    ),
    Component(
        key="plc",
        name="PLC (Raspberry Pi Pico 2 W)",
        src_path="plc/plc-key-receiver/plc-key-receiver.ino",
        fqbn="rp2040:rp2040:rpipico2w",
        core="rp2040:rp2040",
        board_name="Pico 2",
    ),
    Component(
        key="unoq",
        name="UNO Q (STM32U585)",
        src_path="key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino",
        fqbn="arduino:zephyr:unoq",
        core="arduino:zephyr@0.90.0",
        board_name="UNO Q",
        extras=["key-authority/uno-q-key-authority-mcu/prj.conf"],
    ),
]


def get_component(key: str) -> Optional[Component]:
    for c in COMPONENTS:
        if c.key == key:
            return c
    return None


def all_keys() -> List[str]:
    return [c.key for c in COMPONENTS]
