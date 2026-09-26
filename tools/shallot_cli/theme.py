"""Färgtema för SHALLOT TUI + demo.

Basfärg: orange. Kontrast: cyan (markering/pekare). Respekterar
``NO_COLOR`` (avaktiverar) och ``FORCE_COLOR`` (tvingar på), enligt
de-facto-konventionen. Default är färg på — befintligt beteende.

Alla funktioner är no-op när färg är avaktiverat (ren text, inga
ANSI-sekvenser), vilket gör dem säkra att använda mot filer och pipes.
"""

import os

ORANGE = "\x1b[38;2;255;140;0m"
ACCENT = "\x1b[96m"
DIM_CODE = "\x1b[2m"
RESET = "\x1b[0m"


def _enabled() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    force = os.environ.get("FORCE_COLOR", "").strip().lower()
    if force in ("0", "false", "no", "off"):
        return False
    if force:
        return True
    return True


USE_COLOR = _enabled()


def fg(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return "%s%s%s" % (code, text, RESET)


def paint(text: str, code: str) -> str:
    """Färglägg varje rad i en flerradig sträng (bevarar konstform)."""
    if not USE_COLOR:
        return text
    return "\n".join(fg(line, code) for line in text.split("\n"))


def orange(text: str) -> str:
    return fg(text, ORANGE)


def accent(text: str) -> str:
    return fg(text, ACCENT)


def dim(text: str) -> str:
    return fg(text, DIM_CODE)
