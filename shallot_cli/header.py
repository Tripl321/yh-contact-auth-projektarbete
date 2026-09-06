"""ASCII-art header for SHALLOT CLI."""

# ASCII art "SHALLOT" rendered in a block style.
# Each letter is 5 rows tall; letters separated by a space column.
_SHALLOT_ART = r"""
  ___ _  _ ___ _    _    ___ ___ ___      _   ___ ___ ___ ___
 / __| || | __| |  | |  | _ \ __| _ \___| |_| _ | __|_ _/ __|
 \__ \ __ | _|| |__| |__|   / _||   /___|  _| || | _| | | (_ |
 |___/_||_|___|____|____|_|_\___|_|_\    \__|___|___|___\___|
"""

SUBTITLE = "Secure-by-Design ID-bricka  •  PAW / PLC / UNO Q"


def render_header(color: bool = True) -> str:
    """Return the SHALLOT banner as a string, optionally ANSI-colored."""
    art = _SHALLOT_ART
    if color:
        # Cyan art, dim subtitle
        CYAN = "\033[36m"
        DIM = "\033[2m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        lines = [f"{CYAN}{BOLD}{line}{RESET}" for line in art.splitlines()]
        lines.append(f"{DIM}{SUBTITLE}{RESET}")
        return "\n".join(lines)
    return art + "\n" + SUBTITLE


def print_header(color: bool = True) -> None:
    """Print the SHALLOT banner to stdout."""
    print(render_header(color=color))
