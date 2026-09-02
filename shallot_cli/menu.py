"""Interactive menu with arrow-key navigation.

Uses curses for arrow-key navigation. Falls back to a simple numbered
prompt if curses is unavailable (e.g. piped stdin, some terminals).
"""

from typing import List, Tuple, Optional


def _curses_menu(title: str, header_art: str, options: List[Tuple[str, str]]) -> int:
    """Show a curses menu. Returns the selected index, or -1 if cancelled.

    Each option is (label, description).
    """
    import curses

    def draw(stdscr, selected: int):
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        row = 0
        # Header art (cyan/dim if colors available)
        if curses.has_colors():
            curses.use_default_colors()
        for line in header_art.splitlines():
            if row < h:
                stdscr.addnstr(row, 0, line, w - 1)
                row += 1
        row += 1  # blank line

        # Title
        if row < h:
            stdscr.addnstr(row, 0, title, w - 1, curses.A_BOLD)
            row += 1
        row += 1  # blank

        # Options
        for i, (label, desc) in enumerate(options):
            if row >= h:
                break
            prefix = "❯ " if i == selected else "  "
            text = f"{prefix}{label}"
            try:
                if i == selected:
                    stdscr.addnstr(row, 0, text, w - 1, curses.A_REVERSE)
                    if desc and row + 1 < h:
                        stdscr.addnstr(row + 1, 2, desc, w - 3, curses.A_DIM)
                else:
                    stdscr.addnstr(row, 0, text, w - 1)
                    if desc and row + 1 < h:
                        stdscr.addnstr(row + 1, 2, desc, w - 3, curses.A_DIM)
            except curses.error:
                pass
            row += 2  # label + description

        # Footer hint
        if row + 1 < h:
            hint = "↑↓ navigera  •  Enter välj  •  q/Esc avbryt"
            stdscr.addnstr(h - 1, 0, hint, w - 1, curses.A_DIM)
        stdscr.refresh()

    def loop(stdscr):
        curses.curs_set(0)  # hide cursor
        stdscr.keypad(True)
        selected = 0
        draw(stdscr, selected)
        while True:
            ch = stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(options)
            elif ch in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(options)
            elif ch in (curses.KEY_ENTER, 10, 13):
                return selected
            elif ch in (ord("q"), 27):  # q or Esc
                return -1
            draw(stdscr, selected)

    try:
        return curses.wrapper(loop)
    except Exception:
        return _fallback_menu(title, options)


def _fallback_menu(title: str, options: List[Tuple[str, str]]) -> int:
    """Numbered prompt fallback when curses is unavailable."""
    print(title)
    print()
    for i, (label, desc) in enumerate(options, 1):
        print(f"  {i}) {label}")
        if desc:
            print(f"      {desc}")
    print(f"  q) Avbryt")
    print()
    while True:
        try:
            choice = input("Val: ").strip().lower()
        except EOFError:
            print()
            return -1
        if choice == "q":
            return -1
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        print("Ogiltigt val, försök igen.")


def select(title: str, header_art: str, options: List[Tuple[str, str]]) -> Optional[int]:
    """Show an interactive menu and return the selected index, or None if cancelled.

    Args:
        title: Menu title.
        header_art: ASCII art string (already rendered, no ANSI codes) to show at top.
        options: List of (label, description) tuples.
    """
    if not options:
        return None
    # Try curses first; fall back to numbered prompt.
    import sys
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            idx = _curses_menu(title, header_art, options)
        except Exception:
            idx = _fallback_menu(title, options)
    else:
        idx = _fallback_menu(title, options)
    return idx if idx >= 0 else None
