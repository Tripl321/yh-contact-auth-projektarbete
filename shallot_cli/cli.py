"""SHALLOT CLI entry point.

Usage:
    shallot                 # interactive arrow-key menu
    shallot sync [paw|plc|unoq]   # sync from repo to sketchbook
    shallot flash paw       # sync + compile + flash
    shallot flash plc
    shallot flash unoq
    shallot list            # list connected boards
    shallot status          # print last status.json entry
"""

import argparse
import json
import sys

from . import __version__
from .components import COMPONENTS, get_component, all_keys
from .header import print_header, render_header
from .menu import select
from .backend import (
    ensure_git, ensure_repo, checkout_branch, sync_component, sync_all,
    ensure_arduino_cli, ensure_pico_index, ensure_core_installed,
    compile_component, flash_component, list_boards, write_status,
    _default_repo_dir, _default_sketchbook, pick_branch,
)


def _no_color_header() -> str:
    """Header art without ANSI codes (for curses display)."""
    return render_header(color=False)


def interactive_menu(repo_dir, sketchbook):
    """Show the SHALLOT header + arrow-key menu, dispatch the choice."""
    header = _no_color_header()
    options = [
        ("Flash PAW",  "Adafruit Feather RP2350 — synka, kompilera, flasha"),
        ("Flash PLC",  "Raspberry Pi Pico 2 — synka, kompilera, flasha"),
        ("Flash UNO Q","STM32U585 — synka, kompilera, flasha"),
        ("Synka alla", "Hämta senaste kod till sketchbook (ingen flashning)"),
        ("Lista boards","Visa anslutna boards med port och FQBN"),
        ("Avsluta",    "Stäng verktyget"),
    ]
    print_header(color=True)
    idx = select("Välj åtgärd:", header, options)
    if idx is None:
        print("Avbruten.")
        return
    if idx == 0:
        do_flash("paw", repo_dir, sketchbook)
    elif idx == 1:
        do_flash("plc", repo_dir, sketchbook)
    elif idx == 2:
        do_flash("unoq", repo_dir, sketchbook)
    elif idx == 3:
        do_sync_all(repo_dir, sketchbook)
    elif idx == 4:
        if not ensure_arduino_cli():
            print("arduino-cli saknas. Installera: brew install arduino-cli")
            return
        list_boards()
    elif idx == 5:
        print("Hej då!")
        return


def do_sync_all(repo_dir, sketchbook):
    sync_all(repo_dir, sketchbook)
    print(f"\n✓ Klar. Alla skisser synkade till {sketchbook}")


def do_flash(key, repo_dir, sketchbook):
    comp = get_component(key)
    if not comp:
        print(f"✗ Okänd komponent: {key}", file=sys.stderr)
        sys.exit(1)
    sync_component(comp, repo_dir, sketchbook)
    write_status(comp, True, "sync", "synkad", repo_dir)
    if not ensure_arduino_cli():
        print("⚠ arduino-cli saknas. Skisser synkade — öppna i Arduino IDE för att flasha.")
        return
    if key in ("paw", "plc"):
        ensure_pico_index()
    ensure_core_installed(comp)
    if not compile_component(comp, sketchbook / comp.src_path.split("/")[-1].removesuffix(".ino")):
        write_status(comp, False, "compile", "kompilering misslyckades", repo_dir)
        print("✗ Kompilering misslyckades — avbryter innan flashning.", file=sys.stderr)
        return
    write_status(comp, True, "compile", "kompilering OK", repo_dir)
    ok = flash_component(comp, sketchbook / comp.src_path.split("/")[-1].removesuffix(".ino"))
    write_status(comp, ok, "flash", "flashad" if ok else "flashning misslyckades", repo_dir)
    if ok:
        print("\n✓ Klar!")


def do_status(repo_dir):
    from pathlib import Path
    f = repo_dir / "status.json"
    if not f.is_file():
        print("Ingen status.json hittades ännu.")
        return
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, ValueError):
        print("✗ status.json kunde inte tolkas.")
        return
    if not data:
        print("status.json är tom.")
        return
    last = data[-1]
    print("Senaste status:")
    print(f"  Tid:       {last.get('timestamp','?')}")
    print(f"  Komponent: {last.get('component','?')}")
    print(f"  Steg:      {last.get('stage','?')}")
    print(f"  OK:        {'ja' if last.get('ok') else 'nej'}")
    print(f"  Detalj:    {last.get('detail','?')}")
    print(f"  Branch:    {last.get('branch','?')}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="shallot",
        description="SHALLOT — sync firmware and flash to PAW/PLC/UNO Q",
    )
    p.add_argument("--version", action="version", version=f"shallot-cli {__version__}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("sync", help="synka från repo till sketchbook")
    sp.add_argument("component", nargs="?", choices=all_keys(),
                    help="vilken komponent (utesluten = alla)")

    fp = sub.add_parser("flash", help="synka + kompilera + flasha")
    fp.add_argument("component", choices=all_keys(), help="vilken komponent")

    sub.add_parser("list", help="lista anslutna boards")
    sub.add_parser("status", help="visa senaste status.json-post")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    repo_dir = _default_repo_dir()
    sketchbook = _default_sketchbook()

    if not args.command:
        # Interactive arrow-key menu
        ensure_git()
        ensure_repo(repo_dir)
        checkout_branch(repo_dir)
        interactive_menu(repo_dir, sketchbook)
        return

    if args.command == "status":
        do_status(repo_dir)
        return

    if args.command == "list":
        if not ensure_arduino_cli():
            print("arduino-cli saknas. Installera: brew install arduino-cli")
            return
        list_boards()
        return

    # sync and flash require git + repo
    ensure_git()
    ensure_repo(repo_dir)
    checkout_branch(repo_dir)

    if args.command == "sync":
        if args.component:
            comp = get_component(args.component)
            sync_component(comp, repo_dir, sketchbook)
            print(f"✓ {comp.key} synkad")
        else:
            do_sync_all(repo_dir, sketchbook)
        return

    if args.command == "flash":
        do_flash(args.component, repo_dir, sketchbook)
        return


if __name__ == "__main__":
    main()
