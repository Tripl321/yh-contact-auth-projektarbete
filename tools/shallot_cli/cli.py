"""shallot — lokal test-/simulerings-CLI för SHALLOT.

Styr eller verifierar ingen fysisk hårdvara. Resultat från `test`
och `simulate` är automatiska tester/simuleringar, inte
hårdvaruverifiering.

Exit-koder: 0 = ok, 1 = fel vid körning/underkända tester,
2 = felaktig användning (ogiltiga argument).

Utan argument startar ett interaktivt TUI-läge (se shallot_cli.tui).
"""

from __future__ import annotations

import argparse
import sys

from shallot_cli import registry, tui


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shallot",
        description="Lokal test-/simulerings-CLI för SHALLOT. "
        "Styr eller verifierar ingen fysisk hårdvara.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    for _cmd in registry.COMMANDS.values():
        _p = sub.add_parser(_cmd.name, help=_cmd.help_text)
        _cmd.add_arguments(_p)
    return p


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return tui.run()
    args = build_parser().parse_args(argv)
    if args.command in registry.COMMANDS:
        return registry.COMMANDS[args.command].run(args)
    return 2  # pragma: no cover — argparse required=True gör detta onåbart


if __name__ == "__main__":
    sys.exit(main())
