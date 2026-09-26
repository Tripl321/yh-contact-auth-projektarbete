"""`shallot mamabear status|test` — läsande fjärrläge över system-SSH.

Kräver tydlig bekräftelse innan SSH-anslutning sker (interaktiv fråga
eller ``--yes``). Vid anslutningsfel, timeout eller oväntad output:
fail closed — ingen skrivning på MamaBear, exit-kod 1.
"""

from __future__ import annotations

import sys

from shallot_cli import mamabear


def _confirm(question: str) -> bool:
    try:
        ans = input("%s [j/N]: " % question).strip().lower()
    except EOFError:
        return False
    return ans in ("j", "ja", "y", "yes")


def _run(
    kind: str, entries: tuple, host: str, yes: bool, output: str | None, confirm=None
) -> int:
    """confirm: injicerbar ja/nej-funktion (ConfirmGateway). Default _confirm
    läser terminalen; yes=True hoppar över frågan (icke-interaktivt)."""
    try:
        alias = mamabear.validate_alias(host)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    ask = confirm or _confirm
    if not yes:
        print("SSH-anslutning till '%s' via system-ssh (~/.ssh/config)." % alias)
        print(
            "Kör %d läsande kommandon. Inget skrivs på MamaBear; "
            "inga lösenord eller nycklar hanteras." % len(entries)
        )
        if not ask("Fortsätt med SSH-anslutning"):
            print("Avbrutet av användaren — ingen anslutning skedde.", file=sys.stderr)
            return 2
    try:
        suite = mamabear.run_suite(alias, entries)
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    payload = mamabear.build_payload("shallot mamabear %s" % kind, alias, suite)
    try:
        out_path = (
            mamabear.resolve_output_path(output)
            if output
            else mamabear.default_output_path(kind)
        )
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    try:
        out_path = mamabear.save_result(out_path, payload)
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print(mamabear.render_summary(payload, out_path))
    return payload["exit_code"]


def run_status(host: str, yes: bool = False, confirm=None) -> int:
    """`shallot mamabear status --host <alias>`.

    Skriver alltid en lokal JSON-resultatfil (mamabear-status-<tid>.json
    i CWD) — även detta är ett läsande läge, inget skrivs på MamaBear.
    """
    return _run("status", mamabear.STATUS_COMMANDS, host, yes, None, confirm=confirm)


def run_test(
    host: str, yes: bool = False, output: str | None = None, confirm=None
) -> int:
    """`shallot mamabear test --host <alias> [--output <fil>]`."""
    return _run("test", mamabear.TEST_COMMANDS, host, yes, output, confirm=confirm)
