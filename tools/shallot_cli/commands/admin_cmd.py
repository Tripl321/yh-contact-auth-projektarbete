"""`shallot admin ...` — Admin-upplevelse (interaktiv + scriptbar).

Tunna wrappers över shallot_cli.admin (som äger flöden, session och
revisionslogg). Exit-koder: 0 = ok, 1 = nekat/körfel, 2 = användning.
"""

from __future__ import annotations

import sys

from shallot_cli import admin


def run_login(user: str, credential: str | None = None,
              mock: bool = False) -> int:
    """`shallot admin login --user <id> [--credential <id>] [--mock]`."""
    return admin.run_login(user, credential=credential, mock=mock)


def run_logout() -> int:
    """`shallot admin logout`."""
    return admin.run_logout()


def run_status() -> int:
    """`shallot admin status` (scriptbar grindprob: 0 = giltig session)."""
    return admin.run_status()


def run_reset_code(confirm: bool = False) -> int:
    """`shallot admin reset-code --confirm` (fysisk återställning)."""
    try:
        admin.check_confirm(confirm, "reset-code")
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    return admin.run_reset_code(confirm=confirm)
