"""Ticket 03: shared/ är frusen LoRa-kontext — inga nya beroenden.

Tillåtna konsumenter av shallot_protocol.h är låsta nedan. Ny kod ska
mot DenUartProtocol/ShallotCrypto, aldrig hit.
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

ALLOWED = frozenset(
    {
        "plc/edge-challenge-response/edge-challenge-response.ino",
        "tests/protocol-test/protocol-test.ino",
        "tests/test_pro52_protocol.py",
        "tests/test_shared_freeze.py",  # this guard itself (no dependency)
        "id-kort/archive/paw-challenge-response-responder/paw-challenge-response.ino",
    }
)


def test_shared_frozen_owner_note():
    src = (ROOT / "shared/shallot_protocol.h").read_text()
    assert "FROZEN" in src
    assert "DenUartProtocol" in src and "ShallotCrypto" in src


def test_shared_no_new_consumers():
    found = set()
    for path in (
        list(ROOT.rglob("*.ino")) + list(ROOT.rglob("*.h")) + list(ROOT.rglob("*.py"))
    ):
        posix = path.as_posix()
        if ".git/" in posix or "/.kilo/" in posix or "/worktrees/" in posix:
            continue  # andra worktrees scannas inte — endast denna rot
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if "shallot_protocol.h" in text and path.name != "shallot_protocol.h":
            found.add(path.relative_to(ROOT).as_posix())
    assert found <= ALLOWED, found - ALLOWED
