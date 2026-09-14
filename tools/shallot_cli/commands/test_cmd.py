"""`shallot test` — kör repoets befintliga pytest-sviter via subprocess.

Testfiler återanvänds aldrig som bibliotek; de körs som separata
pytest-processer och endast pass/fail/skip-räkningar rapporteras.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

#: Svitnamn -> pytest-mål (relativt repo-roten). Tillsammans täcker de
#: alla 14 testfiler under tests/.
SUITES = {
    "protocol": ["tests/test_pro87_uart.py"],
    "den": [
        "tests/test_pro88_den.py",
        "tests/test_pro51_nonce_generation.py",
        "tests/test_pro49_key_derivation.py",
    ],
    "paw": [
        "tests/test_pro84_paw.py",
        "tests/test_pro50_hmac_paw.py",
        "tests/test_paw_responsive.py",
        "tests/test_paw_uart_split.py",
    ],
    "mamabear": [
        "tests/test_pro45_key_generation.py",
        "tests/test_pro46_usb_distribution.py",
        "tests/test_pro47_key_storage.py",
    ],
    "e2e": [
        "tests/test_pro61_e2e_integration.py",
        "tests/test_pro62_failure_scenarios.py",
        "tests/test_pro94_security_review.py",
    ],
    "fido2": [
        "tools/shallot_cli/tests/test_fido2.py",
        "tools/shallot_cli/tests/test_fido2_backend.py",
        "tools/shallot_cli/tests/test_fido2_store.py",
        "tools/shallot_cli/tests/test_fido2_sanitize.py",
        "tools/shallot_cli/tests/test_fido2_cmd.py",
        "tools/shallot_cli/tests/test_fido2_ctap.py",
    ],
    "all": ["tests"],
}

_COUNT_RES = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) failed"),
    "skipped": re.compile(r"(\d+) skipped"),
    "errors": re.compile(r"(\d+) error"),
}


def run_suite(suite: str, as_json: bool = False) -> int:
    """Kör en svit. Exit 0 = alla godkända, 1 = fel/underkända, 2 = användning."""
    if suite not in SUITES:
        print("error: okänd svit %r (välj: %s)" % (suite, "|".join(SUITES)), file=sys.stderr)
        return 2
    targets = SUITES[suite]
    missing = [t for t in targets if not (REPO_ROOT / t).exists()]
    if missing:
        print("error: saknade testmål: %s" % ", ".join(missing), file=sys.stderr)
        return 1
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", *targets, "-q", "--tb=short"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print("error: python-tolken hittades inte.", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("error: pytest tog längre än 600 s — avbrutet.", file=sys.stderr)
        return 1
    output = (proc.stdout or "") + (proc.stderr or "")
    counts = {k: (int(r.search(output).group(1)) if r.search(output) else 0)
              for k, r in _COUNT_RES.items()}
    ok = proc.returncode == 0 and counts["failed"] == 0 and counts["errors"] == 0
    if as_json:
        print(json.dumps({
            "suite": suite, "targets": targets,
            "passed": counts["passed"], "failed": counts["failed"],
            "skipped": counts["skipped"], "errors": counts["errors"],
            "pytest_exit": proc.returncode, "ok": ok,
        }, indent=2))
    else:
        tail = "\n".join((proc.stdout or "").strip().splitlines()[-8:])
        print("shallot test: svit '%s' (%s)" % (suite, ", ".join(targets)))
        if tail:
            print(tail)
        print("passerade=%d misslyckade=%d hoppade_över=%d fel=%d" % (
            counts["passed"], counts["failed"], counts["skipped"], counts["errors"]))
        if not ok:
            print("SVIKT: inte alla tester godkända (pytest exit %d)." % proc.returncode,
                  file=sys.stderr)
    return 0 if ok else 1
