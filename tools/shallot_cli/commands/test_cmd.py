"""`shallot test` — kör repoets befintliga pytest-sviter via subprocess.

Testfiler återanvänds aldrig som bibliotek; de körs som separata
pytest-processer. Rapporterar pass/fail/skip-räkningar samt en kort
svans av output för felsökning.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

#: Svitnamn -> pytest-mål (relativt repo-roten). "all" täcker både
#: tests/ och tools/shallot_cli/tests/.
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
    "all": ["tests", "tools/shallot_cli/tests"],
}

_COUNT_RES = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) failed"),
    "skipped": re.compile(r"(\d+) skipped"),
    "errors": re.compile(r"(\d+) error"),
}


def _stream_pytest(cmd: list[str]) -> tuple[str, int]:
    """Kör pytest med live-output (så långa sviter inte ser ut att ha
    fastnat). Returnerar (sammanslagen output, exit-kod). Timeout 600 s."""
    proc = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    chunks: list[str] = []
    deadline = time.monotonic() + 600
    try:
        import select
        haveselect = True
    except ImportError:
        haveselect = False
    try:
        while True:
            if proc.poll() is not None:
                rest = proc.stdout.read()
                if rest:
                    print(rest, end="")
                    chunks.append(rest)
                break
            if haveselect:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    raise subprocess.TimeoutExpired(cmd, 600)
                try:
                    ready, _, _ = select.select([proc.stdout], [], [],
                                                min(remaining, 0.5))
                except (OSError, ValueError):
                    haveselect = False
                    continue
                if not ready:
                    continue
            line = proc.stdout.readline()
            if not line:
                continue  # låt poll() avgöra om processen är klar
            print(line, end="", flush=True)
            chunks.append(line)
    finally:
        if proc.poll() is None:
            proc.kill()
    return "".join(chunks), proc.returncode


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
    cmd = [sys.executable, "-m", "pytest", *targets, "-q", "--tb=short"]
    if as_json:
        try:
            proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True,
                                  text=True, timeout=600)
        except FileNotFoundError:
            print("error: python-tolken hittades inte.", file=sys.stderr)
            return 1
        except subprocess.TimeoutExpired:
            print("error: pytest tog längre än 600 s — avbrutet.", file=sys.stderr)
            return 1
        except OSError as e:
            print("error: kunde inte starta pytest: %s" % e, file=sys.stderr)
            return 1
        output = (proc.stdout or "") + (proc.stderr or "")
        returncode = proc.returncode
    else:
        print("shallot test: svit '%s' (%s)" % (suite, ", ".join(targets)),
              flush=True)
        try:
            output, returncode = _stream_pytest(cmd)
        except FileNotFoundError:
            print("error: python-tolken hittades inte.", file=sys.stderr)
            return 1
        except subprocess.TimeoutExpired:
            print("error: pytest tog längre än 600 s — avbrutet.", file=sys.stderr)
            return 1
        except OSError as e:
            print("error: kunde inte starta pytest: %s" % e, file=sys.stderr)
            return 1
    counts = {k: (int(r.search(output).group(1)) if r.search(output) else 0)
              for k, r in _COUNT_RES.items()}
    ok = returncode == 0 and counts["failed"] == 0 and counts["errors"] == 0
    if as_json:
        print(json.dumps({
            "suite": suite, "targets": targets,
            "passed": counts["passed"], "failed": counts["failed"],
            "skipped": counts["skipped"], "errors": counts["errors"],
            "pytest_exit": returncode, "ok": ok,
        }, indent=2))
    else:
        print("passerade=%d misslyckade=%d hoppade_över=%d fel=%d" % (
            counts["passed"], counts["failed"], counts["skipped"], counts["errors"]))
        if not ok:
            print("SVIKT: inte alla tester godkända (pytest exit %d)." % returncode,
                  file=sys.stderr)
    return 0 if ok else 1
