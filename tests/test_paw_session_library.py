"""Beteendetester för den verkliga PawSession-header-only-modulen.

C-harnesset `paw_session_host.c` kompileras mot den faktiska
`libraries/PawSession/src/PawSession.h` (och dess beroenden ShallotCrypto +
ProvisioningProtocol) på host och exekveras. Inga Python-speglar: allt
tillstånd ägs av biblioteket och valideras C-seitigt.
"""
import pathlib
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAW_HDR_DIR = ROOT / "libraries/PawSession/src"
PROV_HDR_DIR = ROOT / "libraries/ProvisioningProtocol/src"
CRYPTO_HDR_DIR = ROOT / "libraries/ShallotCrypto/src"
HARNESS = ROOT / "tests/paw_session_host.c"


def _build():
    tmp = tempfile.TemporaryDirectory()
    exe = str(pathlib.Path(tmp.name) / "paw_session_host")
    proc = subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
         "-I", str(PAW_HDR_DIR),
         "-I", str(PROV_HDR_DIR),
         "-I", str(CRYPTO_HDR_DIR),
         str(HARNESS), "-o", exe],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        tmp.cleanup()
        pytest.fail(f"compile failed:\n{proc.stderr}")
    return tmp, exe


@pytest.fixture(scope="module")
def host_exe():
    tmp, exe = _build()
    yield exe
    tmp.cleanup()


def test_paw_session_harness_compiles(host_exe):
    """C-harnesset bygger rent mot den verkliga headern."""


def test_paw_session_behavior(host_exe):
    """Alla transport-fria tillståndsmaskinscenarier passerar i C."""
    out = subprocess.run([host_exe], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "SUMMARY: all paw_session scenarios passed" in out.stdout
    assert "FAIL" not in out.stdout
