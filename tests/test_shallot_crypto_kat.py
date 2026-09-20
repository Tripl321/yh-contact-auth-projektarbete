"""Ticket 01: ShallotCrypto library skeleton + KAT (host-executed C).

Compiles libraries/ShallotCrypto with the host toolchain and runs
known-answer vectors through the REAL header: RFC 4231 (HMAC),
FIPS 180-4 (SHA-256) and the repo DEV vectors both nodes rely on.
"""

import hashlib
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
HDR = ROOT / "libraries/ShallotCrypto/src/ShallotCrypto.h"
HARNESS = ROOT / "tests/shallot_crypto_kat.c"

EXPECTED = {
    "crc_ref": "cbf43926",
    "sha_empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha_abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha_56": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "hmac_rfc1": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "hmac_rfc2": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    "hmac_rfc3": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "dev_kmac": "99c7117275f487623752e6d5d0eb438f",
    "dev_hmac": "782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda",
    "fail_msg": "00" * 32,
    "fail_key": "00" * 32,
}


def _run_kat():
    with tempfile.TemporaryDirectory() as tmp:
        exe = str(pathlib.Path(tmp) / "kat")
        compile_proc = subprocess.run(
            ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
             "-I", str(HDR.parent), str(HARNESS), "-o", exe],
            capture_output=True, text=True, timeout=120,
        )
        assert compile_proc.returncode == 0, compile_proc.stderr
        run = subprocess.run([exe], capture_output=True, text=True, timeout=60)
        assert run.returncode == 0, run.stderr
        out = {}
        for line in run.stdout.splitlines():
            name, hexval = line.split()
            out[name] = hexval
        return out


def test_shallot_crypto_adoption_state():
    """PAW + DEN + UNO-Q migrated (tickets 02/03/04)."""
    assert HDR.exists()
    assert (ROOT / "libraries/ShallotCrypto/library.properties").exists()
    paw = (ROOT / "id-kort/paw-main/paw-main.ino").read_text()
    assert "#include <ShallotCrypto.h>" in paw
    assert "void sha256(" not in paw and "void hmac_sha256(" not in paw
    den = (ROOT / "plc/den-main/den-main.ino").read_text()
    assert "#include <ShallotCrypto.h>" in den
    assert "static void den_sha256(" not in den
    assert "static void den_hmac_sha256(" not in den
    assert "static void den_derive_k_mac(" not in den
    uno = (ROOT / "key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino").read_text()
    assert "#include <ShallotCrypto.h>" in uno
    assert "static void sha256(" not in uno
    assert "sha256_k" not in uno


def test_shallot_crypto_kat_vectors():
    out = _run_kat()
    for name, want in EXPECTED.items():
        assert out[name] == want, name


def test_shallot_crypto_kenc_matches_oracle():
    out = _run_kat()
    master = bytes(range(16))
    want = hashlib.sha256(master + b"ENC").digest()[:16].hex()
    assert out["dev_kenc"] == want


def test_shallot_crypto_no_duplicate_compare():
    src = HDR.read_text()
    assert "den_ct_compare(" not in src  # owned by DenUartProtocol, reused
    assert "memcmp(" not in src
