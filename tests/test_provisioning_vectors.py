"""Biljett: provisioneringsprotokollet (0xA-serien) — corpus + host C-harness.

tests/vectors/provisioning.json är enda sanningen; C-harnesset
(ProvisioningProtocol.h, kompilerat på host) och MockProv-mirrors
bevisar samma paketbygge/CRC. Sträng-guards ersätts där de täcker
detta protokoll.
"""

import json
import pathlib
import subprocess
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "tests/vectors/provisioning.json").read_text())["packets"]
PROV_HDR = ROOT / "libraries/ProvisioningProtocol/src/ProvisioningProtocol.h"


def _harness():
    tmp = tempfile.TemporaryDirectory()
    exe = str(pathlib.Path(tmp.name) / "pvect")
    proc = subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
         "-I", str(PROV_HDR.parent),
         "-I", str(ROOT / "libraries/ShallotCrypto/src"),
         str(ROOT / "tests/provisioning_vectors_host.c"), "-o", exe],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return tmp, exe


@pytest.fixture(scope="module")
def pvect():
    tmp, exe = _harness()
    yield exe
    tmp.cleanup()


def test_corpus_ids_unique():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)) and len(ids) >= 4


def test_c_key_data_build_and_crc(pvect):
    """C-harness bygger KEY_DATA-paketet ur corpuset: CRC(matchar BE)."""
    vec = next(v for v in VECTORS if v["id"] == "key_data")
    out = subprocess.run([pvect, "keydata", vec["key_hex"]],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stdout + out.stderr
    frame = out.stdout.strip()
    assert len(frame) == 44  # 22 byte
    assert frame[:2] == "a3"  # MSG_KEY_DATA
    assert frame[2:6] == "1000"  # len u16 LE = 16
    assert frame[4:36] == vec["key_hex"]
    assert frame[36:] == vec["expect_crc_be"]


def test_c_crc_verifies_and_rejects(pvect):
    vec = next(v for v in VECTORS if v["id"] == "key_data")
    ok = subprocess.run([pvect, "verify", vec["key_hex"], vec["expect_crc_be"]],
                        capture_output=True, text=True, timeout=30)
    assert ok.returncode == 0 and ok.stdout.strip() == "OK"
    bad = subprocess.run([pvect, "verify", vec["key_hex"], "00000001"],
                         capture_output=True, text=True, timeout=30)
    assert bad.returncode != 0 and "ERR" in bad.stdout


def test_mockprov_crc_matches_corpus():
    """MockProv-mirrors (binascii) ger samma CRC som corpuset — båda
    sidor av 0xA-tråden låsta mot samma sanning."""
    import binascii
    vec = next(v for v in VECTORS if v["id"] == "key_data")
    crc = binascii.crc32(bytes.fromhex(vec["key_hex"])) & 0xFFFFFFFF
    assert "%08x" % crc == vec["expect_crc_be"]
