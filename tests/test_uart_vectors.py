"""Ticket 06(a): UART-vektorcorpus konsumerat på båda sidor.

tests/vectors/uart.json är enda sanningen för ramvektorer: C-harnesset
(DenUartProtocol, kompilerat på host) och shallot_cli.uart bevisar
samma encode/decode mot det. Hand-synk mellan C och Python är borta.
"""

import json
import pathlib
import subprocess
import tempfile

import pytest
from shallot_cli import uart

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "tests/vectors/uart.json").read_text())["frames"]


def _harness():
    tmp = tempfile.TemporaryDirectory()
    exe = str(pathlib.Path(tmp.name) / "uvect")
    proc = subprocess.run(
        [
            "cc",
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "libraries/DenUartProtocol/src"),
            str(ROOT / "tests/uart_vectors_host.c"),
            "-o",
            exe,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return tmp, exe


def _run(exe, *args):
    proc = subprocess.run([exe, *args], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


@pytest.fixture(scope="module")
def uvect():
    tmp, exe = _harness()
    yield exe
    tmp.cleanup()


def test_uart_corpus_ids_unique():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)) and len(ids) >= 5


def test_c_encode_matches_corpus(uvect):
    for vec in VECTORS:
        assert _run(uvect, "encode", str(vec["type"]), vec["payload"]) == vec["frame"]


def test_c_decode_matches_corpus(uvect):
    for vec in VECTORS:
        want = ("%d %s" % (vec["type"], vec["payload"])).strip()
        assert _run(uvect, "decode", vec["frame"]) == want


def test_python_matches_corpus():
    for vec in VECTORS:
        assert (
            uart.encode(vec["type"], bytes.fromhex(vec["payload"])).hex()
            == vec["frame"]
        )
        t, p = uart.decode(bytes.fromhex(vec["frame"]))
        assert t == vec["type"] and p.hex() == vec["payload"]
