"""
PRO-98 Ed25519 adapter: host-compiled KAT proof (skips without toolchain).

Compiles libraries/Ed25519/src/Ed25519.cpp together with the rweather
Crypto sources it forwards to, then proves the seam against Python
cryptography (strict verifier) and the repo's own blocklist vector:
- pubkey derivation matches TEST_ED25519_PUBLIC_KEY
- C signatures verify under Python, byte-equal to Python signatures
- repo TEST_BLOCKLIST_V1 verifies; tampered rejects
- NULL guards return 0 without crashing

Skips cleanly when g++ or the Crypto library sources are unavailable
(Crypto location: CRYPTO_LIB_SRC env or Arduino user libraries dir).
No hardware needed; no network use.
"""
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from tests.test_pro88_den import (TEST_BLOCKLIST_V1, TEST_ED25519_PRIVATE_KEY,
                                  TEST_ED25519_PUBLIC_KEY)

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADAPTER_SRC = ROOT / "libraries/Ed25519/src/Ed25519.cpp"
ADAPTER_INC = ROOT / "libraries/Ed25519/src"

HARNESS_CPP = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include "Ed25519.h"
static int hexout(const char* tag, const uint8_t* b, size_t n) {
    printf("%s", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
    return 0;
}
static size_t hexin(const char* s, uint8_t* out, size_t maxn) {
    size_t n = strlen(s) / 2;
    if (n > maxn) n = maxn;
    for (size_t i = 0; i < n; i++) sscanf(s + 2*i, "%2hhx", &out[i]);
    return n;
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    uint8_t sk[32], pk[32], msg[256], sig[64];
    memset(sk, 0, sizeof(sk));
    if (argc >= 3) hexin(argv[2], sk, 32);
    if (!strcmp(argv[1], "pubkey")) {
        if (!ed25519_public_key(pk, sk)) return 3;
        return hexout("PUBKEY:", pk, 32);
    }
    if (!strcmp(argv[1], "sign") && argc >= 4) {
        size_t ml = hexin(argv[3], msg, sizeof(msg));
        if (!ed25519_public_key(pk, sk)) return 3;
        if (!ed25519_sign(sig, msg, ml, sk)) return 3;
        hexout("SIG:", sig, 64);
        return 0;
    }
    if (!strcmp(argv[1], "verify") && argc >= 6) {
        uint8_t pub[32];
        size_t ml = hexin(argv[3], msg, sizeof(msg));
        hexin(argv[4], sig, 64);
        hexin(argv[5], pub, 32);
        int ok = ed25519_verify(sig, msg, ml, pub);
        printf("VERIFY:%d\n", ok);
        return ok ? 0 : 1;
    }
    if (!strcmp(argv[1], "nullguard")) {
        int r = ed25519_sign(0, msg, 0, sk) | ed25519_verify(0, msg, 0, sk)
              | ed25519_public_key(0, sk);
        printf("NULLGUARD:%d\n", r);
        return r == 0 ? 0 : 1;
    }
    return 2;
}
"""

CRYPTO_SOURCES = ["Ed25519.cpp", "SHA512.cpp", "Curve25519.cpp",
                  "BigNumberUtil.cpp", "Crypto.cpp", "Hash.cpp"]

# Link stub for the RNG singleton (referenced but never called by the
# sign/verify/derive paths under test; aborts loudly if ever reached).
RNG_STUB_CPP = r"""
#include <cstddef>
#include <cstdint>
#include <cstdlib>
class RNGClass {
public:
    void rand(uint8_t *data, size_t len);
};
void RNGClass::rand(uint8_t *data, size_t len) { (void)data; (void)len; abort(); }
RNGClass RNG;
"""


def _crypto_src_dir():
    env = os.environ.get("CRYPTO_LIB_SRC")
    if env and pathlib.Path(env).is_dir():
        return pathlib.Path(env)
    home = pathlib.Path.home()
    for cand in [
        home / "Documents/Arduino/libraries/Crypto/src",
        home / "Arduino/libraries/Crypto/src",
    ]:
        if (cand / "Ed25519.cpp").exists():
            return cand
    return None


def _build_harness(tmp_path):
    crypto = _crypto_src_dir()
    if shutil.which("g++") is None or crypto is None:
        pytest.skip("needs g++ and rweather Crypto sources (CRYPTO_LIB_SRC)")
    srcs = [tmp_path / "harness.cpp", tmp_path / "rng_stub.cpp", ADAPTER_SRC]
    srcs += [crypto / name for name in CRYPTO_SOURCES]
    (tmp_path / "harness.cpp").write_text(HARNESS_CPP)
    (tmp_path / "rng_stub.cpp").write_text(RNG_STUB_CPP)
    binary = tmp_path / ("harness.exe" if sys.platform == "win32" else "harness")
    proc = subprocess.run(
        ["g++", "-std=c++11", "-O1", "-o", str(binary),
         *(str(s) for s in srcs),
         "-I" + str(ADAPTER_INC), "-I" + str(crypto)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, "host build failed:\n" + proc.stderr[-2000:]
    return binary


def _run(binary, *args):
    proc = subprocess.run([str(binary), *args], capture_output=True,
                          text=True, timeout=120)
    return proc


def test_hostkat_pubkey_matches_repo_vector(tmp_path):
    harness = _build_harness(tmp_path)
    proc = _run(harness, "pubkey", TEST_ED25519_PRIVATE_KEY.hex())
    assert proc.returncode == 0
    assert proc.stdout.strip() == "PUBKEY:" + TEST_ED25519_PUBLIC_KEY.hex()


def test_hostkat_sign_matches_python_byte_exact(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    harness = _build_harness(tmp_path)
    sk = Ed25519PrivateKey.from_private_bytes(TEST_ED25519_PRIVATE_KEY)
    msg = b"SHALLOT-KAT"
    proc = _run(harness, "sign", TEST_ED25519_PRIVATE_KEY.hex(), msg.hex())
    assert proc.returncode == 0
    c_sig = bytes.fromhex(proc.stdout.strip().split("SIG:")[1].strip())
    assert len(c_sig) == 64
    sk.public_key().verify(c_sig, msg)  # strict verifier accepts C signature
    assert sk.sign(msg) == c_sig  # deterministic: byte-exact match


def test_hostkat_repo_blocklist_vector(tmp_path):
    harness = _build_harness(tmp_path)
    bl = TEST_BLOCKLIST_V1
    data_len = 1 + 16 + 1 + 4
    data, sig = bl[:data_len], bl[data_len:]
    proc = _run(harness, "verify", "00", data.hex(), sig.hex(),
                TEST_ED25519_PUBLIC_KEY.hex())
    assert proc.returncode == 0 and "VERIFY:1" in proc.stdout
    bad = bytearray(sig)
    bad[-1] ^= 0x01
    proc = _run(harness, "verify", "00", data.hex(), bytes(bad).hex(),
                TEST_ED25519_PUBLIC_KEY.hex())
    assert proc.returncode == 1 and "VERIFY:0" in proc.stdout


def test_hostkat_null_guards(tmp_path):
    harness = _build_harness(tmp_path)
    proc = _run(harness, "nullguard")
    assert proc.returncode == 0 and "NULLGUARD:0" in proc.stdout


def test_adapter_source_guards():
    """Adapter forwards to the reviewed lib: derive-then-sign order,
    rweather verify arg order, null guards, no vendored curve math."""
    src = ADAPTER_SRC.read_text()
    assert "Ed25519::derivePublicKey(public_key, private_key)" in src
    assert "Ed25519::sign(signature, private_key, public_key, message, message_len)" in src
    assert "Ed25519::verify(signature, public_key, message, message_len)" in src
    assert "if (!signature || !message" in src
    for banned in ["sc_reduce", "hram", "u64 K[80]", "gf121666",
                   "cswap", "scalar_mult", "base_mul"]:
        assert banned not in src, f"vendored math remnant: {banned}"
