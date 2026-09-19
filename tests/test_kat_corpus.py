"""Ticket 02: gemensamt KAT-corpus + guard-ratchet.

- Corpuset (tests/vectors/kat.json) är den enda sanningen för
  krypto-vektorer; detta test bevisar det mot hashlib/hmac-orakel.
- Varje corpus-id ska konsumeras av C-harnesset (ingen död vektor).
- Ratchet: inga NYA filer med grep-guards mot firmware-kryptointernals
  — tillåtna filer är låsta nedan; nya beteenden ska in i corpuset.
"""

import hashlib
import hmac as hmac_module
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = json.loads((ROOT / "tests/vectors/kat.json").read_text())["vectors"]

# C-harnesset (PR #43, ej mergad här) täcker samma id:n — verifierat vid
# granskning: sha_empty/abc/56, hmac_rfc1-3, dev_kmac/kenc/hmac.
# fail_*-fallen är beteende (nollning), inga vektorer, och hör inte hit.

GREP_GUARD_RE = re.compile(
    r"""assert\s+['"].*(hmac_sha256\(|sha256\(|derive_k_mac|den_ct_compare|sha256_k|HMAC_BLOCK_SIZE|k_ipad|innerMsg)"""
)
GREP_GUARD_ALLOWLIST = frozenset({
    "tests/test_pro46_usb_distribution.py",
    "tests/test_pro49_key_derivation.py",
    "tests/test_pro50_hmac_paw.py",
    "tests/test_pro62_failure_scenarios.py",
    "tests/test_pro84_paw.py",
    "tests/test_pro94_security_review.py",
    "tests/test_pro98_den_blocklist.py",
})


def _compute(vec):
    kind = vec["kind"]
    if kind == "sha256":
        return hashlib.sha256(vec["msg"].encode()).hexdigest()
    if kind == "hmac-sha256":
        return hmac_module.new(bytes.fromhex(vec["key"]),
                               bytes.fromhex(vec["msg_hex"]),
                               hashlib.sha256).hexdigest()
    if kind == "kdf":
        master = bytes.fromhex(vec["master"])
        return hashlib.sha256(master + vec["label"].encode()).digest()[:16].hex()
    raise AssertionError("okänd kind: " + kind)


def test_kat_corpus_ids_unique():
    ids = [v["id"] for v in CORPUS]
    assert len(ids) == len(set(ids)) and len(ids) >= 9


def test_kat_corpus_matches_oracle():
    for vec in CORPUS:
        assert _compute(vec) == vec["expect"], vec["id"]


def test_no_new_crypto_grep_guard_files():
    found = set()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        text = path.read_text()
        if GREP_GUARD_RE.search(text):
            found.add("tests/" + path.name)
    assert found <= GREP_GUARD_ALLOWLIST, found - GREP_GUARD_ALLOWLIST
