"""Tester för USB-nyckelsändaren (PRO-48/PRO-46, bänk/testnycklar).

Trådformat pinnat mot tests/vectors/provisioning.json + firmware:
HANDSHAKE [0xA1, target] -> READY [0xA2, id×4] -> KEY_DATA (22 byte)
-> STORED [0xA4, sha256(key)[:4]] / ERROR [0xA5]. Inga riktiga
hemligheter: fast testvektor, aldrig i loggar.
"""

import hashlib
import json
import pathlib
import zlib

import pytest

from shallot_cli import provision

VECTORS = json.loads((pathlib.Path(__file__).resolve().parent.parent.parent.parent
                      / "tests" / "vectors" / "provisioning.json").read_text(encoding="utf-8"))

TEST_KEY = bytes(range(16))


def _packet(pid):
    for p in VECTORS["packets"]:
        if p["id"] == pid:
            return p
    raise AssertionError(pid)


def test_handshake_bytes_match_vectors():
    assert provision.build_handshake("paw") == bytes([0xA1, 0x02])
    assert provision.build_handshake("den") == bytes([0xA1, 0x01])
    vec = _packet("handshake")
    assert vec["type"] == 0xA1
    with pytest.raises(ValueError):
        provision.build_handshake("router")


def test_key_data_matches_vector_crc():
    vec = _packet("key_data")
    pkt = provision.build_key_data(TEST_KEY)
    assert pkt[0] == 0xA3 and pkt[1] == 16 and pkt[2:18] == TEST_KEY
    assert pkt[18:22].hex() == vec["expect_crc_be"] == "cecee288"
    assert pkt[18:22] == zlib.crc32(TEST_KEY).to_bytes(4, "big")
    assert len(pkt) == 22


def test_all_zero_key_refused_before_touching_device():
    with pytest.raises(ValueError):
        provision.build_key_data(bytes(16))


def test_ready_parse():
    assert provision.parse_ready(bytes([0xA2]) + b"PAW1") == b"PAW1"
    assert provision.parse_ready(bytes([0xA2, 0x01])) is None
    assert provision.parse_ready(bytes([0xA5])) is None
    assert provision.parse_ready(b"") is None


def test_stored_verify_uses_sha256_fingerprint():
    fp = hashlib.sha256(TEST_KEY).digest()[:4]
    assert provision.expected_fingerprint(TEST_KEY) == fp
    assert provision.parse_stored(bytes([0xA4]) + fp, TEST_KEY) is True
    assert provision.parse_stored(bytes([0xA4]) + b"\x00\x00\x00\x00", TEST_KEY) is False
    with pytest.raises(provision.ProvisionError):
        provision.parse_stored(bytes([0xA5]), TEST_KEY)
    with pytest.raises(provision.ProvisionError):
        provision.parse_stored(b"\xA4\x01\x02", TEST_KEY)


class FakeTransport:
    """Skriptad enhet: kö av svar, loggar allt skrivet."""

    def __init__(self, replies):
        self._replies = [bytes(r) for r in replies]
        self.written = bytearray()

    def write(self, data):
        self.written += bytes(data)

    def read(self, n, timeout=1.0):
        if not self._replies:
            return b""
        chunk = self._replies[0][:n]
        self._replies[0] = self._replies[0][n:]
        if not self._replies[0]:
            self._replies.pop(0)
        return bytes(chunk)


def test_full_flow_paw_grants_and_audits_without_secrets():
    fp = hashlib.sha256(TEST_KEY).digest()[:4]
    t = FakeTransport([bytes([0xA2]) + b"PAW1", bytes([0xA4]) + fp])
    res = provision.provision_device(t, "paw", TEST_KEY)
    assert res["result"] == "granted"
    assert res["device_id"] == b"PAW1" and res["fingerprint"] == fp
    assert bytes(t.written[:2]) == bytes([0xA1, 0x02])
    assert bytes(t.written[2:24]) == provision.build_key_data(TEST_KEY)
    for entry in res["audit"]:
        blob = json.dumps(entry)
        assert TEST_KEY.hex() not in blob


def test_full_flow_den_uses_target_01():
    fp = hashlib.sha256(TEST_KEY).digest()[:4]
    t = FakeTransport([bytes([0xA2]) + b"DEN\x01", bytes([0xA4]) + fp])
    res = provision.provision_device(t, "den", TEST_KEY)
    assert res["result"] == "granted"
    assert bytes(t.written[:2]) == bytes([0xA1, 0x01])


def test_open_provision_rejects_bad_port():
    from shallot_cli import serial_adapters
    with pytest.raises(RuntimeError):
        serial_adapters.open_provision("")
    with pytest.raises(RuntimeError):
        serial_adapters.open_provision("x\x00y")


def test_timeout_fails_closed():
    t = FakeTransport([])
    entries = []
    with pytest.raises(provision.ProvisionError, match="timeout"):
        provision.provision_device(t, "paw", TEST_KEY, timeout=0.01,
                                   audit=entries)
    assert entries == [{"action": "provision",
                        "details": {"target": "paw", "result": "DENY",
                                    "reason": "timeout"}}]


def test_deny_paths_leave_exactly_one_audit_entry():
    cases = [
        ([bytes([0xA2]) + b"PAW1", bytes([0xA5])], "device-error"),
        ([bytes([0xA2]) + b"PAW1", bytes([0xA4]) + b"\xDE\xAD\xBE\xEF"],
         "fingerprint-mismatch"),
        ([b"\x00\x00\x00\x00\x00"], "bad-ready"),
    ]
    for replies, reason in cases:
        entries = []
        with pytest.raises(provision.ProvisionError):
            provision.provision_device(FakeTransport(replies), "paw",
                                       TEST_KEY, timeout=0.05, audit=entries)
        assert [e["details"]["reason"] for e in entries] == [reason]


def test_device_error_fails_closed():
    t = FakeTransport([bytes([0xA2]) + b"PAW1", bytes([0xA5])])
    with pytest.raises(provision.ProvisionError, match="ERROR"):
        provision.provision_device(t, "paw", TEST_KEY)


def test_wrong_fingerprint_fails_closed():
    t = FakeTransport([bytes([0xA2]) + b"PAW1", bytes([0xA4]) + b"\xDE\xAD\xBE\xEF"])
    with pytest.raises(provision.ProvisionError, match="fingeravtryck"):
        provision.provision_device(t, "paw", TEST_KEY)
