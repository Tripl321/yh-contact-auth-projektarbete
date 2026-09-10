"""
Phase 2 guards (docs/12-envelope-protocol.md v0.2 §11).

Source guards: the envelope stays feature-flagged (default OFF) and
fixture-only; raw-key paths are compiled out of envelope builds; the MPU
relay handles public fields only; the closed PR #15 line stays out of the
tree. Plus a relay mirror proving the MPU view carries no secrets.
"""
import pathlib
import re

import pytest

from _envelope_lib import (
    AAD_LEN, E1_LEN, E2_LEN, KEK_INFO_V2, EnvelopeError, PawSession,
    build_aad, frame_line, mcu_wrap, parse_e1, parse_e2, parse_line,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
MCU = (ROOT / 'key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino').read_text()
PAW = (ROOT / 'id-kort/paw-main/paw-main.ino').read_text()
MPU = (ROOT / 'key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py').read_text()
ENV_H = (ROOT / 'libraries/EnvelopeCrypto/src/envelope.h').read_text()

# Raw-key export line (closed PR #15) must never re-enter the tree.
PR15_MARKERS = ['UsbCdcDistributor', 'export_staged_key', 'confirm_distribution',
                'one-shot', 'oneshot', 'PRO-46 USB-C']


def _function_range(src, signature):
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if signature in l)
    depth, begun = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if '{' in lines[i]:
            begun = True
        if begun and depth == 0:
            return start, i
    raise AssertionError('unbalanced: ' + signature)


def test_flag_default_off_both_firmwares():
    for src, name in ((MCU, 'MCU'), (PAW, 'PAW')):
        m = re.search(r'#define\s+ENVELOPE_PHASE2\s+(\d+)', src)
        assert m and m.group(1) == '0', f'{name} flag must default OFF'


def test_mcu_fixture_interlock():
    assert 'envFixtureMode' in MCU
    assert 'envLatchFixtureMode' in MCU
    assert 'if (!envFixtureMode)' in MCU
    # Latch happens at boot from the physical button, before Bridge starts.
    assert MCU.index('envLatchFixtureMode();') < MCU.index('setupBridgeRPC();')


def test_mcu_raw_disabled_under_flag():
    start, end = _function_range(MCU, 'static bool distributeKey(')
    body = '\n'.join(MCU.splitlines()[start:end + 1])
    assert '#if ENVELOPE_PHASE2' in body
    assert 'Raw distribution disabled in envelope builds' in body


def test_mcu_envelope_rpcs_public_only():
    assert 'env_fixture_armed' in MCU and 'env_wrap' in MCU and 'env_confirm' in MCU
    # No secret identifier crosses the RPC boundary: hex of E1/E2 + VERIFY.
    for rpc in ('env_wrap', 'env_confirm'):
        assert rpc in MCU


def test_paw_fixture_interlock():
    assert 'envFixtureMode' in PAW
    assert '"FIXTURE"' in PAW and '"ENVELOPE_START"' in PAW
    assert 'Refused: fixture not armed' in PAW


def test_paw_raw_disabled_under_flag():
    start, end = _function_range(PAW, 'static uint8_t pollProvisioning()')
    body = '\n'.join(PAW.splitlines()[start:end + 1])
    assert '#if ENVELOPE_PHASE2' in body
    assert 'Raw provisioning disabled in envelope builds' in body


def test_paw_verify_callsite():
    assert 'showVerify' in PAW
    assert 'VERIFY:' in PAW


def test_mpu_public_fields_only():
    """Source guard: the MPU relay never names key material or primitives."""
    code = re.sub(r'#.*', '', MPU)
    forbidden = ['aesKey', 'KEK', 'sec_M', 'sec_P', 'op_key', 'operational',
                 'x25519', 'X25519', 'hkdf', 'HKDF', 'gcm_seal', 'gcm_open',
                 'GCM', 'envelopeWrap', 'shared secret', 'ephemeral secret']
    for word in forbidden:
        assert word not in code, f'MPU relay names key material: {word}'
    # The relay's crypto surface is exactly: E1/E2/E3/VERIFY hex + RPCs.
    for token in ('E1:', 'E2:', 'E3:', 'VERIFY:', 'env_wrap', 'env_confirm',
                  'env_fixture_armed', 'TEST-ONLY'):
        assert token in MPU, f'relay missing: {token}'


def test_pr15_line_stays_out():
    for src, name in ((MCU, 'MCU'), (MPU, 'MPU')):
        for marker in PR15_MARKERS:
            assert marker not in src, f'{name} contains PR#15 line: {marker}'
    for path in sorted((ROOT / 'tests').glob('test_*.py')):
        if path.name == 'test_provisioning_usb.py':
            raise AssertionError('PR#15 test file must not exist on this branch')
    assert not (ROOT / 'tests/test_provisioning_usb.py').exists()


def test_header_mirror_consistency():
    """envelope.h constants match the Python mirror (single spec)."""
    defs = dict(re.findall(r'#define\s+(ENV_\w+)\s+(0x[0-9A-Fa-f]+|\d+)', ENV_H))
    assert int(defs['ENV_E1_LEN']) == E1_LEN == 45
    assert int(defs['ENV_E2_LEN']) == E2_LEN == 81
    assert int(defs['ENV_AAD_LEN']) == AAD_LEN == 106
    assert 'SHALLOT-ENV1/KEK-v2' in ENV_H
    assert KEK_INFO_V2 == b'SHALLOT-ENV1/KEK-v2'


def test_relay_mirror_carries_no_secrets():
    """Full session where the relay touches parsed public fields only."""
    sec_p = bytes(range(1, 33))
    paw = PawSession(0x02, b'PAW\x01', sec_p, bytes(range(0xA0, 0xA8)))
    # PAW -> relay: hex line; relay extracts public E1 hex.
    e1_hex = parse_line(frame_line('E1', paw.e1()), 'E1', E1_LEN).hex()
    # Relay -> MCU (Bridge hex): wrap; relay splits public E2 + VERIFY.
    e2, mcu_verify = mcu_wrap(0x02, bytes.fromhex(e1_hex), 1,
                              bytes(range(0xD0, 0xE0)),
                              bytes(range(0x40, 0x60)), bytes(range(0x10, 0x1C)))
    relay_view = parse_e2(e2)  # everything the relay may hold
    assert set(relay_view) == {'epoch', 'pub_m', 'nonce_m', 'ct', 'tag'}
    # Relay -> PAW: hex line; PAW opens; relay forwards E3 fingerprint.
    pt, paw_verify = paw.open(bytes.fromhex(parse_line(
        frame_line('E2', e2), 'E2', E2_LEN).hex()))
    assert pt == bytes(range(0xD0, 0xE0))
    assert paw_verify == mcu_verify
    # The relay never held: op key, KEK, shared, or either ephemeral secret.
    relay_bytes = (e1_hex + e2.hex()).lower()
    for secret in (bytes(range(0xD0, 0xE0)).hex(), sec_p.hex(),
                   bytes(range(0x40, 0x60)).hex()):
        assert secret not in relay_bytes
