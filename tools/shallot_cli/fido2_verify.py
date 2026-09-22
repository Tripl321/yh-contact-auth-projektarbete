"""Verifieraren — hela ALLOW/DENY-beslutet på ett ställe (proof of concept).

Äger first-failure-wins-kontraktet för både mock- och HW-spåret:
unknown/revoked/backend/replay/timeout/origin/rp-id/presence, därefter
UV, signatur och (HW) counter. Ceremony i fido2.py är endast challenge-
lagret; denna modul tar emot det som parameter och importerar aldrig
fido2 (envägsberoende — ingen cykel).

RP-identiteten (expected_origin/expected_rp_id) parametriseras med flit:
fido2 binder SHALLOTs värden, verifieraren jämför mot det den får.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from shallot_cli import fido2_backend, fido2_store

CHALLENGE_TIMEOUT_S = 120


def signed_data(challenge: bytes, origin: str, rp_id: str, user_presence: bool) -> bytes:
    return (bytes(challenge) + b"|" + origin.encode() + b"|"
            + rp_id.encode() + b"|" + (b"UP" if user_presence else b"noUP"))


def _b64unpad(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _client_data_type(client_data) -> str:
    t = getattr(client_data, "type", "")
    return str(getattr(t, "value", t))


def check_backend(credential: dict,
                  expected_backend: str | None) -> str | None:
    """Kontrollera backend-policy utan att konsumera challenge."""
    if expected_backend is None:
        return None
    policy = credential.get("policy")
    if not isinstance(policy, dict) or policy.get("backend") != expected_backend:
        return "wrong-backend"
    return None


def precheck(ceremony, *, credential: dict | None, challenge: bytes,
             origin: str, rp_id: str, user_presence: bool,
             expected_origin: str, expected_rp_id: str,
             expected_backend: str | None = None) -> str | None:
    """Delade billiga kontroller. Returnerar reason eller None vid OK.

    reason-kontraktet ägs här, inte i command-lagret.
    """
    if credential is None:
        return "unknown-credential"
    if credential.get("status") != fido2_store.STATUS_ACTIVE:
        return "revoked-credential"
    reason = check_backend(credential, expected_backend)
    if reason is not None:
        return reason
    slot = ceremony._challenges.get(bytes(challenge).hex())
    if slot is None or slot["used"]:
        return "replay"
    slot["used"] = True
    if ceremony.now_fn() - slot["created"] > CHALLENGE_TIMEOUT_S:
        return "timeout"
    if origin != expected_origin:
        return "wrong-origin"
    if rp_id != expected_rp_id:
        return "wrong-rp-id"
    if not user_presence:
        return "no-user-presence"
    return None


def verify_assertion(ceremony, *, credential: dict | None, challenge: bytes,
                     origin: str, rp_id: str, user_presence: bool,
                     signature: bytes,
                     expected_origin: str, expected_rp_id: str,
                     user_verified: bool = True,
                     require_uv: bool = False,
                     expected_backend: str | None = None) -> tuple[bool, str]:
    """Returnerar (allow, reason-kod). Aldrig undantag för deny-fall."""
    reason = precheck(ceremony, credential=credential, challenge=challenge,
                      origin=origin, rp_id=rp_id,
                      user_presence=user_presence,
                      expected_origin=expected_origin,
                      expected_rp_id=expected_rp_id,
                      expected_backend=expected_backend)
    if reason is not None:
        return False, reason
    if not isinstance(ceremony.backend, fido2_backend.Signer):
        return False, "wrong-backend"
    if require_uv and not user_verified:
        return False, "no-user-verification"
    try:
        credential_id = credential["credential_id"].encode()
        data = signed_data(challenge, origin, rp_id, user_presence)
        signature_bytes = bytes(signature)
    except (KeyError, AttributeError, TypeError):
        return False, "invalid-signature"
    try:
        ok = ceremony.backend.verify(
            credential_id=credential_id,
            signed_data=data, signature=signature_bytes)
    except fido2_backend.BackendUnavailable:
        return False, "backend-unavailable"
    return (True, "ok") if ok else (False, "invalid-signature")


def verify_hw_assertion(*, credential: dict, challenge: bytes,
                        origin: str, rp_id: str,
                        authenticator_data: bytes,
                        client_data_json: bytes, signature: bytes,
                        ceremony,
                        expected_origin: str, expected_rp_id: str,
                        require_uv: bool = False,
                        expected_backend: str | None = None) -> tuple:
    """Verifiera HW-assertion. Returnerar (allow, reason, new_sign_count|None).

    Samma prechecks som mock (replay/timeout/origin/…) plus ECDSA mot
    lagrad publik nyckel och monoton sign-counter (klondetektion).
    Med require_uv krävs UV-flaggan från enheten (PIN/badge), annars
    räcker närvaro.
    """
    reason = precheck(ceremony, credential=credential, challenge=challenge,
                      origin=origin, rp_id=rp_id, user_presence=True,
                      expected_origin=expected_origin,
                      expected_rp_id=expected_rp_id,
                      expected_backend=expected_backend)
    if reason is not None:
        return False, reason, None
    if not credential.get("public_key"):
        return False, "invalid-signature", None
    from fido2.webauthn import AuthenticatorData, CollectedClientData
    from fido2.cose import CoseKey
    try:
        auth_data = AuthenticatorData(bytes(authenticator_data))
        client_data = CollectedClientData(bytes(client_data_json))
    except Exception:
        return False, "invalid-signature", None
    if auth_data.rp_id_hash != hashlib.sha256(rp_id.encode()).digest():
        return False, "invalid-signature", None
    if not auth_data.is_user_present():
        return False, "no-user-presence", None
    if require_uv and not auth_data.is_user_verified():
        return False, "no-user-verification", None
    if (_client_data_type(client_data) != "webauthn.get"
            or not hmac.compare_digest(bytes(client_data.challenge), bytes(challenge))
            or client_data.origin != origin):
        return False, "invalid-signature", None
    stored = credential.get("sign_count", 0)
    new_count = int(auth_data.counter)
    if stored == 0 and new_count == 0:
        pass  # räknare används ej av enheten — ingen klondetektion möjlig
    elif new_count <= stored:
        return False, "clone-detected", None
    try:
        from fido2 import cbor
        key = CoseKey.parse(cbor.decode(_b64unpad(credential["public_key"])))
        key.verify(bytes(authenticator_data)
                   + hashlib.sha256(bytes(client_data_json)).digest(),
                   bytes(signature))
    except Exception:
        return False, "invalid-signature", None
    return True, "ok", new_count
