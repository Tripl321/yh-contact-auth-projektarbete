"""FIDO2-ceremonier för SHALLOT:s härdningsspår (proof of concept).

Kompletterar — ersätter inte — UART/HMAC-autentiseringen mellan PAW
och DEN. FIDO2 verifierar användaridentitet + användarnärvaro för
känsliga administrativa åtgärder; DEN fattar fortsatt lokala
fail-closed beslut för PAW–DEN. Ingen autentisering här ger DEN eller
PAW skrivkommandon — resultatet är endast ett ALLOW/DENY-beslut i text.

Fail-closed-regler (första felet vinner, allt annat är DENY):
  unknown-credential, revoked-credential, replay, timeout,
  wrong-origin, wrong-rp-id, no-user-presence, no-user-verification
  (endast när UV krävs), invalid-signature.
  HW-läget lägger till: no-authenticator, device-error,
  untrusted-attestation, clone-detected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time

from shallot_cli import fido2_backend, fido2_sanitize, fido2_store, fido2_verify

RP_ID = "shallot.local"
ORIGIN = "https://shallot.local"
CHALLENGE_BYTES = 32
# Challenge-timeout + signeringshjälpare ägs av verifieraren (enda källan);
# återexporteras här så befintliga anropare (cmd-lager, tester) är orörda.
CHALLENGE_TIMEOUT_S = fido2_verify.CHALLENGE_TIMEOUT_S
signed_data = fido2_verify.signed_data
_b64unpad = fido2_verify._b64unpad
_client_data_type = fido2_verify._client_data_type

BANNER = "SIMULATED / TEST-ONLY — mock-authenticator, ingen fysisk FIDO2-enhet."

#: Användar-ID:n är anonyma token (aldrig e-post eller personuppgifter).
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

#: Tillåtna UV-policyer (matchar WebAuthn UserVerificationRequirement).
UV_POLICIES = ("required", "preferred", "discouraged")


def _check_uv_policy(user_verification: str) -> str:
    if user_verification not in UV_POLICIES:
        raise ValueError("okänd UV-policy %r (välj: %s)"
                         % (user_verification, "|".join(UV_POLICIES)))
    return user_verification

SCENARIOS = ("success", "unknown-credential", "revoked-credential",
             "wrong-origin", "replay", "timeout", "invalid-signature")


def validate_user(user_id: str) -> str:
    user = (user_id or "").strip()
    if not USER_RE.fullmatch(user):
        raise ValueError("ogiltigt användar-ID %r (tillåt: bokstäver, siffror, ._-; max 64)" % user_id)
    return user


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def approval_fingerprint(credential_id: str, public_key_b64: str | None) -> str:
    """Fingeravtryck för andrahandsverifiering (16 hex).

    fingeravtryck = sha256("<credential_id>|<public_key>")[:16].
    Räkna om var som helst med:
    python3 -c "import hashlib,json; d=json.load(open('fil.json')); \\
    print(hashlib.sha256((d['credential_id']+'|'+(d['public_key'] or '')).encode()).hexdigest()[:16])"
    """
    material = "%s|%s" % (credential_id, public_key_b64 or "")
    return hashlib.sha256(material.encode()).hexdigest()[:16]


class Credential:
    """Lagringsbar credential-post (snitt 1: validering + builders).

    Äger formen {credential_id, user_id, created, status, policy, ...} och
    förbudet mot hemliga fält — store validerar via denna typ i stället för
    egna kontroller (tunna wrappers). Fingerprint/export flyttas hit senare.
    Förbudslistan själv ägs av store (lagringspolicy); upprätthållandet här.
    """

    REQUIRED = ("credential_id", "user_id", "created", "status", "policy")

    def __init__(self, mapping: dict):
        self._data = dict(mapping)

    def to_dict(self) -> dict:
        return dict(self._data)

    @classmethod
    def check_fields(cls, mapping: dict, where: str) -> None:
        """Avvisa förbjudna fält rekursivt (dict + listor). Fail-closed."""
        suffix = " (nycklar sparas aldrig)" if where != "auditpost" else ""
        stack = [mapping]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in fido2_store.FORBIDDEN_FIELDS:
                        raise ValueError(
                            "förbjudet fält i %s: %s%s" % (where, key, suffix))
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)

    @classmethod
    def check_record(cls, mapping: dict) -> None:
        cls.check_fields(mapping, "metadata")
        for req in cls.REQUIRED:
            if req not in mapping:
                raise ValueError("saknar obligatoriskt fält: %s" % req)

    @classmethod
    def create(cls, *, credential_id: str, user_id: str, policy: dict,
               created: str | None = None, status: str | None = None,
               extra: dict | None = None) -> "Credential":
        data = {"credential_id": credential_id, "user_id": user_id,
                "created": created or fido2_store.utcnow(),
                "status": status or fido2_store.STATUS_ACTIVE,
                "policy": dict(policy)}
        if extra:
            data.update(extra)
        cls.check_record(data)
        return cls(data)


class Ceremony:
    """Håller challenge-livscykel (singelbruk + timeout) för en session.

    Endast challenge-lagret bor här; hela ALLOW/DENY-beslutet ägs av
    fido2_verify (metoderna nedan är tunna wrappers som binder SHALLOTs
    RP-identitet).
    """

    def __init__(self, backend=None, rng=None, now_fn=None):
        self.backend = backend or fido2_backend.get_backend("mock")
        self.rng = rng or secrets.token_bytes
        self.now_fn = now_fn or time.time
        self._challenges: dict[str, dict] = {}

    def begin(self) -> bytes:
        challenge = self.rng(CHALLENGE_BYTES)
        self._challenges[challenge.hex()] = {"created": self.now_fn(), "used": False}
        return challenge

    def check_backend(self, credential: dict,
                      expected_backend: str | None) -> str | None:
        """Kontrollera backend-policy utan att konsumera challenge."""
        return fido2_verify.check_backend(credential, expected_backend)

    def precheck(self, *, credential: dict | None, challenge: bytes,
                   origin: str, rp_id: str, user_presence: bool,
                   expected_backend: str | None = None) -> str | None:
        """Delade billiga kontroller. Returnerar reason eller None vid OK."""
        return fido2_verify.precheck(
            self, credential=credential, challenge=challenge,
            origin=origin, rp_id=rp_id, user_presence=user_presence,
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
            expected_backend=expected_backend)

    def verify_assertion(self, *, credential: dict | None, challenge: bytes,
                         origin: str, rp_id: str, user_presence: bool,
                         signature: bytes,
                         user_verified: bool = True,
                         require_uv: bool = False,
                         expected_backend: str | None = None) -> tuple[bool, str]:
        """Returnerar (allow, reason-kod). Aldrig undantag för deny-fall."""
        return fido2_verify.verify_assertion(
            self, credential=credential, challenge=challenge,
            origin=origin, rp_id=rp_id, user_presence=user_presence,
            signature=signature, expected_origin=ORIGIN,
            expected_rp_id=RP_ID, user_verified=user_verified,
            require_uv=require_uv, expected_backend=expected_backend)


def register_user(user_id: str, *, backend=None, rng=None,
                  root=None, user_verification: str = "preferred") -> dict:
    """Registrera credential för användare. Sparar endast sanerad metadata."""
    user = validate_user(user_id)
    _check_uv_policy(user_verification)
    be = backend or fido2_backend.get_backend("mock")
    challenge = (rng or secrets.token_bytes)(CHALLENGE_BYTES)
    credential_id = b64url(hashlib.sha256(
        user.encode() + b"|" + bytes(challenge) + b"|register").digest()[:32])
    data = signed_data(challenge, ORIGIN, RP_ID, True)
    try:
        signature = be.sign(credential_id=credential_id.encode(), signed_data=data)
        valid = be.verify(credential_id=credential_id.encode(),
                          signed_data=data, signature=signature)
    except fido2_backend.BackendUnavailable as e:
        raise RuntimeError(str(e)) from None
    if not valid:
        raise RuntimeError("registrering underkänd: mock-attestation verifierades inte")
    metadata = Credential.create(
        credential_id=credential_id, user_id=user,
        policy={"user_presence": True, "rp_id": RP_ID,
                "origin": ORIGIN, "backend": be.name, "mode": "simulated-test",
                "user_verification": user_verification}).to_dict()
    fido2_store.save_credential(metadata, root=root)
    fido2_store.audit("register", {"user_id": user,
                                   "credential": fido2_sanitize.short_credential(credential_id)},
                      root=root)
    return metadata


#: Attestationsformat RP:n accepterar. "packed" endast som self-attestation
#: (Pico Fido har ingen vendor-CA; x5c saknar trust anchors här och avvisas).
HW_ATTESTATION_FORMATS = ("none", "packed")


def verify_hw_registration(*, attestation_object: bytes, client_data_json: bytes,
                           challenge: bytes, rp_id: str = RP_ID,
                           origin: str = ORIGIN) -> dict:
    """Verifiera HW-registrering (RP-sidan). Returnerar lagringsbar credential-data.

    Kastar ValueError(reason) vid varje avvikelse (fail closed).
    Accepterar fmt "none" samt "packed" self-attestation; allt annat
    (inkl. packed med x5c — inga trust anchors konfigurerade) avvisas.
    """
    from fido2.webauthn import AttestationObject, CollectedClientData
    from fido2.attestation import (AttestationType, InvalidData, InvalidSignature,
                                   NoneAttestation, PackedAttestation)
    try:
        att_obj = AttestationObject(bytes(attestation_object))
        client_data = CollectedClientData(bytes(client_data_json))
        auth_data = att_obj.auth_data
    except Exception as e:
        raise ValueError("untrusted-attestation") from e
    if auth_data.rp_id_hash != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("untrusted-attestation")
    if not auth_data.is_user_present():
        raise ValueError("no-user-presence")
    if (_client_data_type(client_data) != "webauthn.create"
            or not hmac.compare_digest(bytes(client_data.challenge), bytes(challenge))
            or client_data.origin != origin):
        raise ValueError("untrusted-attestation")
    client_data_hash = hashlib.sha256(bytes(client_data_json)).digest()
    try:
        if att_obj.fmt == "none":
            NoneAttestation().verify(att_obj.att_stmt, auth_data, client_data_hash)
            fmt = "none"
        elif att_obj.fmt == "packed":
            result = PackedAttestation().verify(att_obj.att_stmt, auth_data,
                                                client_data_hash)
            if result.attestation_type is not AttestationType.SELF:
                raise ValueError("untrusted-attestation")
            fmt = "packed-self"
        else:
            raise ValueError("untrusted-attestation")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("untrusted-attestation") from e
    cred = auth_data.credential_data
    if cred is None:
        raise ValueError("untrusted-attestation")
    from fido2 import cbor
    try:
        public_key_bytes = cbor.encode(dict(cred.public_key))
    except Exception as e:
        raise ValueError("untrusted-attestation") from e
    return {"credential_id": b64url(bytes(cred.credential_id)),
            "public_key_cose": b64url(public_key_bytes),
            "sign_count": int(auth_data.counter),
            "attestation_fmt": fmt}


def verify_hw_assertion(*, credential: dict, challenge: bytes, origin: str = ORIGIN,
                        rp_id: str = RP_ID, authenticator_data: bytes,
                        client_data_json: bytes, signature: bytes,
                        ceremony: Ceremony,
                        require_uv: bool = False,
                        expected_backend: str | None = None) -> tuple:
    """Verifiera HW-assertion. Returnerar (allow, reason, new_sign_count|None).

    Tunn wrapper som binder SHALLOTs RP-identitet; beslutet ägs av
    fido2_verify (samma prechecks som mock plus ECDSA och monoton
    sign-counter).
    """
    return fido2_verify.verify_hw_assertion(
        credential=credential, challenge=challenge, origin=origin,
        rp_id=rp_id, authenticator_data=authenticator_data,
        client_data_json=client_data_json, signature=signature,
        ceremony=ceremony, expected_origin=ORIGIN, expected_rp_id=RP_ID,
        require_uv=require_uv, expected_backend=expected_backend)


def register_hw_user(user_id: str, *, ctap, root=None,
                     user_verification: str = "preferred") -> dict:
    """Registrera HW-credential för användare. Sparar metadata + publik nyckel."""
    user = validate_user(user_id)
    _check_uv_policy(user_verification)
    challenge = secrets.token_bytes(CHALLENGE_BYTES)
    raw = ctap.register(origin=ORIGIN, rp_id=RP_ID, rp_name="SHALLOT",
                        user_id=user, challenge=challenge,
                        user_verification=user_verification)
    try:
        cred = verify_hw_registration(
            attestation_object=raw["attestation_object"],
            client_data_json=raw["client_data_json"],
            challenge=challenge, rp_id=RP_ID, origin=ORIGIN)
    except (ValueError, KeyError) as e:
        raise RuntimeError("registrering underkänd: %s" % e) from None
    metadata = Credential.create(
        credential_id=cred["credential_id"], user_id=user,
        policy={"user_presence": True, "rp_id": RP_ID, "origin": ORIGIN,
                "backend": "hardware", "mode": "hardware-ctap",
                "attestation": cred["attestation_fmt"],
                "user_verification": user_verification},
        extra={"public_key": cred["public_key_cose"],
               "sign_count": cred["sign_count"]}).to_dict()
    fido2_store.save_credential(metadata, root=root)
    fido2_store.audit("register", {"user_id": user,
                                   "credential": fido2_sanitize.short_credential(
                                       cred["credential_id"]),
                                   "backend": "hardware"},
                      root=root)
    return metadata


def run_scenario(name: str, *, backend=None) -> dict:
    """Kör ett deterministiskt scenario (minneslagring, ingen disk)."""
    if name not in SCENARIOS:
        raise ValueError("okänt scenario: %r (välj: %s)" % (name, "|".join(SCENARIOS)))
    be = backend or fido2_backend.get_backend("mock")
    now = [1000.0]
    cer = Ceremony(backend=be, rng=lambda n: b"\x42" * n, now_fn=lambda: now[0])
    credential = {"credential_id": b64url(b"test-credential-0123456789abcdef"),
                  "user_id": "test-admin", "created": "2026-01-01T00:00:00Z",
                  "status": fido2_store.STATUS_ACTIVE,
                  "policy": {"user_presence": True}}
    out = {"scenario": name,
           "credential": fido2_sanitize.short_credential(credential["credential_id"]),
           "result": "DENY", "reason": "", "decision": "deny (fail closed)"}

    def attempt(**kw):
        args = {"credential": credential, "challenge": kw.get("challenge"),
                "origin": kw.get("origin", ORIGIN), "rp_id": kw.get("rp_id", RP_ID),
                "user_presence": kw.get("user_presence", True),
                "signature": kw.get("signature", b"")}
        return cer.verify_assertion(**args)

    if name == "success":
        ch = cer.begin()
        sig = be.sign(credential_id=credential["credential_id"].encode(),
                      signed_data=signed_data(ch, ORIGIN, RP_ID, True))
        allow, reason = attempt(challenge=ch, signature=sig)
    elif name == "unknown-credential":
        ch = cer.begin()
        sig = be.sign(credential_id="någon-annan".encode(), signed_data=signed_data(ch, ORIGIN, RP_ID, True))
        allow, reason = cer.verify_assertion(
            credential=None, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
            user_presence=True, signature=sig)
    elif name == "revoked-credential":
        credential = dict(credential, status=fido2_store.STATUS_REVOKED)
        ch = cer.begin()
        sig = be.sign(credential_id=credential["credential_id"].encode(),
                      signed_data=signed_data(ch, ORIGIN, RP_ID, True))
        allow, reason = attempt(challenge=ch, signature=sig)
    elif name == "wrong-origin":
        ch = cer.begin()
        sig = be.sign(credential_id=credential["credential_id"].encode(),
                      signed_data=signed_data(ch, "https://evil.example", RP_ID, True))
        allow, reason = attempt(challenge=ch, origin="https://evil.example", signature=sig)
    elif name == "replay":
        ch = cer.begin()
        sig = be.sign(credential_id=credential["credential_id"].encode(),
                      signed_data=signed_data(ch, ORIGIN, RP_ID, True))
        cer.verify_assertion(credential=credential, challenge=ch, origin=ORIGIN,
                             rp_id=RP_ID, user_presence=True, signature=sig)
        allow, reason = attempt(challenge=ch, signature=sig)
    elif name == "timeout":
        ch = cer.begin()
        sig = be.sign(credential_id=credential["credential_id"].encode(),
                      signed_data=signed_data(ch, ORIGIN, RP_ID, True))
        now[0] += CHALLENGE_TIMEOUT_S + 1
        allow, reason = attempt(challenge=ch, signature=sig)
    else:  # invalid-signature
        ch = cer.begin()
        sig = bytearray(be.sign(credential_id=credential["credential_id"].encode(),
                                signed_data=signed_data(ch, ORIGIN, RP_ID, True)))
        sig[0] ^= 0xFF
        allow, reason = attempt(challenge=ch, signature=bytes(sig))

    out["reason"] = reason
    if allow:
        out.update(result="ALLOW", decision="allow")
    return out


def render(res: dict) -> str:
    """Mänsklig text. Alltid banner; aldrig råa hemligheter."""
    lines = [BANNER,
             "scenario : %s" % res["scenario"],
             "credential: %s" % res["credential"],
             "resultat : %s (%s)" % (res["result"], res["reason"]),
             "beslut   : %s" % res["decision"],
             "notera   : FIDO2 skyddar adminidentitet; PAW–DEN skyddas av UART/HMAC."]
    return fido2_sanitize.sanitize("\n".join(lines))
