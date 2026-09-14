"""`shallot fido2 ...` — FIDO2-härdningsspår (proof of concept, mock som standard).

Ger endast ALLOW/DENY-beslut i text. Ingen autentisering här ger DEN
eller PAW skrivkommandon. All output saneras före visning. Registrering
och spärrning kräver explicit bekräftelse.
"""

from __future__ import annotations

import sys

from shallot_cli import fido2, fido2_backend, fido2_sanitize, fido2_store

HARDWARE_MARKER = "HARDWARE — fysisk authenticator via CTAP2/HID (aldrig mock)."


def _confirm(question: str) -> bool:
    try:
        ans = input("%s [j/N]: " % question).strip().lower()
    except EOFError:
        return False
    return ans in ("j", "ja", "y", "yes")


def _say(text: str) -> None:
    print(fido2_sanitize.sanitize(text))


def _uv_policy(require_uv: bool, credential: dict | None = None) -> str:
    """Effektiv UV-policy: CLI-flagga vinner, annars lagrad policy."""
    if require_uv:
        return "required"
    if credential is not None:
        stored = credential.get("policy", {}).get("user_verification", "preferred")
        if stored in fido2.UV_POLICIES:
            return stored
    return "preferred"


def run_register(user: str, yes: bool = False, hardware: bool = False,
                 require_uv: bool = False) -> int:
    """`shallot fido2 register --user <id> [--hardware] [--require-uv]`."""
    try:
        user_id = fido2.validate_user(user)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if hardware:
        print(HARDWARE_MARKER)
    if not yes:
        _say("Registrera FIDO2-credential för användare %s? (%s)" % (
            user_id, "fysisk authenticator" if hardware else "mock, SIMULATED / TEST-ONLY"))
        if not _confirm("Fortsätt med registrering"):
            print("Avbrutet av användaren — inget registrerades.", file=sys.stderr)
            return 2
    try:
        if hardware:
            meta = fido2.register_hw_user(
                user_id, ctap=fido2_backend.CtapHidBackend(),
                user_verification=_uv_policy(require_uv))
        else:
            meta = fido2.register_user(user_id,
                                       user_verification=_uv_policy(require_uv))
    except (fido2_backend.DeviceNotFound, fido2_backend.DeviceError) as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    except (ValueError, RuntimeError) as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    _say("Registrerad: användare %s credential %s status %s" % (
        meta["user_id"], fido2_sanitize.short_credential(meta["credential_id"]),
        meta["status"]))
    return 0


def _pick_credential(user_id: str, credential: str | None) -> dict | None:
    creds = {c: m for c, m in fido2_store.load_credentials().items()
             if m.get("user_id") == user_id}
    if credential:
        return creds.get(credential)
    if len(creds) == 1:
        # Exakt en credential (aktiv eller spärrad) ger precist DENY-skäl.
        return next(iter(creds.values()))
    return None


def run_authenticate(user: str, credential: str | None = None,
                     hardware: bool = False, require_uv: bool = False) -> int:
    """`shallot fido2 authenticate --user <id> [--credential <id>] [--hardware] [--require-uv]`."""
    try:
        user_id = fido2.validate_user(user)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    try:
        cred = _pick_credential(user_id, credential)
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if cred is None:
        _say("DENY (unknown-credential) användare %s" % user_id)
        fido2_store.audit("authenticate", {"user_id": user_id, "result": "DENY",
                                           "reason": "unknown-credential"})
        return 1
    if hardware and cred.get("policy", {}).get("backend") != "hardware":
        _say("DENY (wrong-backend) användare %s — credential är mock, kräver mock-läge" % user_id)
        fido2_store.audit("authenticate", {"user_id": user_id, "result": "DENY",
                                           "reason": "wrong-backend"})
        return 1
    if not hardware and cred.get("policy", {}).get("backend") == "hardware":
        _say("DENY (wrong-backend) användare %s — credential är HW, kräver --hardware" % user_id)
        fido2_store.audit("authenticate", {"user_id": user_id, "result": "DENY",
                                           "reason": "wrong-backend"})
        return 1
    short = fido2_sanitize.short_credential(cred["credential_id"])
    uv_policy = _uv_policy(require_uv, cred)
    if hardware:
        return _run_authenticate_hw(user_id, cred, short, uv_policy)
    cer = fido2.Ceremony()
    challenge = cer.begin()
    data = fido2.signed_data(challenge, fido2.ORIGIN, fido2.RP_ID, True)
    sig = cer.backend.sign(credential_id=cred["credential_id"].encode(), signed_data=data)
    allow, reason = cer.verify_assertion(
        credential=cred, challenge=challenge, origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID, user_presence=True, signature=sig,
        user_verified=True, require_uv=(uv_policy == "required"))
    fido2_store.audit("authenticate", {"user_id": user_id, "credential": short,
                                       "result": "ALLOW" if allow else "DENY",
                                       "reason": reason})
    if allow:
        _say("ALLOW användare %s credential %s (user_presence=True)" % (user_id, short))
        return 0
    _say("DENY (%s) användare %s credential %s" % (reason, user_id, short))
    return 1


def _run_authenticate_hw(user_id: str, cred: dict, short: str,
                           uv_policy: str = "preferred") -> int:
    """HW-assertion mot fysisk authenticator. Aldrig mock-fallback."""
    print(HARDWARE_MARKER)
    ctap = fido2_backend.CtapHidBackend()
    cer = fido2.Ceremony()
    challenge = cer.begin()
    try:
        raw = ctap.authenticate(origin=fido2.ORIGIN, rp_id=fido2.RP_ID,
                                challenge=challenge,
                                credential_id=fido2._b64unpad(cred["credential_id"]),
                                user_verification=uv_policy)
    except (fido2_backend.DeviceNotFound, fido2_backend.DeviceError) as e:
        _say("DENY (device-error) användare %s — %s" % (user_id, e))
        fido2_store.audit("authenticate", {"user_id": user_id, "credential": short,
                                           "result": "DENY", "reason": "device-error",
                                           "backend": "hardware"})
        return 1
    except RuntimeError as e:  # t.ex. saknat fido2-paket
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    allow, reason, new_count = fido2.verify_hw_assertion(
        credential=cred, challenge=challenge, origin=fido2.ORIGIN, rp_id=fido2.RP_ID,
        authenticator_data=raw["authenticator_data"],
        client_data_json=raw["client_data_json"], signature=raw["signature"],
        ceremony=cer, require_uv=(uv_policy == "required"))
    if allow:
        fido2_store.update_sign_count(cred["credential_id"], new_count)
    fido2_store.audit("authenticate", {"user_id": user_id, "credential": short,
                                       "result": "ALLOW" if allow else "DENY",
                                       "reason": reason, "backend": "hardware"})
    if allow:
        _say("ALLOW användare %s credential %s (HW, sign_count=%d%s)" % (
            user_id, short, new_count,
            ", uv=verified" if uv_policy == "required" else ""))
        return 0
    _say("DENY (%s) användare %s credential %s" % (reason, user_id, short))
    return 1


def run_credential_list() -> int:
    """`shallot fido2 credential list`."""
    try:
        creds = fido2_store.load_credentials()
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if not creds:
        print("Inga credentials registrerade.")
        return 0
    for cid, meta in sorted(creds.items(), key=lambda kv: kv[1].get("created", "")):
        _say("%s  användare %s  status %s  skapad %s" % (
            fido2_sanitize.short_credential(cid), meta.get("user_id"),
            meta.get("status"), meta.get("created")))
    return 0


def run_credential_revoke(credential: str, yes: bool = False) -> int:
    """`shallot fido2 credential revoke --credential <id>`."""
    short = fido2_sanitize.short_credential(credential)
    if not yes:
        _say("Spärra credential %s? Spärrade credentials nekas (fail closed)." % short)
        if not _confirm("Fortsätt med spärrning"):
            print("Avbrutet av användaren — inget spärrades.", file=sys.stderr)
            return 2
    try:
        meta = fido2_store.set_status(credential, fido2_store.STATUS_REVOKED)
    except (KeyError, ValueError, RuntimeError) as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1 if isinstance(e, (KeyError, RuntimeError)) else 2
    fido2_store.audit("revoke", {"credential": short, "user_id": meta.get("user_id")})
    _say("Spärrad: credential %s (tidigare status active)" % short)
    return 0


def run_credential_set_policy(credential: str, user_verification: str,
                              yes: bool = False) -> int:
    """`shallot fido2 credential set-policy --credential <id> --user-verification <p>`."""
    short = fido2_sanitize.short_credential(credential)
    if user_verification not in fido2.UV_POLICIES:
        print("error: okänd UV-policy %r (välj: %s)"
              % (user_verification, "|".join(fido2.UV_POLICIES)), file=sys.stderr)
        return 2
    try:
        creds = fido2_store.load_credentials()
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    meta = creds.get(credential)
    if meta is None:
        _say("okänd credential %s" % short)
        return 2
    old = meta.get("policy", {}).get("user_verification", "preferred")
    if old == user_verification:
        _say("Oförändrat: credential %s har redan uv %s." % (short, old))
        return 0
    if not yes:
        _say("Ändra UV-policy för credential %s: %s → %s?" % (short, old, user_verification))
        _say("Verkställs vid nästa authenticate (fail closed utan UV-flagg vid 'required').")
        if not _confirm("Fortsätt med policyändring"):
            print("Avbrutet av användaren — policyn är oförändrad.", file=sys.stderr)
            return 2
    try:
        fido2_store.update_policy(credential, {"user_verification": user_verification})
    except (KeyError, ValueError, RuntimeError) as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    fido2_store.audit("set-policy", {"credential": short,
                                     "user_id": meta.get("user_id"),
                                     "user_verification": {"old": old, "new": user_verification}})
    _say("Policy uppdaterad: credential %s uv %s → %s." % (short, old, user_verification))
    return 0


def run_credential_status(credential: str) -> int:
    """`shallot fido2 credential status --credential <id>`."""
    try:
        creds = fido2_store.load_credentials()
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    meta = creds.get(credential)
    if meta is None:
        _say("okänd credential %s" % fido2_sanitize.short_credential(credential))
        return 2
    _say("credential %s  användare %s  status %s  skapad %s  backend %s  uv %s  user_presence=%s" % (
        fido2_sanitize.short_credential(credential), meta.get("user_id"),
        meta.get("status"), meta.get("created"),
        meta.get("policy", {}).get("backend"),
        meta.get("policy", {}).get("user_verification", "preferred"),
        meta.get("policy", {}).get("user_presence")))
    _say("fingeravtryck %s  (verifiera mot exportfil före godkännande hos MamaBear)" % (
        fido2.approval_fingerprint(credential, meta.get("public_key"))))
    return 0


def run_device_list() -> int:
    """`shallot fido2 device list` — skrivfri CTAP-enumerering."""
    try:
        infos = fido2_backend.CtapHidBackend().describe_devices()
    except RuntimeError as e:  # saknat fido2-paket
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    except fido2_backend.DeviceError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if not infos:
        print("Inga FIDO2-authenticators hittade — anslut enheten via USB.")
        return 0
    for info in infos:
        serial = " serienummer %s" % info["serial"] if info["serial"] else ""
        _say("Hittad: %s%s (CTAP %s)" % (info["product"], serial, info["version"]))
    return 0


def run_credential_export(credential: str, output: str) -> int:
    """`shallot fido2 credential export --credential <id> --output <fil>`.

    Skriver endast publik metadata (aldrig hemligheter) för godkännande
    hos MamaBear. Skriver över filen om den redan finns.
    """
    import json
    try:
        creds = fido2_store.load_credentials()
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    meta = creds.get(credential)
    if meta is None:
        _say("okänd credential %s" % fido2_sanitize.short_credential(credential))
        return 2
    from pathlib import Path
    out_path = Path(output)
    if out_path.parent != Path(".") and not out_path.parent.is_dir():
        print("error: målkatalogen finns inte: %s" % out_path.parent, file=sys.stderr)
        return 1
    doc = {
        "format": "shallot-fido2-approval/1",
        "user_id": meta.get("user_id"),
        "credential_id": credential,
        "public_key": meta.get("public_key"),
        "rp_id": meta.get("policy", {}).get("rp_id", fido2.RP_ID),
        "origin": meta.get("policy", {}).get("origin", fido2.ORIGIN),
        "backend": meta.get("policy", {}).get("backend"),
        "attestation": meta.get("policy", {}).get("attestation"),
        "user_verification": meta.get("policy", {}).get("user_verification", "preferred"),
        "registered": meta.get("created"),
        "status": meta.get("status"),
        "fingerprint": fido2.approval_fingerprint(credential, meta.get("public_key")),
        "exported_at": fido2_store.utcnow(),
        "scope_note": ("Endast publik metadata. Privat nyckel lämnar aldrig "
                       "authenticatorn. Godkännande hos MamaBear är bokföring, "
                       "ännu ej verkställighet."),
    }
    try:
        out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        print("error: kunde inte skriva %s: %s" % (out_path, e), file=sys.stderr)
        return 1
    fido2_store.audit("export", {"user_id": meta.get("user_id"),
                                 "credential": fido2_sanitize.short_credential(credential),
                                 "output": str(out_path)})
    _say("Exporterad: %s  fingeravtryck %s" % (out_path, doc["fingerprint"]))
    return 0


def run_simulate(scenario: str) -> int:
    """`shallot fido2 simulate --scenario <namn>`."""
    try:
        res = fido2.run_scenario(scenario)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print(fido2.render(res))
    return 0


def run_audit(limit: int = 20) -> int:
    """Visa senaste auditposter (används av TUI:t)."""
    try:
        entries = fido2_store.read_audit(limit=limit)
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if not entries:
        print("Auditloggen är tom.")
        return 0
    for entry in entries:
        _say("%s  %s  %s" % (entry.get("ts"), entry.get("action"), entry.get("details")))
    return 0
