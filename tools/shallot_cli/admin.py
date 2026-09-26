"""Admin-upplevelse för SHALLOT CLI (proof of concept).

Interaktiv inloggning = FIDO2-assertion (mock eller fysisk) + sexsiffrig
installationskod. Lyckad inloggning öppnar en session med 15 minuters
glidande inaktivitetstid. Fem felaktiga kodförsök låser koden tills en ny
FIDO2-ceremoni genomförts. Endast kodens saltade hash sparas — i OS:ets
säkra lagring (admin_vault), aldrig koden själv. Fysisk återställning
(färsk HW-assertion + --confirm) är enda sättet att skapa ny kod, även
vid första tillfället (bootstrap).

Känsliga åtgärder kräver giltig session (require_session — avsedd söm
även för framtida flash/provision/blocklist-kommandon) och --confirm
(check_confirm). Allt väsentligt journalförs som JSONL utan hemligheter.
Privata nycklar hanteras aldrig här: koden läses med getpass (eko av),
visas en gång vid skapande och loggas aldrig.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time

from shallot_cli import admin_vault, fido2, fido2_backend, fido2_store
from shallot_cli.fido2_store import _coerce_base, _store_file

SESSION_TIMEOUT_S = 900  # 15 minuters glidande inaktivitetstid
MAX_CODE_ATTEMPTS = 5  # därefter lås tills ny FIDO2-ceremoni
PBKDF2_ITERATIONS = 600_000
CODE_RE = r"^\d{6}$"

SESSION_FILE = "admin-session.json"
AUDIT_FILE = "admin-audit.jsonl"

STEP_NAMES = (
    "Anslutning",
    "Enhetsidentifiering",
    "Admin-verifiering",
    "Kodverifiering",
    "Session",
    "Revisionslogg",
)


class AdminDenied(RuntimeError):
    """Nekad Admin-åtgärd (fail closed) — mappas till exit 1 av anropare."""


class Steps:
    """Numrerad progress med tydlig OK/NEKAD-feedback per steg."""

    def __init__(self, names=STEP_NAMES):
        self._names = list(names)
        self._i = 0

    def ok(self, name: str, detail: str = "") -> None:
        self._i += 1
        extra = " — %s" % detail if detail else ""
        print("  [%d/%d] %s … OK%s" % (self._i, len(self._names), name, extra))

    def fail(self, name: str, why: str) -> None:
        self._i += 1
        print("  [%d/%d] %s … NEKAD (%s)" % (self._i, len(self._names), name, why))


def _state_path():
    return _store_file(_coerce_base(None), SESSION_FILE)


def _audit_path():
    return _store_file(_coerce_base(None), AUDIT_FILE)


def _default_state() -> dict:
    return {"session": None, "code_attempts": 0, "code_locked": False}


def _load_state() -> dict:
    try:
        data = json.loads(_state_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _default_state()
    except (OSError, ValueError) as e:
        raise AdminDenied("kan inte läsa Admin-tillstånd: %s" % e) from None
    if not isinstance(data, dict):
        raise AdminDenied("korrupt Admin-tillstånd.")
    state = _default_state()
    state.update({k: data.get(k, v) for k, v in state.items()})
    return state


def _save_state(state: dict) -> None:
    path = _state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)  # best effort; innehållet är icke-hemligt
        except OSError:
            pass
    except OSError as e:
        raise AdminDenied("kan inte spara Admin-tillstånd: %s" % e) from None


def audit_admin(action: str, details: dict) -> None:
    """Journalför Admin-händelse (JSONL, append-only). Aldrig hemligheter."""
    for key in details:
        if key in fido2_store.FORBIDDEN_FIELDS:
            raise ValueError("förbjudet fält i auditpost: %s" % key)
    line = json.dumps(
        {"ts": fido2_store.utcnow(), "action": action, "details": details}
    )
    path = _audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        raise AdminDenied("kan inte skriva revisionslogg: %s" % e) from None


def hash_code(code: str, salt: bytes | None = None) -> dict:
    """Salta + hasha installationskod. Returnerar lagringsbar post."""
    raw = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", code.encode(), raw, PBKDF2_ITERATIONS)
    return {"salt": raw.hex(), "hash": digest.hex(), "iterations": PBKDF2_ITERATIONS}


def verify_code(code: str, record: dict) -> bool:
    """Jämför kod mot lagrad post (konstanttid). Aldrig undantag."""
    try:
        expect = bytes.fromhex(record["hash"])
        salt = bytes.fromhex(record["salt"])
        rounds = int(record.get("iterations", 0))
    except (KeyError, ValueError, TypeError):
        return False
    if rounds <= 0:
        return False
    got = hashlib.pbkdf2_hmac("sha256", code.encode(), salt, rounds)
    return hmac.compare_digest(got, expect)


def _session_valid(state: dict, now: float) -> bool:
    sess = state.get("session")
    if not isinstance(sess, dict):
        return False
    try:
        return now - float(sess["last_activity"]) <= SESSION_TIMEOUT_S
    except (KeyError, ValueError, TypeError):
        return False


def require_session(action: str, now: float | None = None) -> dict:
    """Kräv giltig session för en känslig åtgärd. Rör (glidande) vid OK.

    Sömmen även för framtida flash/provision/blocklist-kommandon.
    Kastar AdminDenied vid saknad/utgången session (exit 1 hos anropare).
    """
    now = time.time() if now is None else now
    state = _load_state()
    if not _session_valid(state, now):
        state["session"] = None
        _save_state(state)
        audit_admin("auth-denied", {"action": action, "reason": "no-session"})
        raise AdminDenied("ingen giltig Admin-session — logga in: shallot admin login")
    state["session"]["last_activity"] = now
    _save_state(state)
    return state["session"]


def check_confirm(confirm: bool, op: str) -> None:
    """Kräv explicit --confirm för känsliga åtgärder (exit 2 hos anropare)."""
    if not confirm:
        raise ValueError("åtgärden %s kräver --confirm." % op)


def _pick_admin_credential(user_id: str, credential: str | None) -> dict | None:
    try:
        creds = {
            c: m
            for c, m in fido2_store.load_credentials().items()
            if m.get("user_id") == user_id
        }
    except RuntimeError:
        return None
    if credential:
        return creds.get(credential)
    if len(creds) == 1:
        return next(iter(creds.values()))
    return None


def _mock_assertion_ok(user_id: str, cred: dict) -> tuple[bool, str]:
    cer = fido2.Ceremony()
    challenge = cer.begin()
    data = fido2.signed_data(challenge, fido2.ORIGIN, fido2.RP_ID, True)
    sig = cer.backend.sign(
        credential_id=cred["credential_id"].encode(), signed_data=data
    )
    return cer.verify_assertion(
        credential=cred,
        challenge=challenge,
        origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID,
        user_presence=True,
        signature=sig,
        user_verified=True,
        expected_backend="mock",
    )


def _hardware_assertion_ok(user_id: str) -> tuple[bool, str]:
    """Färsk HW-assertion för användaren (fysisk närvaro). Aldrig undantag."""
    creds = {
        c: m
        for c, m in fido2_store.load_credentials().items()
        if m.get("user_id") == user_id
        and m.get("status") == fido2_store.STATUS_ACTIVE
        and isinstance(m.get("policy"), dict)
        and m["policy"].get("backend") == "hardware"
    }
    if len(creds) != 1:
        return False, "no-hw-credential"
    cred = next(iter(creds.values()))
    try:
        devs = fido2_backend.CtapHidBackend().describe_devices()
    except (fido2_backend.DeviceError, RuntimeError):
        return False, "device-error"
    if not devs:
        return False, "device-error"
    cer = fido2.Ceremony()
    challenge = cer.begin()
    try:
        raw = fido2_backend.CtapHidBackend().authenticate(
            origin=fido2.ORIGIN,
            rp_id=fido2.RP_ID,
            challenge=challenge,
            credential_id=fido2._b64unpad(cred["credential_id"]),
            user_verification="preferred",
        )
    except (
        fido2_backend.DeviceNotFound,
        fido2_backend.DeviceError,
        RuntimeError,
        ValueError,
    ):
        return False, "device-error"
    allow, reason, new_count = fido2.verify_hw_assertion(
        credential=cred,
        challenge=challenge,
        origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID,
        authenticator_data=raw["authenticator_data"],
        client_data_json=raw["client_data_json"],
        signature=raw["signature"],
        ceremony=cer,
        expected_backend="hardware",
    )
    if allow:
        try:
            fido2_store.update_sign_count(cred["credential_id"], new_count)
        except (KeyError, ValueError, RuntimeError):
            pass
    return allow, reason


def run_login(
    user: str, credential: str | None = None, mock: bool = False, vault=None
) -> int:
    """Interaktiv Admin-inloggning: FIDO2 + installationskod. 0/1/2.

    Standardläge är fysisk authenticator (ingen flagga). Mockat läge
    kräver explicit mock=True (--mock) och märks SIMULATED / TEST-ONLY.
    """
    steps = Steps()
    try:
        user_id = fido2.validate_user(user)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    vault = admin_vault if vault is None else vault

    # 1. Anslutning: valv + lagring nåbara, kod enrollad?
    try:
        record = vault.load_hash()
        _state_path()
    except RuntimeError as e:
        steps.fail("Anslutning", str(e))
        return 1
    if record is None:
        steps.fail(
            "Anslutning",
            "ingen installationskod — fysisk återställning krävs "
            "(shallot admin reset-code --confirm)",
        )
        audit_admin("auth-denied", {"user_id": user_id, "reason": "no-enrolled-code"})
        return 1
    steps.ok("Anslutning")

    # 2. Enhetsidentifiering.
    if mock:
        print("SIMULATED / TEST-ONLY — mock-authenticator, ingen fysisk enhet.")
        steps.ok("Enhetsidentifiering", "mock")
    else:
        try:
            devs = fido2_backend.CtapHidBackend().describe_devices()
        except (fido2_backend.DeviceError, RuntimeError) as e:
            steps.fail(
                "Enhetsidentifiering",
                "%s (nästa steg: anslut en "
                "FIDO2-authenticator via USB — mockat testläge endast "
                "med --mock)" % e,
            )
            audit_admin("auth-denied", {"user_id": user_id, "reason": "device-error"})
            return 1
        if not devs:
            steps.fail(
                "Enhetsidentifiering",
                "ingen fysisk authenticator hittad (nästa steg: anslut "
                "en FIDO2-authenticator via USB — mockat testläge "
                "endast med --mock)",
            )
            audit_admin("auth-denied", {"user_id": user_id, "reason": "device-error"})
            return 1
        steps.ok("Enhetsidentifiering", "%d enhet(er)" % len(devs))

    # 3. Admin-verifiering (FIDO2). Färsk ceremoni nollställer kodlåset.
    cred = _pick_admin_credential(user_id, credential)
    if not mock:
        allow, reason = _hardware_assertion_ok(user_id)
    elif cred is None:
        allow, reason = False, "unknown-credential"
    else:
        try:
            allow, reason = _mock_assertion_ok(user_id, cred)
        except fido2_backend.BackendUnavailable:
            allow, reason = False, "backend-unavailable"
    state = _load_state()
    if not allow:
        steps.fail("Admin-verifiering", reason)
        audit_admin("auth-denied", {"user_id": user_id, "reason": reason})
        return 1
    steps.ok("Admin-verifiering", "FIDO2")
    if state["code_locked"]:
        # Låst läge: denna färska FIDO2 är själva upplåsningen — koden
        # matas in vid nästa inloggning (ett kodförsök per inloggning,
        # så räknaren nollställs aldrig av FIDO2 i sig).
        state["code_locked"] = False
        state["code_attempts"] = 0
        _save_state(state)
        steps.fail("Kodverifiering", "låst — FIDO2 förnyad, logga in igen för kod")
        audit_admin("auth-denied", {"user_id": user_id, "reason": "locked"})
        return 1

    # 4. Kodverifiering (getpass: inget eko, max ett försök per inloggning).
    try:
        code = getpass.getpass("Installationskod (6 siffror): ")
    except (EOFError, KeyboardInterrupt):
        print("\nAvbrutet — ingen session skapades.", file=sys.stderr)
        return 2
    if not re.fullmatch(CODE_RE, code or "") or not verify_code(code, record):
        state["code_attempts"] += 1
        locked = state["code_attempts"] >= MAX_CODE_ATTEMPTS
        state["code_locked"] = state["code_locked"] or locked
        _save_state(state)
        steps.fail(
            "Kodverifiering",
            "fel kod (%d/%d)%s"
            % (
                state["code_attempts"],
                MAX_CODE_ATTEMPTS,
                " — låst, ny FIDO2 krävs" if locked else "",
            ),
        )
        audit_admin(
            "auth-denied",
            {
                "user_id": user_id,
                "reason": "bad-code",
                "attempt": state["code_attempts"],
            },
        )
        return 1
    steps.ok("Kodverifiering")

    # 5–6. Session + revisionslogg.
    now = time.time()
    state["session"] = {
        "user": user_id,
        "session_id": secrets.token_hex(8),
        "created": now,
        "last_activity": now,
    }
    state["code_attempts"] = 0
    state["code_locked"] = False
    _save_state(state)
    steps.ok("Session", "15 minuters inaktivitetstid")
    audit_admin(
        "login", {"user_id": user_id, "backend": "mock" if mock else "hardware"}
    )
    steps.ok("Revisionslogg")
    print("Inloggad som %s." % user_id)
    return 0


def run_logout() -> int:
    """Avsluta Admin-session. Alltid 0."""
    try:
        state = _load_state()
    except AdminDenied as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    user = (state.get("session") or {}).get("user")
    state["session"] = None
    _save_state(state)
    audit_admin("logout", {"user_id": user})
    print("Utloggad%s." % (" (%s)" % user if user else ""))
    return 0


def run_status() -> int:
    """Visa sessionsstatus (scriptbar grindprob). 0 = giltig, 1 = ingen."""
    try:
        state = _load_state()
    except AdminDenied as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    now = time.time()
    if not _session_valid(state, now):
        print("Ingen giltig Admin-session.")
        return 1
    sess = state["session"]
    left = int(SESSION_TIMEOUT_S - (now - sess["last_activity"]))
    attempts_left = MAX_CODE_ATTEMPTS - state.get("code_attempts", 0)
    try:
        backend = vault_backend_name()
    except RuntimeError:
        backend = "okänt"
    print(
        "Admin-session: %s (giltig i ca %d s till, %d kodförsök kvar, valv: %s)."
        % (sess["user"], max(0, left), max(0, attempts_left), backend)
    )
    return 0


def vault_backend_name() -> str:
    return admin_vault.backend_name()


def run_reset_code(confirm: bool, vault=None) -> int:
    """Fysisk återställning: enda sättet att skapa ny installationskod.

    Kräver --confirm + färsk HW-assertion + (giltig session, utom vid
    bootstrap då ingen kod finns än). Genererad kod visas EN gång och
    måste matas in igen för att aktiveras.
    """
    steps = Steps(
        names=(
            "Session",
            "Bekräftelse",
            "Fysisk närvaro",
            "Ny kod",
            "Lagring",
            "Revisionslogg",
        )
    )
    try:
        check_confirm(confirm, "reset-code")
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    vault = admin_vault if vault is None else vault
    try:
        bootstrap = vault.load_hash() is None
    except RuntimeError as e:
        steps.fail("Session", str(e))
        return 1
    state = _load_state()
    if not bootstrap:
        try:
            sess = require_session("reset-code")
        except AdminDenied as e:
            steps.fail("Session", str(e))
            return 1
        steps.ok("Session", sess["user"])
    else:
        steps.ok("Session", "bootstrap (ingen kod enrollad)")
    steps.ok("Bekräftelse", "--confirm")

    try:
        user_id = fido2.validate_user(
            (state.get("session") or {}).get("user")
            or input("Admin-användare: ").strip()
        )
    except ValueError as e:
        steps.fail("Fysisk närvaro", str(e))
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nAvbrutet — ingen kod skapades.", file=sys.stderr)
        return 2
    allow, reason = _hardware_assertion_ok(user_id)
    if not allow:
        steps.fail("Fysisk närvaro", "%s (kräver fysisk authenticator)" % reason)
        audit_admin(
            "auth-denied",
            {"user_id": user_id, "reason": reason, "action": "reset-code"},
        )
        return 1
    steps.ok("Fysisk närvaro", "HW-assertion")

    code = "%06d" % secrets.randbelow(1_000_000)
    print("Ny installationskod (visas EN gång — skriv upp den nu): %s" % code)
    try:
        again = getpass.getpass("Mata in koden igen för att aktivera: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAvbrutet — ingen kod lagrades.", file=sys.stderr)
        audit_admin(
            "auth-denied",
            {"user_id": user_id, "reason": "aborted", "action": "reset-code"},
        )
        return 2
    if not hmac.compare_digest(again or "", code):
        steps.fail("Ny kod", "matchade inte — ingen kod lagrades")
        audit_admin(
            "auth-denied",
            {"user_id": user_id, "reason": "mismatch", "action": "reset-code"},
        )
        return 1
    steps.ok("Ny kod", "bekräftad av operatören")
    try:
        vault.store_hash(hash_code(code))
    except RuntimeError as e:
        steps.fail("Lagring", str(e))
        return 1
    finally:
        del code
    steps.ok("Lagring", "enbart hash i OS-lagret")
    state["code_attempts"] = 0
    state["code_locked"] = False
    if state.get("session"):
        state["session"]["last_activity"] = time.time()
    _save_state(state)
    audit_admin("reset-code", {"user_id": user_id, "bootstrap": bootstrap})
    steps.ok("Revisionslogg")
    print("Ny installationskod aktiverad.")
    return 0
