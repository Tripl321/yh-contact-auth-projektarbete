"""Simulerad lokal datalagring för FIDO2-spåret (proof of concept).

Sparar endast sanerad credential-metadata: credential-ID, användar-ID,
skapad-tid, status och policy — samt publik nyckel och sign-counter för
HW-credentials (aldrig privata nycklar). Privata nycklar eller hemligt
råmaterial sparas aldrig — lagringen avvisar metadata som innehåller
förbjudna fält, på alla kapslingsnivåer.

Standardsökvägen är beständig produktionslagring för MamaBear och
kräver inga miljövariabler; ``SHALLOT_FIDO2_STORE`` väljer en annan rot
vid behov (främst tester, som alltid isoleras dit). Auditloggen är en
append-only JSONL-fil, en post per administrativ åtgärd.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

STORE_ENV = "SHALLOT_FIDO2_STORE"
#: Beständig produktionslagring för MamaBear — fungerar utan miljövariabler.
#: SHALLOT_FIDO2_STORE väljer annan rot vid behov (främst tester).
DEFAULT_ROOT = Path.home() / ".local" / "share" / "shallot" / "fido2"

CREDENTIALS_FILE = "credentials.json"
AUDIT_FILE = "audit.jsonl"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

#: Fält som aldrig får förekomma i lagrad metadata — på någon nivå.
#: "public_key" är avsiktligt tillåten (publik HW-nyckel, behövs för verify).
FORBIDDEN_FIELDS = (
    "private_key",
    "secret",
    "seed",
    "attestation_raw",
    "attestation_object",
    "cbor",
    "authenticator_data",
    "authenticator_data_raw",
    "client_data_json",
    "signature",
    "token",
    "password",
)


def _credential_type():
    """Credential-typen (lazy import: fido2 importerar denna modul i toppen,
    så toppimport här skulle bli en cykel). Upprätthållandet av förbudet
    bor i posten; dessa wrappers delegerar dit."""
    from shallot_cli.fido2 import Credential

    return Credential


def _reject_forbidden_fields(mapping: dict, where: str) -> None:
    _credential_type().check_fields(mapping, where)


#: Enda filnamn som någonsin får läsas/skrivas i lagringsroten.
#: Allt I/O måste gå via _store_file() som verifierar detta + att den
#: slutliga sökvägen stannar inne i roten (S2083: path injection).
#: Admin-session/audit bor här (innehåller aldrig hemligheter — endast
#: kodhashen ligger i OS-lagret, se admin_vault).
_ALLOWED_FILES = frozenset(
    {CREDENTIALS_FILE, AUDIT_FILE, "admin-session.json", "admin-audit.jsonl"}
)


def store_root() -> Path:
    raw = os.environ.get(STORE_ENV)
    if raw is None:
        return DEFAULT_ROOT
    if "\x00" in raw or not raw.strip():
        raise RuntimeError("ogiltig sökväg i %s" % STORE_ENV)
    return Path(raw).expanduser()


def _coerce_base(root: Path | str | None) -> Path:
    base = store_root() if root is None else root
    if isinstance(base, str):
        base = Path(base)
    if not isinstance(base, Path):
        raise RuntimeError("ogiltig lagringsrot: %r" % (root,))
    text = str(base)
    if "\x00" in text or not text.strip():
        raise RuntimeError("ogiltig lagringsrot")
    return base.expanduser()


def _store_file(base: Path, name: str) -> Path:
    """Returnera verifierad sökväg <rot>/<name>.

    Fail-closed: avvisar allt utom allowlistade filnamn och verifierar
    efter resolve() att filen ligger direkt i roten, så varken en
    manipulerad STORE_ENV-rot eller ett root-argument kan styra I/O
    utanför lagringen (t.ex. via ``..``, separatorer eller absolut namn).
    """
    if name not in _ALLOWED_FILES:
        raise RuntimeError("otillåtet filnamn: %r" % (name,))
    resolved_base = _coerce_base(base).resolve()
    candidate = (resolved_base / name).resolve()
    if candidate.parent != resolved_base or candidate.name != name:
        raise RuntimeError("sökväg lämnar lagringsroten")
    return candidate


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path, default):
    if path.name not in _ALLOWED_FILES:
        raise RuntimeError("otillåtet filnamn: %r" % (path.name,))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        raise RuntimeError("kan inte läsa %s: %s" % (path, e)) from None


class Store:
    """Internt lagringsobjekt: deriverar + verifierar sökvägar en gång.

    Publikt funktions-API nedan är tunna wrappers runt denna typ, så
    anropare och tester är orörda. Miljövariabeln läses fortfarande per
    anrop (via _coerce_base) — inget cachas över anrop.
    """

    def __init__(self, root: Path | str | None = None):
        base = _coerce_base(root)
        self._creds = _store_file(base, CREDENTIALS_FILE)
        self._audit = _store_file(base, AUDIT_FILE)

    def load_credentials(self) -> dict:
        data = _read_json(self._creds, {})
        if not isinstance(data, dict):
            raise RuntimeError("credential-lagringen är korrupt (väntar objekt)")
        return data

    def save_credential(self, metadata: dict) -> None:
        _credential_type().check_record(metadata)
        creds = self.load_credentials()
        if metadata["credential_id"] in creds:
            raise ValueError("credential-ID finns redan: registrera inte om")
        creds[metadata["credential_id"]] = metadata
        _write_json(self._creds, creds)

    def set_status(self, credential_id: str, status: str) -> dict:
        if status not in (STATUS_ACTIVE, STATUS_REVOKED):
            raise ValueError("okänd status: %r" % (status,))
        creds = self.load_credentials()
        if credential_id not in creds:
            raise KeyError("okänd credential: %s" % credential_id)
        creds[credential_id]["status"] = status
        _write_json(self._creds, creds)
        return creds[credential_id]

    def update_sign_count(self, credential_id: str, sign_count: int) -> dict:
        if not isinstance(sign_count, int) or sign_count < 0:
            raise ValueError("ogiltig sign_count: %r" % (sign_count,))
        creds = self.load_credentials()
        if credential_id not in creds:
            raise KeyError("okänd credential: %s" % credential_id)
        creds[credential_id]["sign_count"] = sign_count
        _write_json(self._creds, creds)
        return creds[credential_id]

    def update_policy(self, credential_id: str, policy_updates: dict) -> dict:
        if not isinstance(policy_updates, dict) or not policy_updates:
            raise ValueError("policy_updates måste vara en icke-tom dict")
        _reject_forbidden_fields(policy_updates, "policy")
        creds = self.load_credentials()
        if credential_id not in creds:
            raise KeyError("okänd credential: %s" % credential_id)
        policy = creds[credential_id].get("policy", {})
        if not isinstance(policy, dict):
            raise RuntimeError("korrupt policy för credential: %s" % credential_id)
        policy.update(policy_updates)
        creds[credential_id]["policy"] = policy
        _write_json(self._creds, creds)
        return creds[credential_id]

    def audit(self, action: str, details: dict) -> None:
        _reject_forbidden_fields(details, "auditpost")
        line = json.dumps({"ts": utcnow(), "action": action, "details": details})
        try:
            self._audit.parent.mkdir(parents=True, exist_ok=True)
            with open(self._audit, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            raise RuntimeError("kan inte skriva auditlogg: %s" % e) from None

    def read_audit(self, limit: int = 50) -> list:
        try:
            lines = self._audit.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        except OSError as e:
            raise RuntimeError("kan inte läsa auditlogg: %s" % e) from None
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue  # hoppa över korrupta rader, aldrig krascha visning
        return out


def load_credentials(root: Path | None = None) -> dict:
    """Returnerar {credential_id: metadata}. Tom dict om ingen lagring finns."""
    return Store(root).load_credentials()


def _write_json(path: Path, data: dict) -> None:
    if path.name not in _ALLOWED_FILES:
        raise RuntimeError("otillåtet filnamn: %r" % (path.name,))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise RuntimeError("kan inte skriva %s: %s" % (path, e)) from None


def save_credential(metadata: dict, root: Path | None = None) -> None:
    """Spara credential-metadata. Avvisar förbjudna fält och dubbletter."""
    Store(root).save_credential(metadata)


def set_status(credential_id: str, status: str, root: Path | None = None) -> dict:
    """Byt status (active|revoked). Returnerar uppdaterad metadata."""
    return Store(root).set_status(credential_id, status)


def update_sign_count(
    credential_id: str, sign_count: int, root: Path | None = None
) -> dict:
    """Spara ny sign-counter (HW-klondetektion). Returnerar uppdaterad metadata."""
    return Store(root).update_sign_count(credential_id, sign_count)


def update_policy(
    credential_id: str, policy_updates: dict, root: Path | None = None
) -> dict:
    """Slå samman policyfält. Returnerar uppdaterad metadata."""
    return Store(root).update_policy(credential_id, policy_updates)


def audit(action: str, details: dict, root: Path | None = None) -> None:
    """Lägg till en auditpost (append-only). Aldrig hemligheter i details."""
    Store(root).audit(action, details)


def read_audit(root: Path | None = None, limit: int = 50) -> list:
    """Läs de senaste auditposterna (nyast sist)."""
    return Store(root).read_audit(limit)
