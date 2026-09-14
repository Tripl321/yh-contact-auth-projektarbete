"""Simulerad lokal datalagring för FIDO2-spåret (proof of concept).

Sparar endast sanerad credential-metadata: credential-ID, användar-ID,
skapad-tid, status och policy. Privata nycklar eller hemligt råmaterial
sparas aldrig — lagringen avvisar nycklar som innehåller förbjudna fält.

Testdata separeras från framtida produktionsdata: standardsökvägen
pekar på en katalog märkt ``test`` och miljövariabeln
``SHALLOT_FIDO2_STORE`` väljer en annan rot vid behov. Auditloggen är
en append-only JSONL-fil, en post per administrativ åtgärd.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

STORE_ENV = "SHALLOT_FIDO2_STORE"
DEFAULT_ROOT = Path.home() / ".local" / "share" / "shallot" / "fido2-test"

CREDENTIALS_FILE = "credentials.json"
AUDIT_FILE = "audit.jsonl"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

#: Fält som aldrig får förekomma i lagrad metadata.
FORBIDDEN_FIELDS = ("private_key", "secret", "seed", "attestation_raw",
                    "cbor", "authenticator_data_raw")


def store_root() -> Path:
    return Path(os.environ.get(STORE_ENV, DEFAULT_ROOT))


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        raise RuntimeError("kan inte läsa %s: %s" % (path, e)) from None


def load_credentials(root: Path | None = None) -> dict:
    """Returnerar {credential_id: metadata}. Tom dict om ingen lagring finns."""
    data = _read_json((root or store_root()) / CREDENTIALS_FILE, {})
    if not isinstance(data, dict):
        raise RuntimeError("credential-lagringen är korrupt (väntar objekt)")
    return data


def _write_json(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise RuntimeError("kan inte skriva %s: %s" % (path, e)) from None


def save_credential(metadata: dict, root: Path | None = None) -> None:
    """Spara credential-metadata. Avvisar förbjudna fält och dubbletter."""
    for field in FORBIDDEN_FIELDS:
        if field in metadata:
            raise ValueError("förbjudet fält i metadata: %s (nycklar sparas aldrig)" % field)
    for req in ("credential_id", "user_id", "created", "status", "policy"):
        if req not in metadata:
            raise ValueError("saknar obligatoriskt fält: %s" % req)
    base = root or store_root()
    creds = load_credentials(base)
    if metadata["credential_id"] in creds:
        raise ValueError("credential-ID finns redan: registrera inte om")
    creds[metadata["credential_id"]] = metadata
    _write_json(base / CREDENTIALS_FILE, creds)


def set_status(credential_id: str, status: str, root: Path | None = None) -> dict:
    """Byt status (active|revoked). Returnerar uppdaterad metadata."""
    if status not in (STATUS_ACTIVE, STATUS_REVOKED):
        raise ValueError("okänd status: %r" % (status,))
    base = root or store_root()
    creds = load_credentials(base)
    if credential_id not in creds:
        raise KeyError("okänd credential: %s" % credential_id)
    creds[credential_id]["status"] = status
    _write_json(base / CREDENTIALS_FILE, creds)
    return creds[credential_id]


def update_sign_count(credential_id: str, sign_count: int, root: Path | None = None) -> dict:
    """Spara ny sign-counter (HW-klondetektion). Returnerar uppdaterad metadata."""
    if not isinstance(sign_count, int) or sign_count < 0:
        raise ValueError("ogiltig sign_count: %r" % (sign_count,))
    base = root or store_root()
    creds = load_credentials(base)
    if credential_id not in creds:
        raise KeyError("okänd credential: %s" % credential_id)
    creds[credential_id]["sign_count"] = sign_count
    _write_json(base / CREDENTIALS_FILE, creds)
    return creds[credential_id]


def update_policy(credential_id: str, policy_updates: dict, root: Path | None = None) -> dict:
    """Slå samman policyfält. Returnerar uppdaterad metadata."""
    if not isinstance(policy_updates, dict) or not policy_updates:
        raise ValueError("policy_updates måste vara en icke-tom dict")
    base = root or store_root()
    creds = load_credentials(base)
    if credential_id not in creds:
        raise KeyError("okänd credential: %s" % credential_id)
    policy = creds[credential_id].get("policy", {})
    if not isinstance(policy, dict):
        raise RuntimeError("korrupt policy för credential: %s" % credential_id)
    policy.update(policy_updates)
    creds[credential_id]["policy"] = policy
    _write_json(base / CREDENTIALS_FILE, creds)
    return creds[credential_id]


def audit(action: str, details: dict, root: Path | None = None) -> None:
    """Lägg till en auditpost (append-only). Aldrig hemligheter i details."""
    for field in FORBIDDEN_FIELDS:
        if field in details:
            raise ValueError("förbjudet fält i auditpost: %s" % field)
    base = root or store_root()
    line = json.dumps({"ts": utcnow(), "action": action, "details": details})
    try:
        base.mkdir(parents=True, exist_ok=True)
        with open(base / AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        raise RuntimeError("kan inte skriva auditlogg: %s" % e) from None


def read_audit(root: Path | None = None, limit: int = 50) -> list:
    """Läs de senaste auditposterna (nyast sist)."""
    path = (root or store_root()) / AUDIT_FILE
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
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
