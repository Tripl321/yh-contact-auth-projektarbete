"""OS-säker lagring för Admin-kodhashen (proof of concept).

Endast salt + PBKDF2-hash lagras här — aldrig installationskoden själv.
Backend väljs efter plattform (två verkliga adaptrar, ingen tyst fallback):

- macOS: Keychain via systemets ``security``-binär (BatchMode-tänk:
  shell=False, ingen prompt — misslyckas fail-closed i stället).
- Linux: Secret Service via ``secret-tool`` (hemligheten på stdin,
  aldrig i argv).

Finns ingen av dem: fail-closed RuntimeError i stället för att
degradera till fil. Anropare injicerar fake-valv i tester (samma
store_hash/load_hash/delete_hash-form).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

SERVICE = "shallot-admin"
ACCOUNT = "install-code-hash"


def backend_name() -> str:
    """Vilket OS-lager som skulle användas. Kastar om inget finns."""
    if sys.platform == "darwin" and shutil.which("security"):
        return "macos-keychain"
    if shutil.which("secret-tool"):
        return "secret-tool"
    raise RuntimeError(
        "inget OS-säkert lager tillgängligt (kräver macOS Keychain eller "
        "secret-tool) — vägrar lagra kodhash i fil"
    )


def _run(argv: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, input=stdin, shell=False, capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        raise RuntimeError("OS-lagrets binär hittades inte.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("OS-lagret svarade inte (timeout).") from None
    except OSError as e:
        raise RuntimeError("kunde inte starta OS-lagret: %s" % e) from None


def store_hash(record: dict) -> None:
    """Spara hashpost (salt + hash + iterationer). Skriver över."""
    blob = json.dumps(record)
    name = backend_name()
    if name == "macos-keychain":
        proc = _run(
            [
                "security",
                "add-generic-password",
                "-a",
                ACCOUNT,
                "-s",
                SERVICE,
                "-w",
                blob,
                "-U",
            ]
        )
        if proc.returncode != 0:
            raise RuntimeError("kunde inte lagra kodhash: %s" % proc.stderr.strip())
        return
    proc = _run(
        [
            "secret-tool",
            "store",
            "--label=SHALLOT admin-kodhash",
            "service",
            SERVICE,
            "account",
            ACCOUNT,
        ],
        stdin=blob,
    )
    if proc.returncode != 0:
        raise RuntimeError("kunde inte lagra kodhash: %s" % proc.stderr.strip())


def load_hash() -> dict | None:
    """Hämta hashpost, eller None om ingen finns."""
    name = backend_name()
    if name == "macos-keychain":
        proc = _run(
            ["security", "find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"]
        )
        if proc.returncode != 0:
            return None  # saknas (eller oläsbar) — anroparen avgör
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            raise RuntimeError("korrupt kodhash i OS-lagret.") from None
        return data if isinstance(data, dict) else None
    proc = _run(["secret-tool", "lookup", "service", SERVICE, "account", ACCOUNT])
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        raise RuntimeError("korrupt kodhash i OS-lagret.") from None
    return data if isinstance(data, dict) else None


def delete_hash() -> None:
    """Radera hashpost. Idempotent — saknad post är OK."""
    name = backend_name()
    if name == "macos-keychain":
        _run(["security", "delete-generic-password", "-a", ACCOUNT, "-s", SERVICE])
        return
    _run(["secret-tool", "clear", "service", SERVICE, "account", ACCOUNT])
