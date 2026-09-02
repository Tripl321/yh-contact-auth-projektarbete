"""Backend: git, sync to sketchbook, arduino-cli, port detection, status reporting."""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .components import Component, get_component, all_keys, COMPONENTS


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _run(cmd: List[str], cwd: Optional[str] = None, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True)


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _default_repo_dir() -> Path:
    return Path(os.environ.get("SHALLOT_REPO_DIR", str(Path.home() / "projects" / "yh-lora-auth")))


def _default_sketchbook() -> Path:
    return Path(os.environ.get("SHALLOT_SKETCHBOOK", str(Path.home() / "Documents" / "Arduino")))


def _branch() -> str:
    return os.environ.get("SHALLOT_BRANCH", "")


# ----------------------------------------------------------------------------
# Git
# ----------------------------------------------------------------------------

REPO_URL = "https://github.com/Tripl321/yh-lora-auth-projektarbete.git"
FEATURE_BRANCH = "vibe/paw-line-corruption-fix-bf5bdb"


def ensure_git() -> None:
    if not _have("git"):
        print("✗ git hittades inte. Installera Xcode Command Line Tools: xcode-select --install", file=sys.stderr)
        sys.exit(1)


def ensure_repo(repo_dir: Path) -> None:
    if (repo_dir / ".git").is_dir():
        print(f"Uppdaterar klon: {repo_dir}")
        _run(["git", "-C", str(repo_dir), "fetch", "--prune", "origin"])
    else:
        print(f"Klonar repo till: {repo_dir}")
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", REPO_URL, str(repo_dir)])
        _run(["git", "-C", str(repo_dir), "fetch", "--prune", "origin"])


def pick_branch(repo_dir: Path) -> str:
    b = _branch()
    if b:
        return b
    r = _run(["git", "-C", str(repo_dir), "rev-parse", "--verify", f"origin/{FEATURE_BRANCH}"])
    return FEATURE_BRANCH if r.returncode == 0 else "main"


def checkout_branch(repo_dir: Path) -> str:
    branch = pick_branch(repo_dir)
    _run(["git", "-C", str(repo_dir), "checkout", branch])
    _run(["git", "-C", str(repo_dir), "reset", "--hard", f"origin/{branch}"])
    short = _run(["git", "-C", str(repo_dir), "rev-parse", "--short", "HEAD"]).stdout.strip()
    print(f"✓ På branch {branch} @ {short}")
    return branch


# ----------------------------------------------------------------------------
# Sync to sketchbook
# ----------------------------------------------------------------------------

def sync_component(comp: Component, repo_dir: Path, sketchbook: Path) -> Path:
    src = repo_dir / comp.src_path
    if not src.is_file():
        print(f"✗ Källfil saknas: {src}", file=sys.stderr)
        sys.exit(1)
    sketch_name = src.stem
    dest_dir = sketchbook / sketch_name
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest_dir / f"{sketch_name}.ino")
    print(f"✓ Synkade {comp.key} -> {dest_dir / (sketch_name + '.ino')}")
    for extra_rel in comp.extras:
        extra_src = repo_dir / extra_rel
        if extra_src.is_file():
            shutil.copy2(extra_src, dest_dir / extra_src.name)
            print(f"✓ Synkade extra: {extra_src.name} -> {dest_dir}")
    return dest_dir


def sync_all(repo_dir: Path, sketchbook: Path) -> None:
    for c in COMPONENTS:
        try:
            sync_component(c, repo_dir, sketchbook)
        except Exception as e:
            print(f"⚠ Kunde inte synka {c.key}: {e}")


# ----------------------------------------------------------------------------
# arduino-cli
# ----------------------------------------------------------------------------

def ensure_arduino_cli() -> bool:
    if _have("arduino-cli"):
        return True
    print("⚠ arduino-cli hittades inte. Försöker installera via Homebrew...")
    if not _have("brew"):
        print("✗ Homebrew saknas. Installera från https://brew.sh", file=sys.stderr)
        return False
    _run(["brew", "install", "arduino-cli"])
    return _have("arduino-cli")


def ensure_pico_index() -> None:
    cfg = _run(["arduino-cli", "config", "dump"])
    pico_url = "https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json"
    if pico_url not in (cfg.stdout or ""):
        print("Lägger till arduino-pico board-URL")
        _run(["arduino-cli", "config", "set", "board_manager.additional_urls", pico_url])
        _run(["arduino-cli", "core", "update-index"])
    else:
        _run(["arduino-cli", "core", "update-index"])


def ensure_core_installed(comp: Component) -> None:
    pkg = comp.core.split("@")[0]
    # For RP2040 boards, ensure the pico index is available
    if "rp2040" in comp.core:
        ensure_pico_index()
    _run(["arduino-cli", "core", "update-index"])
    listing = _run(["arduino-cli", "core", "list"]).stdout
    installed = [line.split()[0] for line in listing.splitlines() if line.strip() and len(line.split()) >= 1]
    if pkg not in installed:
        print(f"Installerar core: {comp.core}")
        _run(["arduino-cli", "core", "install", comp.core])
    print(f"✓ Core {pkg} redo")


def compile_component(comp: Component, sketch_dir: Path) -> bool:
    print(f"Kompilerar {comp.key} (FQBN: {comp.fqbn})...")
    r = _run(["arduino-cli", "compile", "--fqbn", comp.fqbn, str(sketch_dir)])
    if r.returncode == 0:
        print(f"✓ Kompilering OK: {comp.key}")
        return True
    print(f"✗ Kompilering misslyckades för {comp.key}", file=sys.stderr)
    print(r.stdout[-1500:] + r.stderr[-1500:])
    return False


# ----------------------------------------------------------------------------
# Port detection (FQBN + board-name matching)
# ----------------------------------------------------------------------------

def list_boards() -> None:
    r = _run(["arduino-cli", "board", "list", "--format", "json"])
    if r.returncode != 0:
        print("✗ kunde inte lista boards", file=sys.stderr)
        return
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        print("✗ kunde inte tolka board list-utdata")
        return
    ports = data.get("ports", []) or data.get("detected_ports", [])
    if not ports:
        print("  Inga anslutna boards.")
        return
    print(f"  {'Port':<28} {'Board Name':<28} {'FQBN':<48}")
    print(f"  {'-'*28} {'-'*28} {'-'*48}")
    for p in ports:
        port = (p.get("address", {}).get("label") if isinstance(p.get("address"), dict)
                else p.get("address") or p.get("port") or "")
        mb = p.get("matching_boards") or p.get("boards") or []
        if mb:
            name = mb[0].get("name", "?")
            fqbn = mb[0].get("fqbn", "?")
        else:
            name = "(okänd board)"
            fqbn = "(ingen FQBN detekterad)"
        print(f"  {str(port):<28} {str(name):<28} {str(fqbn):<48}")


def detect_port(comp: Component) -> Optional[str]:
    """Return port matching the component's FQBN, then board name, else None."""
    override = os.environ.get("SHALLOT_PORT")
    if override:
        return override
    r = _run(["arduino-cli", "board", "list", "--format", "json"])
    if r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
    ports = data.get("ports", []) or data.get("detected_ports", [])
    # 1) exact FQBN match
    for p in ports:
        port = (p.get("address", {}).get("label") if isinstance(p.get("address"), dict)
                else p.get("address") or p.get("port") or "")
        for b in (p.get("matching_boards") or p.get("boards") or []):
            if b.get("fqbn") == comp.fqbn:
                return port
    # 2) board-name substring match (fallback)
    for p in ports:
        port = (p.get("address", {}).get("label") if isinstance(p.get("address"), dict)
                else p.get("address") or p.get("port") or "")
        for b in (p.get("matching_boards") or p.get("boards") or []):
            if comp.board_name and comp.board_name.lower() in (b.get("name", "") or "").lower():
                return port
    return None


def flash_component(comp: Component, sketch_dir: Path) -> bool:
    port = detect_port(comp)
    if not port:
        print(f"✗ Ingen ansluten board hittades som matchar {comp.key}.", file=sys.stderr)
        print("  Anslut boarden via USB och försök igen, eller sätt port explicit:", file=sys.stderr)
        print(f"    SHALLOT_PORT=/dev/cu.usbmodemXXXX shallot flash {comp.key}", file=sys.stderr)
        print("  Lista boards med: shallot list", file=sys.stderr)
        return False
    print(f"⚠ Använder port: {port} (matchad mot {comp.key})")
    r = _run(["arduino-cli", "upload", "-p", port, "--fqbn", comp.fqbn, str(sketch_dir)])
    if r.returncode == 0:
        print(f"✓ Flashning OK: {comp.key} @ {port}")
        return True
    print(f"✗ Flashning misslyckades för {comp.key}", file=sys.stderr)
    print((r.stdout or "")[-1500:] + (r.stderr or "")[-1500:], file=sys.stderr)
    return False


# ----------------------------------------------------------------------------
# Status reporting (writes status.json to repo)
# ----------------------------------------------------------------------------

def write_status(comp: Component, ok: bool, stage: str, detail: str,
                 repo_dir: Path) -> None:
    """Append a structured status entry to status.json in the repo root."""
    status_file = repo_dir / "status.json"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": comp.key,
        "stage": stage,           # sync | compile | flash
        "ok": ok,
        "detail": detail,
        "branch": pick_branch(repo_dir),
    }
    history = []
    if status_file.is_file():
        try:
            history = json.loads(status_file.read_text())
            if not isinstance(history, list):
                history = []
        except (json.JSONDecodeError, ValueError):
            history = []
    history.append(entry)
    # Keep last 100 entries
    history = history[-100:]
    status_file.write_text(json.dumps(history, indent=2, ensure_ascii=False))
    print(f"✓ Status skriven till {status_file}")
    print("  Committa och pusha för att göra den synlig för Vibe-agenten:")
    print(f"    git -C {repo_dir} add status.json && git -C {repo_dir} commit -m 'status: {comp.key} {stage} {('ok' if ok else 'fail')}'")
