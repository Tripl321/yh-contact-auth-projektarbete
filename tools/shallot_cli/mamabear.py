"""Säkert läsande MamaBear-fjärrläge över system-SSH.

MamaBear är en SSH-nod som nås över Tailscale via användarens egna
ssh-alias (``~/.ssh/config``). Denna modul äger allt fjärrrelaterat:

- Hårdkodad allowlist av läsande kommandon — godtyckliga fjärrkommandon
  från användarinput körs aldrig. Ingen nyckelgenerering, distribution,
  provisionering, flashning eller annan skrivande åtgärd finns här.
- Transport via systemets ``ssh``-binär med ``BatchMode=yes`` (frågar
  aldrig efter lösenord — misslyckas fail-closed i stället) och
  ``ConnectTimeout``. Inga lösenord, ``-i``-nycklar, ``user@``-former
  eller IP-adresser hanteras någonsin; endast aliaset skickas vidare.
  Host keys verifieras enligt användarens egen konfiguration och
  accepteras aldrig automatiskt.
- All fjärr-output saneras med :func:`fido2_sanitize.sanitize` (enda
  ägaren av maskningsregler) innan den visas, sparas eller används
  vidare (t.ex. om den skickas till Ollama).
- Tidsstämplade lokala JSON-resultat med kommando, tidpunkt, exit-kod,
  teststatus och sanerad output.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from shallot_cli import fido2_sanitize

CONNECT_TIMEOUT_S = 10
CMD_TIMEOUT_S = 30

#: Tillåtna ssh-alias: enkelt token, aldrig user@-form, sökväg eller flaggor.
ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
#: IPv4-literaler ser ut som adresser, inte alias — avvisas explicit.
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: Läsande statuskommandon (informativa, inga förväntningar på output).
STATUS_COMMANDS = (
    {"name": "uname", "cmd": "uname -a"},
    {"name": "uptime", "cmd": "uptime"},
    {"name": "memory", "cmd": "free -m"},
    {"name": "disk", "cmd": "df -h /"},
)

#: Läsande självtestkommandon med strikta förväntningar.
#: Oväntad output eller nonzero exit betyder teststatus fail.
TEST_COMMANDS = (
    {
        "name": "exec-sanity",
        "cmd": "echo MAMABEAR_SELFTEST_OK",
        "expect_exact": "MAMABEAR_SELFTEST_OK",
    },
    {"name": "pipe-sanity", "cmd": "printf 'a\\nb\\n' | wc -l", "expect_exact": "2"},
    {
        "name": "clock",
        "cmd": "date -u +%Y-%m-%dT%H:%M:%SZ",
        "expect_regex": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
    },
)

#: stderr-fragment som betyder att SSH-transporten fallerade (fail closed).
SSH_ERROR_HINTS = (
    "could not resolve hostname",
    "no route to host",
    "connection refused",
    "connection timed out",
    "operation timed out",
    "host key verification failed",
    "permission denied",
    "network is unreachable",
    "tailnet policy",
)

SCOPE_NOTE = (
    "Fysisk status-/självtestverifiering av MamaBear-noden. "
    "Inte bevis för hela DEN–PAW-autentiseringskedjan."
)

# Maskningsregler ägs av fido2_sanitize (enda ägaren) — denna modul
# importerar modulen, aldrig namnet (inget sanitize-alias här).


def validate_alias(host: str) -> str:
    """Validera ssh-alias. Aldrig adresser, user@-former eller flaggor."""
    alias = (host or "").strip()
    if IPV4_RE.fullmatch(alias) or alias.startswith("["):
        raise ValueError(
            "'%s' ser ut som en adress — ange ssh-alias från ~/.ssh/config." % host
        )
    if alias in (".", ".."):
        raise ValueError("ogiltigt ssh-alias %r." % host)
    if not ALIAS_RE.fullmatch(alias) or alias.startswith("-"):
        raise ValueError(
            "ogiltigt ssh-alias %r — använd ett alias från ~/.ssh/config "
            "(aldrig user@värd, adress, sökväg eller flaggor)." % host
        )
    return alias


#: Exakta fjärrkommandon som någonsin får köras (upprätthålls vid
#: exec-gränsen, inte bara hos anroparen).
_KNOWN_REMOTE_CMDS = frozenset(
    [e["cmd"] for e in STATUS_COMMANDS] + [e["cmd"] for e in TEST_COMMANDS]
)


def run_remote(alias: str, remote_cmd: str, timeout_s: int = CMD_TIMEOUT_S) -> dict:
    """Kör ett allowlistat kommando via system-ssh. Returnerar fakta-dict.

    Kastar RuntimeError om ssh-binären saknas eller inte kan startas.
    Skriver aldrig något på fjärrnoden (kommandot kommer från allowlist).
    Alias och kommando valideras här igen — säkerheten bor vid
    exec-gränsen, inte bara hos anroparen.
    """
    alias = validate_alias(alias)
    if remote_cmd not in _KNOWN_REMOTE_CMDS:
        raise RuntimeError("vägrat: fjärrkommando utanför allowlist.")
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=%d" % CONNECT_TIMEOUT_S,
        alias,
        remote_cmd,
    ]
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
        )
    except FileNotFoundError:
        raise RuntimeError("ssh-binären hittades inte — installera OpenSSH.") from None
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timed_out": True, "stdout": "", "stderr": ""}
    except OSError as e:
        raise RuntimeError("kunde inte starta ssh: %s" % e) from None
    return {
        "exit_code": proc.returncode,
        "timed_out": False,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def is_transport_error(result: dict) -> bool:
    """True om resultatet visar att SSH-transporten fallerade."""
    if result.get("timed_out"):
        return True
    if result.get("exit_code") != 255:
        return False
    blob = ((result.get("stdout") or "") + "\n" + (result.get("stderr") or "")).lower()
    return any(hint in blob for hint in SSH_ERROR_HINTS)


def check_entry(entry: dict, result: dict) -> str:
    """'pass' om kommandot lyckades och output matchar förväntningar."""
    if result.get("timed_out") or result.get("exit_code") != 0:
        return "fail"
    out = (result.get("stdout") or "").strip()
    if "expect_exact" in entry and out != entry["expect_exact"]:
        return "fail"
    if "expect_regex" in entry and not re.fullmatch(entry["expect_regex"], out):
        return "fail"
    return "pass"


def run_suite(alias: str, entries: tuple, timeout_s: int = CMD_TIMEOUT_S) -> dict:
    """Kör en allowlist-svit. Avbryter fail-closed vid transportfel.

    Returnerar {"results", "transport_error", "aborted"}. All output i
    results är redan sanerad.
    """
    results = []
    transport_error = None
    aborted = False
    for entry in entries:
        result = run_remote(alias, entry["cmd"], timeout_s=timeout_s)
        if is_transport_error(result):
            transport_error = fido2_sanitize.sanitize(
                (
                    result.get("stderr") or result.get("stdout") or "okänd transportfel"
                ).strip()
            )
            aborted = True
            if result.get("timed_out"):
                transport_error = "timeout efter %ds: %s" % (timeout_s, entry["name"])
            break
        results.append(
            {
                "name": entry["name"],
                "command": entry["cmd"],
                "exit_code": result["exit_code"],
                "timed_out": False,
                "check": check_entry(entry, result),
                "output": fido2_sanitize.sanitize(result.get("stdout") or ""),
                "stderr": fido2_sanitize.sanitize(result.get("stderr") or ""),
            }
        )
    return {"results": results, "transport_error": transport_error, "aborted": aborted}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: Enda resultattyper default_output_path() kan namnge (S2083: kind
#: når filnamnet och får aldrig bära separatorer eller "..").
_ALLOWED_KINDS = frozenset({"status", "test"})


def default_output_path(kind: str) -> Path:
    if kind not in _ALLOWED_KINDS:
        raise RuntimeError("ogiltig resultattyp: %r" % (kind,))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path.cwd() / ("mamabear-%s-%s.json" % (kind, stamp))


def resolve_output_path(raw: str | Path) -> Path:
    """Validera en användarvald resultatfil (t.ex. CLI --output). Fail-closed.

    Normaliserar (expanduser + resolve mot CWD) och kräver .json-suffix
    samt att målkalogen finns — den skapas aldrig automatiskt, så en
    felstavad sökväg kan inte sprida filer oväntat (S2083: path injection).
    """
    text = str(raw) if isinstance(raw, Path) else raw
    if not isinstance(text, str) or "\x00" in text or not text.strip():
        raise RuntimeError("ogiltig målfil")
    candidate = Path(text).expanduser()
    if candidate.suffix != ".json":
        raise RuntimeError("målfil måste sluta med .json: %s" % text)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (Path.cwd() / candidate).resolve()
    )
    if not resolved.parent.is_dir():
        raise RuntimeError("målkatalogen finns inte: %s" % resolved.parent)
    return resolved


def build_payload(tool: str, alias: str, suite: dict) -> dict:
    """Bygg det tidsstämpta JSON-resultatet (endast sanerad output)."""
    results = suite["results"]
    passed = sum(1 for r in results if r["check"] == "pass")
    failed = len(results) - passed
    aborted = suite["aborted"]
    teststatus = "pass" if (results and failed == 0 and not aborted) else "fail"
    return {
        "tool": tool,
        "host_alias": alias,
        "timestamp_utc": utc_now_iso(),
        "transport": {
            "via": "system-ssh",
            "alias_source": "~/.ssh/config",
            "batch_mode": True,
            "connect_timeout_s": CONNECT_TIMEOUT_S,
            "command_timeout_s": CMD_TIMEOUT_S,
        },
        "commands": results,
        "passed": passed,
        "failed": failed,
        "aborted": aborted,
        "transport_error": suite["transport_error"],
        "teststatus": teststatus,
        "exit_code": 0 if teststatus == "pass" else 1,
        "scope_note": SCOPE_NOTE,
    }


def save_result(path: str | Path, payload: dict) -> Path:
    """Spara resultatfil lokalt. Kastar RuntimeError vid skrivfel.

    Går alltid via resolve_output_path() så även interna anropare får
    samma normalisering (S2083); default-namnen från
    default_output_path() är redan .json i CWD och passerar oförändrat.
    """
    resolved = resolve_output_path(path)
    try:
        resolved.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise RuntimeError(
            "kunde inte skriva resultatfil %s: %s" % (resolved, e)
        ) from None
    return resolved


def render_summary(payload: dict, result_path: Path | None) -> str:
    """Tydlig terminalsammanfattning: anslutning, status, passerat/misslyckat, fil."""
    lines = [
        "%s — läsande fjärrläge, ingen skrivning på MamaBear." % payload["tool"],
        "anslutning : %s ... %s"
        % (
            payload["host_alias"],
            "OK" if not payload["aborted"] else "FEL: %s" % payload["transport_error"],
        ),
    ]
    for r in payload["commands"]:
        first = (r["output"].strip().splitlines() or [""])[0][:100]
        lines.append(
            "  %-12s exit=%s check=%s %s"
            % (r["name"], r["exit_code"], r["check"], first)
        )
    lines.append(
        "status     : %s (passerade=%d misslyckade=%d)"
        % (payload["teststatus"].upper(), payload["passed"], payload["failed"])
    )
    lines.append(
        "resultatfil: %s" % (result_path if result_path else "(ingen fil skriven)")
    )
    lines.append("Notera: %s" % SCOPE_NOTE)
    return "\n".join(lines)
