"""Fysiskt säkert demoläge — 60 sekunders breadboard-demo.

Guidar en presentatör genom en verklig PAW–DEN-demo på breadboard:

  1. Förkontroll — närvaro av MamaBear, PAW, DEN, FIDO2-nyckel, e-paper.
  2. Godkänt fall — PAW → DEN → ÅTKOMST (logg + presentatörsbekräftelse).
  3. Återställning — säkert nekat läge.
  4. Nekat fall — felaktigt HMAC → NEKAD (fail closed).
  5. Export — append-only JSONL-revisionslogg + kort textsammanfattning.

Fysisk FIDO2 är standard. Mock används endast vid uttryckligt testval
och märks alltid `SIMULATED / TEST-ONLY`.

Ärlighet mot hårdvara:
- CLI:et styr ingen hårdvara och lutar sig mot presentatören för det
  som kräver fysiska händer (dockning, omladdning, skärmavläsning).
- PAW/DEN-portar identifieras best-effort (namn matchar "paw"/"den").
  Oidentifierade portar rapporteras som "kandidat" — aldrig som bekräftad.
- e-paper-skärmen betraktas aldrig som verifierad utan uttrycklig
  presentatörsbekräftelse; annars skrivs `ej verifierad`.
- Inga nycklar eller hemligheter loggas — endast fingeravtryck
  (publik metadata) och beslut.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from shallot_cli import theme

MOCK_MARKER = "SIMULATED / TEST-ONLY"

LED_GREEN = "\x1b[92m"
LED_RED = "\x1b[91m"
LED_YELLOW = "\x1b[93m"
LED_BLUE = "\x1b[94m"

SHALLOT_ASCII = r"""
  ███████╗██╗  ██╗ █████╗ ██╗     ██║      ██████╗ ████████╗
  ██╔════╝██║  ██║██╔══██╗██║     ██║     ██╔═══██╗╚══██╔══╝
  ███████╗███████║███████║██║     ██║     ██║   ██║   ██║
  ╚════██║██╔══██║██╔══██║██║     ██║     ██║   ██║   ██║
  ███████║██║  ██║██║  ██║███████╗███████╗╚██████╔╝   ██║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝    ╚═╝
""".strip("\n")

ONION_ASCII = r"""
=+
  *=@@@@@%%%+%%%%%%%%==+%%%%%%%%=*    :*@@@+     +%%%%%%%=    :+%%%%%%%=        :**%@@@@%%+:-++%%%%%%%%%%%%%%%%
-%@@==*=%@@%=*+%@@@==-**++%@@@==**    *@@@@%     :+=%@@%++    :-+=@@@=+:      -*=@@%==*=%@@%=+*%@====%@@%===%@@
=@@@%==* +*:::.=@@@%==   .=@@@%=     -%@%@@@*      +%@@=        -*%@@=       +*%@@*   ::+=@@@%*%=-+++%@@=++-*=%
*%@@@@@@=*+    =@@@%==   .=@@@%=    :%@@*%@@@*     +%@@=        -*%@@=      ++%@@%     ---=@@@   -+++%@@=::
 -=%@@@@@@@@%+ =@@@@@@%%%%@@@@%=    *@@%**@@@@     +%@@=        -*%@@=     :+*%@@+     -++*%@@+  -+++%@@=
    -=%%@@@@@@%=@@%===****%@@@%=   -%@@%==%@@@*    +%@@=        -*%@@=     -+*%@@=     :++*%@@+  -+++%@@=
 +++++ -*%@@@%%=@@@%==   .=@@@%=  :%@@%%%%%%@@@*   +%@@=        -*%@@=      +-%@@=     +++=%@@   -+++%@@=
%@@@@@%+ =@@@===@@@%==   .=@@@%=  *@@@=:   *@@@@+  +%@@=    :*%%-*%@@=   :+*%**%@@=   -++=%@@+   -+++%@@=
=@@@@@@@%@@%*+*=@@@%%%*- +=@@@%%**%@@%=*  ++%@@@%***%@@%%%%%%%@@*=%@@%%%%%=%@%-*%@@@%%%%%@@%-  ++****%@@=+
-=%%%@%%%=*.:%@%%%@@@%==%@%%%@@%@@%%@@@%- =@%%%@@@@@%%%%%%%%%%@%@@%%%%%%%%%%@+..-=%%%@@%%=+    +++=%@%%%@@@
   .--::     ........-  ...............   ...................................      .--::         :.........
""".strip("\n")


DEMO_LOG = "demo-result.jsonl"
SUMMARY_FILE = "demo-summary.txt"

#: Miljövariabler för hermetic lagring (tester pekar om till tmp-träd).
DEMO_LOG_ENV = "SHALLOT_DEMO_LOG"
DEMO_SUMMARY_ENV = "SHALLOT_DEMO_SUMMARY"


def _log_path(path: str | None = None) -> Path:
    return Path(path or os.environ.get(DEMO_LOG_ENV) or DEMO_LOG)


def _summary_path(path: str | None = None) -> Path:
    return Path(path or os.environ.get(DEMO_SUMMARY_ENV) or SUMMARY_FILE)

DEMO_OBSERVE_TIMEOUT_S = 60.0
#: Antal rapporterade moment i run_demo (progressradernas nämnare).
TOTAL_STEPS = 7
DEN_AUTH_NEEDLES = ("[DEN] AUTHENTICATED (code 0)", "[DEN] FAILED: ")
PAW_SUCCESS_NEEDLES = ("[PRO-84] DEN acknowledged success",
                       "[PRO-84] DEN denied (ACK 0x00)")


class DemoAbort(RuntimeError):
    """Avbruten demo (presentatören eller Ctrl-C)."""


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_header() -> str:
    return theme.paint("%s\n%s" % (SHALLOT_ASCII, ONION_ASCII), theme.ORANGE)


def _led(color: str, text: str) -> str:
    return theme.fg(text, color)


def _emit(path: Path, record: dict) -> None:
    """Append-only JSONL-post (revisionslogg). Skapar kataloger vid behov."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    return out


# --- förkontroll -------------------------------------------------------

def _fido2_devices() -> list:
    """Fysiska CTAP2-enheter. Aldrig undantag — tom lista vid fel."""
    try:
        from shallot_cli import fido2_backend
        return list(fido2_backend.CtapHidBackend().describe_devices())
    except Exception:
        return []


def precheck(mock: bool = False, list_ports_fn=None, fido2_desc_fn=None,
             log_path: str | None = None) -> dict:
    """Kontrollera närvaro av MamaBear, PAW, DEN, FIDO2 och e-paper.

    PAW/DEN-portar identifieras best-effort; oidentifierade portar är
    "kandidat". e-paper rapporteras alltid `ej verifierad` — den måste
    bekräftas av presentatören i fält.
    """
    if list_ports_fn is None:
        from shallot_cli import serial_adapters
        list_ports_fn = serial_adapters.list_ports
    if fido2_desc_fn is None:
        fido2_desc_fn = _fido2_devices

    ports = [p for p in list_ports_fn()]

    def _named(key: str) -> list[dict]:
        return [p for p in ports
                if key in p.get("description", "").lower()
                or key in p.get("device", "").lower()]

    paw = _named("paw")
    den = _named("den")
    fid_devs = [] if mock else fido2_desc_fn()

    components = {
        "MamaBear": {
            "status": "anslutning kräver val av SSH-alias i huvudmenyn",
            "ok": None,
            "detail": "läses senare i demot om så önskas"},
        "PAW": {
            "status": "kandidatport: %s" % paw[0]["device"] if paw
            else ("serieportar saknas" if not ports else "ej identifierad"),
            "ok": bool(paw),
            "detail": "identitet bekräftas i loggarna (presentatör)"},
        "DEN": {
            "status": "kandidatport: %s" % den[0]["device"] if den
            else ("serieportar saknas" if not ports else "ej identifierad"),
            "ok": bool(den),
            "detail": "identitet bekräftas i loggarna (presentatör)"},
        "FIDO2-nyckel": {
            "status": (MOCK_MARKER if mock else
                       "fysisk enhet hittad" if fid_devs
                       else "varken fysisk eller mock (test) vald"),
            "ok": mock or bool(fid_devs),
            "detail": MOCK_MARKER if mock else "fysisk default i demot"},
        "e-paper": {
            "status": "ej verifierad",
            "ok": False,
            "detail": "presentatören bekräftar vad skärmen visar"},
    }

    result = {
        "timestamp": _ts(),
        "type": "demo",
        "action": "precheck",
        "details": {
            "mock": mock,
            "mock_marker": MOCK_MARKER if mock else None,
            "ports": [p["device"] for p in ports],
            "components": components,
            "hardware_verified": False,
        },
    }
    _emit(_log_path(log_path), result)
    return result


def render_precheck(precheck_result: dict) -> str:
    details = precheck_result["details"]
    lines = []
    lines.append("  LED  KOMPONENT          STATUS")
    for name, comp in details["components"].items():
        ok = comp["ok"]
        led = _led(LED_GREEN, "GRÖN") if ok is True else (
            _led(LED_RED, "RÖD") if ok is False else _led(LED_YELLOW, "GUL"))
        lines.append("  %s  %-16s  %s (%s)" % (led, name, comp["status"],
                                               comp["detail"]))
    if not details["ports"]:
        lines.append("  _    Serieportar      Inga serieportar hittades — "
                     "koppla in breadboard-riggen via USB.")
    return "\n".join(lines)


# --- standardberoenden (fysiska) --------------------------------------

def _ask_default(prompt: str) -> str:
    return input(prompt).strip()


def _pause_default(prompt: str = "Tryck Enter för nästa steg...") -> None:
    try:
        input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise DemoAbort("avbrutet av presentatören")


def _confirm_default(prompt: str) -> bool:
    try:
        ans = input("%s [j/N]: " % prompt).strip().lower()
    except EOFError:
        return False
    return ans in ("j", "ja", "y", "yes")


def _login_default(user: str, mock: bool) -> int:
    """FIDO2-inloggning + session. Returnerar exit-kod (0 = OK)."""
    from shallot_cli import admin
    from shallot_cli.commands import admin_cmd
    rc = admin_cmd.run_login(user, mock=mock)
    if rc != 0:
        return rc
    try:
        admin.require_session("demo")
    except admin.AdminDenied as e:
        print("error: %s" % e)
        return 1
    return 0


def _read_until_default(port: str, needles: tuple[str, ...]) \
        -> tuple[str | None, str | None]:
    from shallot_cli.commands import monitor_cmd
    hit, line = monitor_cmd.read_until(port, 115200, list(needles),
                                       DEMO_OBSERVE_TIMEOUT_S)
    return hit, line


def _provision_default(role: str, port: str) -> str:
    """Sänd testnyckeln till roll via USB-port. Returnerar fingeravtryck-hex."""
    from shallot_cli import provision, serial_adapters
    from shallot_cli import admin
    ser = serial_adapters.open_provision(port)
    entries: list = []
    try:
        with ser:
            provision.settle(ser)
            res = provision.provision_device(
                provision.SerialTransport(ser), role, audit=entries)
    except provision.ProvisionError as e:
        for entry in entries:
            admin.audit_admin(entry["action"], entry["details"])
        raise DemoAbort("%s nekar provisionering: %s" % (role, e))
    except Exception as e:
        for entry in entries:
            admin.audit_admin(entry["action"], entry["details"])
        raise DemoAbort("%s fel vid provisionering: %s" % (role, e))
    for entry in entries:
        admin.audit_admin(entry["action"], entry["details"])
    return res["fingerprint"].hex()


def run_precheck_cli(mock: bool = False) -> int:
    """`shallot demo precheck` — skrivfri förkontroll, exit 0 = visad."""
    result = precheck(mock=mock)
    print(render_header())
    print("Förkontroll av breadboard-riggen (skrivfritt)")
    print()
    print(render_precheck(result))
    return 0


# --- själva demot -------------------------------------------------------

def run_demo(mock: bool = False,
             pause_fn=None, confirm_fn=None, ask_fn=None,
             login_fn=None, provision_fn=None, read_until_fn=None,
             list_ports_fn=None,
             log_path: str | None = None,
             summary_path: str | None = None) -> dict:
    """Kör breadboard-demon (ca 60 s, fysisk). Returnerar sammandrag.

    Flöde: förkontroll → godkänt PAW→DEN→ÅTKOMST → återställning →
    nekat fall (felaktigt HMAC) → export. Alla hårdvaruberoenden är
    injicerbara för tester; standardvärden är de fysiska vägarna.
    """
    if pause_fn is None:
        pause_fn = _pause_default
    if confirm_fn is None:
        confirm_fn = _confirm_default
    if ask_fn is None:
        ask_fn = _ask_default
    if login_fn is None:
        login_fn = _login_default
    if provision_fn is None:
        provision_fn = _provision_default
    if read_until_fn is None:
        read_until_fn = _read_until_default
    if list_ports_fn is None:
        from shallot_cli import serial_adapters
        list_ports_fn = serial_adapters.list_ports

    log = _log_path(log_path)
    summary_file = _summary_path(summary_path)
    start = time.time()
    steps: list[dict] = []
    verdicts: list[dict] = []

    def step(name: str, result: str, ok: bool = None, detail: str = "") -> None:
        led = _led(LED_GREEN, "OK") if ok is True else (
            _led(LED_RED, "NEKAD") if ok is False else _led(LED_YELLOW, "VÄNTAR"))
        steps.append({"steg": name, "resultat": result, "ok": ok,
                      "detail": detail})
        print("  [%d/%d] %s = %s%s"
              % (len(steps), TOTAL_STEPS, name, led,
                 (" — %s" % detail) if detail else ""))

    if mock:
        print(_led(LED_YELLOW, MOCK_MARKER))

    try:
        print("SHALLOT — FYSISK BREADBOARD-DEMO")
        print(render_header())
        print("Steg 1/5: Förkontroll (visa att riggen är fysisk).")
        pre = precheck(mock=mock, list_ports_fn=list_ports_fn, log_path=log)
        print(render_precheck(pre))
        pause_fn("Tryck Enter när ordföranden kan se breadboard-riggen...")
        step("Förkontroll", "klart", ok=(bool(pre["details"]["ports"])),
             detail="fysisk rigg uppräknad (%d serieportar)"
                    % len(pre["details"]["ports"]))

        print("Steg 2/5: Godkänt fall — PAW → DEN → ÅTKOMST.")
        if not mock:
            print("Fysisk FIDO2-nyckel krävs. Rör vid nyckeln vid prompt.")
        user = ask_fn("Admin-användare (tomt = admin-01): ") or "admin-01"
        if login_fn(user, mock) != 0:
            step("FIDO2", "inloggning nekad", ok=False)
            raise DemoAbort("ingen giltig Admin-session")
        step("FIDO2", MOCK_MARKER if mock else "ok", ok=True,
             detail="inloggad som %s" % user)

        ports = [p.get("device") for p in list_ports_fn() if p.get("device")]
        if len(ports) < 2:
            step("Portar", "för få serieportar", ok=False,
                 detail="behöver två: PAW och DEN")
            raise DemoAbort("kräver två USB-serieportar (PAW och DEN)")
        paw_port = next((p for p in ports if "paw" in p.lower()), ports[0])
        den_port = next((p for p in ports if "den" in p.lower()
                         and p != paw_port), ports[1])
        step("Portar", "ok", ok=True,
             detail="PAW=%s DEN=%s" % (paw_port, den_port))

        print("  Sänder testnyckel till PAW...")
        paw_fp = provision_fn("paw", paw_port)
        print("  Sänder testnyckel till DEN...")
        den_fp = provision_fn("den", den_port)
        step("Nyckelöverföring", "ok", ok=True,
             detail="PAW=%s DEN=%s" % (paw_fp, den_fp))

        pause_fn("Tryck Enter och docka sedan PAW mot DEN för det godkända "
                 "fallet (DEN ska visa ÅTKOMST)...")
        print("  Avläser PAW-logg...")
        paw_hit, _paw_line = read_until_fn(paw_port, PAW_SUCCESS_NEEDLES)
        print("  Avläser DEN-logg...")
        den_hit, _den_line = read_until_fn(den_port, DEN_AUTH_NEEDLES)
        paw_ok = paw_hit == PAW_SUCCESS_NEEDLES[0]
        den_ok = den_hit == DEN_AUTH_NEEDLES[0]
        display_status = "verifierad" if confirm_fn(
            "Visar e-paper-skärmen ÅTKOMST?") else "ej verifierad"
        display_ok = display_status == "verifierad"
        grant = paw_ok and den_ok and display_ok
        print(_led(LED_GREEN, "LED: ÅTKOMST") if grant
              else _led(LED_RED, "LED: NEKAD"))
        verdicts.append({"moment": "godkänt-fall",
                         "resultat": "ÅTKOMST" if grant else "NEKAD",
                         "paw_logg": bool(paw_ok), "den_logg": bool(den_ok),
                         "display": display_status})
        step("Godkänt fall", "ÅTKOMST" if grant else "NEKAD",
             ok=grant, detail="display %s" % display_status)

        print("Steg 3/5: Återställ till säkert nekat läge.")
        pause_fn("Tryck Enter och återställ riggen till säkert nekat läge...")
        verdicts.append({"moment": "återställning",
                         "resultat": "säkert nekat", "ok": True})
        step("Återställning", "säkert nekat läge", ok=True)
        if grant:
            _emit(log, {"timestamp": _ts(), "type": "demo",
                        "action": "reset", "details": {"till": "nekat"}})

        print("Steg 4/5: Nekat fall — felaktigt HMAC.")
        pause_fn("Tryck Enter och docka en PAW med felaktig nyckel "
                 "(DEN ska NEKDA, fail closed)...")
        print("  Avläser DEN-logg...")
        den_hit2, _line2 = read_until_fn(den_port, DEN_AUTH_NEEDLES)
        deny_hit = den_hit2 == DEN_AUTH_NEEDLES[1]
        if not deny_hit:
            print("  ej verifierat — ingen NEKAD-rad i loggen; visa manuellt.")
        verdicts.append({"moment": "nekat-fall",
                         "resultat": "NEKAD" if deny_hit else "ej verifierat",
                         "den_logg": bool(deny_hit),
                         "reason": "HMAC_MISMATCH (fail closed)"})
        step("Nekat fall", "NEKAD" if deny_hit else "ej verifierat",
             ok=deny_hit, detail="felaktigt HMAC -> fail closed")

        if grant and deny_hit:
            overall = "GODKÄNT"
        elif not grant:
            overall = "NEKAD"
        else:
            overall = "EJ FULLT VERIFIERAD"
        summary = _finalize(start, steps, verdicts, overall, mock,
                            log, summary_file)
        print("\n--- DEMO-SAMMANFATTNING ---")
        print(_render_summary(summary))
        print("JSONL-revisionslogg: %s" % log.resolve())
        print("Textsammanfattning:  %s" % summary_file.resolve())
        return summary

    except DemoAbort as e:
        _emit(log, {"timestamp": _ts(), "type": "demo",
                    "action": "aborted", "details": {"orsak": str(e)}})
        print("Demot avbröts: %s" % e)
        summary = _finalize(start, steps, verdicts, "AVBRUTET", mock,
                            log, summary_file, error=str(e))
        return summary
    except KeyboardInterrupt:
        _emit(log, {"timestamp": _ts(), "type": "demo",
                    "action": "aborted", "details": {"orsak": "ctrl-c"}})
        summary = _finalize(start, steps, verdicts, "AVBRUTET", mock,
                            log, summary_file, error="Ctrl-C")
        return summary
    except Exception as e:  # fail closed — vi journalför och fortsätter inte
        _emit(log, {"timestamp": _ts(), "type": "demo",
                    "action": "error", "details": {"orsak": str(e)}})
        print("Fel: %s" % e)
        summary = _finalize(start, steps, verdicts, "FEL", mock,
                            log, summary_file, error=str(e))
        return summary


def _finalize(start, steps, verdicts, overall, mock, log,
              summary_file, error: str | None = None) -> dict:
    duration = round(time.time() - start, 1)
    hardware_verified = any(v.get("display") == "verifierad"
                            for v in verdicts)
    summary = {
        "timestamp": _ts(),
        "type": "demo",
        "action": "run-summary",
        "duration_s": duration,
        "overall": overall,
        "mock": mock,
        "mock_marker": MOCK_MARKER if mock else None,
        "hardware_verified": hardware_verified,
        "verification_note": (
            "e-paper och loggar bekräftades av presentatören i fält"
            if hardware_verified else "ej verifierad — skärm/logg ej bekräftad"),
        "steps": steps,
        "verdicts": verdicts,
        "error": error,
    }
    _emit(log, summary)
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(_render_summary(summary), encoding="utf-8")
    return summary


def _render_summary(summary: dict) -> str:
    lines = []
    lines.append("=== SHALLOT — DEMO-SAMMANFATTNING ===")
    lines.append("Tid: %s" % summary["timestamp"])
    lines.append("Varaktighet: %s s" % summary["duration_s"])
    lines.append("Läge: %s" % (MOCK_MARKER if summary["mock"]
                               else "FYSISKT"))
    lines.append("Övergripande: %s" % summary["overall"])
    lines.append("")
    lines.append("Moment:")
    for i, s in enumerate(summary.get("steps", []), 1):
        lines.append("  %d. %s = %s%s" % (i, s.get("steg"), s.get("resultat"),
                       (" — %s" % s["detail"]) if s.get("detail") else ""))
    lines.append("")
    lines.append("Beslut:")
    for v in summary.get("verdicts", []):
        lines.append("  * %s = %s" % (v.get("moment"), v.get("resultat")))
    lines.append("")
    lines.append("Fysisk verifiering: %s" % summary["verification_note"])
    if summary.get("error"):
        lines.append("Fel/avbrott: %s" % summary["error"])
    lines.append("Inga hemligheter i denna export.")
    return "\n".join(lines)


# --- visa senaste ------------------------------------------------------

def latest_result(log_path: str | None = None) -> dict | None:
    records = _read_jsonl(_log_path(log_path))
    runs = [r for r in records if r.get("action") == "run-summary"]
    if not runs:
        return None
    last = runs[-1]
    last["_log_records"] = len(records)
    return last


def show_latest(log_path: str | None = None,
                summary_path: str | None = None) -> dict | None:
    """Visa senaste demo-resultat/logg (senaste körningen + sammanfattning)."""
    last = latest_result(log_path)
    if last is None:
        print("Inga tidigare demo-resultat hittade.")
        return None
    print("=== SENASTE DEMO-RESULTAT ===")
    print("Loggposter totalt: %d" % last.pop("_log_records"))
    print(json.dumps(last, indent=2, ensure_ascii=False))
    sf = _summary_path(summary_path)
    if sf.exists():
        print("\n=== TEXTSAMMANFATTNING ===")
        print(sf.read_text(encoding="utf-8"))
    return last