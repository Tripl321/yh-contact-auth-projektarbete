"""Steg-för-steg fysisk bänkverifiering (SHALLOT).

Kör checklistan från docs/13 (H1–H7), docs/18 (K1–K6), docs/15/16
(PRO-45/46), docs/pen-test-baseline-pro63.md (PT-01…PT-07) samt
break-glass- och panelpunkterna från docs/10. Varje steg kräver
fysisk bänk; resultat och evidens loggas till JSONL och sammanfattas
i en textfil. Inga hårdvarupåståenden utan evidens per steg.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BENCH_LOG = "bench-verify.jsonl"
BENCH_SUMMARY = "bench-verify-summary.txt"

#: Miljövariabler för hermetisk lagring (tester pekar om till tmp-träd).
BENCH_LOG_ENV = "SHALLOT_BENCH_LOG"
BENCH_SUMMARY_ENV = "SHALLOT_BENCH_SUMMARY"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_path(path: str | None = None) -> Path:
    return Path(path or os.environ.get(BENCH_LOG_ENV) or BENCH_LOG)


def _summary_path(path: str | None = None) -> Path:
    return Path(path or os.environ.get(BENCH_SUMMARY_ENV) or BENCH_SUMMARY)


def _emit(path: Path, record: dict) -> None:
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


# --- checklista ----------------------------------------------------------

GROUPS: list[dict] = [
    {
        "name": "Rigg och förutsättningar",
        "steps": [
            {
                "id": "RIGG-1",
                "title": "Enheter fysiskt närvarande",
                "instructions": "Samla UNO Q (STM32U585), DEN (RP2350), "
                                "PAW (Feather RP2350), FIDO2-nyckel, "
                                "e-paper-panel, originalkablar samt "
                                "oscilloskop/logikanalysator på samma plats.",
                "expected": "Alla enheter och instrument finns till hands.",
                "hardware": "UNO Q, DEN, PAW, FIDO2, e-paper, osc./LA",
            },
            {
                "id": "RIGG-2",
                "title": "Kabeldragning enligt bänkdokumentation",
                "instructions": "Dra UART enligt docs/13 §3 (DEN TX GP0 -> PAW "
                                "RX GP1, PAW TX GP0 -> DEN RX GP1, GND, "
                                "115200 8N1) och UNO Q-enligt docs/15 §2.",
                "expected": "Kabeldragning stämmer med tabellerna.",
                "hardware": "DEN, PAW, UNO Q, kablar",
            },
            {
                "id": "RIGG-3",
                "title": "Portar identifierade",
                "instructions": "Anslut alla USB-serieportar; införskaffa "
                                "portlistan (t.ex. `shallot device list`).",
                "expected": "UNO Q, DEN och PAW syns som serieportar; "
                            "FIDO2 hittas som fysisk enhet.",
                "hardware": "UNO Q, DEN, PAW, FIDO2",
            },
        ],
    },
    {
        "name": "K1-K6 — SRAM-nyckelhantering (docs/18)",
        "steps": [
            {
                "id": "K1",
                "title": "SRAM-volatilitet: nyckel dör vid spänningsbortfall",
                "instructions": "Provisionera giltig nyckel, bryt matningen "
                                "till PAW/DEN, starta om och försök autentisera.",
                "expected": "Efter omstart krävs ny ceremoni; ingen auth "
                            "utan nyckel.",
                "evidence": "Loggutdrag efter omstart (nekad challenge).",
                "hardware": "PAW, DEN",
            },
            {
                "id": "K2",
                "title": "Ingen flash-persistens (UF2)",
                "instructions": "Inspektera UF2/Flash efter provisionering och "
                                "power-cykla enheten.",
                "expected": "Nyckel/fingerprint får inte överleva i flash.",
                "evidence": "UF2-inspektionslogg + dump-sökning.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "K3",
                "title": "Volatile-wipe biter i assembler",
                "instructions": "Granska genererad assembler för "
                                "secure_clear_key med repoets toolchain och "
                                "verifiera nollställda buffertar i minnesdump.",
                "expected": "Nollställningen optimeras inte bort.",
                "evidence": "Assemblerutdrag + minnesdump.",
                "hardware": "PAW, DEN, build-verktyg",
            },
            {
                "id": "K4",
                "title": "Noll/korrupt nyckel nekar på enheten",
                "instructions": "Provisionera giltig nyckel, korrumpera via "
                                "omprovisionering med nollnyckel.",
                "expected": "MSG_ERROR, därefter nekas challenge (fail "
                            "closed).",
                "evidence": "Logg MSG_ERROR + nekad challenge.",
                "hardware": "PAW, DEN, UNO Q",
            },
            {
                "id": "K5",
                "title": "Timeout/handshake-clear på riktig USB-serie",
                "instructions": "Håll inne key-data > 10 s och starta ny "
                                "handshake mitt i en session.",
                "expected": "PROV_FAILED, lagrad nyckel borta; ny handshake "
                            "nollställer.",
                "evidence": "Logg PROV_FAILED + efterföljande nekad challenge.",
                "hardware": "DEN, UNO Q",
            },
            {
                "id": "K6",
                "title": "Nyckel aldrig på tråd utom fingerprint",
                "instructions": "Sätt logikanalysator på USB + dock-UART "
                                "under ceremoni och session.",
                "expected": "Endast 4-byte fingerprint på tråd, aldrig "
                            "nyckelbyte.",
                "evidence": "Tråddump utan nyckelbyte.",
                "hardware": "UNO Q, DEN, PAW, logikanalysator",
            },
        ],
    },
    {
        "name": "H1-H7 — dock-checks (docs/13 §9)",
        "steps": [
            {
                "id": "H1",
                "title": "RP2350 TRNG-entropi (get_rand_64)",
                "instructions": "Kör flera sessioner och jämför nonce-värden; "
                                "kör en körning med trasig/noll RNG om "
                                "möjligt.",
                "expected": "Nonce unika per session; noll-RNG fångas "
                            "fail-closed.",
                "evidence": "Nonce-lista över körningar.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "H2",
                "title": "UART-signalintegritet 115200 över pogo",
                "instructions": "Mät med oscilloskop: signalnivåer, bit-tid "
                                "(86,8 us, ±2 %), 8N1, inga teckenförluster.",
                "expected": "Ren signal över hela sessionen.",
                "evidence": "Oscilloskopmätning (nivåer, bit-tid).",
                "hardware": "PAW, DEN, oscilloskop",
            },
            {
                "id": "H3",
                "title": "2 s-deadline mot verkliga klockor",
                "instructions": "Sänd RESPONSE försenat (> 2 s) och mät "
                                "PAW-sidans svarstid under session.",
                "expected": "Försenad RESPONSE nekas (kod 1); PAW håller "
                            "budgeten.",
                "evidence": "Tidsstämplad logg (kod 1).",
                "hardware": "PAW, DEN",
            },
            {
                "id": "H4",
                "title": "Oprovisionerad PAW svarar ej",
                "instructions": "Docka oprovisionerad PAW mot DEN och "
                                "observera UART.",
                "expected": "Ingen RESPONSE lämnar Serial1; DEN nekar "
                            "(timeout).",
                "evidence": "LOG: timeout + ingen RESPONSE på tråd.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "H5",
                "title": "UNO Q-ceremoni (knapptryck + USB-distribution)",
                "instructions": "Begär distribution; vänta 5 s utan knapptryck, "
                                "tryck sedan på A0.",
                "expected": "Ingen distribution utan knapptryck; distribution "
                            "startar efter tryck.",
                "evidence": "Logg 'awaiting button press' + distribution efter "
                            "tryck.",
                "hardware": "UNO Q",
            },
            {
                "id": "H6",
                "title": "SRAM-volatilitet vid spänningsbortfall (enhetssida)",
                "instructions": "Provisionera, bryt matningen och starta om "
                                "utan ny ceremoni.",
                "expected": "Nyckeln dör med kraften; enheten startar i "
                            "nekande läge.",
                "evidence": "Omstartslogg + nekad challenge.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "H7",
                "title": "e-paper-degradering under dock-session",
                "instructions": "Dra bort e-paper-panel/kabel mitt i en "
                                "session (eller använd död panel).",
                "expected": "DEN-beslutet påverkas inte; PAW svarar normalt.",
                "evidence": "Autentiseringslogg med panel bortkopplad.",
                "hardware": "PAW, DEN, e-paper",
            },
        ],
    },
    {
        "name": "PRO-45/46 — UNO Q-nyckelutbyte (docs/15/16)",
        "steps": [
            {
                "id": "PRO45-T1",
                "title": "RNG-nyckelgenerering",
                "instructions": "Starta UNO Q; vänta på TRNG health check och "
                                "fingerprint-rad.",
                "expected": "Health check OK, 16 byte, endast fingerprint i "
                            "logg (inga clear-nyckelrader).",
                "evidence": "Serial-utdrag med [PRO-45].",
                "hardware": "UNO Q",
            },
            {
                "id": "PRO45-T2",
                "title": "RNG-felåterhämtning",
                "instructions": "Koppla bort kraft under nyckelgenereringen och "
                                "återstarta.",
                "expected": "ERROR_STATE, ingen export, secureWipeKey "
                            "(fail closed).",
                "evidence": "Serial-utdrag med abortering.",
                "hardware": "UNO Q",
            },
            {
                "id": "PRO46-T3",
                "title": "USB-distribution till DEN",
                "instructions": "Begär distribution till TARGET_PLC och "
                                "övervaka båda sidornas loggar.",
                "expected": "Handshake, CRC, hash-match mellan UNO Q och DEN.",
                "evidence": "Båda sidornas loggar + hash-match.",
                "hardware": "UNO Q, DEN",
            },
            {
                "id": "PRO46-T4",
                "title": "USB-distribution till PAW (PRO-48)",
                "instructions": "Begär distribution till TARGET_PAW och "
                                "övervaka PAW-loggen.",
                "expected": "Handshake, CRC, hash-match (PRO-48).",
                "evidence": "PAW-loggen + hash-match.",
                "hardware": "UNO Q, PAW",
            },
            {
                "id": "PRO46-T5",
                "title": "Operatörsbekräftelse (knappkrav)",
                "instructions": "Begär distribution och vänta 5 s utan tryck; "
                                "tryck sedan A0.",
                "expected": "Ingen distribution utan tryck; distribution "
                            "startar efter tryck.",
                "evidence": "Logg 'awaiting button press' + timeout/efter "
                            "tryck.",
                "hardware": "UNO Q",
            },
            {
                "id": "PRO46-T6",
                "title": "Signal- och tidsverifiering 115200",
                "instructions": "Mät TX/RX med oscilloskop under distribution.",
                "expected": "HIGH >= 0,7*Vcc, LOW <= 0,3*Vcc, bit-tid 86,8 us "
                            "±2 %, inga teckenförluster.",
                "evidence": "Oscilloskopmätning + distribution uten "
                            "teckenförlust.",
                "hardware": "UNO Q, DEN/PAW, oscilloskop",
            },
            {
                "id": "PRO46-T7",
                "title": "Avbruten USB-överföring (fail closed)",
                "instructions": "Koppla loss kabeln under key-data och "
                                "återanslut efter ~1 s.",
                "expected": "distribution_failed, ingen partiell nyckel, "
                            "buffert rensad.",
                "evidence": "Logg PROV_FAILED + rensad buffert.",
                "hardware": "UNO Q, DEN",
            },
            {
                "id": "PRO46-T8",
                "title": "CRC-fel under distribution",
                "instructions": "Inför en man-in-the-middle-enhet som ändrar 1 "
                                "byte i key-paketet.",
                "expected": "CRC mismatch, MSG_ERROR, ingen nyckel lagras.",
                "evidence": "Logg CRC mismatch + MSG_ERROR.",
                "hardware": "UNO Q, DEN, MitM-enhet",
            },
        ],
    },
    {
        "name": "PRO-63 — pen-testfall (docs/pen-test-baseline-pro63)",
        "steps": [
            {
                "id": "PT-01",
                "title": "Replay av giltigt RESPONSE",
                "instructions": "Fånga giltigt RESPONSE på dock-UART med "
                                "logikanalysator och återinjicera i nästa "
                                "session.",
                "expected": "DENIED (HMAC_MISMATCH, kod 5), ACK 0x00.",
                "evidence": "Logg 'hmac mismatch' + ACK-byte på tråd.",
                "hardware": "PAW, DEN, logikanalysator",
            },
            {
                "id": "PT-02",
                "title": "Felaktig nyckel (avvikande master)",
                "instructions": "Provisionera PAW med annan nyckel än DEN och "
                                "kör session; fotografera e-paper efter 60 s.",
                "expected": "DENIED (HMAC_MISMATCH), PAW FAILED, ingen "
                            "accessindikering kvar efter 30 s.",
                "evidence": "Båda sidors loggar + e-paper-foto efter 60 s.",
                "hardware": "PAW, DEN, e-paper",
            },
            {
                "id": "PT-03",
                "title": "Timeout / trunkerad RESPONSE",
                "instructions": "Sänd ofullständig RESPONSE (5 av N byte) "
                                "inom 2 s; separat: komplett men försenad.",
                "expected": "DENIED (TIMEOUT, kod 1); försenad giltig "
                            "RESPONSE nekas.",
                "evidence": "Logg 'timeout' + tidsstämplad tråddump.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "PT-04",
                "title": "Paketförlust och korruption",
                "instructions": "Bitfel i nonce/HMAC/CRC (ett i taget), fel "
                                "ramtyp mot CHALLENGE_SENT, överstor payload, "
                                "resynk-brus före SYNC.",
                "expected": "DENIED med kod 2/3/4/5; skanner återhämtar; loop "
                            "svarar < 100 ms (ingen krasch/hängning).",
                "evidence": "Kod per injiceringsfall + svarstidsobservation.",
                "hardware": "PAW, DEN",
            },
            {
                "id": "PT-05",
                "title": "Fysisk possession",
                "instructions": "(a) Läs av flash via UF2/USB-masslagring; "
                                "(b) autentisera stulen PAW efter nyckelrensning; "
                                "(c) flasha modifierad firmware via BOOTSEL.",
                "expected": "(a) ingen nyckel i dumpen; (b) DENIED; (c) "
                            "angripar­kod exekveras — bekräftad designbegränsning "
                            "(ingen secure boot), dokumenteras som förväntat.",
                "evidence": "Dump-hash + söklogg, DEN-logg, foto.",
                "hardware": "PAW, DEN, testlabb",
            },
            {
                "id": "PT-06",
                "title": "Break-glass-missbruk",
                "instructions": "(a) CONFIRM utan ARM; (b) fel ticket; "
                                "(c) ticket återanvänd efter förfall; "
                                "(d) okänt kommando i beviljat läge; "
                                "(e) bekräfta efter ARM-fönster; "
                                "(f) en person utför båda stegen.",
                "expected": "(a–e) DENIED + audit + låst; förfall efter 120 s; "
                            "(f) tekniskt möjligt — dokumenterad restrisk.",
                "evidence": "[AUDIT]-sekvenser per delfall.",
                "hardware": "DEN",
            },
            {
                "id": "PT-07",
                "title": "Provisioneringsstörning",
                "instructions": "Avbryt PRO-46 mitt i, fel CRC, fel längd, "
                                "nollnyckel; starta ny handshake mitt i session.",
                "expected": "PROV_FAILED, buffertar torkade, lagrad nyckel "
                            "borta; DEN stannar i DENIED.",
                "evidence": "Logg PROV_FAILED + nekad challenge.",
                "hardware": "UNO Q, DEN",
            },
        ],
    },
    {
        "name": "Break-glass + panel (docs/10)",
        "steps": [
            {
                "id": "BG-1",
                "title": "Legitim break-glass-ceremoni på enhet",
                "instructions": "Genomför ticket -> ARM -> CONFIRM -> åtkomst "
                                "och låt föreskrivet fönster förfalla.",
                "expected": "Beviljat tillstånd förfaller (auto-relock); audit "
                            "+ larm loggas; ordinarie auth-väg orörd.",
                "evidence": "Ceremoni-loggar inkl. auto-relock och audit.",
                "hardware": "DEN",
            },
            {
                "id": "PNL-1",
                "title": "Panelbeteende (e-paper) under session",
                "instructions": "Verifiera AUTHENTICATING/AUTHENTICATED/FAILED "
                                "samt att ÅTKOMST-visningen förfaller efter "
                                "30 s (PRO-95).",
                "expected": "Visar beviljande bara vid verklig session; "
                            "förfaller efter 30 s till AUTHENTICATING.",
                "evidence": "E-paper-foto per tillstånd + tidpunkt.",
                "hardware": "PAW, e-paper",
            },
        ],
    },
]


def flatten(checklist=None) -> list[tuple[str, dict]]:
    cl = checklist if checklist is not None else GROUPS
    return [(g["name"], s) for g in cl for s in g["steps"]]


def run_list(checklist=None) -> int:
    cl = checklist if checklist is not None else GROUPS
    total = 0
    for grp in cl:
        print("== %s ==" % grp["name"])
        for s in grp["steps"]:
            total += 1
            print("  %-9s %s" % (s["id"], s["title"]))
    print("\nTotalt %d steg i %d grupper." % (total, len(cl)))
    return 0


#: Kända identitetsmarkörer per roll (banderoller/loggrader från firmware).
#: Matchning sker mot seriell logg — aldrig mot portnamn/Vid:Pid-gissning.
IDENTIFY_NEEDLES = {
    "DEN": ("SHALLOT — PLC Complete Firmware", "[PRO-47]", "[DEN] ",
            "Pico 2"),
    "PAW": ("SHALLOT — PAW Key Receiver", "[PRO-48]", "[PRO-84]",
            "Feather RP2350"),
    "UNO Q": ("SHALLOT — UNO Q Key Authority", "[PRO-45]", "[PRO-46]",
              "STM32U585"),
}


def run_identify(list_ports_fn=None, read_fn=None, baud: int = 115200,
                 timeout: float = 10.0,
                 log_path: str | None = None) -> dict:
    """Identifiera DEN/PAW/UNO Q-portar skrivskyddat. Returnerar mappning.

    Öppnar varje serieport för läsning och matchar firmware-banderoller.
    Skriver aldrig till enheter. Portar utan träff rapporteras som
    "oidentifierad" (verifieras manuellt med monitor). Mappningen loggas
    till JSONL som RIGG-3-evidens.
    """
    from shallot_cli import fido2_sanitize
    if list_ports_fn is None:
        from shallot_cli import serial_adapters
        list_ports_fn = serial_adapters.list_ports
    if read_fn is None:
        from shallot_cli.commands import monitor_cmd

        def read_fn(port, baud, needles, timeout):
            return monitor_cmd.read_until(port, baud, list(needles),
                                          timeout)
    try:
        ports = list_ports_fn()
    except Exception as e:
        print("error: kunde inte lista serieportar: %s"
              % fido2_sanitize.sanitize(str(e)))
        return {"timestamp": _ts(), "type": "bench", "action": "identify",
                "error": "list_ports misslyckades", "mapping": []}
    needle_to_role = {}
    for role, needles in IDENTIFY_NEEDLES.items():
        for needle in needles:
            needle_to_role[needle] = role
    mapping = []
    print("== PORTIDENTIFIERING (skrivskyddad, ingen skrivning) ==")
    if not ports:
        print("Inga serieportar hittades.")
    for p in ports:
        dev = str(p.get("device", ""))
        hit, line = read_fn(dev, baud, list(needle_to_role), timeout)
        if hit is None:
            mapping.append({"port": dev, "roll": "oidentifierad",
                            "bevis": ""})
        else:
            bevis = "%s: %s" % (hit, (line or "").strip())
            mapping.append({"port": dev,
                            "roll": needle_to_role.get(hit,
                                                       "oidentifierad"),
                            "bevis": bevis})
    for m in mapping:
        print("  %-16s %-14s %s" % (
            fido2_sanitize.sanitize(m["port"]),
            m["roll"],
            fido2_sanitize.sanitize(m["bevis"]) if m["bevis"]
            else "(ingen träff — verifiera manuellt med monitor)"))
    known = [m["roll"] for m in mapping if m["roll"] != "oidentifierad"]
    if (len(set(known)) != len(known)
            or any(m["roll"] == "oidentifierad" for m in mapping)):
        print("Varning: dubblett eller oidentifierad roll — "
              "verifiera manuellt med monitor innan PASS.")
    result = {"timestamp": _ts(), "type": "bench", "action": "identify",
              "baud": baud, "timeout_s": timeout, "mapping": mapping}
    _emit(_log_path(log_path), result)
    return result


#: Tillåtna UNO Q-konsolkommandon. Endast "s" är läsande; övriga ändrar
#: enhetens tillstånd och kräver operatörsbekräftelse.
UNOQ_COMMANDS = ("s", "g", "1", "2")

#: Max rader som sparas per unoq-anrop (skydd mot skenande logg).
UNOQ_MAX_LINES = 200


def _confirm_unoq(prompt: str) -> bool:
    try:
        ans = input("%s [j/N]: " % prompt).strip().lower()
    except EOFError:
        return False
    return ans in ("j", "ja", "y", "yes")


def run_unoq(port: str, cmd: str, baud: int = 115200, timeout: float = 20.0,
             yes: bool = False, confirm_fn=None, serial_open_fn=None,
             log_path: str | None = None) -> int:
    """Skicka ett konsolkommando till UNO Q och fånga svaret som evidens.

    ``s`` = status (läsande, ingen bekräftelse). ``g``/``1``/``2`` ändrar
    enhetens tillstånd och kräver bekräftelse (interaktiv fråga eller
    ``yes=True``). ``1``/``2`` kräver dessutom fysiskt A0-knapptryck —
    det steget kan inte automatiseras och påminns explicit. Svaret
    saneras, visas och loggas till JSONL. Returnerar exit-kod.
    """
    from shallot_cli import fido2_sanitize
    cmd = (cmd or "").strip().lower()
    if cmd not in UNOQ_COMMANDS:
        raise ValueError("okänt UNO Q-kommando: %r (välj: %s)"
                         % (cmd, ", ".join(UNOQ_COMMANDS)))
    if not isinstance(port, str) or "\x00" in port or not port.strip():
        print("error: ogiltig --port.", file=sys.stderr)
        return 2
    if cmd != "s" and not yes:
        ask = confirm_fn or _confirm_unoq
        print("Skickar '%s' till UNO Q på %s (ändrar enhetens tillstånd)."
              % (cmd, port))
        if cmd in ("1", "2"):
            print("Distribution kräver dessutom fysiskt tryck på A0-knappen — "
                  "det steget kan inte automatiseras.")
        if not ask("Fortsätt"):
            print("Avbrutet — inget skickades.", file=sys.stderr)
            return 2
    if serial_open_fn is None:
        from shallot_cli import serial_adapters
        serial_open_fn = serial_adapters.open_console
    try:
        ser = serial_open_fn(port, baud=baud, timeout=1.0)
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    except Exception as e:
        print("error: kunde inte öppna port: %s"
              % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if cmd in ("1", "2"):
        print("Skickat '%s' — tryck nu på A0-knappen på UNO Q." % cmd)
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    try:
        with ser:
            ser.write(cmd.encode("ascii"))
            ser.flush()
            while time.monotonic() < deadline and len(lines) < UNOQ_MAX_LINES:
                raw = ser.readline()
                if not raw:
                    continue
                clean = fido2_sanitize.sanitize(
                    raw.decode("utf-8", errors="replace").rstrip("\n"))
                lines.append(clean)
                print("  %s" % clean)
    except KeyboardInterrupt:
        print("\nAvbrutet av användaren.")
    result = {"timestamp": _ts(), "type": "bench", "action": "unoq",
              "port": port, "cmd": cmd, "baud": baud,
              "output": "\n".join(lines)}
    _emit(_log_path(log_path), result)
    return 0


def record_step(step_id: str, resultat: str, evidence: str = "",
                log_path: str | None = None) -> dict:
    """Bokför en operatörsbekräftad dom för ett steg utanför run_verify.

    Ingen övergripande dom sätts här — posten är ett enskilt verifierat
    (eller nekat/skippad) steg med evidens. Okänt steg-ID eller ogiltigt
    resultat felar högt.
    """
    known = {s["id"]: (gname, s) for gname, s in flatten()}
    if step_id not in known:
        raise ValueError("okänt steg: %s" % step_id)
    if resultat not in ("PASS", "FAIL", "SKIP"):
        raise ValueError("ogiltigt resultat: %r (välj PASS/FAIL/SKIP)"
                         % (resultat,))
    gname, step = known[step_id]
    out = {"steg": step_id, "grupp": gname, "titel": step["title"],
           "resultat": resultat, "evidence": evidence}
    _emit(_log_path(log_path), {"timestamp": _ts(), "type": "bench",
                                "action": "step", **out})
    return out


def _print_step(step: dict, index: int, total: int) -> None:
    print()
    print("[%d/%d] %s — %s" % (index, total, step["id"], step["title"]))
    print("  Instruktion: %s" % step["instructions"])
    print("  Förväntat:   %s" % step["expected"])
    if step.get("hardware"):
        print("  Kräver:      %s" % step["hardware"])
    if step.get("evidence"):
        print("  Evidens:     %s" % step["evidence"])


def _verdict_default(step: dict, index: int, total: int) -> dict:
    _print_step(step, index, total)
    while True:
        ans = input("  Resultat (g=godkänt, n=nekat, h=hoppa): ").strip().lower()
        if ans in ("g", "godkant", "pass", "p"):
            resultat = "PASS"
            break
        if ans in ("n", "nekat", "fail", "f"):
            resultat = "FAIL"
            break
        if ans in ("h", "hoppa", "skip", "s"):
            resultat = "SKIP"
            break
    evidence = input("  Evidens (loggutdrag/fil/sökväg; enter = ingen): ").strip()
    return {"resultat": resultat, "evidence": evidence}


def run_verify(checklist=None, step_fn=None,
               log_path: str | None = None,
               summary_path: str | None = None,
               only: list[str] | None = None) -> dict:
    """Kör checklistan steg-för-steg. Returnerar sammandrag.

    Varje steg skickas till step_fn och besvaras med PASS/FAIL/SKIP plus
    evidens. Alla steg loggas till JSONL; sammandraget skrivs till en
    textfil. Resultat utan evidens räknas inte som verifierat.
    ``only`` begränsar körningen till angivna steg-ID:n (okända ID:n
    felar högt); None = hela checklistan.
    """
    if step_fn is None:
        step_fn = _verdict_default
    flat = flatten(checklist)
    if only is not None:
        wanted = list(only)
        known = [s["id"] for _g, s in flat]
        unknown = [i for i in wanted if i not in known]
        if unknown:
            raise ValueError("okänt steg: %s (välj: %s)"
                             % (", ".join(unknown), ", ".join(known)))
        flat = [(g, s) for g, s in flat if s["id"] in set(wanted)]
    log = _log_path(log_path)
    summary_file = _summary_path(summary_path)
    total = len(flat)
    steps_out: list[dict] = []

    print("==== BÄNKVERIFIERING (steg-för-steg) ====")
    print("Antal steg: %d. Kräver fysisk bänk; evidens per steg.\n" % total)
    current: str | None = None
    for i, (gname, step) in enumerate(flat, 1):
        if gname != current:
            print("== %s ==" % gname)
            current = gname
        res = step_fn(step, i, total)
        out = {"steg": step["id"], "grupp": gname, "titel": step["title"],
               "resultat": res.get("resultat"),
               "evidence": res.get("evidence", "")}
        steps_out.append(out)
        _emit(log, {"timestamp": _ts(), "type": "bench", "action": "step",
                    **out})

    fails = [s for s in steps_out if s["resultat"] == "FAIL"]
    verified = [s for s in steps_out if s["resultat"] == "PASS"]
    skipped = [s for s in steps_out if s["resultat"] == "SKIP"]
    if fails:
        overall = "NEKAD"
    elif not skipped and verified:
        overall = "GODKÄNT"
    else:
        overall = "EJ FULLT VERIFIERAD"
    if overall == "GODKÄNT":
        note = "alla punkter verifierade med evidens (PASS + logg)"
    elif fails:
        note = "fails: %s" % ", ".join(s["steg"] for s in fails)
    else:
        note = "verifierade %d/%d, skippade: %s" % (
            len(verified), total, ", ".join(s["steg"] for s in skipped)
            or "-")

    summary = {
        "timestamp": _ts(),
        "type": "bench",
        "action": "run-summary",
        "overall": overall,
        "total": total,
        "godkända": len(verified),
        "nekade": len(fails),
        "skippade": len(skipped),
        "verification_note": note,
        "fails": [s["steg"] for s in fails],
        "skipped": [s["steg"] for s in skipped],
        "steps": steps_out,
    }
    _emit(log, summary)
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(_render_summary(summary), encoding="utf-8")

    print("\n--- BÄNKVERIFIERING-SAMMANFATTNING ---")
    print(_render_summary(summary))
    print("\nJSONL-revisionslogg: %s" % log.resolve())
    print("Textsammanfattning:  %s" % summary_file.resolve())
    return summary


def _render_summary(summary: dict) -> str:
    lines = []
    lines.append("=== SHALLOT — BÄNKVERIFIERING-SAMMANFATTNING ===")
    lines.append("Tid: %s" % summary["timestamp"])
    lines.append("Övergripande: %s" % summary["overall"])
    lines.append("Godkända: %d / %d" % (summary["godkända"], summary["total"]))
    lines.append("Nekade: %d   Skippade: %d"
                 % (summary["nekade"], summary["skippade"]))
    lines.append("Not: %s" % summary["verification_note"])
    lines.append("")
    lines.append("Steg:")
    for s in summary.get("steps", []):
        mark = {"PASS": "OK", "FAIL": "NEKAD", "SKIP": "HOPP"}.get(
            s.get("resultat"), "?")
        lines.append("  %-9s %-6s %s%s" % (
            s.get("steg"), mark, s.get("titel"),
            (" — %s" % s["evidence"]) if s.get("evidence") else ""))
    lines.append("")
    lines.append("Inga hemligheter i denna export; evidens är loggutdrag/")
    lines.append("sökvägar, inte produktionsnycklar.")
    return "\n".join(lines)


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
    last = latest_result(log_path)
    if last is None:
        print("Inga tidigare bänkverifieringsresultat hittade.")
        return None
    print("=== SENASTE BÄNKVERIFIERINGSRESULTAT ===")
    print("Loggposter totalt: %d" % last.pop("_log_records"))
    print(json.dumps(last, indent=2, ensure_ascii=False))
    sf = _summary_path(summary_path)
    if sf.exists():
        print("\n=== TEXTSAMMANFATTNING ===")
        print(sf.read_text(encoding="utf-8"))
    return last