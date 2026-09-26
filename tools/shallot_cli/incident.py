"""Presentationvänlig simulerad säkerhetsincident (SIMULERING / DEMOSYSTEM).

Scenografi för projektion/skärminspelning: börjar som ett inzoomat
driftlarm och avslöjar sedan SHALLOT CLI. Allt är deterministiskt
(fasta tidsstämplar) och hårdvarufritt. Utdata utger sig aldrig för
att vara data från ett verkligt OT-system eller en verklig incident:
SIMULERING-märkning finns överst, i sc rubriken och underst.

Händelsen speglar verklig SHALLOT-semantik (fail-closed deny vid
misslyckad HMAC, jfr `shallot simulate auth --scenario wrong-key`)
utan att röra befintliga flöden — denna modul återanvänder inga
verkliga beslutsvägar och ändrar ingen semantik.
"""

from __future__ import annotations

import sys

BANNER_TOP = [
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    "!!! SIMULERING — DEMOSYSTEM. Ingen verklig incident.      !!!",
    "!!! Ingen fysisk hårdvara styrs eller avläses.            !!!",
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
]

BANNER_BOTTOM = [
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    "!!! SLUT PÅ SIMULERINGEN — DEMOSYSTEM.                    !!!",
    "!!! Detta var inte data från ett verkligt OT-system.      !!!",
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
]

#: Fast bastid (UTC) — deterministisk för repris och test.
BASE_TS = "2026-09-15T10:00:00Z"

SCENE_TITLE = "DRIFTLARM (SIMULERAT SCENARIO): overifierad ändringsbegäran"

#: (offset_s, händelsetext) — de fyra krävda raderna ordagrant inkluderade.
EVENTS = (
    (0, "Ändringsbegäran upptäckt — skrivkommando mot process, avsändare overifierad"),
    (
        1,
        "Verifiering saknas eller misslyckades — HMAC-kontroll föll (DEN: HMAC_MISMATCH, kod 5)",
    ),
    (1, "Åtgärd nekad — fail closed — ACK 0x00, session avbruten"),
    (2, "Ingen processändring genomförd — tillstånd verifierat oförändrat"),
)

REVEAL_TITLE = "ZOOMA UT — AVSLÖJANDE: SHALLOT CLI (SIMULERING)"

REVEAL_LINES = (
    "Det du just såg var en simulering, inte ett verkligt driftlarm.",
    "Verklig semantik som speglas: DEN nekar överifierad ändring fail-closed.",
    "Motsvarar: shallot simulate auth --scenario wrong-key",
    "  -> DENIED (kod 5: HMAC_MISMATCH), beslut deny (fail closed), ACK 0x00.",
    "Kör själv den verkliga kontrollen (deterministisk, hårdvarufri):",
    "  shallot simulate auth --scenario wrong-key",
    "  shallot test den",
    "Ingen hårdvara har styrts eller avlästs under denna demonstration.",
)


def _ts(offset_s: int) -> str:
    """Fast tidsstämpel: bastid + offset (alltid samma utdata)."""
    base_h, base_m, base_s = 10, 0, 0
    total = base_h * 3600 + base_m * 60 + base_s + offset_s
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return "2026-09-15T%02d:%02d:%02dZ" % (h, m, s)


def run_incident() -> dict:
    """Bygg incidenten som fakta-dict (deterministisk, utan hemligheter)."""
    events = [{"ts": _ts(off), "line": text} for off, text in EVENTS]
    return {
        "scenario": "unsigned-change-request",
        "base_ts": BASE_TS,
        "events": events,
        "reveal": list(REVEAL_LINES),
    }


def render(res: dict) -> str:
    """Mänsklig text: banner, larm-scen med tidsstämplar, avslöjande, banner."""
    lines = list(BANNER_TOP)
    lines += ["", SCENE_TITLE, ""]
    for ev in res["events"]:
        lines.append("%s  %s" % (ev["ts"], ev["line"]))
    lines += ["", REVEAL_TITLE, ""]
    lines += list(res["reveal"])
    lines += ["", *BANNER_BOTTOM]
    return "\n".join(lines)


def run_cli() -> int:
    """CLI-presentation av incidenten. Exit 0 = visad, 1 = körfel."""
    try:
        print(render(run_incident()))
    except Exception as e:
        print("error: kunde inte visa demo: %s" % e, file=sys.stderr)
        return 1
    return 0
