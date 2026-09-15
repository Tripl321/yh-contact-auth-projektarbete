"""Reproducerbart 4-stegs testflöde (SIMULATED / TEST-ONLY).

Kedjar distribution -> DEN-challenge -> PAW-response -> verifiering +
e-paper-status i en deterministisk körning, för lyckat flöde och
fail-closed-fall. Återanvänder ``uart`` (ramar) och ``sim`` (testvektorer,
HMAC-orakel) — importerar aldrig repoets testfiler.

- Allt här är automatiserat och hårdvarufritt; stegen under
  ``hardware_steps`` måste köras på fysisk bänk separat (se docs/16).
- Inget nyckelmaterial lämnar motorn: resultat innehåller nonce, ramar,
  HMAC-svar och fingerprint — aldrig master- eller K_mac-byte.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module

from shallot_cli import sim
from shallot_cli import uart

BANNER = sim.BANNER

STAGES = ("key-distribution", "den-challenge", "paw-response", "verify-and-display")

SCENARIOS = ("success", "wrong-key", "timeout", "crc", "disconnect", "late-ack", "no-key")

#: Förväntat utfall per scenario (resultat, beslut, skälkod).
EXPECTED = {
    "success": ("AUTHENTICATED", "grant", 0),
    "wrong-key": ("DENIED", "deny (fail closed)", 5),
    "timeout": ("DENIED", "deny (fail closed)", 1),
    "crc": ("DENIED", "deny (fail closed)", 4),
    "disconnect": ("DENIED", "deny (fail closed)", 6),
    "late-ack": ("DENIED", "deny (fail closed)", 1),
    "no-key": ("DENIED", "deny (fail closed)", 5),
}

#: PAW-display per utfall (ikon, text) — samma kontrakt som firmwaren.
EPAPER = {
    "authenticating": ("dots-in-circle", None),
    "authenticated": ("checkmark-in-circle", "AUTHENTICATED"),
    "failed": ("x-in-circle", None),
}

#: Fysiska bänksteg (körs separat — ingår ej i denna körning).
HARDWARE_STEPS = (
    ("H1", "Provisionera via UNO Q-ceremoni (knapptryck + USB); jämför "
           "4-byte fingerprint mot flödets (se docs/16)."),
    ("H2", "Docka PAW–DEN (pogo, 115200); DEN sänder CHALLENGE — jämför "
           "challenge-ram (se docs/13 §3)."),
    ("H3", "PAW svarar med RESPONSE; jämför HMAC mot flödets svar."),
    ("H4", "Läs DEN-verdict i USB-loggen (AUTHENTICATED/FAILED + kod); "
           "bekräfta ACK 0x01/0x00."),
    ("H5", "Kontrollera e-paper visuellt: bock + text endast vid grant — "
           "aldrig vid pågående/nekad (se paw-main README)."),
)

_T_CHALLENGE_AT = 0
_T_ANSWER_OK_MS = 100
_T_ANSWER_LATE_MS = uart.RESPONSE_DEADLINE_MS + 1


def _fingerprint(master: bytes) -> str:
    """4-byte SHA-256-fingerprint (samma som STORED-meddelandet)."""
    return hashlib.sha256(bytes(master)).digest()[:4].hex()


def run_flow(name: str) -> dict:
    """Kör ett scenario genom alla fyra steg. Returnerar fakta-dict utan
    nyckelmaterial. ``matches_expected`` är True om utfallet följer
    förväntad fail-closed-tabell (annars motorfel)."""
    if name not in SCENARIOS:
        raise ValueError("okänt flöde: %r (välj: %s)" % (name, "|".join(SCENARIOS)))
    nonce = sim.TEST_NONCE
    stages: list[dict] = []

    # Steg 1: nyckeldistribution (USB-ceremoni, mockad deterministiskt).
    if name == "no-key":
        stages.append({"stage": STAGES[0], "ok": False,
                       "detail": "ingen nyckel provisionerad — båda noder "
                                 "oprovisionerade (fail closed nedströms)."})
        master = None
        fingerprint = None
    else:
        master = sim.TEST_MASTER
        if not any(master):  # samma nollavvisning som firmwaren
            raise AssertionError("testnyckeln får aldrig vara noll")
        fingerprint = _fingerprint(master)
        stages.append({"stage": STAGES[0], "ok": True,
                       "detail": "master (16 B) -> K_mac härledd hos båda "
                                 "noderna; fingerprint %s (samma som STORED)." % fingerprint})

    # Steg 2: DEN-challenge (färsk deterministisk test-nonce).
    challenge = uart.encode(uart.T_CHALLENGE, nonce)
    stages.append({"stage": STAGES[1], "ok": True,
                   "detail": "CHALLENGE sänd, svarsdeadline %d ms." % uart.RESPONSE_DEADLINE_MS})

    # Steg 3: PAW-response (fail-closed-varianter per scenario).
    response_frame = None
    response_hmac = None
    if name in ("success", "late-ack"):
        mac = sim.paw_answer(nonce)
        response_hmac = mac.hex()
        response_frame = uart.encode(uart.T_RESPONSE, mac).hex()
        detail = "korrekt HMAC-svar kodat (%d B)." % len(uart.encode(uart.T_RESPONSE, mac))
    elif name == "wrong-key":
        mac = sim.paw_answer(nonce, master=sim.WRONG_MASTER)
        response_hmac = mac.hex()
        response_frame = uart.encode(uart.T_RESPONSE, mac).hex()
        detail = "svar under fel nyckel (HMAC-matchning väntas fallera)."
    elif name == "crc":
        bad = bytearray(uart.encode(uart.T_RESPONSE, sim.paw_answer(nonce)))
        bad[-1] ^= 0x01
        response_frame = bytes(bad).hex()
        detail = "RESPONSE med korrupt CRC (ramen ska kasseras hel)."
    elif name == "timeout":
        full = uart.encode(uart.T_RESPONSE, sim.paw_answer(nonce))
        response_frame = full[:5].hex()
        detail = "ofullständig RESPONSE (%d/%d B) inom deadline." % (5, len(full))
    else:  # disconnect, no-key: inte en byte från PAW
        detail = ("inga byte från PAW sedan CHALLENGE." if name == "disconnect"
                  else "oprovisionerad PAW svarar aldrig (noll sändningar).")
    stages.append({"stage": STAGES[2], "ok": response_frame is not None or name in ("disconnect", "no-key"),
                   "detail": detail})

    # Steg 4: DEN-verifiering + e-paper-status (verkliga kontroller på ramarna).
    if name == "success":
        ptype, payload = uart.decode(bytes.fromhex(response_frame))
        assert ptype == uart.T_RESPONSE
        expect = sim.paw_answer(nonce)
        if not (hmac_module.compare_digest(expect, payload)
                and _T_ANSWER_OK_MS <= uart.RESPONSE_DEADLINE_MS):
            raise AssertionError("motorfel: korrekt svar underkändes")
        result = ("AUTHENTICATED", "grant", 0, "OK")
    elif name == "wrong-key":
        ptype, payload = uart.decode(bytes.fromhex(response_frame))
        ok = hmac_module.compare_digest(sim.paw_answer(nonce), payload)
        if ok:
            raise AssertionError("motorfel: fel nyckel matchade")
        result = ("DENIED", "deny (fail closed)", 5, "HMAC_MISMATCH")
    elif name == "crc":
        try:
            uart.decode(bytes.fromhex(response_frame))
        except uart.UartError:
            result = ("DENIED", "deny (fail closed)", 4, "PARSE_ERROR")
        else:
            raise AssertionError("motorfel: korrupt CRC avkodades")
    elif name == "timeout":
        result = ("DENIED", "deny (fail closed)", 1, "TIMEOUT")
    elif name == "disconnect":
        result = ("DENIED", "deny (fail closed)", 6, "DISCONNECT")
    elif name == "late-ack":
        ptype, payload = uart.decode(bytes.fromhex(response_frame))
        ok = hmac_module.compare_digest(sim.paw_answer(nonce), payload)
        late = _T_ANSWER_LATE_MS > uart.RESPONSE_DEADLINE_MS
        if not (ok and late):
            raise AssertionError("motorfel: sent svar förväntades")
        result = ("DENIED", "deny (fail closed)", 1, "TIMEOUT")
    else:  # no-key: DEN-grind (saknad nyckel) nekar utan HMAC-jämförelse
        result = ("DENIED", "deny (fail closed)", 5, "HMAC_MISMATCH")
    res_text, decision, code, reason = result
    if name == "no-key":
        epaper_status = "authenticating"  # PAW-display orörd utan credential
    else:
        epaper_status = "authenticated" if res_text == "AUTHENTICATED" else "failed"
    icon, text = EPAPER[epaper_status]
    stages.append({"stage": STAGES[3], "ok": res_text == "AUTHENTICATED" or code in (1, 4, 5, 6),
                   "detail": "DEN-verdict %s (kod %d: %s); PAW-display %s." % (res_text, code, reason, epaper_status)})

    out = {
        "scenario": name,
        "stages": stages,
        "nonce_hex": nonce.hex(),
        "fingerprint_hex": fingerprint,
        "challenge_frame_hex": challenge.hex(),
        "response_frame_hex": response_frame,
        "response_hmac_hex": response_hmac,
        "result": res_text,
        "decision": decision,
        "reason_code": code,
        "reason": reason,
        "ack": "0x01" if res_text == "AUTHENTICATED" else "0x00",
        "epaper": {"status": epaper_status, "icon": icon, "text": text},
        "hardware_steps": [{"id": i, "step": t} for i, t in HARDWARE_STEPS],
    }
    out["matches_expected"] = (res_text, decision, code) == EXPECTED[name]
    return out


def render(res: dict) -> str:
    """Mänsklig text: banner, steg, ramar, resultat, display — sedan
    hårdvarustegen som måste köras separat. Aldrig nyckelmaterial."""
    lines = [
        BANNER,
        "flöde     : distribution -> challenge -> response -> display",
        "scenario  : %s" % res["scenario"],
    ]
    for st in res["stages"]:
        lines.append("steg %-18s : %s — %s" % (st["stage"], "OK" if st["ok"] else "FAIL", st["detail"]))
    lines += [
        "nonce     : %s (8 byte test-nonce)" % res["nonce_hex"],
        "challenge : %s" % res["challenge_frame_hex"],
    ]
    if res.get("fingerprint_hex"):
        lines.append("fingerprint: %s (4 byte, samma som STORED)" % res["fingerprint_hex"])
    if res.get("response_frame_hex"):
        lines.append("response  : %s" % res["response_frame_hex"])
    if res.get("response_hmac_hex"):
        lines.append("hmac      : %s" % res["response_hmac_hex"])
    lines.append("resultat  : %s (kod %s: %s)" % (res["result"], res["reason_code"], res["reason"]))
    lines.append("beslut    : %s" % res["decision"])
    ep = res["epaper"]
    lines.append("e-paper   : %s (ikon %s%s)" % (
        ep["status"], ep["icon"], ", text %r" % ep["text"] if ep["text"] else ", ingen text"))
    lines.append("nyckel    : deterministisk testnyckel (visas aldrig)")
    lines.append("Fysisk hårdvara (körs separat — ingår ej i denna körning):")
    for h in res["hardware_steps"]:
        lines.append("  [%s] %s" % (h["id"], h["step"]))
    return "\n".join(lines)
