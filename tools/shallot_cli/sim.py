"""Deterministisk DEN–PAW challenge-response-simulering (SIMULATED / TEST-ONLY).

Speglar firmwarens fail-closed session (DENIED → CHALLENGE_SENT →
AUTHENTICATED → DENIED, 2 s deadline) utan att röra hårdvara.

- Endast deterministiska TESTNYCKLAR (samma publika vektor som
  repoets pytest-suite använder). Hemliga nycklar skrivs aldrig ut —
  resultat-dictar och renderad text innehåller varken nyckelbyte
  eller nyckelhashar, endast nonce, ramar och HMAC-svar (som i
  verkligheten ändå sänds öppet över UART).
- Alla felscenarier slutar fail-closed (deny), precis som firmwaren.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import sys

from shallot_cli import uart

BANNER = "SIMULATED / TEST-ONLY — ingen fysisk hårdvara styrs eller verifieras."

#: Deterministisk testnyckel (publik testvektor, ALDRIG hemlig).
TEST_MASTER = bytes(range(16))
#: Fel nyckel för wrong-key-scenariot (också publik testdata).
WRONG_MASTER = bytes(range(1, 17))
#: Deterministisk test-nonce (8 byte / 64 bit, som firmwarens DEN_NONCE_LEN).
TEST_NONCE = bytes(range(0x10, 0x18))

DEADLINE_MS = uart.RESPONSE_DEADLINE_MS

REASONS = {
    0: "OK",
    1: "TIMEOUT",
    2: "UNEXPECTED_TYPE",
    3: "INVALID_SIZE",
    4: "PARSE_ERROR",
    5: "HMAC_MISMATCH",
    6: "DISCONNECT",
    7: "STALE_RESPONSE",
}

SCENARIOS = ("success", "wrong-key", "timeout", "crc", "disconnect", "late-ack")


def derive_k_mac(master: bytes) -> bytes:
    """K_mac = SHA-256(master || "MAC")[:16] (samma som firmwaren)."""
    return hashlib.sha256(bytes(master) + b"MAC").digest()[:16]


def paw_answer(nonce: bytes, master: bytes = TEST_MASTER) -> bytes:
    """PAW-svar: HMAC-SHA256(K_mac, nonce), 32 byte."""
    return hmac_module.new(derive_k_mac(master), bytes(nonce), hashlib.sha256).digest()


def _base(nonce: bytes) -> dict:
    challenge = uart.encode(uart.T_CHALLENGE, nonce)
    return {
        "nonce_hex": nonce.hex(),
        "frame_type": "CHALLENGE 0x01 -> RESPONSE 0x02 -> ACK 0xFF",
        "challenge_frame_hex": challenge.hex(),
        "response_frame_hex": None,
        "response_hmac_hex": None,
        "result": "DENIED",
        "decision": "deny (fail closed)",
        "reason_code": None,
        "reason": None,
        "ack": "0x00",
    }


def run_scenario(name: str) -> dict:
    """Kör ett scenario. Returnerar en dict utan något nyckelmaterial."""
    if name not in SCENARIOS:
        raise ValueError("okänt scenario: %r (välj: %s)" % (name, "|".join(SCENARIOS)))
    nonce = TEST_NONCE
    out = _base(nonce)
    out["scenario"] = name

    if name == "success":
        mac = paw_answer(nonce)
        out["response_frame_hex"] = uart.encode(uart.T_RESPONSE, mac).hex()
        out["response_hmac_hex"] = mac.hex()
        expect = paw_answer(nonce)
        if hmac_module.compare_digest(expect, mac):
            out.update(result="AUTHENTICATED", decision="grant",
                       reason_code=0, reason=REASONS[0], ack="0x01")
        return out

    if name == "wrong-key":
        mac = paw_answer(nonce, master=WRONG_MASTER)
        out["response_frame_hex"] = uart.encode(uart.T_RESPONSE, mac).hex()
        out["response_hmac_hex"] = mac.hex()
        out.update(reason_code=5, reason=REASONS[5],
                   detail="PAW använde fel nyckel; konstanttidsjämförelsen fallerade.")
        return out

    if name == "timeout":
        full = uart.encode(uart.T_RESPONSE, paw_answer(nonce))
        out["response_frame_hex"] = full[:5].hex()
        out.update(reason_code=1, reason=REASONS[1],
                   detail="ofullständig RESPONSE inom %d s-deadline (5/%d byte); "
                          "sessionen avbröts." % (DEADLINE_MS // 1000, len(full)))
        return out

    if name == "crc":
        bad = bytearray(uart.encode(uart.T_RESPONSE, paw_answer(nonce)))
        bad[-1] ^= 0x01
        out["response_frame_hex"] = bytes(bad).hex()
        try:
            uart.decode(bytes(bad))
        except uart.UartError:
            pass
        out.update(reason_code=4, reason=REASONS[4],
                   detail="CRC32-fel i RESPONSE; ramen kasserades i sin helhet.")
        return out

    if name == "disconnect":
        out.update(reason_code=6, reason=REASONS[6],
                   detail="inga byte från PAW sedan CHALLENGE (länken antas nere).")
        return out

    if name == "late-ack":
        mac = paw_answer(nonce)
        out["response_frame_hex"] = uart.encode(uart.T_RESPONSE, mac).hex()
        out["response_hmac_hex"] = mac.hex()
        out.update(reason_code=1, reason=REASONS[1],
                   detail="giltig RESPONSE anlände efter %d s-deadline; för sent svar nekas."
                          % (DEADLINE_MS // 1000))
        return out

    raise AssertionError("unreachable")  # pragma: no cover


def render(res: dict) -> str:
    """Mänsklig text. Innehåller alltid BANNER, nonce, ramtyp, resultat
    och fail-closed-beslut — aldrig nyckelmaterial."""
    lines = [
        BANNER,
        "scenario : %s" % res["scenario"],
        "nonce    : %s (8 byte, deterministisk test-nonce)" % res["nonce_hex"],
        "ramtyp   : %s" % res["frame_type"],
        "challenge: %s" % res["challenge_frame_hex"],
    ]
    if res.get("response_frame_hex"):
        lines.append("response : %s" % res["response_frame_hex"])
    if res.get("response_hmac_hex"):
        lines.append("hmac     : %s" % res["response_hmac_hex"])
    lines.append("resultat : %s (kod %s: %s)" % (res["result"], res["reason_code"], res["reason"]))
    lines.append("beslut   : %s" % res["decision"])
    if res.get("detail"):
        lines.append("detalj   : %s" % res["detail"])
    lines.append("nyckel   : deterministisk testnyckel (visas aldrig)")
    return "\n".join(lines)


def run_cli(scenario: str) -> int:
    """CLI-presentation av en simulering. Exit 0 = visad, 2 = användning."""
    try:
        res = run_scenario(scenario)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print(render(res))
    return 0
