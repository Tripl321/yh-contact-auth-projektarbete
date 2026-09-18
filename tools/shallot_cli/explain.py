"""Lokala förklaringstexter om SHALLOT (PRO-100).

Endast publik, kuraterad text — inga nycklar, noncer, fingeravtryck eller
hex-vektorer. Texterna visas alltid direkt (fungerar offline); Ollama kan
i tillägg utveckla ett ämne via `shallot explain <ämne> --ai`, varvid
prompten enbart innehåller texten nedan (se `build_prompt`).
"""

from __future__ import annotations

TOPICS = {
    "auth": (
        "Challenge-response (DEN-PAW)",
        "DEN skickar en färsk slump-nonce som challenge över dock-UART. "
        "PAW svarar med HMAC-SHA256 över noncen, beräknad med den "
        "provisionerade nyckelns härledda MAC-nyckel. DEN jämför i konstant "
        "tid och beviljar endast vid exakt match inom 2 sekunders deadline. "
        "Allt annat — fel typ, fel storlek, CRC-fel, HMAC-fel, timeout, "
        "tystnad — nekas fail-closed med ACK 0x00.",
    ),
    "provisioning": (
        "USB-provisionering (PRO-46)",
        "UNO-Q genererar AES-nyckeln i hårdvaru-TRNG och distribuerar den "
        "över USB-UART med CRC-kontroll och hash-bekräftelse tillbaka. "
        "Operatören bekräftar fysiskt med knapp på UNO-Q. Nollnyckel "
        "avvisas; timeout eller fel torkar nyckeln och låser. Skyddet är "
        "fysisk närvaro — ingen kryptografisk sändarautentisering.",
    ),
    "fail-closed": (
        "Fail-closed",
        "Systemets grundregel: varje fel, timeout, omstart eller ogiltigt "
        "resultat lämnar eller återför till låst läge (DENIED). PAW svarar "
        "aldrig utan giltig nyckel, DEN beviljar aldrig utan verifierat "
        "svar, och nyckelmaterial torkas vid varje felväg. Nekande är "
        "default — beviljande kräver fullständig, giltig kedja.",
    ),
    "break-glass": (
        "Break-glass serviceläge (PRO-97)",
        "Kortlivat lokalt serviceläge för definierade åtgärder (STATUS och "
        "ABORT) — inte generell upplåsning och aldrig nödstoppsersättning. "
        "Ceremoni: BG ARM visar en färsk ticket, BG CONFIRM ekar den inom "
        "60 sekunder, beviljat läge varar 120 sekunder med larm. Allt "
        "förfaller till låst läge; varje användning larmar och auditloggas.",
    ),
    "session": (
        "Session och giltighet (PRO-95)",
        "En beviljad session är kortlivad: DEN återgår till DENIED efter "
        "sessionsgapet och PAW:s beviljandevisning förfaller efter 30 "
        "sekunder oavsett protokolltillstånd. Omstart kräver ny nyckel "
        "och ny ceremoni — ingen åtkomst överlever strömavbrott eftersom "
        "nyckeln bara finns i flyktigt SRAM.",
    ),
    "audit": (
        "Larm och audit",
        "DEN rapporterar beslut som icke-hemliga sifferkoder över USB-serie "
        "och skriver [AUDIT]-rader med sekvensnummer, tid och händelse för "
        "provisionering och break-glass. Auditringen är flyktig SRAM (16 "
        "poster, äldst skrivs över) — konsolsidan måste fånga den. "
        "Känsliga värden loggas aldrig i defaultbyggen.",
    ),
    "fido2": (
        "FIDO2-admin (MamaBear)",
        "Administrativt godkännande via FIDO2-authenticator. Den privata "
        "nyckeln lämnar aldrig authenticatorn; repot bär endast publik "
        "metadata. Credential-ID:n och tokens maskeras i loggar. En stulen "
        "token kan läsas ur flash utan Secure Boot — produktionsläge "
        "kräver Secure Boot och OTP.",
    ),
    "uart": (
        "Dock-UART-ramformat",
        "En ram är SYNC-byte, längd, typ, payload (0–64 byte) och CRC32. "
        "Kända ramtyper är challenge, response, heartbeat, alarm och ack "
        "med fast payload-storlek per typ. Allt ogiltigt — fel SYNC, längd, "
        "typ eller CRC — kasseras fail-closed och skannern söker ny SYNC.",
    ),
}


def topic_names() -> list[str]:
    """Ämnesnycklar i stabil ordning."""
    return sorted(TOPICS)


def render(topic: str) -> str:
    """Lokal text för ett ämne. Kastar KeyError för okänt ämne."""
    title, body = TOPICS[topic]
    return "%s\n\n%s\n\nLokal text — ingen extern tjänst använd." % (title, body)


def build_prompt(topic: str) -> str:
    """Bygg AI-prompten. Innehåller endast den kuraterade texten ovan —
    aldrig nycklar, loggar, repoinnehåll eller användardata."""
    title, body = TOPICS[topic]
    return (
        "Du förklarar säkerhetssystemet SHALLOT kort på svenska. "
        "Utgå endast från KÄLLTEXTEN nedan — hitta inte på nycklar, "
        "kommandon, koder eller tidsgränser utöver vad som står där. "
        "Svara koncist (högst 150 ord).\n\n"
        "KÄLLTEXT (%s):\n%s" % (title, body)
    )
