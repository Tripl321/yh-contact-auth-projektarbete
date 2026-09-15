# 11 — Dockat UART-protokoll PAW↔DEN (PRO-87)

**Status:** Utkast 2026-09-09 | **Scope:** protokolldefinition + delad modulskelett.
Ingen radio, ingen autentiseringsfirmware (PRO-88 DEN TX / PRO-84 PAW RX kommer
senare), inga hårdvaruändringar. Enda transporten här är dockad UART (Serial1)
över pogo-pins/USB-C; LoRa används ej.

## 1. Roller och session

| Roll | Beteende |
|---|---|
| DEN (dockningsstation) | Initierar alltid. Skickar CHALLENGE, fattar fail-closed beslut, bekräftar med ACK |
| PAW (ID-bricka) | Svarar endast — initierar aldrig trafik. Svarar på CHALLENGE med RESPONSE, kan skicka ALARM + svara HEARTBEAT |

Sessionsflöde: `DEN --CHALLENGE--> PAW --RESPONSE--> DEN --ACK--> PAW`.
**Svarsdeadline 2 s** från challenge-sändning. Vid uteblivet/ogiltigt svar:
sessionen avbryts, åtkomst nekas (fail closed), ingen automatisk retry inom
sessionen — ny session kräver ny CHALLENGE med färsk nonce.

## 2. Ramformat (little-endian, inga escape-sekvenser)

```
[SYNC 1B = 0xAA] [LEN u16 LE] [TYPE u8] [PAYLOAD 0–64B] [CRC32 u32 LE]
```

- `LEN` = antal PAYLOAD-byte (inte header/CRC).
- Max payload **64 byte**; större LEN avvisas innan fler byte läses.
- CRC32-scope: **LEN + TYPE + PAYLOAD** (allt utom SYNC och CRC-fältet).
- CRC32 = IEEE 802.3 (polynom 0xEDB88320, init 0xFFFFFFFF, xorout 0xFFFFFFFF).
  Referens: CRC32("123456789") = 0xCBF43926.
- SYNC-byte inuti PAYLOAD är data (längdavgränsat format, ingen escaping).

## 3. Meddelandetyper (exakta payload-storlekar)

| Typ | Värde | Riktning | Payload | Storlek |
|---|---|---|---|---|
| CHALLENGE | 0x01 | DEN → PAW | färsk nonce (RP2350 TRNG, 64-bit) | **8 B** |
| RESPONSE | 0x02 | PAW → DEN | HMAC-SHA256(K_mac, nonce) — se avvikelsenot nedan | **32 B** |
| HEARTBEAT | 0x03 | valfri → valfri | ingen (närvaro = liv) | **0 B** |
| ALARM | 0x04 | PAW → DEN | larmkod (t.ex. 0x01 sabotage, 0x02 lågt batteri) | **1 B** |
| ACK | 0xFF | DEN → PAW | status (0x01 godkänd / 0x00 nekad) | **1 B** |

Avvikande payload-storlek för känd typ, okänd typ, LEN > 64, eller CRC-fel
→ ramen kasseras i sin helhet (fail closed, ingen delvis tolkning).

> **Avvikelsenot (låst beteende, se README "Kända specifikationskonflikter"):**
> tidigare revisioner angav `HMAC-SHA256(K, epoch || nonce)`. Båda
> firmwaresidorna + pytest-sviten implementerar och pinnar
> `HMAC-SHA256(K_mac, nonce)` med härledd nyckel
> `K_mac = SHA-256(master || "MAC")[:16]` och utan epoch — epoch finns
> endast i provisioneringsprotokollet (`docs/12`, `docs/14`), där ingen
> epoch distribueras över dock-länken. Ändra inte ensidigt: det bryter
> DEN↔PAW-interop.

## 4. Parser: resynk, partial frames, timeout, fel

- **Resynk:** taggförankrad skanning på SYNC. Skräpbyte före SYNC droppas
  (max `DEN_MAX_RESYNC_SKIPS` = 64, sedan fel). Efter fel (CRC/typ/längd)
  återgår parsern till SYNC-sökning; felbyten kan själv vara nästa SYNC.
- **Partial frames:** ofullständig ram väntar på fler byte (blockerar aldrig;
  anroparen matar in byte allteftersom de anländer).
- **Timeout:** > `DEN_BYTE_TIMEOUT_MS` = 100 ms utan byte mitt i en ram →
  påbörjad ram kasseras (`DEN_ERR_TIMEOUT`). Sessionsdeadline 2 s
  (`DEN_RESPONSE_DEADLINE_MS`) övervakas av sessionslagret (DEN), ej parsern.
- **Felkoder:** `DEN_ERR_CRC`, `DEN_ERR_LENGTH`, `DEN_ERR_TYPE`,
  `DEN_ERR_TIMEOUT`, `DEN_ERR_RESYNC` — alla betyder "kassera, lagra inget".

## 5. Säkerhetskrav

- **Aldrig nyckelmaterial över UART** — varken master-nyckel, K_enc/K_mac
  eller delnycklar. Endast nonce, HMAC, larmkod och status (allt enligt §3).
- **Konstanttidsjämförelse** av RESPONSE-HMAC på DEN-sidan (`den_ct_compare`,
  aldrig `memcmp`); tidig avbrytning får inte läcka matchningsposition.
- HMAC binder svar till challenge (`epoch || nonce`); replay av gammal
  RESPONSE mot ny nonce faller i jämförelsen.
- PAW initierar aldrig: oombedd trafik från PAW-sidan ignoreras av DEN.
- Deadline-överskridning, CRC-fel eller sessionsavbrott = neka (fail closed).

## 6. Implementation

- Delad header-only modul: `libraries/DenUartProtocol/src/DenUartProtocol.h`
  (konstanter, `den_crc32`, `den_encode`, `den_decode`, `den_ct_compare`,
  `DenScanner` med timeout-policy). Transportfri — anroparen matar byte +
  `millis()`; ingen Serial-beroende, ingen allokering.
- Transport (Serial1 TX/RX) implementeras i PRO-88 (DEN) / PRO-84 (PAW).
- Testvektorer: `tests/test_pro87_uart.py` (ramkodning, CRC, ogiltiga ramar,
  resynk, deadline-regel). KAT-digests är hårdkodade IEEE CRC32-värden.

## Referenser

- Arkitektur-pivot (kontaktbaserad primärtransport): `docs/architecture-pivot-2026-09-09.md`
- roadmap: PRO-88 (DEN UART TX), PRO-84 (PAW UART RX), PRO-85 (pogo-docka)
