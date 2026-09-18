# 09 — Integrationsbeskrivning (PRO-67)

**Status:** Utkast 2026-09-18 | PRO-67 | Beskriver aktuell implementation
sådan den står i `pro-demo-incident-cli` (kod + tester + bänkdokumentation).
Markering i varje avsnitt: **[I]** implementerat och testlåst i suite,
**[B]** kräver fysisk bänkverifiering, **[R]** kvarvarande restrisk.
Dokumentet hävdar varken produktionsmognad eller full compliance.

## 1. Systemöversikt

SHALLOT är ett dockat autentiseringssystem i tre noder: PAW (ID-bricka),
DEN (docken som fattar beslut) och UNO-Q (nyckelauktoritet med MPU-del).
Primärtransport är UART; LoRa är explicit ur aktivt scope
(`docs/00-scope.md`).

```text
[UNO-Q MCU] --USB UART PRO-46--> [PAW] [DEN]   (nyckelceremoni, knappbekräftelse)
[PAW] <--dock-UART Serial1--> [DEN]            (challenge-response, 2 s-deadline)
[DEN] --USB-serie--> [konsol]                  (logg, reason codes, audit, BG-ceremoni)
[MamaBear/MPU] --Bridge-RPC--> [UNO-Q MCU]     (status/fingerprint, aldrig nyckel)
[FIDO2-authenticator] --USB/CTAP--> [admin]    (provisioneringsgodkännande)
```

## 2. PAW — ID-bricka (Feather RP2350) [I]

Firmware `id-kort/paw-main/paw-main.ino`. Tar emot challenge (8-byte
TRNG-nonce) över dock-UART, svarar HMAC-SHA256(`kMac`, nonce) och visar
status på e-paper. Svarar aldrig utan giltig provisionerad nyckel
(`key_is_valid` nekar även all-zero master); obeställda ramar ignoreras.
Nyckel, `kMac`/`kEnc` i SRAM; torkas vid boot/timeout/fel/ny session
(PRO-94). Beviljandevisning förfaller efter 30 s oavsett tillstånd;
boot visar låst läge (PRO-95). Känsliga loggar bakom `SECURE_DEBUG`.

## 3. DEN — beslutsnod (Pico 2, RP2350) [I]

Firmware `plc/den-main/den-main.ino`. Tillstånd
`DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED`; beviljande kräver
komplett giltigt RESPONSE inom exakt 2 s, konstanttidsjämförelse och
godkänd blocklist-grind. Varje felväg går via `den_fail` → DENIED +
nonce-wipe; beviljande bor ~1 sessionsgap. Icke-hemliga reason codes
0–11 över USB-serie. Ed25519-blocklist verifieras mot inbyggd publik
nyckel (placeholder-nollor = neka allt fail-closed, PRO-98).

## 4. UNO-Q — nyckelauktoritet (STM32U585 + MPU) [I]

MCU (`uno-q-key-authority-mcu.ino`) genererar AES-128 ur hårdvaru-TRNG
med hälsokontroll, distribuerar via USB-UART med CRC + lagrings-hash och
kräver fysisk knappbekräftelse. MPU-skriptet (`uno-q-key-authority-mpu.py`)
orkestrerar via Bridge-RPC och ser endast tillstånd/fingerprint —
aldrig nyckelmaterial. Sign-fel torkar signatur och stoppar sändning;
`keyPacket` torkas efter transmit (PRO-94). Blocklist-privatnyckeln är
oprovisionerad: sign/distribute är fail-closed död kod tills HSM-process
finns **[R]**.

## 5. UART challenge-response [I/B]

Per session: `CHALLENGE(8B)` → `RESPONSE(32B HMAC)` inom 2000 ms →
konstanttidsverifiering → `ACK(0x01/0x00)` + `AUTHENTICATED/FAILED`-logg.
Ramformat, CRC32 och parser delas via `libraries/DenUartProtocol`
(ingen duplicering). Logik och felvägar är mock- och KAT-testade
(`test_pro87/88/84/61/62`); **2 s-deadline och happy path är enligt
projektets bänkdokumentation hårdvarubevisade** (`docs/12`,
`docs/13-pro-53-fail-closed`) **[B]** — suite bevisar logik, inte
kiseltiming. E2E på sammansatt bänk återstår **[R]**.

## 6. USB-provisionering (PRO-46) [I/B]

Ceremoni: handshake → nyckel (16 B) + CRC32 → lagrings-hash tillbaka →
jämförelse i konstant tid. Nollnyckel avvisas; timeout/fel torkar nyckel
och låser. Skyddet är fysisk närvaro + knapp + CRC/hash — **ingen
kryptografisk sändarautentisering** **[R]**. Delad USB-tråd med
servicekonsol: strikt ASCII endast i viloläge **[I]**.

## 7. FIDO2-admin (MamaBear) [I/R]

Administrativt godkännande via FIDO2-authenticator (`docs/19`,
`tools/shallot_cli/fido2*`). Privat nyckel lämnar aldrig authenticatorn;
repot bär endast credential-ID + publik nyckel. Credential-ID:n, tokens
och hex maskeras i loggar (testlåst). **Stulen admin-token kan
flash-dumpas utan Secure Boot** — Secure Boot + OTP krävs för
produktionsläge **[R]**.

## 8. E-paper-status [I/R]

Visar AUTHENTICATING / AUTHENTICATED (bock + text) / FAILED; aldrig PII,
endast ikoner + statustext. Icke-blockerande (request + background-poll
med degraded-läge). **Bistabil panel behåller sista bilden utan ström**
— strömavbrott fryser indikationen tills boot (alltid låst; ingen
åtkomst kvarstår då nyckeln dör med SRAM) **[R]**.

## 9. Larm, audit och break-glass (avgränsat) [I]

DEN loggar beslut som icke-hemliga koder; `[AUDIT]`-rader (seq/tid/
händelse) för provisionering och break-glass; SRAM-ring (16, äldst
skrivs över) — konsolen måste fånga, flyktighet dokumenterad **[R]**.
Break-glass (PRO-97): kortlivat lokalt serviceläge för definierade
åtgärder (`STATUS`/`ABORT`), ticket-ceremoni 60 s + grant-fönster 120 s
med larm, auto-relock vid timeout/fel/omstart. **Inte generell
upplåsning, aldrig nödstoppsersättning; tvåperson är fysisk
prototypprocedur** som firmwaren inte kan bevisa **[R]**.

## 10. Statusmatris

| Område | Implementerat [I] | Bänk krävs [B] | Restrisk [R] |
|---|---|---|---|
| Dock-auth + fail-closed | Logik + felvägar testlåsta | 2 s-timing, happy path (delvis gjord, se docs/12) | E2E sammansatt bänk |
| Nyckelhantering SRAM/wipe | Källguards + 30 tester | K1–K6 (volatilitet, UF2-inspektion, trådanalys) | K7 bitfel, ingen ECC |
| Beviljandevisning | 30 s-förfall testlåst | Panelbeteende på enhet | Bildfrys vid strömavbrott |
| Break-glass | Ceremoni + relock + audit testlåst | Ceremoni på enhet | Single-operator, flyktig audit, ingen duress |
| Blocklist | Verify + fail-closed tom lista | Lista signerad av HSM-nyckel | Provisioneringsflöde saknas |
| FIDO2-admin | Flöde + maskning testlåst | Token på enhet | Dump utan Secure Boot |
| Krypto | KAT + mirrors i suite | TRNG-statistik (NIST 800-90B), assembler-wipe | Oberoende audit, sidokanaler |
| Supply chain | CI-byggen, doctor-guards | — | UF2/beroenden utan full pinning-review |

## 11. Icke-påståenden

Detta dokument påstår inte att systemet är produktionsmoget, inte att
compliance (NIST/CSF/IEC eller annan ram) är uppfylld — framework-
mappningen (`docs/framework-mappning.md`) är en spårbarhetsartefakt, inte
ett certifikat — och inte att bänkverifiering K1–K6 är utförd. Kvarstående
arbete styrs av öppna PR:er och bänkguiderna (`docs/15`, `docs/16`).
