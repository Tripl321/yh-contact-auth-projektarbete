# 08 — Hotmodellering (PRO-55)

**Status:** Utkast 2026-09-18 | PRO-55 | Manuell granskning mot verifierad
implementation. Docker-körning av OWASP Let's Threat Model förberedd
(config + exkluderingar klara) men avvaktar `PROVIDER_API-nyckel`; detta
dokument innehåller därför endast egenskaper verifierade i kod/test/bänk
samt tydliga restrisker — inga verktygsgenererade påståenden.

Scope: PAW, DEN, UNO-Q (MCU+MPU), dock-UART, USB/provisionering, FIDO2-
admin, break-glass-serviceläge, larm/audit. LoRa är explicit ur scope
(`docs/00-scope.md`); arkiverad LoRa-kod hotmodelleras inte.

## 1. Tillgångar

| Tillgång | Var | Skydd |
|---|---|---|
| AES-128 operationsnyckel + `kMac`/`kEnc` | SRAM (PAW/DEN/UNO-Q MCU) | Aldrig flash/logg/tråd utom 4-byte fingerprint; wipe efter bruk (PRO-94) |
| Ed25519 blocklist-privatnyckel | SRAM (UNO-Q MCU, oprovisionerad) | Fail-closed död kod tills HSM-process finns |
| Ed25519 blocklist-publiknyckel | DEN flash (placeholder-nollor) | Verifierar aldrig → deny (fail closed) |
| FIDO2 privat nyckel (admin) | Authenticator (lämnar aldrig) | Hårdvarugräns; repo bär endast publik metadata |
| Challenge-nonce / HMAC-svar | UART-tråd + SRAM | Färska per session (TRNG), nollvakt, konstanttidsjämförelse |
| Auditspår (`[AUDIT]`, reason codes) | USB-serie + SRAM-ring | Icke-hemliga koder; flyktiga — konsolen måste fånga |

## 2. Trust boundaries och dataflöden

```
[FIDO2-authenticator] --(USB/CTAP, privat nyckel lämnar aldrig)--> [MamaBear/MPU]
[Operatör A/B] --(fysisk USB-konsol, BG-ceremoni)--> [DEN]
[UNO-Q MCU] --(UART + Bridge-RPC, endast status/fingerprint)--> [MPU/Linux]
[UNO-Q MCU] --(USB UART, PRO-46 nyckel + CRC)--> [PAW/DEN]
[PAW] <--(dock-UART Serial1, challenge/response/ACK)--> [DEN]
[DEN] --(USB-serie, logg/reason codes/audit)--> [Operatörskonsol]
[CI/GitHub] --(UF2-artefakter, Actions)--> [Flash via UF2 drag-and-drop]
```

Gräns 1 — Dock-UART (PAW↔DEN): öppen serieport; hot = injicering/avlyssning/replay.
Gräns 2 — USB provisionering (UNO-Q→nod): fysisk USB; hot = falsk sändare, avlyssning vid ceremoni.
Gräns 3 — Bridge MCU↔MPU: MPU ser endast status/fingerprint; hot = nyfiken/fientlig MPU.
Gräns 4 — FIDO2: privat nyckel i authenticator; hot = stulen token, falsk registrering.
Gräns 5 — Break-glass-konsol: lokal USB; hot = obehörig lokal operatör.
Gräns 6 — Fysisk enhet: ingen secure boot; hot = flash-dump, omflashning, strömavbrott.
Gräns 7 — Supply chain (CI/bibliotek/UF2): hot = manipulerad artefakt/beroende.

## 3. Hot per område (verifierat läge)

### PAW (id-kort/paw-main)
- **Replay/injicering över dock-UART** — Hanteras: HMAC över färsk TRNG-nonce,
  2 s-deadline (DEN-sida), konstanttidsjämförelse, obeställda ramar ignoreras.
  Verifierat: `test_pro84`, `test_pro88`, `test_pro61`.
- **Stale grant-indikation** — Åtgärdat (PRO-95): beviljandevisning förfaller
  efter 30 s oavsett protokolltillstånd; boot låst + nyckeltork.
- **Noll/korrupt nyckel autentiserar** — Hanteras: `key_is_valid` nekar
  all-zero master även med flagga satt (PRO-94-testlåst).

### DEN (plc/den-main)
- **Fel öppnar åtkomst** — Hanteras: alla felvägar via `den_fail` → DENIED +
  nonce-wipe; tillståndet AUTHENTICATED bor endast ~1 sessionsgap (PRO-53).
- **Revokerad PAW beviljas** — Hanteras fail-closed: utan giltig signerad
  lista nekas allt (placeholder trust root verifierar aldrig);(payload
  blocklist-grind i `den_on_response`, PRO-98).
- **Break-glass blir permanent bypass** — Hanteras: separat tillstånd,
  60 s arm + 120 s grant, auto-relock vid timeout/fel/omstart, ingen flash,
  ordinarie auth-väg orörd (testlåst), definierade åtgärder STATUS/ABORT
  (PRO-97, PR #35). Larmljud: LED-blink + banner + kod 10.

### UNO-Q nyckelauktoritet (MCU + MPU)
- **Nyckel lämnar MCU** — Hanteras: MPU ser endast tillstånd/fingerprint;
  Bridge-RPC returnerar aldrig nyckelmaterial (PRO-94-testlåst).
- **TRNG-fel ger svag nyckel** — Hanteras: hälsokontroll + nollavvisning,
  wipe + ERROR_STATE vid fel; DEN avbryter challenge vid noll-nonce.
- **Sign-fel sänder skräp** — Åtgärdat (PRO-94/PR #33): wipe + ingen
  sändning utan giltig signatur; `keyPacket` torkas efter sändning.
- **Fientlig MPU** — Hanteras arkitekturellt: MPU kan varken smida
  Ed25519-signaturer eller dekryptera (`docs/14`, verifierat mönster).

### USB/provisionering (PRO-46)
- **Falsk sändare / eavesdrop vid ceremoni** — Delvis: CRC + hash-verifiering
  + knappbekräftelse på UNO-Q (fysisk auktorisering); nollnyckel avvisas;
  fel torkar nyckel. Ceremonin kräver fysisk närvaro — ingen
  kryptografisk sändarautentisering (restrisk).
- **Delad tråd med servicekonsol** — Hanteras: strikt ASCII i viloläge,
  binära MSG-bytes triggar aldrig; vilsekommen byte kan högst beväpna
  (aldrig bevilja), beväpning förfaller loggat.

### FIDO2-admin (MamaBear)
- **Privat nyckel exponeras** — Hanteras: lämnar aldrig authenticatorn;
  repot bär endast credential-ID + publik nyckel; PIN via getpass.
- **Stulen admin-token** — Känd designbegränsning (`docs/19`): flash-dump
  möjlig utan Secure Boot; mitigering kräver Secure Boot + OTP (restrisk).
- **Loggläckage** — Hanteras: credential-ID:n/tokens/hex maskeras
  (`fido2_sanitize`, `mamabear.py`, testlåst); status-JSON redactar IP.

### CLI/simulering
- **Testnycklar läcker** — Hanteras: `sim.py` TEST-ONLY + test som bevisar
  att master/K_mac aldrig renderas; deterministiska vektorer delas med
  pytest-sviten avsiktligt.
- **Demo förväxlas med verklighet** — Hanteras: SIMULERING-banners överst/
  underst + titel, deterministiska tidsstämplar, inga SCADA/IP-tokens
  (testlåst, PR #31).

## 4. Verifierade säkerhetsegenskaper (kod + test)

| Egenskap | Verifiering |
|---|---|
| SRAM-only nycklar, wipe efter bruk | PRO-94-granskning + 30 källguardtester |
| Inga hårdkodade dev-nycklar i aktiv firmware | PRO-93 + doctor-guard + CI (edge-fil bakom fail-closed opt-in) |
| Känsliga loggar bakom SECURE_DEBUG (default av) | Rad-för-rad-granskning + guardtester |
| Fail-closed sessioner (PAW/DEN) | PRO-53/PRO-84/PRO-88 + bänkacceptans |
| Kortlivad beviljandevisning | PRO-95 + 11 tester |
| Break-glass: ingen bypass, auto-relock, audit | PRO-97 + 20 tester (PR #35) |
| Ingen nyckel via Bridge-RPC | PRO-94-testlåst |
| Ed25519-separation (privat endast UNO-Q) | PRO-94/PRO-98-tester |

## 5. Kvarvarande restrisker

1. **Fysisk possession = full kontroll.** Ingen secure boot/flashkryptering:
   omflashning via BOOTSEL/UF2, flash-dump, SRAM-kvarlevor vid kallstart.
   Mitigering idag: proceduriell (fysisk säkerhet) + SRAM-only nycklar
   (dump ger inga nycklar). Kvarstår.
2. **Provisioneringsceremonin saknar kryptografisk sändarautentisering.**
   Skyddet är fysisk närvaro + knapp + CRC/hash. Kvarstår.
3. **Blocklist-privatnyckelns provisioneringsflöde saknas** (HSM-process
   öppen); stigen är fail-closed död kod. Kvarstår.
4. **Audit är flyktig** (SRAM-ring + serielogg): försvinner vid omstart,
   skriver över äldst; konsolfångst krävs. Kvarstår.
5. **Break-glass single-operator**: en operatör vid konsolen kan båda
   stegen; proceduren + audit täcker. Kvarstår.
6. **Ingen oberoende kryptoaudit** (Ed25519-port, SHA/HMAC, RNG-config,
   wipe-mönster mot toolchain-assembler). Kvarstår.
7. **Sidokanaler** (effekt/EM/timing) oanalyserade — labbutrustning krävs.
   Kvarstår.
8. **Bistabil e-paper fryser sista bilden vid strömavbrott** tills boot
   (alltid låst; ingen åtkomst kvarstår då nyckeln dör). Accepterad.
9. **SRAM-bitfel odetekterade** (ingen ECC; nollkoll fångar wipe, ej
   bitflip) — K7, accepterad tills fingerprint-jämförelse vid hämtning.
10. **Bänkverifiering K1–K6** ej utförd (SRAM-volatilitet, UF2-inspektion,
    nollnyckel-nekande på enhet, timeout-clear, trådanalys). Öppen punkt.
11. **Supply chain**: UF2-artefakter byggs i CI (GITHUB_TOKEN), beroenden
    (arduino-pico, RadioLib, Crypto, pip) utan pinning-review. Kvarstår.
12. **Ingen tvångskod (duress)** i break-glass; 120 s-fönstret avvägt.
    Kvarstår.
