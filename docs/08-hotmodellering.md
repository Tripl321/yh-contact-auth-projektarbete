# 08 — Hotmodellering (PRO-55)

**Status:** Utkast 2026-09-18 | PRO-55 | Manuell granskning mot verifierad implementation. Docker-körning av OWASP Let's Threat Model förberedd men avvaktar provider-nyckel; detta dokument innehåller därför endast egenskaper verifierade i kod, test eller bänk samt tydliga restrisker.

Scope: PAW, DEN, UNO-Q (MCU+MPU), dock-UART, USB/provisionering, FIDO2-admin, break-glass-serviceläge och larm/audit. LoRa är ur aktivt scope; arkiverad LoRa-kod hotmodelleras inte.

## Tillgångar

| Tillgång | Var | Skydd |
|---|---|---|
| AES-128 operationsnyckel samt `kMac`/`kEnc` | SRAM i PAW/DEN/UNO-Q MCU | Inte flash, logg eller tråd utom fingerprint; wipe efter bruk |
| Ed25519 blocklist-privatnyckel | SRAM i UNO-Q MCU, oprovisionerad | Fail-closed tills HSM-process finns |
| FIDO2 privat nyckel | Authenticator | Lämnar aldrig authenticatorn |
| Challenge-nonce och HMAC-svar | UART-tråd och SRAM | Färska per session, nollvakt och konstanttidsjämförelse |
| Auditspår | USB-serie och SRAM-ring | Icke-hemliga koder; flyktiga och måste fångas av konsolen |

## Trust boundaries och dataflöden

```text
[FIDO2-authenticator] -- USB/CTAP --> [MamaBear/MPU]
[Operatör A/B] -- fysisk USB-konsol --> [DEN]
[UNO-Q MCU] -- UART + Bridge-RPC, status/fingerprint --> [MPU/Linux]
[UNO-Q MCU] -- USB UART, nyckel + CRC --> [PAW/DEN]
[PAW] <-- dock-UART challenge/response/ACK --> [DEN]
[DEN] -- USB-serie, reason codes/audit --> [Operatörskonsol]
[CI/GitHub] -- UF2-artefakter --> [Flash via UF2]
```

- Dock-UART: injicering, avlyssning och replay.
- USB-provisionering: falsk sändare och avlyssning vid ceremoni.
- Bridge MCU↔MPU: nyfiken eller fientlig MPU.
- FIDO2: stulen token eller falsk registrering.
- Break-glass-konsol: obehörig lokal operatör.
- Fysisk enhet: flash-dump, omflashning och strömavbrott.
- Supply chain: manipulerad artefakt eller beroende.

## Verifierat läge

### PAW
- Replay och injicering över dock-UART hanteras med HMAC över färsk TRNG-nonce, deadline, konstanttidsjämförelse och ignorerade obeställda ramar.
- Beviljandevisning förfaller efter 30 sekunder oavsett protokolltillstånd; boot är låst och nyckelmaterial rensas.
- All-zero master-nyckel nekas.

### DEN
- Felvägar leder till DENIED och nonce-wipe.
- Utan giltig signerad blocklista nekas åtkomst fail-closed.
- Break-glass är ett separat, tidsbegränsat serviceläge med auto-relock vid timeout, fel och omstart. Endast STATUS och ABORT är tillåtna; ordinarie auth-väg ändras inte.

### UNO-Q
- MPU får endast status och fingerprint, inte nyckelmaterial.
- TRNG-fel ger wipe och felläge.
- Signeringsfel leder till wipe och ingen sändning; `keyPacket` rensas efter sändning.

### USB, FIDO2 och CLI
- Provisionering saknar kryptografisk sändarautentisering men har fysisk närvaro, knappbekräftelse, CRC/hash och fail-closed-rensning.
- FIDO2 privata nycklar lämnar inte authenticatorn; känsliga värden maskeras i loggar.
- Simulerade CLI-flöden är tydligt märkta som simulering och visar inga SCADA- eller IP-token.

## Verifierade säkerhetsegenskaper

| Egenskap | Verifiering |
|---|---|
| SRAM-only nycklar och wipe | PRO-94-granskning och källguardtester |
| Inga ogardade dev-nycklar | PRO-93 doctor-guard och CI |
| Känsliga loggar bakom `SECURE_DEBUG` | Kodgranskning och guardtester |
| Fail-closed sessioner | PRO-53/PRO-84/PRO-88 |
| Kortlivad beviljandevisning | PRO-95-tester |
| Break-glass auto-relock och audit | PRO-97-tester |
| Ingen nyckel via Bridge-RPC | PRO-94-tester |

## Kvarvarande restrisker

1. Fysisk possession möjliggör omflashning och flash-dump eftersom secure boot och flashkryptering saknas.
2. Provisioneringsceremonin saknar kryptografisk sändarautentisering.
3. Blocklist-privatnyckelns provisioneringsflöde saknas; stigen är fail-closed död kod.
4. Audit är flyktig och skriver över äldre händelser.
5. Break-glass-tvåpersonsförfarandet är operativt: firmwaren kan inte skilja två personer åt, och en ensam operatör vid samma konsol kan genomföra båda stegen.
6. Ingen oberoende kryptoaudit eller sidokanalsanalys är utförd.
7. Bänkverifiering av K1–K6 återstår.
8. Supply-chain-beroenden saknar full pinning- och granskningsprocess.
9. Ingen tvångskod finns i break-glass.
