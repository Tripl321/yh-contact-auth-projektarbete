# Kravspecifikation — SHALLOT

> Status: Krav formulerade 2026-09-07, fysisk verifiering ej paaborjad | Vecka: 3 | Linear: PRO-30

## 1. Bakgrund

SHALLOT (Secure-by-Design ID-bricka foer OT-miljoe) aer en prototyp foer portabel autentisering i industriella OT-miljoeer. Systemet anvander LoRa P2P-kommunikation och HMAC-SHA256 challenge-response foer att verifiera en baerbar ID-bricka (PAW) mot en edge enforcement-nod.

## 2. Funktionella krav

Status per krav: **Verifierat** / **Ej verifierat** / **Avvikelse**.
Belaeggskoder: (A) automatiserat (CI-bygge, lokal pytest, host-test),
(I) kodgranskning, (H) fysisk testplan (docs/13–15 — samtliga ej
exekverade paa haardvara i denna revision, A-kolumner tomma).

| ID | Krav | Prioritet | Status | Belaegg / kommentar |
|----|------|-----------|--------|---------------------|
| F1 | UNO Q genererar AES-128-nyckel med haardvaru-TRNG; avbryt fail-closed vid TRNG-fel | Hoeg | Ej verifierat | (H) doc 13 NP-01 foer floede; entropikvalitet kraever separat analys |
| F2 | Nyckeldistribution oever USB med handshake/READY/key+CRC/STORED/COMMIT, seq-retry och resync | Hoeg | Ej verifierat | (A) pytest kd_*-spegling passerar; (H) doc 13 FA/FR/CR/ACK/COM |
| F3 | LoRa challenge-response med HMAC-SHA256-verifiering PAW–PLC | Hoeg | Ej verifierat | (H) doc 14 LR-01/LR-02; C-implementationen saknar kaenda-vektor-test |
| F4 | Avvisning av replay/duplikat (nonce-cache 16/60 s, epoch+seq-dubbletter, stale epoch) | Hoeg | Ej verifierat | (A) pytest replay/cache-tester passerar; (H) doc 14 LR-05, doc 13 COM-01 |
| F5 | Timeout (30 s), avgraensade aaterfoersoek (5 fel) och 60 s lockout med aaterupptag | Hoeg | Ej verifierat | (A) pytest lockout-spegling passerar; (H) doc 14 LR-06/07/08 |
| F6 | Nyckellivscykel: validera foere lagring (avvisa noll/uniform), wipe vid ersaettning/commit/expiry, endast fingerprint exponeras | Hoeg | Ej verifierat | (A) pytest lifecycle- och loggskanningstester passerar; (H) doc 13 CR-02/RB-02/LOG-01 |
| F7 | E-paper-statuslaegen (autentiserar/godkaend/nekad/tom) med refresh-begraensning och testlaege | Medel | Ej verifierat | (A) policy-mirror + g++ -Werror passerar; (H) doc 15 EP-01/EP-02 |
| F8 | Watchdog (8 s) med matning i blockeringar, radio/e-paper-aaterinitiering, fail-closed reboot utan SRAM-nyckel | Medel | Ej verifierat | (A) pytest WDT/radio/stall-spegling passerar; (H) doc 15 WD-01/02/03 |
| F9 | MPU-orkestrering med session, engangs-grant, frasch knapptryckning och audit utan hemligheter | Hoeg | Ej verifierat | (A) pytest grant/audit-tester passerar; (H) doc 13 NP-01/LOG-01 |

## 3. Icke-funktionella krav

| ID | Krav | Kategori | Status | Belaegg / kommentar |
|----|------|----------|--------|---------------------|
| NF1 | Fail-closed vid fel, avbrott, timeout och (om)start: inget godkaennande utan full verifierad kedja, ingen nyckel i SRAM efter stroemboertfall | Saekerhet | Ej verifierat | (A) logikmirror passerar; (H) doc 13 RB/FA-matris, doc 14-matris, doc 15 WD-01 |
| NF2 | Inget nyckelmaterial i loggar eller audit — endast fingerprint/status/epoch | Saekerhet | Verifierat | (A) `test_no_key_material_in_logs` + audit-tester passerar paa aktuell kaella (lokal pytest, ej CI-grindad); fysisk bekaerftelse via doc 13 LOG-01 och doc 14 LR-11 aaterstaar |
| NF3 | USB CDC aer den enda provisioneringsvaegen; ingen nyckeltrafik oever UART | Saekerhet | Verifierat | (I) kodgranskning: produktionsfirmware anropar aldrig Serial1 foer nycklar (enbart ett oanvänt `Serial1.begin` kvar i UNO Q); aaldre testskissen `test_key_distribution/unoq_bridge_rpc_key_authority.ino` anvander aennu UART och ingaar ej i den verifierade vaegen |
| NF4 | Alla tre firmware bygger reproducerbart med explicita kaernor och bibliotek | Byggbarhet | Verifierat | (A) GitHub Actions-workflow foer PAW/PLC/UNO Q; identiska arduino-cli-kommandon verifierade lokalt (Actions-koerning ej bekaerftad haerifraan) |

## 4. Avgraensningar

- Ingen FIDO2/WebAuthn-implementation
- Ingen AI- eller agentintegration
- Ingen UX-utvaerdering
- Prototyp paa breadboard, ej produktionsklar haardvara

## 5. Betygskrav

- G: Fungerande prototyp med teknisk dokumentation
- VG: Foerdjupad analys (hotmodellering, framework-mappning, pen-test)

## 6. Kaenda avvikelser och begraensningar

| ID | Beskrivning | Paaverkar | Status |
|----|-------------|-----------|--------|
| AV1 | FIDO2 aeger oever placeholder (ingen aekta attestering) | F9 | Avvikelse (dokumenterad slice-plan, doc 02 slices) |
| AV2 | Recovery-kod hashas med SHA-256+peppar, ej Argon2 (prototyp) | F9 | Avvikelse |
| AV3 | Epoch och nycklar i flyktigt SRAM (nollstaells vid stroemboertfall per design, fail-closed) | F6, NF1 | Avvikelse (designval, dokumenterat) |
| AV4 | Fysiska testplaner docs/13–15 ej exekverade; samtliga H-belaegg ovan aaterstaar | F1–F9, NF1 | Avvikelse (process) |
| AV5 | Serieportens debug-loggar skriver nonce/HMAC i klartext (luftsynligt per protokoll, men boer DEBUG-grindas foer produktion) | NF2 | Observation (accepterat foer prototyp) |

Sammanfattning: 3 av 13 krav aer verifierade (NF2–NF4, kaell- och
byggaranoivaer); 10 aaterstaar till fysisk testning enligt docs/13–15.
