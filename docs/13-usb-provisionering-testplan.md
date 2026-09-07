# 13 — USB-provisionering: manuell testplan

Manuella systemtester för nyckelprovisionering över USB mellan UNO Q
(Mama Bear, nyckelauktoritet), PAW (ID-bricka) och PLC (edge-nod).
Planen täcker normal provisionering, avbruten USB-anslutning,
trasiga/partiella ramar, CRC-fel, tappade ACK, dubblett-COMMIT och
omstart av mottagaren — samt att nycklar aldrig hamnar i logg och att
enheten förblir fail-closed vid fel och efter omstart.

Sanningskälla för protokoll och trösklar är firmwaren
(`libraries/ShallotLoRaProtocol.h`, respektive `.ino`). Förväntade
loggsträngar nedan är citerade ur koden; mindre textavvikelser mellan
firmwareversioner är acceptabla så länge betydelsen är densamma.

## 1. Referenser och avgränsning

- Fixtur och kablage: `docs/10-hardware-test-checklist.md` (denna plan
  förutsätter att fixturen där är godkänd).
- Hotmodell: `docs/11-threat-model-limitations.md`.
- Felinjiceringsskript: `scripts/kd_inject.py` (appendix A).
- Ramformat: appendix B.

Testas **inte** här: LoRa-autentisering PAW↔PLC (separat),
FIDO2-hårdvara (placeholder-läge), penetrationstestning av USB-hubben.

## 2. Testmiljö

| Komponent | Port/baud | Boot-banner att vänta |
|---|---|---|
| UNO Q MCU-konsol | USB CDC, **115200** | `SHALLOT — UNO Q Key Authority (PRO-45/PRO-46)` |
| PAW | USB CDC, **115200** | `SHALLOT PAW Main Firmware` |
| PLC | USB CDC, **115200** | `SHALLOT — PLC Complete Firmware` |
| MPU-meny | körs på UNO Q MPU (QRB2210 Linux) | `SHALLOT UNO Q — Orchestration (MPU)` |

Förutsättningar för varje fall om inget annat anges:

1. Fixtur enligt doc 10: alla tre på USB-hubb, externt strömförsörjd.
2. Samma firmware på alla enheter (notera commit-hash i protokollet).
3. Tre seriella terminaler öppna (en per enhet), loggning till fil påslagen
   (t.ex. `screen -L`, eller spara monitorfönstrens innehåll som
   `loggar/<FALL>_{unoq,paw,plc}.txt`).
4. UNO Q är IDLE (ingen pågående distribution) om inte fallet kräver annat.
5. MPU-session aktiv där fallet kräver MPU-vägen (menyval `0`, recovery code
   ≥ 16 alfanumeriska tecken i prototypen).

Viktiga tider (för väntans toleranser): mottagarens fas-timeout 10 s,
UNO Q per försök 5 s (3 försök handshake/key-data, 2 försök COMMIT-ACK),
MPU bekräftelsepoll 30 s, knappens giltighetsfönster ~5 s efter fräsch
knapptryckning.

Normalflöde (MPU-vägen): `0` starta session → `1` generera (tryck på
UNO Q-knappen, kör inom fönstret) → `2` distribuera PLC (MPU armerar,
tryck knapp, MPU bekräftar) → `3` distribuera PAW → `6` validera.
Fallback: UNO Q-konsolen `g` / `1` / `2` (med fräsch knapptryckning),
`s` visar `Key state`, `Active/Pending epoch` och fingerprint.

Konventioner nedan: **F** = förutsättningar, **S** = steg,
**E** = förväntat resultat, **A** = faktiskt resultat (fylls i),
**G** = godkänt-kriterium.

---

## NP-01 Normal provisionering av båda enheterna

**Syfte:** Hela kedjan generera → distribuera PLC → distribuera PAW →
commit med matchande epoch och fingerprint överallt.

**F:** Färska enheter (active epoch 0 överallt; omstartade om osäkert).

**S:**
1. MPU: `0` (recovery code), `1` (generera; tryck UNO Q-knapp inom fönstret).
2. UNO Q-konsol: `s`. Notera `Pending epoch` (P) och `Pending fingerprint`.
3. MPU: `2` (PLC). Tryck UNO Q-knapp när MPU ber om det. Vänta på bekräftelse.
4. MPU: `3` (PAW). Tryck knapp. Vänta på bekräftelse.
5. MPU: `4` (state) och `5` (fingerprint). Spara loggarna.

**E:**
1. PAW-logg visar `Handshake received epoch P seq 0`, `Sending READY`,
   `CRC verified OK.`, `Pending key stored epoch P hash HHHHHHHH`.
   Motsvarande `[PRO-47]`-rader i PLC-loggen.
2. UNO Q-logg visar `Key successfully distributed to PLC/PAW`,
   därefter `Both staged and committed epoch P`.
3. UNO Q `s` visar `Key state: DISTRIBUTED (BOTH)` före commit och
   `Active epoch: P` efter; `Active fingerprint` = `HHHHHHHH` på alla tre.
4. MPU `6` rapporterar godkänd validering.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | READY/STORED-rundor utan retries i loggarna | AVBROT: Knapptryckning krävs för 'g'-kommando. MCU svarar "[PRO-45] Need fresh button press for 'g'". Ej autonomt utförbart. | ❌ |
| 2 | Samma epoch P + fingerprint H på UNO Q/PAW/PLC | Ej testad (blockerad av steg 1) | ❌ |
| 3 | MPU-validering godkänd | Ej testad (blockerad av steg 1) | ❌ |

**G:** ❌ Ej slutförd - manuell knapptryckning på UNO Q krävs för 'g'-kommando.

**Loggutdrag:**
```
MCU initial status:
=== UNO Q Key Authority Status ===
Key state: UNINITIALIZED
Active epoch: 0
Pending epoch: 0
Commands: g=generate(needs fresh button) 1=dist PLC 2=dist PAW s=status
=====================================

MCU svar på 'g':
[PRO-45] Need fresh button press for 'g'

=== UNO Q Key Authority Status ===
Key state: UNINITIALIZED
Active epoch: 0
Pending epoch: 0
Commands: g=generate(needs fresh button) 1=dist PLC 2=dist PAW s=status
=====================================
```

**Avvikelse:** MCU kräver fysisk knapptryckning för nyckelgenerering. Ej möjligt att utföra autonomt.
**Åtgärd:** Kräver manuell intervention för knapptryckning på UNO Q hårdvara.

## NP-02 Status och fingerprint efter commit

**Syfte:** Endast status/fingerprint är observerbart — ingen nyckeldata.

**F:** NP-01 godkänd.

**S:**
1. UNO Q: `s`. PAW/PLC: granska sparade loggar. MPU: `5`, `7`.

**E:**
1. Överallt syns endast epoch-nummer, 8 hex-tecken fingerprint, tillstånd
   och klartextstatus. Inga 16-byte-blobar (32+ hex-tecken i följd).
2. MPU audit-loggen innehåller `fingerprint`/`epoch`/`result`, aldrig
   nyckel, grant eller recovery code i klartext (se även LOG-01).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Bara fingerprint/status synligt på alla tre + MPU | | |

**G:** Raden OK.

## FA-01 USB avbruten före/under handshake

**Syfte:** Mottagare som aldrig svarar ska ge avgränsade retries och
avbryt fail-closed; mottagaren opåverkad.

**F:** Genererad pending-nyckel på UNO Q (MPU `1` klar). PAW inkopplad.

**S:**
1. MPU: `3` (PAW). När UNO Q loggar `Sending handshake epoch P`,
   dra ur **PAW:s** USB-kabel direkt.
2. Observera UNO Q i ~20 s. Sätt tillbaka kabeln (PAW startar om).

**E:**
1. UNO Q loggar `Retrying handshake seq 1`, `seq 2`, sedan
   `FAILED (no READY response)` + `distribution_failed`. Exakt 3 försök.
2. PAW efter återanslutning: boot-banner, väntar på nyckel, ingen pending,
   e-paper visar fel-läge. Inget staged.
3. Ny MPU `3` + knapp lyckas (NP-01-steg) — rundan är återhämtningsbar.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | 3 handshake-försök, sedan kontrollerat avbrott | | |
| 2 | PAW opåverkad efter återanslutning | | |
| 3 | Ny runda lyckas | | |

**G:** Alla tre rader OK.

## FA-02 USB avbruten efter READY (mitt i key-data)

**Syfte:** Avbrott mitt i rundan ska inte lämna halv stagedata.

**F:** Som FA-01.

**S:**
1. MPU: `3`. Vänta tills PAW-loggen visar `Sending READY epoch P`.
2. Dra ur PAW direkt. Observera UNO Q ~40 s (identity 5 s + 3 key-data-
   försök à 5 s). Sätt tillbaka kabeln.

**E:**
1. UNO Q fullföljer inte: identity-timeout (`identity verification FAILED`)
   eller `FAILED (no STORED response)` efter retries med samma seq.
   Tillstånd stannar före commit; ingen `epoch_committed`.
2. PAW efter återanslutning: boot-banner, ingen pending/aktiv nyckel
   (fail-closed), e-paper fel-läge.
3. Ny MPU `3` + knapp lyckas fullt ut.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Ingen commit, kontrollerat avbrott med retries i loggen | | |
| 2 | PAW fail-closed efter återanslutning | | |
| 3 | Ny runda lyckas | | |

**G:** Alla tre rader OK.

## FA-03 UNO Q bortkopplad mitt i rundan

**Syfte:** Mottagaren ska timeouta utan att stagea något.

**F:** PAW väntande (färsk boot, `Waiting for key distribution...` i loggen).

**S:**
1. MPU: `3`, tryck knapp. När PAW loggar `Handshake received`,
   dra ur **UNO Q:s** USB-kabel.
2. Observera PAW ~15 s. Sätt tillbaka UNO Q-kabeln.

**E:**
1. PAW loggar `Timeout waiting for key data.` (efter ~10 s). Ingen
   `Pending key stored`, ingen nyckel staged.
2. Efter återanslutning kan rundan köras om från MPU och lyckas.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Timeout utan staging (fail-closed) | | |
| 2 | Omtag lyckas | | |

**G:** Båda raderna OK.

## FR-01 Skräpbyte tolereras (resync)

**Syfte:** Enstaka främmande bytes före//libsunder rundan ska skippas,
inte desynka protokollet. Deterministiskt utan verktyg.

**F:** Färsk PAW, UNO Q idle. Terminal mot PAW öppen för både logg och input.

**S:**
1. I PAW-terminalen: skriv `x` + Enter **innan** distribution startar.
2. MPU: `3` + knapp som vanligt.

**E:**
1. Rundan lyckas ändå (`Pending key stored`, commit vid behov). `x`
   (0x78) matchar ingen ramtagg och droppas av resyncen.
2. Skriv aldrig bytes ≥ 0x80 eller kontrolltecken i detta fall (de kan
   råka bilda taggar över CDC/UTF-8 — utanför fallets scope).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Runda lyckas trots skräpbyte | | |

**G:** Raden OK. (Skräpmängd > 64 bytes ska i stället ge kontrollerat
`Resync budget exhausted`-avbrott — notera om det observeras.)

## FR-02 Partiell ram (kd_inject `partial`)

**Syfte:** En ram som anländer i två delar ska reassembleras, inte förkastas.

**F:** Färsk mottagare (valfri av PAW/PLC), UNO Q idle, `scripts/kd_inject.py`
tillgänglig på värddatorn.

**S:**
1. `python3 scripts/kd_inject.py --port <MOTTAGARPORT> --target paw|plc --case partial --epoch 1`
2. Notera verdict.

**E:** `READY mottagen`, `STORED efter komplett ram`, verdict `GODKÄND`.
Mottagarloggen visar `CRC verified OK.` + `Pending key stored epoch 1`.
**Städa:** provisionera om enheten via normalflödet efteråt (testnyckel!).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND + STORED i loggen, sedan omprovisionerad | | |

**G:** Raden OK.

## FR-03 Stale epoch avvisas (kd_inject `stale`)

**Syfte:** Sessions-ID (epoch) ska skydda mot återuppspelade gamla rundor.

**F:** Som FR-02. Enhet får vara provisionerad eller färsk.

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case stale`

**E:** Ingen READY inom 12 s (`ingen READY för epoch 0`), verdict `GODKÄND`.
Mottagarloggen visar `Stale handshake epoch - reject` (färsk enhet) eller
tystnad/timeout. Inget staged.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND, inget staged | | |

**G:** Raden OK.

## FR-04 Fel sekvensnummer droppas (kd_inject `wrongseq`)

**Syfte:** Key-data med främmande seq ska droppas; rätt retry ska lyckas.

**F:** Som FR-02 (färsk mottagare).

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case wrongseq --epoch 1`

**E:** `ingen STORED för fel seq`, därefter `STORED för rätt seq`,
verdict `GODKÄND`. Loggen visar `Key-data from another round; dropped.`
**Städa:** provisionera om efteråt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND + drop-rad i loggen, sedan omprovisionerad | | |

**G:** Raden OK.

## CR-01 CRC-fel + retry (kd_inject `crc`)

**Syfte:** Korrupt nyckeldata ska underkännas med CRC och aldrig staged;
retry med samma seq ska konvergera.

**F:** Som FR-02 (färsk mottagare).

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case crc --epoch 1`

**E:** `ingen STORED för korrupt ram`, `STORED efter korrekt retry`,
verdict `GODKÄND`. Loggen visar `CRC mismatch; waiting for retry.`
följt av `CRC verified OK.`
**Städa:** provisionera om efteråt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND + båda loggraderna, sedan omprovisionerad | | |

**G:** Raden OK.

## CR-02 Nollnyckel avvisas (kd_inject `zero`)

**Syfte:** Oinitierade (noll-)värden ska avvisas före lagring även med
giltig CRC.

**F:** Som FR-02 (färsk mottagare).

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case zero --epoch 1`

**E:** `ingen STORED för nollnyckel`, därefter `STORED efter giltig nyckel`,
verdict `GODKÄND`. Loggen visar
`Refusing to stage degenerate key (fail-closed).`
**Städa:** provisionera om efteråt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND + refuse-rad i loggen, sedan omprovisionerad | | |

**G:** Raden OK.

## ACK-01 Tappad READY (kd_inject `drop-ready`)

**Syfte:** Tappad READY ska ge handshake-retry med seq+1 och idempotent
omsändning — ingen dubbel-staging.

**F:** Som FR-02 (färsk mottagare).

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case drop-ready --epoch 1`

**E:** Båda READY tas emot, `STORED för seq 1`, verdict `GODKÄND`.
Nyckeln staged exakt en gång (samma bytes).
**Städa:** provisionera om efteråt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND, sedan omprovisionerad | | |

**G:** Raden OK.

## ACK-02 Tappad STORED (kd_inject `drop-stored`)

**Syfte:** Tappad STORED ska ge key-data-retry med samma seq och identisk
omsändning — ingen dubbel-lagring.

**F:** Som FR-02 (färsk mottagare).

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case drop-stored --epoch 1`

**E:** Två STORED med **samma hash**, verdict `GODKÄND`.
**Städa:** provisionera om efteråt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND, identiska hash, sedan omprovisionerad | | |

**G:** Raden OK.

## COM-01 Dubblett-COMMIT (kd_inject `dupcommit`)

**Syfte:** Upprepad COMMIT för aktiv epoch ska bara omsända ack —
tillståndet ändras inte.

**F:** Enhet provisionerad via **NP-01** (aktiv epoch E känd från loggen).
Öppna porten försiktigt (115200, aldrig 1200 baud): om boot-banner
syns har enheten startat om — kör då NP-01 igen först.

**S:**
1. `python3 scripts/kd_inject.py --port <PORT> --target paw|plc --case dupcommit --epoch E`

**E:** Två ack med samma hash, verdict `GODKÄND`. Mottagarloggen visar
`Duplicate COMMIT for active epoch; resending ack` (PAW) /
motsvarande `[PRO-47]`-rad (PLC). Aktiv epoch och nyckel oförändrade
(verifiera med MPU `4`/`5` efteråt — samma värden).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | GODKÄND + duplikat-rad i loggen, värden oförändrade | | |

**G:** Raden OK.

## RB-01 Omstart av mottagaren mitt i provisionering

**Syfte:** Reset under pågående runda ska ge fail-closed boot; UNO Q ska
avbryta kontrollerat.

**F:** PAW eller PLC väntande/under runda (MPU `3` armerad eller HS mottagen).

**S:**
1. MPU: `3` + knapp. När mottagarloggen visar `Handshake received`
   (eller `Sending READY`), tryck **reset-knappen** på mottagaren.
2. Observera båda loggarna ~30 s.

**E:**
1. Mottagaren bootar (banner), visar väntande/fel-läge (PAW e-paper:
   fel-ikon), ingen pending/aktiv nyckel.
2. UNO Q: retries (`seq 1`, `seq 2`) sedan `FAILED (...)`, ingen commit.
3. Ny MPU-runda lyckas.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Fail-closed boot hos mottagaren | | |
| 2 | Kontrollerat UNO Q-avbrott | | |
| 3 | Ny runda lyckas | | |

**G:** Alla tre rader OK.

## RB-02 Omstart efter lyckad provisionering

**Syfte:** SRAM-nyckel ska vara borta efter omstart; enheten nekar allt
tills omprovisionering med ny epoch.

**F:** NP-01 godkänd (aktiv epoch E på alla tre).

**S:**
1. Bryt strömmen till **PAW** (drag ur USB) 10 s. Sätt tillbaka.
2. Granska PAW-loggen. MPU: `4`.
3. MPU: `1` (ny epoch E+1 kräver knapp), `3` + knapp för PAW
   (PAW blir nu staged-pending — commit kräver båda, se nästa steg).
4. MPU: `2` + knapp för PLC. Först nu slår commit igenom för båda.
5. Symmetri för PLC (valfritt men rekommenderat): bryt strömmen till PLC
   10 s, verifiera fail-closed boot, provisionera sedan om båda till E+2
   (MPU `1`, `2`, `3`, `6`).

**E:**
1. Efter omstart: boot-banner, ingen nyckel (`Key reception FAILED /
   Waiting...`, PAW e-paper fel-ikon). LoRa-svar uteblir/nekas —
   enheten är oautentiserad.
2. Gamla epoch E accepteras inte längre som ny (stale-avvisning vid försök).
3. Efter steg 4: epoch E+1 aktiv med ny, matchande fingerprint på alla
   tre (commit sker först vid `DISTRIBUTED_BOTH`, MPU `6` godkänd).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Nyckel borta + nekande läge efter omstart (PAW och PLC) | | |
| 2 | Omprovisionering E+1 med matchande fingerprint | | |

**G:** Båda raderna OK.

## LOG-01 Loggrevision: ingen nyckeldata i loggar

**Syfte:** Bevisa att endast fingerprint/status exponeras, aldrig nyckeln.

**F:** Loggfiler från NP-01 (alla tre enheter) + MPU audit-logg
(`audit/provisioning_log.jsonl` på MPU).

**S:**
1. Sök efter 16-byte-blobar (32+ hex-tecken i följd) i alla enhetsloggar:
   `grep -Eo '[0-9A-Fa-f]{32,}' <loggfil>` — ska ge **tomt** resultat.
2. Bekräfta att fingeravtryck syns som exakt 8 hex-tecken och matchar
   överallt: `grep -Eo '[0-9A-F]{8}' <loggfil> | sort | uniq -c`.
3. MPU audit: varje rad ska innehålla `fingerprint`/`epoch`/`event`,
   aldrig nyckel, grant-token eller recovery code i klartext
   (sök `grant`, `recovery`, samt 32+ hex som ovan).
4. Cross-check: auditens fingerprint == enheternas fingerprint för epoch E.

**E:** Steg 1 och 3a tomma träfflistor; steg 2 och 4 visar samma
8-teckens fingerprint överallt.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Inga ≥32-hex-sekvenser i någon logg | | |
| 2 | Matchande 8-hex fingerprint överallt inkl. audit | | |
| 3 | Ingen grant/recovery-kod i klartext i audit | | |

**G:** Alla tre rader OK.

## 3. Fail-closed-matris (sammanfattning)

| Fall | Fail-closed-bevis |
|---|---|
| NP-01/NP-02 | Commit kräver båda ack + matchande hash/epoch; annars ingen aktivering |
| FA-01/02/03 | Timeout + avgränsade retries → avbrott; inget staged/aktiverat |
| FR-01–04 | Skräp/partiellt/främmande droppas; stale epoch avvisas |
| CR-01/02 | CRC-fel och nollnyckel stageas aldrig |
| ACK-01/02, COM-01 | Omsändningar är idempotenta; tillstånd ändras inte |
| RB-01/02 | Omstart = tom SRAM = oautentiserad; kräver ny epoch |
| LOG-01 | Inget nyckelmaterial observerbart någonstans |

## Appendix A — kd_inject.py

Deterministisk felinjicering direkt mot en mottagares CDC-port.
UNO Q ska vara idle under körning. Efter varje fall med testnyckel:
**provisionera om enheten via normalflödet** (testnycklar genereras
lokalt med `os.urandom` och hör inte hemma i drift).

```bash
python3 scripts/kd_inject.py --port /dev/ttyACM0 --target paw --case crc --epoch 1
python3 scripts/kd_inject.py --port /dev/ttyACM1 --target plc --case drop-stored --epoch 1
python3 scripts/kd_inject.py --port /dev/ttyACM0 --target paw --case dupcommit --epoch 2
```

Fall: `crc`, `zero`, `partial`, `stale`, `wrongseq`, `drop-ready`,
`drop-stored`, `dupcommit`. Varje fall skriver ut `[OK]`/`[FAIL]` per
steg och `RESULTAT: GODKÄND/UNDERKÄND` (exit-kod 0/1). Port 115200 baud
— öppna aldrig med 1200 baud (återställer RP2040 till bootloader).
Om boot-banner syns vid portöppning har enheten startat om: för
`dupcommit` måste NP-01 då köras om först.

## Appendix B — ramformat (källa: ShallotLoRaProtocol.h)

Alla flerb
...[truncated 1587 chars]