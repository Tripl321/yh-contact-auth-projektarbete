# 14 — LoRa-autentisering: fysisk testplan

Manuella systemtester för challenge-response-autentisering över LoRa
mellan PAW (ID-bricka) och PLC (edge-nod): giltig challenge-response,
felaktig HMAC, fel nonce/epoch, för korta paket, dubblettsvar, timeout,
fem misslyckanden i följd med 60 s lockout, budgetåterställning vid
lyckad autentisering — samt att PLC alltid nekar åtkomst vid fel,
saknad nyckel eller nedkopplad radio.

Sanningskälla är firmwaren (`plc-key-receiver.ino`, `paw-main.ino`,
`libraries/ShallotLoRaProtocol.h`). Förväntade loggsträngar är citerade
ur koden. Loggarna nedan innehåller noncer och HMAC (sänds i klartext
enligt protokollet) men **aldrig nyckelmaterial** — se LR-11.

## 1. Referenser och avgränsning

- Provisionering (inkl. epoch/fingerprint-match): `docs/13-*` NP-01.
- Fixtur och koppling: `docs/10-*`, pinntabell `docs/04-*` §2.
- Rogue-sändare för felinjicering: `test_key_distribution/rogue_lora_attacker/`
  (appendix A). Utan den är HMAC/nonce/short/duplicate inte manuellt testbart.

Testas **inte** här: USB-provisionering (doc 13), RSSI-gränsens exakta
tröskelvärde, räckviddsmätning, störningstålighet.
Utanför scope på 2-radiorsbänk (PRO-53, 2026-09-08): LR-02–LR-05 i den
mån de kräver rogue-sändare (tredje radio, appendix A). Bänken har
endast PLC + PAW och ingen reservhårdvara, så angriparfallen är inte
körbara. Ogiltig-HMAC-avslag täcks av automatiska tester
(`test_pro53_invalid_hmac_denied`, `test_lora_invalid_hmac`) genom
samma `verifyResponse`-väg som all mottagen trafik passerar.

## 2. Testmiljö

1. PAW + PLC provisionerade med **samma epoch och fingerprint** (doc 13 NP-01).
2. Samma rum, **1–3 m** avstånd (RSSI-gränsen −70 dBm ska inte slå till —
   syns `too weak, discard` i loggen: flytta närmare och gör om fallet).
3. Seriella terminaler mot **både PLC och PAW** (115200), loggning till fil:
   `loggar/LR-<NN>_{plc,paw}.txt`. Rogue-terminal vid rogue-fall.
4. Rogue-enhet (reserv-Pico 2 + Core1262, kopplad exakt som PLC per
   doc 04 §2.1, flashad per appendix A) **avstängd** om inte fallet kräver den.
5. Klocka/tidtagning för timeout- och lockout-fall.

Viktiga tider: challenge-takt ~5 s, svarstimeout 30 s (≈35 s per
misslyckad cykel), 5 fel i rad → 60 s lockout, PAW resultattimeout 30 s.

Konventioner: **F** = förutsättningar, **S** = steg, **E** = förväntat
resultat, **A** = faktiskt resultat, **G** = godkänt-kriterium.

---

## LR-01 Giltig challenge-response

**Syfte:** Baslinje — full cykel med godkännande i båda ändar.

**F:** Provisionerade, båda på, rogue av.

**S:**
1. Nollställ loggarna. Observera i minst 3 hela cykler (~30 s).

**E (per cykel):**
1. PLC: `Generated nonce: …`, `Challenge sent over LoRa to PAW.`,
   `Response received from PAW over LoRa`, `HMAC verification SUCCESS.`,
   `Result sent to PAW: SUCCESS` + 5×100 ms LED-blink.
2. PAW: `Challenge received from PLC over LoRa`,
   `HMAC Response computed epoch …`, `Response sent over LoRa to PLC.`,
   `Authentication SUCCESS (LoRa)`, e-paper visar **bock** (godkänd-ikon).
3. Aldrig `FAILED`, aldrig `Mismatch`, aldrig lockout-rader.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | ≥3 felfria cykler båda loggar + bock på e-paper | | |

**G:** Raden OK. Loggar sparade (återanvänds som referens i LR-11).

## LR-02 Felaktig HMAC nekas

**Syfte:** Förfalskad MAC ska underkännas med explicit RESULT-nekande.

**F:** Provisionerade. **PAW avstängd** (annars race mellan PAWs giltiga
svar och roguens förfalskning). Rogue på, PLC på.

**S:**
1. Vänta tills rogue loggar `sniffed PLC CHALLENGE`.
2. Rogue-terminal: `b`. Upprepa för 2 olika challenges.

**E (per försök):**
1. PLC: `Response received from PAW over LoRa`,
   `HMAC verification FAILED.`, `Result sent to PAW: FAILED` +
   10×50 ms LED-blink. Aldrig `SUCCESS`.
2. Rogue: `TX bad-HMAC response (53B): sent`.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | 2× FAILED + RESULT-nekande, inget SUCCESS | | |

**G:** Raden OK.

## LR-03 Fel nonce / fel epoch nekas

**Syfte:** Svar som inte ekar live-nonce (eller bär fel epoch) ska
avvisas före all HMAC-beräkning.

**F:** Som LR-02 (PAW av, rogue på).

**S:**
1. Vid sniffad challenge: rogue `n`. Vid nästa challenge: rogue `e`.

**E:**
1. `n`: PLC `Nonce mismatch (replay or wrong challenge)` +
   `Result sent to PAW: FAILED`. Aldrig `HMAC verification …`.
2. `e`: PLC `Epoch mismatch expected … got …` +
   `Result sent to PAW: FAILED`. Aldrig HMAC-rad.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Nonce-avvisning utan HMAC-beräkning | | |
| 2 | Epoch-avvisning utan HMAC-beräkning | | |

**G:** Båda raderna OK.

## LR-04 För kort paket avvisas

**Syfte:** Undermåliga ramar ska avvisas på längd, aldrig tolkas.

**F:** Som LR-02 (PAW av, rogue på).

**S:**
1. Rogue-terminal: `s`.

**E:**
1. PLC: `Malformed LoRa packet rejected: type 0xB2 len 4`. Ingen
   verifiering, ingen RESULT-sändning för paketet, inget tillståndsbyte.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Explicit längdavvisning, tyst i övrigt | | |

**G:** Raden OK.

## LR-05 Dubblettsvar avvisas

**Syfte:** Återuppspelat godkänt svar ska nekas ur replay-cachen.

**F:** Provisionerade, alla tre på. Rogue på.

**S:**
1. Vänta på en lyckad cykel (PLC `HMAC verification SUCCESS`).
   Rogue har nu sniffat PAWs svar (`sniffed PAW RESPONSE`).
2. **Dra ur PAW direkt** (så inget nytt äkta svar kan racea).
3. Vänta på nästa `Challenge sent over LoRa to PAW.` i PLC-loggen,
   rogue-terminal: `d` inom några sekunder.
4. Sätt tillbaka PAW. Provisionera om båda (doc 13 NP-01-steg —
   PAW tappade nyckeln vid strömbortfallet).

**E:**
1. PLC: `Duplicate response (replay); rejected.` Aldrig nytt `SUCCESS`
   för reprisen. (Skulle reprisen anlända efter avslutad väntan gäller
   i stället `Stray response with no live challenge` — också nekande
   och godkänt, men notera vilken väg som togs.)
2. Efter steg 4: normala cykler + matchande fingerprint igen.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Repris nekad (duplicate- eller stray-vägen), inget SUCCESS | | |
| 2 | Omprovisionering återställd | | |

**G:** Båda raderna OK.

## LR-06 Timeout vid tyst motpart

**Syfte:** Uteblivet svar ska ge kontrollerad re-issue, aldrig godkännande.

**F:** Provisionerade. PAW avstängd, rogue av.

**S:**
1. Observera PLC i ~75 s (≥2 timeout-cykler).

**E (per cykel, ~35 s):**
1. `Challenge sent over LoRa to PAW.` → 30 s tystnad →
   `Challenge response timed out; re-issuing.` → ny challenge ~5 s senare.
2. Aldrig `Response received`, aldrig `Result sent`, aldrig LED-succéblink.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | ≥2 timeout-cykler med re-issue, noll godkännanden | | |

**G:** Raden OK.

## LR-07 Fem fel i rad → 60 s lockout

**Syfte:** Avgränsade återförsök med fail-closed cooldown och återupptag.

**F:** Provisionerade. PAW av, rogue av. Klocka redo.

**S:**
1. Starta tidtagning vid första `Challenge sent`. Vänta ~4 min utan att
   röra något. Anteckna tiden för varje `timed out`-rad.

**E:**
1. Femte felet i rad loggar
   `Retry budget exhausted; entering auth lockout (fail-closed).`
2. Därefter **60 s total tystnad**: ingen `Challenge sent`, ingen annan
   LoRa-aktivitet. (Normaltakt hade gett ~12 challenges på den tiden —
   räkna i loggen.)
3. Sedan `Auth lockout expired; resuming challenges.` + ny challenge.
   Fortfarande PAW av → nya timeout-cykler (förväntat).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Lockout-rad efter 5:e felet (~3 min in) | | |
| 2 | 60 s sändningstystnad, sedan återupptag | | |

**G:** Båda raderna OK.

## LR-08 Lyckad autentisering återställer felbudgeten

**Syfte:** En framgång ska nollställa räknaren — 4+1+4 fel får aldrig
låsa ute. (PAW får **inte** strömbrytas här — nyckeln ligger i SRAM.
Dämpning sker med metallåda, jfr LR-10 variant B.)

**F:** Provisionerade, alla på, rogue på. Metallåda redo.

**S:**
1. Ställ innesluten påslagen PAW i lådan, stäng locket. Vid 4 på varandra
   följande challenges: rogue `b` per challenge (4×
   `HMAC verification FAILED.` i PLC-loggen, ~30 s totalt).
2. Ta ut PAW (rogue tyst). Vänta på en lyckad cykel
   (`HMAC verification SUCCESS.` + e-paper-bock).
3. Ställ tillbaka PAW i lådan. Rogue `b` vid 4 nya challenges.
4. Ta ut PAW; normala cykler återupptas.

**E:**
1. Aldrig någon lockout-rad under hela fallet (4 fel, succé, 4 fel —
   budgeten nollställdes i steg 2).
2. Steg 2 visar full LR-01-cykel inkl. e-paper-bock.
3. Sätt på PAW efteråt; normala cykler återupptas.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Ingen lockout trots 8 fel totalt (brutna av succé) | | |
| 2 | Succé + återgång till normal drift efter uttag | | |

**G:** Båda raderna OK. (Motexempel: 5× `b` i rad utan mellanliggande
succé SKA ge lockout — valfri kontroll.)

## LR-09 Nekad åtkomst utan nyckel

**Syfte:** Oprovisionerad PLC ska aldrig sända challenges eller godkänna.

**F:** PLC färskstartad utan provisionering (nyflashad eller omstartad —
SRAM är tom). PAW på (lyssnar). Rogue av. MPU visar inget aktivt epoch
för PLC-sidan.

**S:**
1. Observera båda loggarna i 2 min.

**E:**
1. PLC-loggen innehåller **aldrig** `Challenge sent over LoRa`,
   aldrig `Response received`, aldrig `Result sent`, aldrig
   `HMAC verification …`. (Sändfunktionen nås inte utan nyckel.)
2. PAW-loggen visar ingen inkommande challenge; e-paper står kvar i
   autentiserar/fel-läge — aldrig bock.
3. Provisionera sedan (doc 13 NP-01) och verifiera att LR-01-cykler
   startar: nekandet berodde på saknad nyckel, inte trasig radio.

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Total LoRa-tystnad från PLC i 2 min | | |
| 2 | Drift efter provisionering (kontrapositiv) | | |

**G:** Båda raderna OK.

## LR-10 Nedkopplad radio nekar alltid

**Syfte:** Utan fungerande radio ska inget godkännande kunna utfärdas;
efter återanslutning ska driften återhämta sig.

**F:** Provisionerade. Välj variant efter montering:
**A** (breadboard med byglar): DIO1-bygeln på PLC kan lossas.
**B** (fastlött): metallåda som RF-skärm åt PAW (t.ex. urkopplad
mikrovågsugn — **aldrig** påslagen). Rör aldrig 3V3/GND/SPI under drift.

**S (variant A):**
1. Lossa DIO1-bygeln på PLC medan driften är normal.
2. Observera i ~4 min (täck timeout-cykler + lockout).
3. Sätt tillbaka bygeln. Vänta på återhämtning.

**S (variant B):**
1. Ställ innesluten avstängd PAW i metallådan, stäng locket.
2. Observera PLC i ~4 min. Ta ut PAW.

**E (båda varianter):**
1. PAW-loggen (A) visar fortsatt inkommande `Challenge received`
   — PLC sänder alltså, men hör aldrig svar.
2. PLC: `Challenge response timed out; re-issuing.` → efter 5:e felet
   lockout-raden → 60 s tystnad → `resuming challenges`. Aldrig
   `HMAC verification SUCCESS`, aldrig `Result sent …: SUCCESS`.
3. Efter återanslutning/uttag: normala LR-01-cykler + e-paper-bock
   (i variant A direkt efter lockout-fönstret löpt ut).

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | Noll godkännanden under avbrottet (variant A/B) | | |
| 2 | Timeout→lockout→återupptag synligt i PLC-loggen | | |
| 3 | Full återhämtning efteråt | | |

**G:** Alla tre rader OK.

## LR-11 Loggrevision: inget nyckelmaterial

**Syfte:** Bevisa att loggarna bär noncer/HMAC/fingerprint (luftsynligt
per protokollet) men aldrig nyckelbytes.

**F:** Loggfiler från LR-01 (PLC + PAW, ≥3 cykler).

**S:**
1. Lista alla 64-hex-blobbar: `grep -Eo '[0-9A-Fa-f]{64}' <logg>`.
   Varje träff ska stå på en `HMAC Response computed`-rad (PAW) —
   aldrig någon annanstans.
2. Lista alla 32-hex-blobbar: `grep -Eo '[0-9A-Fa-f]{32}' <logg>`.
   Varje träff ska stå på en nonce-märkt rad (`Generated nonce`,
   `Challenge nonce`) **och** värdena ska skilja mellan på varandra
   följande challenges (färskhet — en läckt statisk nyckel hade
   upprepats identiskt varje gång).
3. Bekräfta att inga andra långa hex-blobbar finns än stegen ovan
   (fingerprints är 8 tecken och står på `hash`/`fingerprint`-rader).

**E:** Steg 1–3 uppfyllda i båda loggarna. (Garanti i kod: pytest-fallet
`test_no_key_material_in_logs` skannar logg-satserna statiskt.)

| # | Förväntat (sammandrag) | Faktiskt (datum/sign) | OK |
|---|---|---|---|
| 1 | HMAC endast på märkta rader | | |
| 2 | Noncer märkta + unika per challenge | | |
| 3 | Inga övriga långa blobbar | | |

**G:** Alla tre rader OK.

## 3. Fail-closed-matris (sammanfattning)

| Fall | Nekande-bevis |
|---|---|
| LR-01 | Godkännande kräver full kedja challenge→korrekt HMAC→RESULT 0x01 |
| LR-02/03/04 | Fel HMAC/nonce/epoch/kort paket → explicit avvisning + RESULT 0x00 |
| LR-05 | Repris nekas ur cachen (eller som stray) — inget nytt godkännande |
| LR-06/07 | Timeout räknas; 5 fel → 60 s sändningstyst lockout |
| LR-08 | Budgeten nollställs endast av verifierad framgång |
| LR-09/10 | Utan nyckel/radio: noll challenges eller noll godkännanden |
| LR-11 | Inget nyckelmaterial observerbart i någon logg |

## Appendix A — rogue-sändaren

Kontrollerad motpart för LR-02–LR-05. Reserv-Pico 2 + Core1262 kopplad
**exakt som PLC** (doc 04 §2.1), USB till värddatorn för kommandon.

```bash
# Flasha (från reporoten):
arduino-cli compile --fqbn rp2040:rp2040:rpipico2 \
  --library libraries/ShallotLoRa \
  --output-dir /tmp/rogue \
  test_key_distribution/rogue_lora_attacker/rogue_lora_attacker.ino
# Dra UF2 till RPI-RP2-enheten. Öppna serieporten i 115200 baud.
```

Kommandon: `b` fel-HMAC · `n` fel-nonce · `e` fel-epoch ·
`s` kort paket · `d` repris av sniffat PAW-svar · `?` hjälp.
Rogue lyssnar passivt och lagrar senaste challenge/svar; den sänder
**endast** på kommando och lär sig aldrig nycklar (förfalskad HMAC är
slumpdata). Håll PAW **avstängd** i `b`/`n`/`e`/`s`-fallen (determinism),
påslagen endast i `d`-fallet. Använd aldrig nära driftsystem.

## Appendix B — ramformat (källa: ShallotLoRaProtocol.h)

Alla flerb
...[truncated 911 chars]