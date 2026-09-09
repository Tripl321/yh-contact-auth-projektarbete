# 15 — E-paper och watchdog: fysisk testplan

Manuella systemtester för PAW:s e-paper-display och hårdvaru-watchdog:
boot-testläge med statusordning, refresh-begränsning, kontrollerad
watchdog-återställning samt fail-closed återhämtning (oautentiserad,
tom SRAM-nyckel). Varje fall dokumenteras med observerade tider, loggar
och avvikelser.

Sanningskälla är firmwaren (`libraries/ShallotEpd/`, `paw-main.ino`).
Förväntade loggsträngar är citerade ur koden. Loggarna innehåller
noncer/HMAC (luftsynligt per protokollet) men aldrig nyckelmaterial.

## 1. Referenser och avgränsning

- Statuslägen/policy: `libraries/ShallotEpd/src/EpdPolicy.h`.
- Provisionering: `docs/13-*` NP-01. LoRa-trafik: `docs/14-*` LR-01.
- Watchdog-grunder (RP2350, max ~8,3 s, matningspunkter): kodkommentarer
  i `paw-main.ino` (avsnittet watchdog/radio recovery).

Testas **inte** här: LoRa-innehåll (doc 14), USB-ramar (doc 13),
exakt refresh-tid i ms, strömförbrukning.

## 2. Testmiljö

1. PAW flashad med aktuell firmware, USB-terminal 115200 baud med
   loggning till fil (`loggar/EP-WD-<NN>_paw.txt`). Tidsstämplar på.
2. Klocka/tidtagning. Kamera för displayfoto (rekommenderat, ej krav).
3. EP-02 kräver provisionerade PAW+PLC med live LoRa-trafik (doc 14 LR-01).
4. Övriga fall kräver endast PAW på USB (ingen nyckel, ingen trafik).

Tidsbudgetar: full refresh ~14 s, testcykel ≈ 62 s (4× refresh + hålltider),
WDT-timeout 8 s, boot-testfönster 2 s, nyckelväntan obegränsad.

Konventioner: **F** = förutsättningar, **S** = steg,
**E** = förväntat resultat, **A** = faktiskt resultat (fylls i med
tid, loggutdrag och avvikelser), **G** = godkänt-kriterium.

Ikonlexikon (fysisk avläsning): autentiserar = cirkel + 3 prickar,
godkänd = cirkel + bock, nekad = cirkel + kryss, tom = endast ram.

---

## EP-01 Boot-testläge: ordning på statuslägen

**Syfte:** Alla fyra lägen visas exakt en gång, i rätt ordning, slutande blankt.

**F:** PAW på USB, terminal öppen. Enheten får vara oprovisionerad.

**S:**
1. Resetta PAW (reset-knapp eller dra/sätt tillbaka USB).
2. Inom 2 s efter boot-bannern: skriv `t` i terminalen (utan Enter om
   möjligt; ett extra radbrytningstecken skadas inte — det droppas som
   stray-byte av USB-protokollets resync).
3. Fotografera/anteckna displayen vid varje växling i ~70 s.

**E:**
1. Loggen visar `Display test mode: cycling all states.` följt av, i ordning:
   `Test mode: showing state 0` → `show authenticating: refresh`,
   `state 1` → `show authenticated: refresh`,
   `state 2` → `show failed: refresh`,
   `state 3` → `show blank: refresh`.
2. Displayen visar prickar → bock → kryss → enbart ram, varje läge
   ca 14 s + 1,5 s hålltid. Total cykeltid ≈ 60–65 s.
3. Efter cykeln fortsätter normal boot (`Waiting for key distribution...`).

| # | Förväntat (sammandrag) | Tid (uppmätt) | Loggutdrag | Avvikelse | OK |
|---|---|---|---|---|---|
| 1 | Ordning 0→1→2→3 med refresh-rader | | | | |
| 2 | Ikoner prickar/bock/kryss/ram, cykel ≈62 s | | | | |
| 3 | Normal boot efteråt | | | | |

**G:** Alla tre rader OK.

## EP-02 Upprepad status ger ingen extra refresh

**Syfte:** Bevisa att guard-reglerna håller — dubbletter suppressas,
displayen flimrar inte i onödan under trafik.

**F:** Provisionerade PAW+PLC med live-trafik (doc 14 LR-01 pågående).

**S:**
1. Vänta tills e-paper visar bock (första godkännandet). Anteckna tiden T0.
2. Observera display + logg i 2 min utan att röra något.
3. Räkna i loggen: rader `show …: refresh` vs `show …: suppressed (guard)`
   efter T0.

**E:**
1. Displayen står stabilt på bock — inga full-refresh-flimmer efter T0
   (enstaka omväxling vid genuint tillståndsbyte accepteras ej här;
   vid stabil trafik: noll).
2. Loggen efter T0 innehåller `suppressed (guard)`-rader (upprepade
   autentiserar-begäranden från challenge-trafiken) och **inga nya**
   `…: refresh`-rader.
3. Minst 5 suppress-rader observerade (trafiktakt ~5 s ger ~24 på 2 min).

| # | Förväntat (sammandrag) | Tid (uppmätt) | Loggutdrag | Avvikelse | OK |
|---|---|---|---|---|---|
| 1 | Stabil bock, inget flimmer efter T0 | | | | |
| 2 | Suppress-rader, noll nya refresh-rader | | | | |

**G:** Båda raderna OK. (Ny `refresh`-rad utan tillståndsbyte = avvikelse —
notera exakt rad och tid.)

## WD-01 Watchdog-återställning via self-test

**Syfte:** Bevisa hela kedjan utlösning → reboot → WDT-logg → fail-closed
boot utan SRAM-nyckel, samt full återhämtning via omprovisionering.

**F:** PAW på USB (provisionerad eller ej — fallet verifierar båda
lägena; notera vilket). Terminal öppen.

**S:**
1. Resetta PAW. Inom 2 s: skriv `w`.
2. Anteckna tiden från `Self-test`-raden till nästa boot-banner (T_trip).
3. Granska boot-loggen. Anteckna WDT-raden.
4. Verifiera oautentiserat läge: invänta `Key reception FAILED / Waiting...`
   (alternativt `Timeout waiting …`), e-paper visar fel-ikon. Om PLC sänder
   challenges: PAW-loggen visar epoch-avvisning, aldrig `HMAC Response computed`.
5. Provisionera om (doc 13 NP-01) och verifiera en LR-01-cykel.

**E:**
1. Loggen visar `[WDT] Self-test: 100 ms timeout, blocking 5 s without feed...`
   och **ingen** `ERROR: watchdog did not fire!`.
2. T_trip ≈ 0,1–0,5 s till tystnad; ny boot-banner inom ~3 s.
3. Boot-loggen innehåller
   `[WDT] Rebooted by watchdog; starting unauthenticated (fail-closed).`
4. Ingen nyckel i SRAM: inget HMAC-svar, ingen bock, MPU/UNO Q-sidan
   opåverkad (deras tillstånd ändras inte av PAW-rebooten).
5. Efter steg 5: normal drift (bevisar återhämtning, inte bara omstart).

| # | Förväntat (sammandrag) | Tid (uppmätt) | Loggutdrag | Avvikelse | OK |
|---|---|---|---|---|---|
| 1 | Self-test-rad, ingen ERROR-rad | | | | |
| 2 | T_trip + ny banner inom ~3 s | | | | |
| 3 | WDT-reboot-rad i boot-loggen | | | | |
| 4 | Oautentiserad, SRAM tom (inget HMAC-svar) | | | | |
| 5 | Full drift efter omprovisionering | | | | |

**G:** Alla fem rader OK.

## WD-02 Ingen falsk reset vid lång väntan (negativ kontroll)

**Syfte:** Bevisa att legitima blockeringar matar hunden — 60 s
nyckel-väntan får aldrig reseta.

**F:** Oprovisionerad PAW (färsk boot eller efter WD-01 utan omprovisionering).

**S:**
1. Låt enheten stå orörd i 60 s med terminalen öppen.

**E:**
1. **Ingen** boot-banner upprepas, **ingen** WDT-rad. Samma
   `Waiting for key distribution...`-väntan pågår hela minuten
   (10 s-fas-timeouter får återkomma — det är normalt).
2. Enheten svarar fortfarande (skriv `x`: droppas tyst som stray-byte,
   jfr doc 13 FR-01 — ingen omstart).

| # | Förväntat (sammandrag) | Tid (uppmätt) | Loggutdrag | Avvikelse | OK |
|---|---|---|---|---|---|
| 1 | Noll reboots på 60 s väntan | | | | |

**G:** Raden OK. (En reboot här = allvarlig avvikelse: matning saknas i
en blockeringsväg — notera tidpunkt och föregående loggrad.)

## WD-03 Ingen falsk reset vid full refresh (negativ kontroll)

**Syfte:** Bevisa att busy-callback-matningen täcker panelens ~14 s block.

**F:** PAW på USB. Inget annat krav.

**S:**
1. Kör EP-01 (boot + `t`) och fullfölj hela ~62 s-cykeln.

**E:**
1. Alla 4 refreshar slutförs; **ingen** WDT-rad och **ingen** oväntad
   boot-banner mitt i cykeln.
2. Skulle `e-Paper refresh stalled; flagging for re-init.` synas är det
   stall-detektorn (godkänt beteende, ej WDT) — notera som observation,
   och nästa `show` ska då logga `Re-initializing wedged e-paper…`.

| # | Förväntat (sammandrag) | Tid (uppmätt) | Loggutdrag | Avvikelse | OK |
|---|---|---|---|---|---|
| 1 | Full cykel utan reboot | | | | |

**G:** Raden OK.

## 3. Fail-closed-matris (sammanfattning)

| Fall | Återhämtningsbevis |
|---|---|
| EP-01 | Testläge ändrar inget tillstånd; normal boot tar vid |
| EP-02 | Suppressade visningar kan aldrig visa felaktig status |
| WD-01 | Trip → WDT-logg → tom SRAM → omprovisionering möjlig |
| WD-02/03 | Inga falska resettar: matning täcker väntan + refresh |

## Appendix A — tider (budgetreferens)

| Moment | Förväntat | Källa |
|---|---|---|
| Boot-testfönster | 2 s | `epdPollTestRequest(2000)` |
| Full refresh | ~14 s | panelkommentar i driver |
| Testcykel (4 lägen) | ≈ 62 s | 4× refresh + 1,5 s hålltid |
| WDT-timeout drift | 8 s | `PAW_WDT_TIMEOUT_MS` (HW-max ~8,3 s) |
| Self-test trip | ~0,1 s + boot ~3 s | `wdt_begin(100)` + `delay(2000)` i setup |
| Stall-detektor | 30 s | `EPD_STALL_MS` (panel-timeout 20 s + marginal) |

## Appendix B — felsökning

- Ingen testcykel efter `t`: tangenten kom utanför 2 s-fönstret (gör om
  från reset), eller terminalen skickade inte tecknet (prova utan Enter).
- `w` ger ingen reboot: se till att tecknet sänds inom fönstret; om
  `ERROR: watchdog did not fire!` syns är det ett fel på WDT-vägen —
  stoppa och rapportera som blockerande avvikelse.
- Oväntad reboot under EP-01: notera exakt läge/tid/loggrad — äkta
  WDT-trip under refresh tyder på trasig busy-matning eller fast panel.
- E-paper förblir svart: kontrollera SPI0-kablage per doc 04 §1.1
  (CS=5, DC=A0, RST=A1, BUSY=D25) och 3V3-matning; kör EP-01 igen.
- Främmande byte i testfönstret (t.ex. från UNO Q): pollen lämnar
  byten orörd för protokollet och hoppar över testläge — starta om fallet.
