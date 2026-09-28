# Bänkdiagnos: UNO Q-dock + beslut om topologi — 2026-09-27

## Sammanfattning

Dock-distribution UNO Q → DEN över D0/D1 är tyst i båda riktningarna.
Rotorsak (fyra oberoende belägg): `Serial1` i core 1.0.0 är `usart1`
(PA9/PA10, konsol mot Linux-SoC) — **inte** D0/D1 (PB7/PB6, ren GPIO).
Kabeln sitter på döda pinnar. Ingen firmwareändring på DEN-sidan kan
avhjälpa detta; signalvägen måste läggas om.

## Beläggskedja

1. Kärnmakro (`cores/arduino/zephyrSerial.h`): `ARDUINO_HARDWARE_SERIAL`
   = `ZARD_SERIAL_NAME(0)` = `Serial1` = `serials[0]` = `usart1`.
   Kommentaren säger "usually on D0/D1" — avsikten, inte verkligheten.
2. Register (SWD, live): skissen har startat `usart1` @115200
   (CR1=0x2D, BRR=0x56D). `usart3` (enda header-UART:en, D20/D21) är
   aldrig startad (CR1=0, BRR=0).
3. Overlay (`arduino_uno_q_stm32u585xx.overlay`): `usart1` utan
   pinctrl-override = SoC-default PA9/PA10 (konsol). D0=PB7, D1=PB6
   (GPIO). `usart3` = PB10/PB11 = D21/D20.
4. Beteende: tre beväpnade distributioner (knapp tryckt, LED-sekvens
   bekräftad, `pendingDistributionTarget` konsumerad i RAM) — alla med
   total timeout i samtliga fyra 5 s-faser. Mottagaren (frisk, lyssnar)
   såg aldrig en byte.

## Bänkläge vid passets slut

- UNO Q: länk uppe (SWD-reset mot startad router återställer; supersession
  kräver MCU-reset — periodisk re-BIND räcker inte, se nedan).
  Nyckel genererad via RPC, fingeravtryck `F1831222`, state GENERATED.
  Äldre nyckel `27A9B480` förlorad vid strömavbrott mitt under passet
  (SRAM-fysik, förväntat).
- DEN: `plc-key-receiver` (sha `f77f2f75…`, byggd från `27802ac` +
  SPI1-fix för core 6.1.1: `spi1` → kärnans `SPI1`, död
  `SPIClassRP2040 spi1`-deklaration borttagen — kolliderade med
  pico-SDK:ts `spi1`-makro). Verifierad flash via picotool, lyssnar.
- PAW: `paw-main` (orörd), nyckellös.
- Känd firmware-brist (uppföljning): `Bridge.begin()`-fel förgiftar
  retry-vägen — efter routeromstart krävs MCU-reset trots
  60 s-refreshens påstådda självläkning. Gäller även efter strömavbrott
  där MCU:n bootar före routern.

## Beslut: topologi (operatör 2026-09-27)

```
mamabear ── USB ──→ [USB-hubb, strömförsörjd] ──┬──→ DEN (monitor + USB-prov + flash)
                                                 └──→ PAW (monitor + USB-prov + flash)

ceremonivagga (pogo): UNO Q UART ──→ DEN | PAW (en i taget, + GND + DOCK_DETECT)
```

- USB = övervakning/provisionering/testnyckel/flash. Pogo = ceremoni/
  riktig nyckel. Rollerna separerade fysiskt.
- Krav: hubben strömförsörjd (ej buss-ström). Dockkontakt: TX, RX, GND,
  DOCK_DETECT. MCU-jord måste med i dock-kabeln (går ej via hubben).
  USB-C-formad dockkontakt kräver omisskännlig märkning/mekanisk
  nyckling (får ej kunna pluggas i laptop).
- Vagga framtvingar "en i taget" mekaniskt; kryssning fastlödd;
  provisioneringslyssnare grindad på dock-detect (uppföljning i firmware).
- Transport (UART-direkt vs USB-via-värd) och mekanik (vagga vs
  flygande kablar) är oberoende beslut. USB-vagga är giltig produktväg
  om airgap + härdad värd dokumenteras; UART-vagga endast om
  förtroendemodellen kräver MCU-förvaring.

## Tillägg 09:xx — spår 1 klart (act2=OK)

- Orsak till nekad auth: **returtråden PAW→DEN bar inget**
  (`DEN_REASON_DISCONNECT` = 2 s-deadline, noll byte mottaget).
  DEN→PAW fungerade hela tiden (PAW svarade och tog emot ACK 0x00).
  Efter omläggning av returtråden (PAW-GPIO0 → DEN-GP1 + jord):
  `record-demo.py act2` → `act2=OK`, AUTHENTICATED-banner,
  fingeravtryck `be45cb26` på båda.
- Bänklära: `cat /dev/ttyACM*` blockerar ibland på open (modemlinjer)
  — använd pyserial. Portöppning återställer korten (SRAM-nycklar
  raderas): öppna EN gång, provisionera sedan, läs utan att stänga/
  öppna igen. `record-demo.py` gör rätt ordning själv.
- DEN kräver signerad tom blocklista efter nyckel (PRO-98-grind);
  utan den nekar allt trots korrekt HMAC. Demoskriptets baslinje
  skickar den — kör alltid hela baslinjen, aldrig manuell
  provisionering utan blocklista.
- Kvar: riktig ceremoni blockerad på Serial3-rework (spår 2);
  PAW kör `paw-main`, DEN `den-main-TESTROOT-W` (sha `ca7ef4fd`),
   båda med TEST-nyckel `be45cb26` (TEST-ONLY).

## Tillägg — operatörens väg: MCU→MPU→USB med riktig nyckel (GENOMFÖRD)

- Operatörsbeslut: MCU:n exponerar nyckeln till MPU:n, vidare via USB
  till DEN/PAW. Implementerat som ny RPC `get_key_material` (32 hex,
  fail-closed tom utan genererad nyckel). Medveten avvikelse från
  status-only-Bridge + `docs/14`:s hårda regel — motiverat med
  airgappad värd (operatörens beslut).
- Bygge: mamabear, `arduino:zephyr:unoq`, `-DSHALLOT_NO_ED25519`
  (kringgår Crypto/RNG.cpp↔CMSIS `RNG`-kollisionen; blocklistsignering
  stubbad fail-closed). Flasha **ELF-zsk** (`*.elf-zsk.bin`, 109344 B,
  sha `ee102563…`) till `0x08100000` — BIN-zsk avvisas tyst av loadern
  (första flashen tog ej; verify + mailbox + reset krävs).
- Ceremoni: nyckel genererad i MCU (`fp 71190F5C`), hämtad via RPC av
  `/tmp/prov/usb_ceremony2.py` (nyckeln aldrig på kommandoraden),
  provisionerad över USB till DEN + PAW (fp-match båda), signerad tom
  blocklista direkt efter DEN-provisionering (15 s-fönstret).
  Resultat: e-paper **Bock + AUTHENTICATED** — paret cyklar code 0 med
  riktig nyckel.
- Varning: `record-demo.py` provisionerar TEST-nyckel — körning skriver
  över den riktiga nyckeln. Demos kräver medvetet val av nyckel.
- Ocommitat i trädet: skissens `DOCK_SERIAL`+`get_key_material`,
  mottagarens SPI1-fix. Shellhistorik på mamabear innehåller RPC-anrop;
  nyckelmaterial för supersederad nyckel förekom i sessionslogg —
  rotera vid behov.

## Öppna spår (uppdaterat)

1. **USB-testnyckel** (demos): ✅ KLART — `act2=OK`.
2. **MCU→MPU→USB med riktig nyckel**: ✅ KLART — e-paper AUTHENTICATED
   med `fp 71190F5C` (operatörens väg, se tillägg ovan).
3. **Serial3-rework** (dock-ceremoni): STRUKET som irrelevant sedan
   operatören beslutat MCU→MPU→USB. `DOCK_SERIAL` återställd till
   `Serial1` (o verifierad experimentkod hör inte hemma i trädet);
   usart3/D20/D21 förblir verifierad-i-register men obevisad ände-till-ände.
   Notera vid ev. dock-hårdvara: `usart3`=D20/D21 krockar med `i2c2`
   SoC-default (PB10/PB11) — skissen använder ej Wire.
