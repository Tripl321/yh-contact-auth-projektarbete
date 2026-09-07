# 01 — Kravspecifikation

| Fält | Värde |
|------|-------|
| Dokument | 01 — Kravspecifikation |
| Version | 2.0 |
| Status | Aktiv |
| Datum | 2026-09-07 |
| Ansvarig | Johannes Olerås |
| Linear | PRO-30 |

---

## 1. Inledning

Detta dokument definierar mätbara funktionella och icke-funktionella krav för SHALLOT — ett säkert-och-designat ID-bricka-autentiseringssystem. Kraven har utarbetats utifrån den faktiska implementationen i firmware för UNO Q, PLC (edge enforcement-nod) och PAW (ID-bricka). Funktioner som ännu inte är implementerade markeras explicit som avgränsningar i avsnitt 5 och beskrivs inte som färdiga.

### 1.1 Systemöversikt

SHALLOT består av tre hårdvaruenheter:

1. **UNO Q** — Luftgapad provisioneringshubb. Genererar AES-128-nycklar med STM32U585 TRNG. Distribuerar nycklar via UART.
2. **PLC (edge enforcement-nod)** — Raspberry Pi Pico 2 (RP2350) + Core1262 (SX1262 LoRa). Genererar nonce, skickar challenge över LoRa, verifierar HMAC, fattar fail-closed-beslut.
3. **PAW (ID-bricka)** — Adafruit Feather RP2350 + Core1262 (SPI1) + e-Paper (SPI0). Tar emot challenge, beräknar HMAC, returnerar svar, visar status.

Konceptuellt ramverk: FIDO2/HMAC. Implementation: AES-128 + HMAC-SHA256.

### 1.2 Definitioner

| Term | Definition |
|------|-----------|
| UNO Q | Arduino UNO Q (STM32U585), luftgapad provisioneringshubb |
| PLC | Edge enforcement-nod, Raspberry Pi Pico 2 + Core1262 |
| PAW | ID-bricka, Adafruit Feather RP2350 + Core1262 + e-Paper |
| TRNG | True Random Number Generator (STM32U585) |
| Nonce | Engångs-slumpval, 128 bitar |
| Challenge | Nonce som skickas från PLC till PAW över LoRa |
| Response | HMAC-SHA256 av challenge med delad nyckel |
| Fail-closed | Systemet nekar access om validering misslyckas eller uteblir |
| Air-gap | Fysiskt isolerad enhet utan nätverksinterface |
| SRAM | Volatilt minne för nyckellagring (kraft bort = nyckel bort) |

---

## 2. Funktionella krav

Varje krav har unikt ID, prioritet (Måste = krav, Borde = bör, Kan = kan) och verifieringsmetod (T = test, I = inspektion, D = demonstration).

### 2.1 Nyckelprovisionering (FR-NP)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| FR-NP-001 | UNO Q ska generera AES-128-nycklar (16 byte) med STM32U585 TRNG | Måste | T | Implementerad |
| FR-NP-002 | Nyckelgenerering ska ske på luftgapad enhet utan nätverksanslutning | Måste | I | Implementerad |
| FR-NP-003 | UNO Q ska distribuera nycklar till PLC via UART (Serial1, D0/D1) | Måste | D | Implementerad |
| FR-NP-004 | UNO Q ska distribuera nycklar till PAW via UART (Serial1, D0/D1) | Måste | D | Implementerad |
| FR-NP-005 | Operator ska fysiskt bekräfta varje nyckeldistribution med knapptryckning | Måste | D | Implementerad |
| FR-NP-006 | UNO Q MPU (QRB2210/Linux) ska logga nyckelavtryck (SHA-256[:4]), aldrig nyckelmaterial | Måste | I | Implementerad |
| FR-NP-007 | Nyckelmaterial ska lagras i SRAM på PLC (RP2350), inte i beständigt minne | Måste | I | Implementerad |
| FR-NP-008 | Nyckelmaterial ska lagras i SRAM på PAW (RP2350), inte i beständigt minne | Måste | I | Implementerad |
| FR-NP-009 | Kraftbortfall på PLC ska radera nyckelmaterial (SRAM volatilt) | Måste | T | Implementerad |
| FR-NP-010 | Kraftbortfall på PAW ska radera nyckelmaterial (SRAM volatilt) | Måste | T | Implementerad |
| FR-NP-011 | UNO Q MCU (STM32U585) ska kommunicera status till MPU via Bridge RPC | Borde | D | Implementerad |
| FR-NP-012 | Bridge RPC ska överföra endast status och bekräftelsemeddelanden, aldrig nyckelmaterial | Måste | I | Implementerad |

### 2.2 Challenge-Response (FR-CR)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| FR-CR-001 | PLC ska generera en 128-bitars (16 byte) nonce | Måste | T | Avgränsning (PRO-51) |
| FR-CR-002 | PLC ska skicka challenge (nonce) till PAW över LoRa | Måste | D | Avgränsning (PRO-52) |
| FR-CR-003 | PAW ska beräkna HMAC-SHA256 av challenge med delad AES-128-nyckel | Måste | T | Avgränsning (PRO-50) |
| FR-CR-004 | PAW ska returnera response (32 byte) till PLC över LoRa | Måste | D | Avgränsning (PRO-52) |
| FR-CR-005 | PLC ska beräkna HMAC-SHA256 av challenge med delad nyckel för verifiering | Måste | T | Avgränsning (PRO-49) |
| FR-CR-006 | PLC ska jämföra mottagen response med lokalt beräknad HMAC | Måste | T | Avgränsning (PRO-53) |
| FR-CR-007 | PLC ska fatta autentiseringsbeslut (godkänd eller avvisad) baserat på HMAC-matchning | Måste | D | Avgränsning (PRO-53) |
| FR-CR-008 | Varje challenge ska vara unik (engångsbruk) | Måste | T | Avgränsning (PRO-51) |
| FR-CR-009 | PLC:s challenge-response-protokoll över LoRa är framtida arbete | Måste | I | Avgränsning |

### 2.3 LoRa-kommunikation (FR-LR)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| FR-LR-001 | PLC och PAW ska kommunicera över LoRa P2P med Core1262 (SX1262) | Måste | T | Implementerad |
| FR-LR-002 | Core1262 ska initieras via SPI1 med RadioLib-biblioteket | Måste | T | Implementerad |
| FR-LR-003 | PLC ska kunna sända och ta emot LoRa-paket | Måste | T | Implementerad |
| FR-LR-004 | PAW ska kunna sända och ta emot LoRa-paket | Måste | T | Implementerad |
| FR-LR-005 | LoRa-kommunikationen ska vara dubbelriktad (bidirektionell) | Måste | D | Implementerad |
| FR-LR-006 | Paketformat ska definieras med fast struktur för challenge, response och status | Måste | I | Avgränsning (PRO-37) |
| FR-LR-007 | Systemet ska hantera överföringsfel och retransmissioner | Borde | T | Avgränsning (PRO-41) |

### 2.4 Statusvisning (FR-SV)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| FR-SV-001 | PAW ska visa autentiseringsstatus på e-Paper-display (Waveshare 1.54" V2, 200x200) | Måste | D | Implementerad |
| FR-SV-002 | Displayen ska visa tre statuslägen: authenticating, authenticated, failed (fail-closed) | Måste | D | Implementerad |
| FR-SV-003 | Displayen ska visa endast abstrakta statusikoner (cirkel+checkmark, cirkel+X, trippelpunkt) | Måste | I | Implementerad |
| FR-SV-004 | Displayen ska aldrig visa text, namn eller roll | Måste | I | Implementerad |
| FR-SV-005 | E-Paper-drivrutinen ska gå in i sleep mode efter varje uppdatering (säkerhetskrav Waveshare) | Måste | I | Implementerad |
| FR-SV-006 | Displayen ska använda SPI0 (separat från LoRa SPI1) | Måste | I | Implementerad |

### 2.5 Fail-closed (FR-FC)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| FR-FC-001 | Systemet ska neka access (fail-closed) om PAW inte svarar inom fastställd tid | Måste | T | Avgränsning (PRO-53) |
| FR-FC-002 | Systemet ska neka access om HMAC-verifiering misslyckas | Måste | T | Avgränsning (PRO-53) |
| FR-FC-003 | Systemet ska neka access om nyckel saknas (SRAM raderad efter kraftbortfall) | Måste | T | Implementerad |
| FR-FC-004 | Systemet ska neka access om LoRa-kommunikation fallerar | Måste | T | Avgränsning (PRO-53) |
| FR-FC-005 | Fail-closed-beslut ska drivas av watchdog på PLC | Måste | T | Avgränsning (PRO-53) |
| FR-FC-006 | Displayen ska visa "failed"-status vid fail-closed | Måste | D | Implementerad |
| FR-FC-007 | Systemet ska starta i fail-closed-läge (default deny) | Måste | I | Avgränsning (PRO-53) |

---

## 3. Icke-funktionella krav

### 3.1 Säkerhet (NFR-SEC)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| NFR-SEC-001 | Nyckelmaterial ska aldrig överföras över nätverksinterface | Måste | I | Implementerad |
| NFR-SEC-002 | Nyckelmaterial ska aldrig lagras i beständigt minne (endast SRAM) | Måste | I | Implementerad |
| NFR-SEC-003 | UNO Q ska vara fysiskt luftgapad (inget nätverksinterface aktivt) | Måste | I | Implementerad |
| NFR-SEC-004 | HMAC-SHA256 ska användas för challenge-response-autentisering | Måste | I | Avgränsning (PRO-49/50) |
| NFR-SEC-005 | AES-128-nycklar (128 bitar) ska genereras av STM32U585 TRNG | Måste | I | Implementerad |
| NFR-SEC-006 | RP2350 hardware-accelererad SHA-256 ska utnyttjas på PLC | Borde | I | Avgränsning (PRO-49) |
| NFR-SEC-007 | Nyckelavtryck i audit log ska vara SHA-256[:4] (första 4 byte), aldrig full nyckel | Måste | I | Implementerad |
| NFR-SEC-008 | Systemet ska vara säkert-und-design med defense-in-depth | Måste | I | Implementerad |

### 3.2 Tidsgränser (NFR-TIM)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| NFR-TIM-001 | LoRa-challenge ska sändas och response mottagas inom 5 sekunder | Måste | T | Avgränsning (PRO-52) |
| NFR-TIM-002 | Watchdog-timeout på PLC ska fastställas till 10 sekunder (fail-closed) | Måste | T | Avgränsning (PRO-53) |
| NFR-TIM-003 | E-Paper full refresh tar cirka 2 sekunder (normalt enligt Waveshare manual) | Borde | I | Implementerad |
| NFR-TIM-004 | Nyckeldistribution via UART ska kompletteras inom 30 sekunder per enhet | Borde | D | Implementerad |
| NFR-TIM-005 | Nonce-generering ska ske under 100 millisekunder | Borde | T | Avgränsning (PRO-51) |

### 3.3 Radio (NFR-RAD)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| NFR-RAD-001 | LoRa-modul: Waveshare Core1262 (SX1262), 868/915 MHz | Måste | I | Implementerad |
| NFR-RAD-002 | LoRa ska köra i P2P-läge (ej LoRaWAN) | Måste | I | Implementerad |
| NFR-RAD-003 | SPI1-konfiguration: SCK=D10, MOSI=D11, MISO=D24, CS=D9 | Måste | I | Implementerad |
| NFR-RAD-004 | RadioLib-biblioteket ska användas för LoRa-initiering | Måste | I | Implementerad |
| NFR-RAD-005 | Exakta LoRa-parametrar (frekvens, bandbredd, spreading factor) ska dokumenteras i 06-radio-parametrar | Borde | I | Avgränsning (PRO-43) |

### 3.4 Sekretess (NFR-PRV)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| NFR-PRV-001 | E-Paper-display ska aldrig visa personligt identifierbar information | Måste | I | Implementerad |
| NFR-PRV-002 | Audit log ska lagra endast nyckelavtryck, inte användaridentitet | Måste | I | Implementerad |
| NFR-PRV-003 | Systemet ska inte lagra historik över autentiseringsförsök i beständigt minne | Borde | I | Implementerad |
| NFR-PRV-004 | Display visar endast abstrakta ikoner, inget textinnehåll | Måste | I | Implementerad |
| NFR-PRV-005 | NFC/RFID-läsare (framtida) ska bevara air-gap genom fysisk närvaro (1-10 cm) | Måste | I | Avgränsning |

### 3.5 Drift (NFR-OPS)

| ID | Krav | Prioritet | Metod | Status |
|----|------|-----------|-------|--------|
| NFR-OPS-001 | Systemet ska starta i fail-closed-läge (default deny) | Måste | I | Avgränsning (PRO-53) |
| NFR-OPS-002 | Byggmiljö: Arduino IDE 2.x för PLC och PAW (arduino-pico core) | Måste | I | Implementerad |
| NFR-OPS-003 | Byggmiljö: ArduinoCore-zephyr för UNO Q (STM32U585) | Måste | I | Implementerad |
| NFR-OPS-004 | UNO Q MPU: Python via Arduino App Lab (QRB2210/Linux) | Måste | I | Implementerad |
| NFR-OPS-005 | PlattformIO-stöd ska finnas för PAW (paw-main) | Borde | I | Implementerad |
| NFR-OPS-006 | Systemet ska vara testbart med separata enheter (ingen simulator nödvändig) | Måste | D | Implementerad |
| NFR-OPS-007 | Dokumentation ska följa YH-skolans dokumentationsmall | Borde | I | Implementerad |

---

## 4. Kravmatris

Sammanställning av krav per kategori:

| Kategori | Antal krav | Implementerade | Avgränsningar |
|----------|-----------|----------------|---------------|
| FR-NP (nyckelprovisionering) | 12 | 12 | 0 |
| FR-CR (challenge-response) | 9 | 0 | 9 |
| FR-LR (LoRa-kommunikation) | 7 | 5 | 2 |
| FR-SV (statusvisning) | 6 | 6 | 0 |
| FR-FC (fail-closed) | 7 | 2 | 5 |
| NFR-SEC (säkerhet) | 8 | 5 | 3 |
| NFR-TIM (tidsgränser) | 5 | 2 | 3 |
| NFR-RAD (radio) | 5 | 4 | 1 |
| NFR-PRV (sekretess) | 5 | 4 | 1 |
| NFR-OPS (drift) | 7 | 6 | 1 |
| Totalt | 71 | 46 | 25 |

---

## 5. Avgränsningar

Funktioner som ännu inte är implementerade beskrivs här som avgränsningar. De ska inte tolkas som färdiga.

| ID | Avgränsning | Relaterad Linear | Planerad |
|----|-------------|------------------|----------|
| AL-001 | Challenge-response-protokoll över LoRa är inte implementerat | PRO-52 | 2026-09-17 |
| AL-002 | HMAC-SHA256-beräkning på PLC är inte implementerad | PRO-49 | 2026-09-16 |
| AL-003 | HMAC-SHA256-beräkning på PAW är inte implementerad | PRO-50 | 2026-09-16 |
| AL-004 | Nonce-generering på PLC är inte implementerad | PRO-51 | 2026-09-16 |
| AL-005 | Autentiseringsbeslut med fail-closed watchdog är inte implementerat | PRO-53 | 2026-09-17 |
| AL-006 | Paketformat för LoRa är inte formellt definierat | PRO-37 | 2026-09-08 |
| AL-007 | Felhantering och retransmission över LoRa är inte implementerad | PRO-41 | 2026-09-12 |
| AL-008 | NFC/RFID-komponent är inte vald eller integrerad | — | Ej planerad |
| AL-009 | Knappsats (keypad) är inte vald eller integrerad | — | Ej planerad |

---

## 6. Verifieringsmetoder

| Metod | Beskrivning |
|-------|------------|
| T (Test) | Kravet verifieras genom att utföra ett test och mäta resultatet |
| I (Inspektion) | Kravet verifieras genom inspektion av kod, design eller konfiguration |
| D (Demonstration) | Kravet verifieras genom demonstration av funktionen i drift |

---

## 7. Spårbarhet

Kraven i detta dokument spåras till implementationen via Linear-identifiers (PRO-X) och firmware i GitHub-repo Tripl321/yh-lora-auth-projektarbete:

| Kravgrupp | Firmware-katalog | Nyckelfiler |
|-----------|------------------|-------------|
| FR-NP | key-authority/ | uno-q-key-authority-mcu.ino, uno-q-key-authority-mpu.py, plc-key-receiver.ino, paw-key-receiver.ino |
| FR-CR | (ej implementerad) | — |
| FR-LR | plc/, id-kort/ | spi-bringup-test.ino, paw-main.ino |
| FR-SV | id-kort/ | epaper-status-display.ino |
| FR-FC | (delvis implementerad) | — |

---

## 8. Historik

| Version | Datum | Ändring |
|---------|-------|---------|
| 1.0 | 2026-09-04 | Första utkast |
| 2.0 | 2026-09-07 | Omskriven utifrån faktisk implementation. Krav strukturerade med ID, prioritet, metod och spårbarhet. Avgränsningar för oimplementerade funktioner tillagda. |
