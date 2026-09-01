# PAW Main Firmware

Kombinerad firmware för **Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper**.

## Funktioner

- **PRO-48**: Tar emot AES-128 nyckel från Arduino UNO Q via UART
- **PRO-50**: Beräknar HMAC-SHA256 svar på LoRa challenge från PLC
- **PRO-57**: Visar autentiseringsstatus på e-Paper (endast ikoner, ingen PII)
- **PRO-58**: LoRa P2P kommunikation med PLC (simulerad för test)

## Hårdvarukonfiguration

### Pin-tilldelning

| Funktion | Feather Pin | Notering |
|----------|-------------|----------|
| **UART till UNO Q** | GP0 (TX), GP1 (RX) | Serial1 |
| **LoRa SPI1** | GP10 (CLK), GP11 (MOSI), GP28 (MISO) | Core1262 |
| &nbsp; | GP9 (CS), GP6 (BUSY), GP8 (RESET) | Core1262 |
| &nbsp; | GP21 (DIO1) | Core1262 |
| **e-Paper SPI0** | GP23 (DIN/MOSI), GP22 (SCK) | Waveshare 1.54" |
| &nbsp; | GP5 (CS), GP24 (DC), GP25 (RST) | Waveshare 1.54" |
| &nbsp; | GP7 (BUSY) | Waveshare 1.54" |
| **LED** | LED_BUILTIN | Inbyggd NeoPixel |

## Flashningsinstruktioner

### Metod 1: Arduino IDE

1. **Installera nödvändiga bibliotek:**
   ```bash
   # Installera via Library Manager i Arduino IDE:
   - arduino-pico (earlephilhower) - för RP2350 support
   - RadioLib (jgromes) - för SX1262 LoRa (när du ersätter mock-implementationen)
   ```

2. **Konfigurera Arduino IDE:**
   - Board: `Adafruit Feather RP2350`
   - USB Mode: `CDC`
   - Upload Method: `UF2`
   - Port: Välj din Feather

3. **Öppna och flasha:**
   - Öppna `paw-main.ino` i Arduino IDE
   - Klicka på Upload-knappen
   - Håll nere BOOTSEL-knappen på Feather när den startar om (om UF2-metoden kräver det)

### Metod 2: PlatformIO (rekommenderad)

1. **Installera PlatformIO:**
   ```bash
   pio init --board feather_rp2350
   ```

2. **Skapa `platformio.ini`:**
   ```ini
   [env:feather_rp2350]
   platform = raspberrypi
   board = feather_rp2350
   framework = arduino
   monitor_speed = 115200
   
   ; Bibliotek (avkommentera när du använder riktig LoRa)
   ; lib_deps =
   ;   jgromes/RadioLib @ ^5.0.0
   ```

3. **Flasha:**
   ```bash
   pio run --target upload
   ```

### Metod 3: UF2 Bootloader (manuell)

1. **Ladd ner UF2-fil:**
   - Kompilera med Arduino IDE eller PlatformIO
   - Kopiera den genererade `.uf2`-filen

2. **Aktivera bootloader:**
   - Håll nere BOOTSEL-knappen på Feather
   - Koppla in USB-kabeln
   - Feather dyker upp som enhet `RPI-RP2`

3. **Kopiera firmware:**
   ```bash
   cp paw-main.ino.uf2 /Volumes/RPI-RP2/
   ```
   - Enheten startar om automatiskt

## Test och Felsökning

### Serial Monitor

- Öppna Serial Monitor i Arduino IDE (115200 baud)
- Du bör se:
  ```
  ============================================
  SHALLOT PAW Main Firmware
  Hardware: Adafruit Feather RP2350
  Components: Core1262 LoRa + e-Paper
  ============================================
  [PRO-57] Initializing e-Paper...
  [PRO-58] Initializing LoRa...
  [PRO-48] Starting key reception...
  [PRO-48] Waiting for key distribution from UNO Q...
  ```

### e-Paper Status

- **AUTHENTICATING**: Tre punkter i triangelmönster (väntar på nyckel/challenge)
- **AUTHENTICATED**: Bock i en cirkel (lyckad autentisering)
- **FAILED**: X i en cirkel (misslyckad autentisering)

### LED Indikator

- **Snabb blinkning**: Ingen nyckel mottagen
- **Långsam blinkning**: Nyckel mottagen, väntar på challenge
- **5 snabba blinkningar**: Autentisering lyckades
- **10 snabba blinkningar**: Autentisering misslyckades

## Integration med UNO Q

1. Flasha UNO Q med `uno-q-key-authority-mcu.ino`
2. Anslut UNO Q Serial1 till Feather Serial1 (GP0/GP1)
3. Starta UNO Q först, sedan Feather
4. UNO Q kommer att skicka nyckeln automatiskt

## Integration med PLC

1. Flasha PLC med motsvarande firmware
2. Anslut LoRa-moduler (samma frekvens: 868MHz)
3. PLC skickar challenge, PAW svarar med HMAC-SHA256

## Säkerhetsnotiser

- AES-128 nyckeln lagras i **volatilt SRAM** - försvinner vid strömbortfall
- e-Paper visar **endast statusikoner** - ingen text, ingen PII
- HMAC-SHA256 beräknas med mottagen nyckel och challenge
- CRC32-verifiering av nyckel vid mottagande

## Att göra (TODO)

- [ ] Ersätt `MockLoRa` med riktig RadioLib implementation
- [ ] Lägg till LoRa-konfiguration (frekvens, bandwidth, etc.)
- [ ] Implementera riktig felhantering för LoRa
- [ ] Lägg till watchdog timer för stabilitet
- [ ] Optimera strömförbrukning för batteridrift
