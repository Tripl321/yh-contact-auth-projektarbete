# PAW Main Firmware

Kombinerad firmware för **Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper**.

## Funktioner

- **PRO-48**: Tar emot AES-128 nyckel från Arduino UNO Q via UART
- **PRO-50**: Beräknar HMAC-SHA256 svar på LoRa challenge från PLC
- **PRO-57**: Visar autentiseringsstatus på e-Paper (endast ikoner, ingen PII)
- **PRO-58**: LoRa P2P kommunikation med PLC (simulerad för test)

## Hårdvarukonfiguration

### Pin-tilldelning

| Funktion            | Feather Pin                          | Notering         |
| ------------------- | ------------------------------------ | ---------------- |
| **UART till UNO Q** | GP0 (TX), GP1 (RX)                   | Serial1          |
| **LoRa SPI1**       | GP10 (CLK), GP11 (MOSI), GP28 (MISO) | Core1262         |
| &nbsp;              | GP9 (CS), GP6 (BUSY), GP8 (RESET)    | Core1262         |
| &nbsp;              | GP21 (DIO1)                          | Core1262         |
| **e-Paper SPI0**    | GP23 (DIN/MOSI), GP22 (SCK)          | Waveshare 1.54"  |
| &nbsp;              | GP5 (CS), GP24 (DC), GP25 (RST)      | Waveshare 1.54"  |
| &nbsp;              | GP7 (BUSY)                           | Waveshare 1.54"  |
| **LED**             | LED_BUILTIN                          | Inbyggd NeoPixel |

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
- **AUTHENTICATED**: Bock i en cirkel + texten `AUTHENTICATED` (PRO-59) —
  visas endast efter beviljad autentisering
- **FAILED**: X i en cirkel (nekad autentisering / timeout)

Grant-kontrakt: `AUTHENTICATED` kräver en beviljad session — dock-ACK
`0x01` med väntande svar (`paw_ack_pending`) eller LoRa-`RESULT 0x01`
under `STATE_WAITING_FOR_RESULT`. Obeställd ACK/RESULT ignoreras utan
displayändring; pågående eller nekad autentisering visar därför aldrig
`AUTHENTICATED`. Boot visar endast `AUTHENTICATING`.

PRO-95 (kortlivad giltighet): beviljande-visningen förfaller efter
`AUTH_GRANTED_DISPLAY_MS` (30 s) och återgår till `AUTHENTICATING`.
Protokolltillståndet återgår redan vid beviljandet till
`STATE_WAITING_FOR_CHALLENGE`; DEN låser efter `DEN_SESSION_GAP_MS`.
Sessionen upphör alltså vid timeout, fel, omstart eller ogiltigt resultat
— aldrig stillastående beviljad.

Kvarvarande begränsningar: e-paper är bistabil och behåller sista bilden
utan ström — ett strömavbrott fryser indikationen tills nästa boot (som
alltid visar låst läge; nyckeln dör med SRAM så ingen åtkomst kvarstår).
Visningsfönstret (30 s) överlever DEN-beslutet (~1 s) avsiktligt som
mänskligt läsbar bekräftelse — det är en indikation, inte en behörighet.

Panelnot: firmwaren driver 1.54"-panelen monokromt (svart plan; rött plan
hålls vitt) — grön färg finns inte på denna panel, så bock + text är
beviljandesignalen. Ingen PII visas någonsin (endast ikoner + statustext).

Bänkcheck: provocera nekat (fel nyckel), timeout (ingen ACK inom 2,5 s)
och obeställd `RESULT 0x01` utan föregående svar — displayen ska aldrig
visa bock/text förrän vid verklig beviljad session.

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

## Dockad UART mot DEN (PRO-84/87)

PAW är responder-only på Serial1 (115200): giltig CHALLENGE (16 B nonce)
besvaras med RESPONSE (32 B HMAC, dev-nyckel); allt annat ignoreras
fail-closed.

**Transporter (delade, aldrig gemensamma):** Mama Bear-provisionering går
över USB Serial (USB-C); Serial1 (GPIO0/1) tillhör exklusivt DEN-dockan.
Ingen parser läser någonsin den andras transport.

### Fysisk UART-koppling PAW↔DEN (+ delad GND)

| Från           | Till           | Notering                           |
| -------------- | -------------- | ---------------------------------- |
| DEN GPIO0 (TX) | PAW GPIO1 (RX) | RP2350 UART0-defaults, ingen remap |
| DEN GPIO1 (RX) | PAW GPIO0 (TX) |                                    |
| GND            | GND            | gemensam jord krävs                |

### Bygg och upload (Feather RP2350)

```bash
arduino-cli compile \
  --fqbn rp2040:rp2040:adafruit_feather_rp2350_hstx \
  --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
  --library libraries/DenUartProtocol \
  --output-dir build \
  id-kort/paw-main/paw-main.ino
```

Håll BOOTSEL + anslut USB (RPI-RP2 visas), kopiera `build/paw-main.ino.uf2`
dit; övervaka USB-loggen i 115200 baud. Bänkcheck utan DEN: tystnad på
Serial1 ger ingen trafik; TX0↔RX1-loopback ger `FAILED: unexpected type`
aldrig något svar på skräp.

## Säkerhetsnotiser

- AES-128 nyckeln lagras i **volatilt SRAM** - försvinner vid strömbortfall
- e-Paper visar **endast statusikoner + beviljandetext** - ingen PII
- HMAC-SHA256 beräknas med mottagen nyckel och challenge
- CRC32-verifiering av nyckel vid mottagande

## Att göra (TODO)

- [ ] Ersätt `MockLoRa` med riktig RadioLib implementation
- [ ] Lägg till LoRa-konfiguration (frekvens, bandwidth, etc.)
- [ ] Implementera riktig felhantering för LoRa
- [ ] Lägg till watchdog timer för stabilitet
- [ ] Optimera strömförbrukning för batteridrift
