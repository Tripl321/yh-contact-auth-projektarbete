# SPI Bring-up Test — PAW e-Paper (PRO-29)

Standalone bring-up and diagnostics for the Waveshare **1.54" e-Paper Module (B) V2**
(black/white/red, 200×200, SSD1681) on SPI0. Implements the official Waveshare
B V2 driver protocol (init sequence, separate 0x24 black/white + 0x26 red/white
framebuffers, 0x22 + 0xF7 full update). No radio, no UART-GPIO, no MISO.

Physically verified 2026-09-09: white clear → black diagnostic → checkerboard
with red border and red "EPD OK" / "B-V2" text. Full updates take ~18 s on the
bench panel — the sketch blocks on BUSY until truly idle between phases.

## Target

- Board: **Adafruit Feather RP2350** (`rp2040:rp2040:adafruit_feather_rp2350_hstx`)
- Arduino core: `rp2040:rp2040` (earlephilhower) + `ARDUINO_USB_CDC_ONLY`
- Libraries: none (Arduino core + SPI only)

## Wiring (confirmed — do not change)

| Signal | Feather pin | GPIO |
|---|---|---|
| SCK | SCK | 22 |
| MOSI | MO | 23 |
| CS | D5 | 5 |
| DC | A0 | 26 |
| RST | A1 | 27 |
| BUSY | A3 | 29 |
| VCC / GND | 3V3 / GND | — |

No MISO. UART pins GPIO0/GPIO1 untouched. LoRa SPI1 bus untouched.

## Build

```bash
arduino-cli compile \
  --fqbn rp2040:rp2040:adafruit_feather_rp2350_hstx \
  --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
  --output-dir build \
  id-kort/spi-bringup-test-epaper/spi-bringup-test-epaper.ino
```

## Upload (UF2 drag-and-drop)

1. Hold BOOTSEL, connect USB (or: open the serial port at 1200 baud to reboot
   into BOOTSEL), release — an `RPI-RP2` drive appears.
2. Copy `build/spi-bringup-test-epaper.ino.uf2` onto it; the board reboots.
3. Monitor at 115200 baud:
   ```bash
   arduino-cli monitor -p /dev/ttyACM0 -c baudrate=115200
   ```
   (Replace `/dev/ttyACM0` with the Feather's port.)

## Expected output

```
BUSY swreset: HIGH right after trigger (panel executes)
--- Clear / demo phases with BUSY waits ---
BUSY ever HIGH during run: YES (panel executes)
=== LOOK AT PANEL: ... checker + red border/text ===
```

- `BUSY ... HIGH right after trigger` after every update = panel executes.
- End state on glass: black checkerboard, red border, red text.
- If BUSY never goes HIGH: check VCC/GND, FPC orientation, then wiring.
- If updates stay HIGH far beyond ~20 s: measure the 3V3 rail under load.
