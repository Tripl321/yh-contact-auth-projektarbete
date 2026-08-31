# ID-kort (Feather RP2350 + Core1262-868M + e-Paper)

Firmware for ID-kort-noden: Adafruit Feather RP2350 med Core1262-868M och 1.54" Waveshare e-Paper.

## Ansvar

- Ta emot challenge (nonce) fran PLC over LoRa P2P
- Berakna HMAC-SHA256(nyckel, nonce) och returnera svar
- Visa status pa e-Paper-display

## Pin-tilldelning -- e-Paper (SPI0)

| Feather | e-Paper |
|---|---|
| MO (GPIO23) | DIN |
| SCK (GPIO22) | CLK |
| D5 (GPIO5) | CS |
| D24 (GPIO24) | DC |
| D25 (GPIO25) | RST |
| D7 (GPIO7) | BUSY |

## Pin-tilldelning -- Core1262 (SPI1)

| Feather | Core1262 |
|---|---|
| D10 (GPIO10) | CLK |
| D11 (GPIO11) | MOSI |
| A2 (GPIO28) | MISO |
| D9 (GPIO9) | CS |
| D6 (GPIO6) | BUSY |
| D8 (GPIO8) | RESET |
| D21 (GPIO21) | DIO1 |

## Bibliotek

- arduino-pico (earlephilhower) karna
- RadioLib (jgromes) for SX1262
- Waveshare e-Paper bibliotek (officiella exempel for Pico/Pico2)
