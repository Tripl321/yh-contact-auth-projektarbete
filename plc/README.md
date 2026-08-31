# PLC (Raspberry Pi Pico 2 + Core1262-868M)

Firmware for PLC-noden: Raspberry Pi Pico 2 (RP2350A) med Waveshare Core1262-868M (SX1262 LoRa, 868 MHz).

## Ansvar

- Skicka challenge (nonce) till ID-kort over LoRa P2P
- Ta emot HMAC-svar och verifiera
- Drivare for SX1262 via RadioLib over SPI1

## Pin-tilldelning (SPI1)

| Pico 2 GP | Core1262 |
|---|---|
| GP10 | CLK |
| GP11 | MOSI |
| GP12 | MISO |
| GP9 | CS |
| GP6 | BUSY |
| GP8 | RESET |
| GP21 | DIO1 |

## Bibliotek

- arduino-pico (earlephilhower) kärna
- RadioLib (jgromes) for SX1262
