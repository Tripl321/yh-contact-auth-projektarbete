# PLC (Raspberry Pi Pico 2 W + Core1262-868M)

Firmware for PLC-noden: Raspberry Pi Pico 2 W (RP2350A + CYW43439, WiFi/BT oanvänt) med Waveshare Core1262-868M (SX1262 LoRa, 868 MHz).

> **2026-09-04:** Nyckeldistribution sker via **USB** (USB CDC). Tidigare UART-beskrivning är föråldrad. PLC ansluts via USB-hubb för nyckelmottagning.

> **Hårdvarunotering 2026-09-03:** Kortet identifierades som `Pico 2 W` (RP2350 + CYW43439). `LED_BUILTIN` är `PIN_LED 64` (CYW43) — ej `GP25`. Använd `FQBN rp2040:rp2040:rpipico2w`. Vanlig `rpipico2` ger ingen LED-blink men UART/LoRa fungerar.

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
