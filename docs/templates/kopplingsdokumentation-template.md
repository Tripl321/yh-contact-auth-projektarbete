# Kopplingsdokumentation

## Dokumentinformation
- **Projekt**: SHALLOT
- **Dokument ID**: 04-kopplingsdokumentation
- **Författare**: Johannes Olerås
- **Datum**: 2026-09-05
- **Version**: 1.0

## Inledning
Detta dokument beskriver den fysiska och logiska kopplingen mellan systemets komponenter.

## Systemarkitektur

UNO Q (Provisioning) <--> Edge Enforcement Node (PLC) <--> PAW (ID-bricka)

## Fysiska Anslutningar

### 1. UNO Q Koppling
- USB: Ansluts till edge node och PAW för nyckeldistribution
- Strömförsörjning: USB-C eller extern 5V
- Debug: Serial via USB (D0/D1)

### 2. Edge Enforcement Node (Pico 2) Koppling

#### LoRa Core1262 (SPI1)
- SCK (GPIO 10) -> Core1262 SCK
- MOSI (GPIO 11) -> Core1262 MOSI
- MISO (GPIO 24) -> Core1262 MISO
- CS (GPIO 9) -> Core1262 CS
- RESET -> Core1262 RESET
- BUSY -> Core1262 BUSY
- DIO1 (GPIO 28) -> Core1262 DIO1

### 3. PAW (Feather RP2350) Koppling

#### LoRa Core1262 (SPI1)
- SCK (GPIO 10) -> Core1262 SCK
- MOSI (GPIO 11) -> Core1262 MOSI
- MISO (GPIO 24) -> Core1262 MISO
- CS (GPIO 9) -> Core1262 CS
- RESET (GPIO 4) -> Core1262 RESET
- BUSY (GPIO 7) -> Core1262 BUSY
- DIO1 (GPIO 28) -> Core1262 DIO1

#### e-Paper Display (SPI0)
- DIN (GPIO 23) -> e-Paper DIN
- CLK (GPIO 22) -> e-Paper CLK
- CS (GPIO 5) -> e-Paper CS
- DC (GPIO 26) -> e-Paper DC
- RST (GPIO 27) -> e-Paper RST
- BUSY (GPIO 29) -> e-Paper BUSY

## Kommunikationsflöde

1. Provisionering (UNO Q -> Edge/PAW): USB nyckeldistribution
2. Autentisering (Edge <-> PAW): LoRa utmaning/svar

## Felsökningsguide

### LoRa Kommunikation Fel
- Verifiera SPI-anslutningar
- Kontrollera RadioLib-konfiguration
- Testa med kort avstånd

### Nyckeldistribution Fel
- Verifiera USB-anslutning
- Kontrollera Serial baud rate
- Testa med annan USB-kabel

### e-Paper Display Fel
- Verifiera SPI0-anslutningar
- Kontrollera CS, DC, RST pins
- Testa med minimalt kod-exempel

---
Dokument genererat: 2026-09-05
Version: 1.0
