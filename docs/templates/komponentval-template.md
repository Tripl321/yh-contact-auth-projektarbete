# Komponentval

## Dokumentinformation
- **Projekt**: SHALLOT
- **Dokument ID**: 03-komponentval
- **Författare**: Johannes Olerås
- **Datum**: 2026-09-05
- **Version**: 1.0

## Inledning
Detta dokument beskriver de valda hårdvaru- och mjukvarukomponenterna för SHALLOT-projektet, inklusive motivering för varje val.

## Systemöversikt
SHALLOT är ett säkert ID-bricka autentiseringsystem som använder LoRa P2P-kommunikation och HMAC-SHA256 utmanings-svar autentisering.

## Valda Komponenter

### 1. UNO Q - Air-gapped Provisioning Hub
- **Typ**: Arduino UNO Q
- **Processor**: STM32U585
- **Syfte**: Nyckelgenerering via hårdvaru-TRNG, säker nyckellagring, UART-nyckeldistribution
- **Motivering**: 
  - Hårdvaru-baserad TRNG för säkra nycklar
  - Minimal attackyta (air-gapped)
  - Fysisk entropi-källa
  - Pålitlig USB/Serial kommunikation

### 2. Edge Enforcement Node (PLC)
- **Huvudenhet**: Raspberry Pi Pico 2 (RP2350)
- **LoRa-modul**: Waveshare Core1262 (SX1262)
- **SPI-buss**: SPI1
- **Syfte**: Genererar 128-bit nonce, skickar utmaning via LoRa, verifierar HMAC-svar, fattar fail-closed autentiseringsbeslut
- **Motivering**:
  - RP2350 har hårdvaruaccelererad SHA-256
  - Core1262 ger pålitlig LoRa-kommunikation
  - Fail-closed arkitektur säkerställer säkerhet vid fel

### 3. PAW (ID-bricka)
- **Huvudenhet**: Adafruit Feather RP2350
- **LoRa-modul**: Waveshare Core1262 (SX1262)
- **Display**: Waveshare 1.54 inch e-Paper Module V2
- **SPI-bussar**: SPI0 (e-Paper), SPI1 (LoRa)
- **Syfte**: Mottar utmaning, beräknar HMAC, returnerar svar, visar autentiseringsstatus
- **Motivering**:
  - Kompakt formfaktor för bärbar enhet
  - e-Paper ger låg strömförbrukning och privatesskydd
  - Separata SPI-bussar undviker konflikter

## Pin-mappning

### Feather RP2350 (PAW)

#### Core1262 LoRa (SPI1)
| Funktion | GPIO | Anslutning |
|----------|------|-------------|
| SCK | 10 | SPI1 SCK |
| MOSI | 11 | SPI1 MOSI |
| MISO | 24 | SPI1 MISO |
| CS | 9 | SPI1 CS |
| RESET | 4 | Digital ut |
| BUSY | 7 | Digital in |
| DIO1 | 28 | Digital in/Interrupt |

#### e-Paper Display (SPI0)
| Funktion | GPIO | Anslutning |
|----------|------|-------------|
| DIN | 23 | SPI0 MOSI |
| CLK | 22 | SPI0 SCK |
| CS | 5 | SPI0 CS |
| DC | 26 | Digital ut |
| RST | 27 | Digital ut |
| BUSY | 29 | Digital in |

## Kostnadsanalys
| Komponent | Antal | Enhetspris (SEK) | Totalt (SEK) |
|-----------|-------|------------------|---------------|
| UNO Q | 1 | 500 | 500 |
| Pico 2 | 1 | 150 | 150 |
| Feather RP2350 | 1 | 200 | 200 |
| Core1262 | 2 | 200 | 400 |
| e-Paper | 1 | 300 | 300 |
| **Totalt** | | | **1550** |

## Säkerhetsaspekter
- TRNG: STM32U585 hårdvaru-TRNG för nyckelgenerering
- Nyckellagring: Nycklar lagras i RP2350-minne
- Kommunikation: LoRa P2P med AES-128 kryptering
- Autentisering: HMAC-SHA256 utmanings-svar protokoll
- Privacy: e-Paper visar endast abstrakt status

---
Dokument genererat: 2026-09-05
Version: 1.0
