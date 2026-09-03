# Komponentval — SHALLOT

> Status: Ej paabörjad | Vecka: 1 | Linear: PRO-32

## 1. Oeversikt

| Komponent | Tillverkare | Modell | Antal | Pris (SEK) | Motivering |
|-----------|------------|--------|-------|-----------|------------|
| PAW MCU | Adafruit | Feather RP2350 | 1 | | |
| LoRa-modul | Waveshare | Core1262-868M | 2 | | |
| e-Paper | Waveshare | 1.54 e-Paper V2 3-färg B/W/R (SSD1682) | 1 | | |
| Edge MCU | Raspberry Pi | Pico 2 (RP2350A) | 1 | | |
| Provisioner | Arduino | UNO Q | 1 | | |

## 2. Motivering per komponent

### 2.1 Adafruit Feather RP2350 (PAW)

(Detaljerad motivering tillkommer)

### 2.2 Waveshare Core1262-868M

(Detaljerad motivering tillkommer)

### 2.3 Waveshare 1.54 e-Paper

**3-färg B/W/R (GDEH0154Z90, styrenhet SSD1682), 200×200.**

Verifierad 2026-09-03 under bringup. Skärmen var först klassad som 2-färg B/W
(GDEY0154D67/SSD1681), men driver `GxEPD2_154_D67` visar ihållande röd bakgrund
eftersom röda planet (0x26) aldrig skrivs. Korrekt drivare är GxEPD2 3-färg
`GxEPD2_154_Z90c` (SSD1682) som alltid skriver röda planet till vitt.

- Full refresh-tid ~14 s (GxEPD2 `full_refresh_time = 14000 ms`).
- 4-line SPI (CS/DC/RST/BUSY + SCK/MOSI) på SPI0.
- PAW visar endast statusikoner (privacy): AUTHENTICATING (cirkel + 3 prickar),
  AUTHENTICATED (cirkel + bock), FAILED (cirkel + X). Ingen text, inga PII.
- Kräver minst 180 s mellan refreshes och full refresh minst 1 gång per 24 h
  (Waveshare rekommendation).

### 2.4 Raspberry Pi Pico 2 (Edge enforcement-nod)

(Detaljerad motivering tillkommer)

### 2.5 Arduino UNO Q (Provisioneringshubb)

(Detaljerad motivering tillkommer)

## 3. Budget

Total budget: 4000 SEK. All haardvara inkoeppt.

(Faktisk kostnadsredovisning tillkommer)
