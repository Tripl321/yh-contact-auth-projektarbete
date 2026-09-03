# Kopplingsdokumentation — SHALLOT

> Status: Uppdaterad 2026-09-03 — matchar kod (paw-main.ino / plc-key-receiver.ino) | Vecka: 1 | Linear: PRO-33

## 1. PAW (Portable Authentication Wearable)

### 1.1 Pin-tilldelning

| Funktion | GPIO | Komponent | Notering |
|----------|------|-----------|----------|
| SPI0 MOSI | GPIO23 | e-Paper MO | Feather MO, SPI0 MOSI |
| SPI0 SCK | GPIO22 | e-Paper SCK | Feather SCK, SPI0 SCK |
| e-Paper CS | GPIO5 | e-Paper CS | Feather pin 5 — **rätt, tidigare felaktigt D24 i doc** |
| e-Paper DC | GPIO26 (A0) | e-Paper DC | Feather A0 — **rätt, tidigare GPIO5 i doc** |
| e-Paper RST | GPIO27 (A1) | e-Paper RST | Feather A1 — **rätt, tidigare GPIO25 i doc** |
| e-Paper BUSY | GPIO25 (D25) | e-Paper BUSY | Feather D25 — **flyttad 2026-09-03 från A3 (upptagen) till ledig pin 25 per breadboard** |
| SPI1 CS | GPIO9 | Core1262 CS | Feather D9 |
| SPI1 MOSI | GPIO11 | Core1262 MOSI | Feather D11 |
| SPI1 MISO | GPIO24 (D24) | Core1262 MISO | Feather D24 — **hårdvaru-SPI1 MISO, tidigare felaktigt GPIO28/A2 i doc** |
| SPI1 SCK | GPIO10 | Core1262 SCK | Feather D10 — **rätt, tidigare felaktigt GPIO9 i doc** |
| Core1262 BUSY | GPIO7 | Core1262 BUSY | Feather pin 7 — **rätt, tidigare GPIO6 i doc** |
| Core1262 RST | GPIO4 | Core1262 RESET | Feather pin 4 — **rätt, tidigare GPIO8 i doc** |
| Core1262 DIO1 | GPIO28 (A2) | Core1262 DIO1 | Feather A2 — **rätt, tidigare GPIO21 i doc** |

### 1.2 SPI-bussar

- SPI0: e-Paper
- SPI1: Core1262

## 2. Edge enforcement-nod

### 2.1 Pin-tilldelning

| Funktion | GP | Komponent | Notering |
|----------|-----|-----------|----------|
| SPI1 SCK | GP10 | Core1262 CLK | |
| SPI1 MOSI | GP11 | Core1262 MOSI | |
| SPI1 MISO | GP12 | Core1262 MISO | |
| SPI1 CS | GP9 | Core1262 CS | |
| Core1262 BUSY | GP6 | Core1262 BUSY | |
| Core1262 RST | GP8 | Core1262 RESET | |
| Core1262 DIO1 | GP21 | Core1262 DIO1 | |

### 2.2 SPI-bussar

- SPI1: Core1262

## 3. Provisioneringshubb (UNO Q)

USB-anslutning till PAW och edge enforcement-nod foer nyckeldistribution. Inga SPI-kopplingar.

## 4. Fysisk montering

(Fotografier av breadboards tillkommer i docs/assets/photos/)
