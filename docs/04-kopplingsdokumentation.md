# Kopplingsdokumentation — SHALLOT

> Status: Ej paabörjad | Vecka: 1 | Linear: PRO-33

## 1. PAW (Portable Authentication Wearable)

### 1.1 Pin-tilldelning

| Funktion | GPIO | Komponent | Notering |
|----------|------|-----------|----------|
| SPI0 MOSI | GPIO23 | e-Paper MO | |
| SPI0 SCK | GPIO22 | e-Paper SCK | |
| e-Paper DC | GPIO5 | e-Paper D5 | |
| e-Paper CS | GPIO24 | e-Paper D24 | |
| e-Paper RST | GPIO25 | e-Paper D25 | |
| e-Paper BUSY | GPIO7 | e-Paper D7 | |
| SPI1 CS | GPIO10 | Core1262 D10 | |
| SPI1 MOSI | GPIO11 | Core1262 D11 | |
| SPI1 MISO | GPIO28 (A2) | Core1262 A2 | |
| SPI1 SCK | GPIO9 | Core1262 D9 | |
| Core1262 BUSY | GPIO6 | Core1262 D6 | |
| Core1262 RST | GPIO8 | Core1262 D8 | |
| Core1262 DIO1 | GPIO21 | Core1262 D21 | |

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
