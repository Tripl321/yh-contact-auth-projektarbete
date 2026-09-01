# ID-kort (Feather RP2350 + Core1262-868M + e-Paper)

Firmware for ID-kort-noden: Adafruit Feather RP2350 med Core1262-868M och 1.54" Waveshare e-Paper.

## Ansvar

- Ta emot challenge (nonce) fran PLC over LoRa P2P
- Berakna HMAC-SHA256(nyckel, nonce) och returnera svar
- Visa status pa e-Paper-display

## Repositoriestruktur

```
id-kort/
├── README.md                    # Detta dokument
├── paw-main/                    # **Huvud-firmware (flasha denna!)**
│   ├── paw-main.ino             # Kombinerad firmware
│   ├── README.md                # Flashningsinstruktioner
│   └── platformio.ini           # PlatformIO-konfiguration
├── paw-key-receiver/           # PRO-48: Nyckelmottagning (referens)
│   └── paw-key-receiver.ino
└── epaper-status-display/      # PRO-57: e-Paper driver (referens)
    └── epaper-status-display.ino
```

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

## Pin-tilldelning -- UART till UNO Q

| Feather | UNO Q |
|---|---|
| GP0 (TX) | Serial1 RX |
| GP1 (RX) | Serial1 TX |

## Bibliotek

- **arduino-pico** (earlephilhower) - RP2350 karnan
- **RadioLib** (jgromes) - for SX1262 LoRa (när du ersätter mock-implementationen)

## Flasha PAW

Se [paw-main/README.md](paw-main/README.md) för detaljerade instruktioner.

### Snabbstart med Arduino IDE:

1. Installera `arduino-pico` board support
2. Välj board: **Adafruit Feather RP2350**
3. Öppna `paw-main/paw-main.ino`
4. Klicka **Upload** (håll BOOTSEL om UF2 krävs)

### Snabbstart med PlatformIO:

```bash
cd id-kort/paw-main
pio run --target upload
```
