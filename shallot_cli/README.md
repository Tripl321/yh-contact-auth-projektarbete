# SHALLOT CLI

CLI-verktyg för att synkronisera och flasha SHALLOT-firmware till PAW, PLC och UNO Q.

## Installation

```bash
# Gå till repo-roten
cd /path/to/yh-lora-auth-projektarbete

# Installera paketet i editable-läge
pip install -e ./shallot_cli

# Kontrollera att det funkar
shallot --version
```

## Användning

### Interaktiv meny (pilknappar)
```bash
shallot
```
Välj med piltangenterna och tryck Enter.

### Synkronisera skisser till Arduino sketchbook
```bash
shallot sync          # alla komponenter
shallot sync paw      # endast PAW
shallot sync plc      # endast PLC
shallot sync unoq     # endast UNO Q
```

### Kompilera och flasha
```bash
shallot flash paw
shallot flash plc
shallot flash unoq
```

### Lista anslutna boards
```bash
shallot list
```

### Visa senaste status
```bash
shallot status
```

## Miljövariabler

| Variabel | Beskrivning | Default |
|----------|--------------|---------|
| `SHALLOT_REPO_DIR` | Sökväg till git-repot | `~/projects/yh-lora-auth` |
| `SHALLOT_SKETCHBOOK` | Arduino sketchbook | `~/Documents/Arduino` |
| `SHALLOT_BRANCH` | Branch att checka ut | `vibe/paw-line-corruption-fix-bf5bdb` (eller `main`) |
| `SHALLOT_PORT` | Explicit seriell port | auto-detekterad |

## Statusrapportering

CLI:n skriver en `status.json` till repo-roten med information om varje synk/kompilering/flash-operation. Du måste committa och pusha denna fil för att göra den synlig för Vibe-agenten.

```json
[
  {
    "timestamp": "2025-01-15T14:30:00+00:00",
    "component": "paw",
    "stage": "flash",
    "ok": true,
    "detail": "flashad",
    "branch": "vibe/paw-line-corruption-fix-bf5bdb"
  }
]
```

## Krav

- Python 3.9+
- git
- arduino-cli (installeras automatiskt via Homebrew om saknas)
- Relevant board-core för din target (installeras automatiskt)

### macOS
```bash
# Installera beroenden
xcode-select --install  # för git
brew install arduino-cli
```

### Linux (Ubuntu/Debian)
```bash
# Installera beroenden
sudo apt install git python3 python3-pip
# arduino-cli kan hämtas från https://arduino.github.io/arduino-cli/
```

## Komponenter

| Key | Namn | Board | FQBN |
|-----|------|-------|------|
| paw | PAW | Adafruit Feather RP2350 | `arduino-pico:rp2040:adafruit_feather_rp2350_hstx` |
| plc | PLC | Raspberry Pi Pico 2 | `arduino-pico:rp2040:rpipico2` |
| unoq | UNO Q | Arduino UNO Q | `arduino:zephyr:arduino_uno_q_stm32u585xx` |
