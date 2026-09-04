# SHALLOT — Sync & Flash

Ett skript som hämtar senaste `.ino`-filerna från GitHub-repot, lägger dem i din
Arduino-sketchbook, kompilerar och flashar — allt i ett steg.

Löser flaskhalsen där ändringar i repot inte hamnar i din lokala
Arduino-mapp automatiskt.

## Snabbstart (macOS)

```bash
# Från repots rot:
chmod +x scripts/sync-and-flash.sh

# Interaktivt — välj komponent:
./scripts/sync-and-flash.sh

# Eller direkt:
./scripts/sync-and-flash.sh paw    # PAW (Feather RP2350)
./scripts/sync-and-flash.sh plc    # PLC (Pico 2)
./scripts/sync-and-flash.sh unoq   # UNO Q (STM32U585)
./scripts/sync-and-flash.sh sync   # bara synka, ingen flashning
```

## Vad skriptet gör

1. **Klonar/uppdaterar repot** till `~/projects/yh-lora-auth` (kan överstyras)
2. **Väljer branch automatiskt** — föredrar `vibe/paw-line-corruption-fix-bf5bdb`
   om den finns, annars `main`
3. **Kopierar .ino-filerna** till `~/Documents/Arduino/<sketchnamn>/`
   (prj.conf för UNO Q följer med)
4. **Installerar arduino-cli** via Homebrew om det saknas
5. **Installerar rätt board-core** (arduino-pico för PAW/PLC, zephyr för UNO Q)
6. **Kompilerar** skissen med rätt FQBN
7. **Flashar** till första hittade USB-port

## Krav

- **git** (finns på macOS med Xcode Command Line Tools)
- **arduino-cli** — installeras automatiskt via Homebrew om det saknas
  (Homebrew installeras från https://brew.sh om det inte finns)
- **Arduino IDE 2.x** rekommenderas installerat (för dess board-paket och drivrutiner)

## Konfiguration (miljövariabler)

| Variabel | Default | Beskrivning |
|----------|---------|-------------|
| `SHALLOT_REPO_DIR` | `~/projects/yh-lora-auth` | Var git-klonen ligger |
| `SHALLOT_SKETCHBOOK` | `~/Documents/Arduino` | Arduino sketchbook-mapp |
| `SHALLOT_BRANCH` | auto | Tvinga en specifik branch |
| `SHALLOT_PORT` | auto-detektera | Tvinga en specifik USB-port |

Exempel — egen repo-plats och explicit port:
```bash
SHALLOT_REPO_DIR=~/code/shallot \
SHALLOT_PORT=/dev/cu.usbmodem14301 \
./scripts/sync-and-flash.sh paw
```

## Komponent → Board-mappning

| Komponent | FQBN | Core |
|-----------|------|------|
| PAW | `rp2040:rp2040:adafruit_feather_rp2350_hstx` | rp2040:rp2040 |
| PLC | `rp2040:rp2040:rpipico2w` (Pico 2 W, CYW43 LED) / `rpipico2` (plain Pico 2) | rp2040:rp2040 |
| UNO Q | `arduino:zephyr:unoq` | arduino:zephyr |

FQBN-värdena är verifierade: UNO Q via `arduino-cli board list` på `MamaBear.local` (`arduino:zephyr:unoq`), RP2350 via Earle Philhower `rp2040:rp2040` core. PLC noterad som Pico 2 W därför `rpipico2w` (LED CYW43 pin 64) annars `rpipico2`.

## Felsökning

### "Ingen ansluten board hittades"
Anslut komponenten via USB och kör igen, eller sätt port explicit:
```bash
SHALLOT_PORT=/dev/cu.usbmodem14301 ./scripts/sync-and-flash.sh paw
```
Lista tillgängliga portar med `arduino-cli board list`.

### "Homebrew är inte installerat"
Installera från https://brew.sh, kör sedan skriptet igen.

### Pico-boards (PAW/PLC) dyker inte upp
- Håll **BOOTSEL** intryckt när du kopplar in USB (UF2-bootloader-läge)
- För normal flashning via arduino-cli behövs ingen BOOTSEL — drivrutiner
  från Arduino IDE-installationen gör att boarden syns som serial-port

### UNO Q — "Please install Arduino_RouterBridge library"
Skriptet installerar nu `Arduino_RouterBridge` automatiskt. Om manuellt behövs:
```bash
arduino-cli lib install Arduino_RouterBridge
```

### Jag vill bara synka, inte flasha
```bash
./scripts/sync-and-flash.sh sync
```

## Varför detta skript behövs

Git-klonen i VSCodium och Arduino-sketchbooken är två separata platser.
Arduino IDE:s inbyggda sync hämtar inte ändringar från ett godtyckligt
GitHub-repo till din sketchbook. Detta skript bygger bron: repo → sketchbook → board.
