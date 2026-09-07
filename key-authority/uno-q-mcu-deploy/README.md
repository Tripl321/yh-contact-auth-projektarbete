# SHALLOT — UNO Q MCU Deployment

**Säker, reproducerbar deployment för Arduino UNO Q MCU (STM32U585)**

## Arkitektur

```
┌─────────────────────────────────────────┐
│         UNO Q (MAMA BEAR)                │
│  ┌─────────────┐    ┌─────────────┐     │
│  │  STM32U585  │    │   QRB2210   │     │
│  │   MCU       │◄───►│   MPU       │     │
│  │  (Zephyr)   │    │  (Linux)    │     │
│  └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────┘
              │
         USB CDC @ 115200 baud
              ▼
    ┌─────────────────────┐
    │   Host Dator        │
    │  (build & flash)    │
    └─────────────────────┘
```

---

## 📁 Filer

| Fil | Syfte | CI-säker |
|-----|--------|----------|
| [`build.sh`](build.sh) | Bygg firmware | ✅ Ja |
| [`flash.sh`](flash.sh) | Flasha till enhet | ❌ Nej (abort i CI) |
| [`verify-device.sh`](verify-device.sh) | Verifiera enhetsidentitet | ✅ Ja |

---

## 🔧 Användning

### 1. Bygg firmware (CI-säker)

```bash
# Bygg med standardinställningar
./build.sh

# Rensa byggartefakter
./build.sh clean

# Visa hjälp
./build.sh help
```

**Output:**
- `build/uno-q-key-authority-mcu.hex` — HEX-fil för flashning
- `build/uno-q-key-authority-mcu.elf` — ELF-fil för debug

---

### 2. Flasha firmware (Kräver bekräftelse)

```bash
# Interaktiv flashning
./flash.sh

# Visa hjälp
./flash.sh help
```

**Säkerhetsåtgärder:**
- ❌ **Körs aldrig i CI** (avbryts omedelbart)
- ✅ Kräver **explicit bekräftelse** (skriv "FLASH")
- ✅ **Dynamisk enhetsdetektering** (hittar UNO Q automatiskt)
- ✅ **Verifierar enhetsidentitet** ("UNO Q" i board-info)
- ✅ **Verifierar boot-banner** (115200 baud)

**Flöde:**
1. Hittar alla seriella enheter
2. Detekterar UNO Q (om arduino-cli finns)
3. Begär **explicit bekräftelse** ("FLASH")
4. Flashar firmware med `arduino-cli upload`
5. Väntar 5s på omstart
6. Verifierar boot-banner

---

### 3. Verifiera enhetsidentitet

```bash
# Auto-detektering
./verify-device.sh

# Specifik enhet
./verify-device.sh /dev/cu.usbmodem27559688122

# Visa hjälp
./verify-device.sh help
```

**Verifiering:**
- ✅ Kontrollerar **boot-banner** ("SHALLOT — UNO Q Key Authority")
- ✅ Kontrollerar **enhetsstatus** ("Key state: UNINITIALIZED")
- ❌ **Avbryter** med exit code 1 vid osäker identitet

---

## 🔒 Säkerhetsprinciper

### 1. CI-Säkerhet
- **Build** tillåts i CI (skapar HEX/ELF)
- **Flash** avbryts **omedelbart** i CI
- Miljövariabler detekteras: `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`

### 2. Användarbekräftelse
- Flashning kräver **explicit** bekräftelse
- Användaren måste skriva **"FLASH"** (exakt match)
- All annat avbryter

### 3. Enhetsverifiering
- Kontrollerar **boot-banner** för korrekt enhet
- Kontrollerar **enhetsnamn** via `arduino-cli`
- **Avbryter** vid osäker identitet

### 4. Dynamisk enhetsdetektering
- Hittar alla seriella enheter automatiskt
- Detekterar UNO Q via board-info (macOS/Linux)
- Manual urval möjligt

---

## 📊 Miljövariabler

| Variabel | Beskrivning | Standard |
|----------|-------------|----------|
| `CI` | CI-miljö (abort flash) | - |
| `GITHUB_ACTIONS` | GitHub Actions (abort flash) | - |
| `GITLAB_CI` | GitLab CI (abort flash) | - |

---

## 🧪 CI-Integration

### GitHub Actions Example

```yaml
name: Build UNO Q MCU

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Arduino CLI
        run: |
          curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
          echo "$HOME/bin" >> $GITHUB_PATH
      
      - name: Build firmware
        run: cd key-authority/uno-q-mcu-deploy && ./build.sh
      
      # Flashing is NEVER done in CI
      # - ./flash.sh would abort immediately
```

---

## 📋 Build- & Flash-checklista

### ⬜ För bygg (CI)
- [ ] `arduino-cli` installerad
- [ ] `arduino:zephyr` plattform installerad
- [ ] `prj.conf` finns i sketch-mappen
- [ ] Bibliotek `ShallotLoRa` finns
- [ ] Bygg lyckas utan fel
- [ ] HEX-fil skapas

### ⬜ För flash (Lokal)
- [ ] Enhet **fysiskt ansluten** via USB
- [ ] Korrekt USB-enhet valdes
- [ ] **Explicit bekräftelse** given ("FLASH")
- [ ] Flashning lyckades
- [ ] Boot-banner verifierad
- [ ] Enhetsidentitet bekräftad

---

## 🔍 Felsökning

### Bygg misslyckas
```bash
# Installera Zephyr-plattformen
arduino-cli core install arduino:zephyr

# Verifiera prj.conf
ls -l key-authority/uno-q-key-authority-mcu/prj.conf

# Full build-log
cd key-authority/uno-q-mcu-deploy
./build.sh 2>&1 | tee build.log
```

### Enhet hittas inte
```bash
# Kontrollera anslutna enheter (macOS)
ls /dev/cu.usbmodem*

# Kontrollera anslutna enheter (Linux)
ls /dev/ttyACM* /dev/ttyUSB*

# Installera arduino-cli för bättre detektering
arduino-cli board list
```

### Flash misslyckas
```bash
# Verifiera att HEX-fil existerar
ls -l build/uno-q-key-authority-mcu.hex

# Verifiera enhetsidentitet före flash
./verify-device.sh

# Testa manuell flashning
arduino-cli upload -p /dev/cu.usbmodemXXXX -b arduino:zephyr:unoq -i build/uno-q-key-authority-mcu.hex
```

---

## 📚 Se även

- [MCU Firmware](../../uno-q-key-authority-mcu/) — Källkod
- [prj.conf](../../uno-q-key-authority-mcu/prj.conf) — TRNG-konfiguration
- [MPU Deployment](../uno-q-mpu-deploy/) — MPU-installation
- [Testplan](../../../docs/13-usb-provisionering-testplan.md) — NP-01 test

---

## 📜 License

Som övriga repo.

---

*Generated for SHALLOT project*
