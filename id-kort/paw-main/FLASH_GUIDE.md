# 🚀 Flashningsguide - PAW Firmware

## Snabbaste Metoden: Drag-and-Drop UF2 (Rekommenderad) ⭐

Feather RP2350 har en **inbyggd UF2 bootloader** som gör flashning så enkel som att dra och släpp en fil.

### Steg för Steg:

```
1. 📥 LADD NER UF2-FIL
   ├─ Från GitHub Releases: [paw-latest.uf2](https://github.com/Tripl321/yh-lora-auth-projektarbete/releases)
   └─ Eller bygg själv: ./build-uf2.sh

2. 🖱️  AKTIVERA BOOTLOADER
   ├─ Håll nere BOOTSEL-knappen på Feather
   ├─ Koppla in USB-kabeln
   └─ Släpp BOOTSEL-knappen
   
   → Enheten dyker upp som: RPI-RP2 (en USB-enhet)

3. 🗃️  DRAG AND DROP
   ├─ Dra paw-main.uf2 till RPI-RP2 enheten
   └─ Filen kopieras automatiskt

4. 🔄 AUTO-REBOOT
   → Enheten startar om med ny firmware (tar ~5 sekunder)
```

**✅ Klar!** PAW är nu flashad och redo att ta emot nyckel från UNO Q.

---

## Alternativ Metod 1: Arduino IDE

### Förberedelser:
1. Installera **Arduino IDE 2.x**
2. Lägg till **arduino-pico** board support:
   - File → Preferences → Additional Boards Manager URLs
   - Lägg till: `https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json`
   - OK → Tools → Board → Boards Manager
   - Sök efter "pico" och installera "Raspberry Pi Pico RP2040 Boards by Earle F. Philhower"

### Flasha:
1. Öppna `paw-main.ino` i Arduino IDE
2. Välj board: **Adafruit Feather RP2350**
3. Välj port: COMx (Feather)
4. Klicka **Upload** (→)
5. **Håll nere BOOTSEL** när Arduino säger "Uploading..." (om UF2-metoden används)

---

## Alternativ Metod 2: PlatformIO (Rekommenderad för utveckling)

### Förberedelser:
```bash
# Installera PlatformIO
pip install platformio

# Eller via VS Code extension
# Sök efter "PlatformIO" i Extensions
```

### Flasha:
```bash
# Navigera till paw-main mappen
cd id-kort/paw-main

# Bygg och flasha
pio run --target upload
```

**Fördelar med PlatformIO:**
- Bättre felhantering
- Bibliotekshantering
- Debugging support
- Multi-plattform

---

## Alternativ Metod 3: Kommandorad (Arduino CLI)

### Installera Arduino CLI:
```bash
# macOS (Homebrew)
brew install arduino-cli

# Linux
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/arduino/arduino-cli/releases/latest/download/arduino-cli_latest_Windows_64bit.zip" -OutFile "arduino-cli.zip"
Expand-Archive -Path "arduino-cli.zip" -DestinationPath "C:\Program Files\arduino-cli"
```

### Bygg och Flasha:
```bash
# Installera arduino-pico core
arduino-cli core update-index
arduino-cli core install arduino-pico:rp2040

# Bygg
arduino-cli compile --fqbn arduino-pico:rp2040:feather_rp2350 id-kort/paw-main/paw-main.ino

# Flasha (om UF2 genereras automatiskt)
# Eller använd: cp build/*.uf2 /Volumes/RPI-RP2/
```

---

## Felsökning

### Problem: Enheten dyker inte upp som RPI-RP2
- **Lösning 1**: Tryck BOOTSEL **innan** du kopplar in USB
- **Lösning 2**: Använd en annan USB-kabel (vissa är bara för ström)
- **Lösning 3**: Test på en annan dator

### Problem: UF2 filen kopieras men ingenting händer
- **Lösning**: Vänta 5-10 sekunder, enheten startar om automatiskt
- **Lösning**: Koppla ur och in USB-kabeln

### Problem: "Device not found" i Arduino IDE
- **Lösning**: Installera **CH340 driver** (om du använder klon)
- **Lösning**: Använd UF2-metoden istället

### Problem: Build error
```
# Vanliga orsaker:
- Saknar arduino-pico core → Installera via Boards Manager
- Fel board val → Välj "Adafruit Feather RP2350"
- Saknar bibliotek → Installera RadioLib om du använder riktig LoRa
```

---

## Verifiera Flashning

### 1. Serial Monitor
- Öppna Serial Monitor (115200 baud)
- Du bör se:
  ```
  ============================================
  SHALLOT PAW Main Firmware
  Hardware: Adafruit Feather RP2350
  ============================================
  [PRO-57] Initializing e-Paper...
  [PRO-58] Initializing LoRa...
  [PRO-48] Waiting for key distribution from UNO Q...
  ```

### 2. e-Paper Display
- Ska visa **AUTHENTICATING** ikon (3 punkter i triangel)
- Väntar på nyckel från UNO Q

### 3. LED Indikator
- **Snabb blinkning**: Väntar på nyckel
- **Långsam blinkning**: Nyckel mottagen, väntar på challenge
- **5 blinkningar**: Autentisering lyckades

---

## Automatiserad Build (CI/CD)

Projektet har **GitHub Actions** som automatiskt bygger UF2-filer:

- **Trigger**: Push till main branch
- **Output**: UF2-fil i GitHub Releases
- **Länk**: [https://github.com/Tripl321/yh-lora-auth-projektarbete/releases](https://github.com/Tripl321/yh-lora-auth-projektarbete/releases)

För att aktivera:
1. Gå till Actions tab i GitHub
2. Enable workflows
3. Push en ändring för att trigga build

---

## Snabbreferens

| Metod | Komplexitet | Kräver | Tid |
|-------|-------------|--------|------|
| **UF2 Drag-and-Drop** | ⭐⭐⭐⭐⭐ | Ingenting | 30s |
| **Arduino IDE** | ⭐⭐⭐ | Arduino IDE | 2min |
| **PlatformIO** | ⭐⭐⭐⭐ | VS Code + PlatformIO | 3min |
| **Arduino CLI** | ⭐⭐ | Terminal | 2min |

**💡 Tips: Använd UF2-metoden för snabbaste flashning!**
