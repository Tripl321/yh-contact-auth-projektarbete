# PlatformIO Setup Guide for Adafruit Feather RP2350

## Problem

Du får felet:
```
UnknownBoard: Unknown board ID 'feather_rp2350'
```

Detta beror på att **Adafruit Feather RP2350 ännu inte är officiellt stött** i standard PlatformIO raspberrypi-plattformen.

---

## 🔧 Lösning 1: Använd Raspberry Pi Pico 2 (Rekommenderad)

Raspberry Pi Pico 2 använder **samma RP2350 chip** som Feather RP2350, så du kan använda den som bas.

### Steg:

1. **Installera PlatformIO** (om inte redan gjort):
   ```bash
   pip install platformio
   ```

2. **Installera raspberrypi plattformen:**
   ```bash
   pio platform install raspberrypi
   pio platform update raspberrypi
   ```

3. **Använd Pico 2 board:**
   ```bash
   cd id-kort/paw-main
   
   # Bygg med Pico 2 (RP2350)
   pio run -e raspberry_pi_pico2
   
   # Eller uppdatera platformio.ini att använda:
   # board = raspberry_pi_pico2
   ```

4. **Flasha:**
   ```bash
   pio run -e raspberry_pi_pico2 -t upload
   ```

---

## 🔧 Lösning 2: Använd earlephilhower's Platform (Bäst för RP2350)

Earle Philhower underhåller den **bästa RP2040/RP2350 stödet**.

### Steg:

1. **Installera earlephilhower's plattform:**
   ```bash
   pio platform install https://github.com/earlephilhower/platform-raspberrypi.git
   ```

2. **Uppdatera `platformio.ini`:**
   ```ini
   [env:feather_rp2350]
   platform = https://github.com/earlephilhower/platform-raspberrypi.git
   board = feather_rp2350
   framework = arduino
   monitor_speed = 115200
   upload_protocol = uf2
   
   build_flags =
       -DARDUINO_USB_CDC_ONLY
   ```

3. **Bygg och flasha:**
   ```bash
   pio run -t upload
   ```

---

## 🔧 Lösning 3: Lägg till Feather RP2350 som Custom Board

Om du vill använda exakt `feather_rp2350` som board-ID:

### Steg:

1. **Skapa en custom board definition:**
   ```bash
   mkdir -p ~/.platformio/platforms/raspberrypi
   cd ~/.platformio/platforms/raspberrypi
   git clone https://github.com/earlephilhower/platform-raspberrypi.git .
   ```

2. **Eller lägg till i ditt projekt:**
   ```bash
   cd id-kort/paw-main
   mkdir -p .pio/platforms
   cd .pio/platforms
   git clone https://github.com/earlephilhower/platform-raspberrypi.git raspberrypi
   ```

3. **Använd feather_rp2350:**
   ```ini
   [env:feather_rp2350]
   platform = raspberrypi
   board = feather_rp2350
   framework = arduino
   ```

---

## 🔧 Lösning 4: Använd Arduino IDE istället (Snabbaste)

Om du vill undvika PlatformIO-konfiguration:

### Steg:

1. **Installera Arduino IDE 2.x**
2. **Lägg till arduino-pico URL:**
   - File → Preferences → Additional Boards Manager URLs
   - Lägg till: `https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json`
3. **Installera board support:**
   - Tools → Board → Boards Manager
   - Sök "pico" → Installera "Raspberry Pi Pico RP2040 Boards"
4. **Välj board:**
   - Tools → Board → Adafruit Feather RP2350
5. **Öppna och flasha:**
   - Öppna `paw-main.ino`
   - Klicka Upload

---

## 📋 Sammanfattning: Vad ska du göra?

| Lösning | Komplexitet | Rekommenderad för | Notering |
|---------|-------------|-------------------|----------|
| **Lösning 1: Pico 2** | ⭐⭐ | Snabb test | Använder standard PlatformIO |
| **Lösning 2: earlephilhower** | ⭐⭐⭐ | Bäst RP2350 stöd | Kräver custom plattform |
| **Lösning 3: Custom board** | ⭐⭐⭐⭐ | Avancerade | Full kontroll |
| **Lösning 4: Arduino IDE** | ⭐ | Nybörjare | Enklast |

---

## 🎯 Rekommendation

**För snabbaste lösning:** Använd **Lösning 4 (Arduino IDE)** - den fungerar direkt med Feather RP2350.

**För PlatformIO:** Använd **Lösning 1 (Pico 2)** - den är enklast och fungerar med standard PlatformIO.

---

## 🔗 Användbara kommandon

```bash
# Lista alla tillgängliga boards
pio boards

# Sök efter RP2350 boards
pio boards | grep -i "rp2350\|pico2"

# Installera specifik plattform
pio platform install raspberrypi
pio platform update raspberrypi

# Bygg för specifikt board
pio run -e raspberry_pi_pico2

# Flasha
pio run -e raspberry_pi_pico2 -t upload

# Monitor
pio run -e raspberry_pi_pico2 -t monitor
```

---

## ❓ Vanliga problem

### "Unknown board ID 'feather_rp2350'"
- **Orsak:** Standard PlatformIO känner inte till Feather RP2350
- **Lösning:** Använd `raspberry_pi_pico2` istället, eller installera earlephilhower's plattform

### "Platform not found"
- **Orsak:** raspberrypi plattformen är inte installerad
- **Lösning:** `pio platform install raspberrypi`

### "Board not supported"
- **Orsak:** För gammal PlatformIO version
- **Lösning:** `pip install --upgrade platformio`

---

## 📚 Resurser

- [PlatformIO Documentation](https://docs.platformio.org/)
- [earlephilhower/arduino-pico](https://github.com/earlephilhower/arduino-pico)
- [earlephilhower/platform-raspberrypi](https://github.com/earlephilhower/platform-raspberrypi)
- [Adafruit Feather RP2350](https://www.adafruit.com/product/5723)
