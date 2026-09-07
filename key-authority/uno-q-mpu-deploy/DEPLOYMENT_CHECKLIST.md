# SHALLOT — UNO Q MPU Deployment Checklist

**Checklista för säker installation och verifiering av MPU (QRB2210 Linux)**

---

## 📋 Förberedelser

- [ ] **UNO Q Hårdvara** är ansluten och strömförsörjd
- [ ] **USB-anslutning** till host-dator fungerar
- [ ] **Linux-terminal** är tillgänglig på UNO Q MPU (via SSH eller direkt)
- [ ] **Root-åtkomst** eller sudo-rättigheter på UNO Q MPU
- [ ] **Arduino Bridge** är installerat på UNO Q MPU

---

## 🔧 Installation

### 1. Miljökrav

- [ ] **Python 3.7+** installerat
  ```bash
  python3 --version
  ```
- [ ] **pip3** installerat
  ```bash
  pip3 --version
  ```
- [ ] **Krävda Python-paket** installerade
  ```bash
  pip3 install pyserial msgpack
  ```
- [ ] **Arduino Bridge** installerat och körbart
  ```bash
  which ArduinoBridge
  ```

### 2. Konfiguration

- [ ] **Audit log-katalog** skapad
  ```bash
  ls -ld /home/user/shallot/audit
  ```
- [ ] **Konfigurationsfil** skapad
  ```bash
  ls -l /etc/shallot/shallot-mpu.conf
  ```
- [ ] **Bridge socket-sökväg** korrekt
  ```bash
  grep BRIDGE_SOCKET_PATH /etc/shallot/shallot-mpu.conf
  ```
- [ ] **Audit log-sökväg** korrekt och skrivbar
  ```bash
  grep AUDIT_LOG_DIR /etc/shallot/shallot-mpu.conf
  touch $(grep AUDIT_LOG_DIR /etc/shallot/shallot-mpu.conf | cut -d'=' -f2)/test.log
  ```

### 3. Installation av Skript och Tjänster

- [ ] **MPU-skript** kopierat till korrekt sökväg
  ```bash
  ls -l /home/user/shallot/key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py
  ```
- [ ] **Service-filer** kopierade till systemd
  ```bash
  ls -l /etc/systemd/system/shallot-mpu.service
  ls -l /etc/systemd/system/arduino-bridge.service
  ```
- [ ] **systemd** omladdad
  ```bash
  sudo systemctl daemon-reload
  ```
- [ ] **Tjänster aktiverade** (startas vid boot)
  ```bash
  sudo systemctl is-enabled shallot-mpu.service
  sudo systemctl is-enabled arduino-bridge.service
  ```
- [ ] **Tjänster startade**
  ```bash
  sudo systemctl is-active shallot-mpu.service
  sudo systemctl is-active arduino-bridge.service
  ```

---

## ✅ Verifiering

### 1. Bridge/RPC Verifiering

- [ ] **Bridge socket existerar**
  ```bash
  ls -l /var/run/arduino-router.sock
  ```
- [ ] **Bridge socket är tillgänglig**
  ```bash
  ./verify-bridge.sh quick
  ```
- [ ] **Arduino Bridge-process körs**
  ```bash
  pgrep -x ArduinoBridge
  ```
- [ ] **Full verifiering passerar**
  ```bash
  ./verify-bridge.sh
  ```

### 2. MPU Skript Verifiering

- [ ] **Skriptet körs** (som service eller manuellt)
  ```bash
  ps aux | grep uno-q-key-authority-mpu.py
  ```
- [ ] **Skriptet svarar på kommandon**
  ```bash
  # Om kört manuellt: testa i terminalen
  # Om kört som service: checka loggar
  journalctl -u shallot-mpu.service -n 20
  ```
- [ ] **Meny visas korrekt**
  ```
  SHALLOT UNO Q — Orchestration (MPU)
  ====================================
  0. Start provisioning session
  1. Generate key
  ...
  ```

---

## 🔒 Säkerhetsverifiering

### 1. Nyckelisolering

- [ ] **MCU hanterar alla nycklar** (aldrig MPU)
- [ ] **MPU ser endast hash/fingerprint** (aldrig klartext-nycklar)
- [ ] **Audit log innehåller endast hash** (aldrig nycklar)

### 2. Fysisk Säkerhet

- [ ] **Fysisk knapp krävs** för nyckeloperationer
- [ ] **Recovery code krävs** för session-start (≥16 alfanumeriska)
- [ ] **Ingen fjärråtkomst** till nyckeloperationer

### 3.Bridge RPC Säkerhet

- [ ] **Kommunikation via Unix socket** (inte nätverk)
- [ ] **Endast status/kommandon** skickas (aldrig nycklar)
- [ ] **Socket finns på säker plats** (`/var/run/arduino-router.sock`)

---

## 🎯 Provning (NP-01)

### Förberedelser

- [ ] **MCU firmware** är flashad och verifierad
  ```bash
  cd ../uno-q-mcu-deploy
  ./build.sh
  ./flash.sh
  ./verify-device.sh
  ```
- [ ] **PLC firmware** är flashad och fungerar
- [ ] **PAW firmware** är flashad och fungerar
- [ ] **Alla enheter** är anslutna till USB-hub

### NP-01 Flöde via MPU-Meny

| Steg | Kommando | Förväntat Resultat | ✅ | ❌ | Noteringar |
|------|----------|---------------------|---|---|------------|
| 1 | `0` + recovery code | Session startad | | | |
| 2 | `1` | Nyckel genererad, MCU ber om knapp | | | |
| 3 | Fysisk knapptryck | MCU bekräftar | | | |
| 4 | `4` | `Key state: GENERATED` | | | |
| 5 | `2` | Distribuerar till PLC, MCU ber om knapp | | | |
| 6 | Fysisk knapptryck | MCU bekräftar | | | |
| 7 | `4` | `Key state: DISTRIBUTED_PLC` | | | |
| 8 | `3` | Distribuerar till PAW, MCU ber om knapp | | | |
| 9 | Fysisk knapptryck | MCU bekräftar | | | |
| 10 | `4` | `Key state: DISTRIBUTED_BOTH` | | | |
| 11 | `6` | Validering OK | | | |
| 12 | `8` | Session avslutad | | | |

### Verifiering av Resultat

- [ ] **PLC** visar korrekt epoch och fingerprint
- [ ] **PAW** visar korrekt epoch och fingerprint
- [ ] **MCU** visar `Key state: DISTRIBUTED_BOTH`
- [ ] **MCU** visar `Active epoch: 1` (eller nästa)
- [ ] **Audit log** innehåller alla händelser
- [ ] **Inga nycklar** i loggar (endast hash)

---

## 📊 Efter Deployment

### 1. Säkerhetskopiering

- [ ] **Konfigurationsfil** säkerhetskopierad
  ```bash
  sudo cp /etc/shallot/shallot-mpu.conf /etc/shallot/shallot-mpu.conf.bak
  ```
- [ ] **Service-filer** säkerhetskopierade
  ```bash
  sudo cp /etc/systemd/system/shallot-mpu.service /etc/shallot/
  sudo cp /etc/systemd/system/arduino-bridge.service /etc/shallot/
  ```

### 2. Dokumentation

- [ ] **Deployment-datum** dokumenterat
- [ ] **Versioner** dokumenterade (MCU firmware, MPU script)
- [ ] **Checklista** arkiverad
- [ ] **Eventuella avvikelser** dokumenterade

---

## 🚨 Avbrottskriterier

**AVBRYT OCH RAPPORTERA om något av följande inträffar:**

- [ ] **Enhetsidentitet** kan inte verifieras
- [ ] **Bridge socket** saknas eller är otillgänglig
- [ ] **MCU firmware** svarar inte på kommandon
- [ ] **PLC/PAW** svarar inte på USB-distribution
- [ ] **Nycklar** visas i loggar (säkerhetsbrott)
- [ ] **Oväntade fel** uppstår under provisionering
- [ ] **Timeout** på mer än 30 sekunder för något steg

---

## 📝 Signering

| Namn | Roll | Datum | Signatur |
|------|------|-------|----------|
| | | | |
| | | | |

---

## 📚 Referenser

- [MCU Deployment](../uno-q-mcu-deploy/) — MCU firmware deployment
- [MPU Script](../../uno-q-key-authority-mpu/uno-q-key-authority-mpu.py) — Källkod
- [Testplan](../../../docs/13-usb-provisionering-testplan.md) — NP-01 specifikation
- [Arduino UNO Q Dokumentation](https://docs.arduino.cc/hardware/uno-q)

---

*Generated for SHALLOT project*
