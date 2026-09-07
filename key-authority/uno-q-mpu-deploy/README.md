# SHALLOT — UNO Q MPU Deployment

**Säker installation av orchestrator-skript för Arduino UNO Q MPU (QRB2210 Linux)**

---

## 📁 Arkitektur

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
         Bridge RPC (Unix Socket)
         /var/run/arduino-router.sock
              │
    ┌─────────────────────┐
    │  uno-q-key-authority-│
    │     mpu.py          │
    │  (Orchestrator)      │
    └─────────────────────┘
```

---

## 🎯 Syfte

MPU-skriptet (`uno-q-key-authority-mpu.py`) ansvarar för:

| Funktion | Beskrivning | Säkerhetsnivå |
|----------|-------------|---------------|
| Orchestration | Hanterar nyckelgenerering och distribution | aldrig hanterar nyckelmaterial |
| Audit Log | Lagrar alla provisioneringshändelser | endas hash-värden |
| Validation | Verifierar korrekt provisionering | jämför fingerprint |
| FIDO2 | Hanterar session-credentials | placeholder (utökas senare) |

---

## 📁 Filstruktur

```
key-authority/uno-q-mpu-deploy/
├── README.md                  # Denna fil
├── install.sh                 # Installationsskript
├── verify-bridge.sh           # Verifiera Bridge/RPC
├── DEPLOYMENT_CHECKLIST.md    # Checklista för deployment
├── config/
│   └── shallot-mpu.conf       # Konfiguration (exempel)
└── service/
    ├── shallot-mpu.service    # systemd service
    └── arduino-bridge.service # Arduino Bridge service
```

---

## 🔧 Installation

### 1. Förutsättningar

#### På UNO Q MPU (Linux):
- Debian-baserat system (QRB2210)
- Python 3.7+
- `pip` installerat
- `screen` eller `python3-serial` för seriell kommunikation
- Root-åtkomst för service-installation

#### Krävda Python-paket:
```bash
# Installera beroenden
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# Installera krävda paket
pip3 install pyserial msgpack fido2
```

#### Arduino Bridge:
Arduino Bridge skall finnas förinstallerat på UNO Q. Verifiera med:
```bash
ls -l /var/run/arduino-router.sock
```

Om socket saknas, se [Arduino Bridge Service](#arduino-bridge-service).

---

### 2. Konfiguration

#### Miljövariabler (valfria)

| Variabel | Beskrivning | Standard |
|----------|-------------|----------|
| `AUDIT_LOG_PATH` | Sökväg för audit-log | `/home/user/shallot/audit/provisioning_log.jsonl` |
| `BRIDGE_SOCKET_PATH` | Socket för Bridge RPC | `/var/run/arduino-router.sock` |
| `FIDO2_AVAILABLE` | Aktivera FIDO2-stöd | `False` (placeholder) |

#### Konfigurationsfil

Skapa `/etc/shallot/shallot-mpu.conf` (eller valfri sökväg):

```ini
# Audit log konfiguration
AUDIT_LOG_DIR=/home/user/shallot/audit
AUDIT_LOG_FILE=$AUDIT_LOG_DIR/provisioning_log.jsonl

# Bridge RPC konfiguration
BRIDGE_SOCKET_PATH=/var/run/arduino-router.sock

# Recovery code konfiguration
RECOVERY_CODE_PEPPER=shallot_recovery_pepper_2026
```

---

### 3. Installation

#### Metod A: Manuell installation (för test)

```bash
# 1. Kopiera skript till UNO Q
scp uno-q-key-authority-mpu.py user@uno-q-ip:/home/user/shallot/key-authority/uno-q-key-authority-mpu/

# 2. Starta skript manuellt
cd /home/user/shallot/key-authority/uno-q-key-authority-mpu
python3 uno-q-key-authority-mpu.py
```

#### Metod B: Service-installation (rekommenderat för produktion)

```bash
# 1. Kopiera service-filer
sudo cp service/shallot-mpu.service /etc/systemd/system/
sudo cp service/arduino-bridge.service /etc/systemd/system/

# 2. Ladda om systemd
sudo systemctl daemon-reload

# 3. Aktivera tjänster
sudo systemctl enable shallot-mpu.service
sudo systemctl enable arduino-bridge.service

# 4. Starta tjänster
sudo systemctl start arduino-bridge.service
sudo systemctl start shallot-mpu.service

# 5. Verifiera
systemctl status shallot-mpu.service
systemctl status arduino-bridge.service
```

---

## 📋 service/arduino-bridge.service

```ini
[Unit]
Description=Arduino Bridge RPC Socket
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/ArduinoBridge
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 📋 service/shallot-mpu.service

```ini
[Unit]
Description=SHALLOT MPU Orchestration Service
After=network.target arduino-bridge.service
Requires=arduino-bridge.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/user/shallot/key-authority/uno-q-key-authority-mpu
ExecStart=/usr/bin/python3 /home/user/shallot/key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
EnvironmentFile=/etc/shallot/shallot-mpu.conf

[Install]
WantedBy=multi-user.target
```

---

## ✅ Verifiering

Kör verifieringsskriptet för att kontrollera att Bridge/RPC fungerar:

```bash
./verify-bridge.sh
```

Eller manuellt:

```bash
# 1. Kontrollera socket
ls -l /var/run/arduino-router.sock

# 2. Kontrollera service-status
systemctl status shallot-mpu.service
systemctl status arduino-bridge.service

# 3. Testa Bridge-anslutning (Python)
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/run/arduino-router.sock')
    print('✓ Bridge socket accessible')
    s.close()
except Exception as e:
    print(f'✗ Bridge socket error: {e}')
"

# 4. Kontrollera loggar
journalctl -u shallot-mpu.service -f
```

---

## 🎯 Användning (MPU-Meny)

När skriptet körs (antingen manuellt eller som service), presenteras följande meny:

```
SHALLOT UNO Q — Orchestration (MPU)
====================================
0. Start provisioning session
1. Generate key
2. Distribute to PLC
3. Distribute to PAW
4. Get key state
5. Get key fingerprint
6. Validate provisioning
7. Show audit log
8. End session
q. Quit
Select option:
```

### NP-01 Flöde via MPU-Meny

| Steg | Kommando | Åtgärd |
|------|----------|--------|
| 1 | `0` | Starta session (ange recovery code) |
| 2 | `1` | Generera nyckel (MCU ber om fysisk knapp) |
| 3 | `4` | Kontrollera status: `Key state: GENERATED` |
| 4 | `2` | Distribuera till PLC (MCU ber om knapp) |
| 5 | `4` | Kontrollera: `Key state: DISTRIBUTED_PLC` |
| 6 | `3` | Distribuera till PAW (MCU ber om knapp) |
| 7 | `4` | Kontrollera: `Key state: DISTRIBUTED_BOTH` |
| 8 | `6` | Validera provisionering |
| 9 | `8` | Avsluta session |

---

## 🔒 Säkerhetsprinciper

### 1. Nyckelmaterial hanteras aldrig av MPU
- ✅ MCU genererar nycklar (hardware TRNG)
- ✅ MCU lagrar nycklar (STM32U585)
- ✅ MPU får endast **hash/fingerprint**
- ✅ Audit log lagrar endast **hash**, aldrig nycklar

### 2. Bridge RPC Kommunikation
- ✅ Kommunicering via **Unix socket** (inte serial)
- ✅ Endast **status** och **kommandon** skickas
- ✅ Nyckelmaterial skickas **aldrig** över Bridge

### 3. Fysisk Säkerhet
- ✅ Kräver **fysisk knapp** på UNO Q för nyckeloperationer
- ✅ Session kräver **recovery code** (≥16 alfanumeriska)
- ❌ **Ingen** fjärrållgång till nyckeloperationer

### 4. Audit Log
- ✅ Alla provisioneringshändelser loggas
- ✅ Endast **hash/fingerprint** lagras
- ✅ **Recovery code** lagras aldrig (endast hash)
- ✅ Loggfiler skrivs till konfigurerbar sökväg

---

## 📋 DEPLOYMENT_CHECKLIST.md

Se [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)

---

## 🔍 Felsökning

### Bridge socket saknas
```bash
# 1. Kontrollera att Arduino Bridge körs
ps aux | grep ArduinoBridge

# 2. Starta Arduino Bridge manuellt
ArduinoBridge &

# 3. Vänta på socket-skapande
sleep 3
ls -l /var/run/arduino-router.sock
```

### Python-beroenden saknas
```bash
# Installera krävda paket
pip3 install pyserial msgpack

# Testa import
python3 -c "import serial, msgpack; print('OK')"
```

### Skriptet startar inte
```bash
# Kontrollera Python-version
python3 --version

# Kontrollera filrättigheter
ls -l uno-q-key-authority-mpu.py
chmod +x uno-q-key-authority-mpu.py

# Testa direkt exekvering
python3 uno-q-key-authority-mpu.py
```

### service startar inte
```bash
# Kontrollera service-log
journalctl -u shallot-mpu.service -xe

# Kontrollera konfigurationsfil
cat /etc/shallot/shallot-mpu.conf

# Testa service manuellt
sudo systemctl stop shallot-mpu.service
sudo /etc/systemd/system/shallot-mpu.service
```

---

## 📚 Konfigurerbar Audit Log Sökväg

### Miljövariabel (högsta prioritet)
```bash
export AUDIT_LOG_PATH=/custom/path/audit.log
python3 uno-q-key-authority-mpu.py
```

### Konfigurationsfil
Skapa `/etc/shallot/shallot-mpu.conf`:
```ini
AUDIT_LOG_DIR=/var/log/shallot
AUDIT_LOG_FILE=$AUDIT_LOG_DIR/provisioning_log.jsonl
```

### Standard för test
```bash
# Skapar automatiskt katalog om den saknas
mkdir -p /home/user/shallot/audit
```

---

## 📊 Verifiering av Bridge/RPC

Se [verify-bridge.sh](verify-bridge.sh)

---

## 📚 Se även

- [MCU Deployment](../uno-q-mcu-deploy/) — MCU firmware
- [MCU Firmware](../../uno-q-key-authority-mcu/) — Källkod
- [Testplan](../../../docs/13-usb-provisionering-testplan.md) — NP-01 test
- [Arduino UNO Q Dokumentation](https://docs.arduino.cc/hardware/uno-q)

---

## 📜 License

Som övriga repo.

---

*Generated for SHALLOT project*
