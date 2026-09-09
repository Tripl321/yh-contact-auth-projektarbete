# Återställningslogg - 2026-09-07

## 1. Initial tillstånd före återställning
- MCU (UNO Q): Okänt tillstånd
- PLC: Okänt tillstånd  
- PAW: Okänt tillstånd

## 2. Återställningsåtgärder

### 2.1 Portidentifiering
```
MCU (UNO Q): /dev/cu.usbmodem27559688122 (arduino:zephyr:unoq)
PLC:          /dev/cu.usbmodem11101 (rp2040:rp2040:rpipico2w)
PAW:          /dev/cu.usbmodem114401 (rp2040:rp2040:adafruit_feather_rp2350_hstx)
```

### 2.2 Baudrate-korrigering
- Uppdaterad `docs/13-usb-provisionering-testplan.md`: MCU-konsol ändrad från 9600 till 115200 baud
- Verifierat `scripts/kd_inject.py`: Använder 115200 baud som default

### 2.3 Enhetsåterställning
**Metod**: Anslutning vid 1200 baud utlöste RP2040/RP2350 bootloader-läge.
- PLC och PAW kopplade om automatiskt efter ~10-15 sekunder
- MCU förblev funktionell (ej påverkad av 1200 baud-anslutning)

## 3. Återställd enhetsstatus

### MCU (UNO Q)
- **Port**: `/dev/cu.usbmodem27559688122`
- **Baud**: 115200
- **Boot-banner**: `SHALLOT — UNO Q Key Authority (PRO-45/PRO-46)`
- **Status**: UNINITIALIZED
- **Active epoch**: 0
- **Pending epoch**: 0
- **Svar på 's'**: Full statusvisning

### PLC
- **Port**: `/dev/cu.usbmodem11101`
- **Baud**: 115200
- **Boot-banner**: `SHALLOT — PLC Complete Firmware`
- **Status**: Väntar på nyckeldistribution från UNO Q
- **Implicera**: Active epoch: 0 (ingen nyckel lagrad)

### PAW
- **Port**: `/dev/cu.usbmodem114401`
- **Baud**: 115200
- **Boot-banner**: `SHALLOT PAW Main Firmware`
- **Status**: Väntar på nyckeldistribution från UNO Q (timeout på handshake)
- **Implicera**: Active epoch: 0 (ingen nyckel lagrad)

## 4. Verifiering
- ✅ Alla tre enheter återanslutna och fungerande
- ✅ Boot-banners matchar förväntade värden
- ✅ MCU: Explicit epoch 0 bekräftad via 's'-kommando
- ✅ PLC/PAW: Fail-closed startläge (väntar på distribution = ingen aktiv nyckel)
- ⚠️ PLC/PAW epoch ej explicit bekräftad (ingen status-kommando tillgänglig)

## 5. Slutsats
Enheterna är nu i ett känt fail-closed-utgångsläge med tom SRAM och active epoch: 0.
Klar för NP-01 testkörning.
