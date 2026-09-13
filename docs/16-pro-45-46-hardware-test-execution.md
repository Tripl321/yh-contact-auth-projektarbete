# PRO-45 & PRO-46 — Fysisk verifiering: körguide

> **Status:** Väntar på fysisk testning. Fyll i resultat under varje test.
> **Firmware:** Kompilerad och redo i `/tmp/paw-build`, `/tmp/den-build`, `/tmp/uno-q-build`.

---

## 1. Förberedelser

### 1.1 Identifiera serialportar

Kör följande kommando på din dator:

```bash
# macOS/Linux
ls -la /dev/cu.* /dev/tty.*

# Windows (PowerShell)
Get-Counter -Counter "\PhysicalMemory\Available MBytes"
```

**Förväntade portar:**

- UNO Q: `/dev/cu.usbmodemXXXX` eller `/dev/cu.usbserialXXXX`
- DEN (Pico 2): `/dev/cu.usbmodemXXXX` eller `/dev/cu.usbserialXXXX`
- PAW (Feather RP2350): `/dev/cu.usbmodemXXXX` eller `/dev/cu.usbmodemXXXX`

**Observerad port-mappning (ifyll):**

| Enhet | Port     | Obs |
| ----- | -------- | --- |
| UNO Q | `______` |     |
| DEN   | `______` |     |
| PAW   | `______` |     |

### 1.2 Kabeldragning

```
Dator ─── USB ─── UNO Q (Serial1 D0/D1) ─── USB ─── DEN (Serial1 GP0/GP1)
                                          └── USB ─── PAW (Serial USB)
```

- UNO Q D0 (TX) → DEN GP1 (RX)
- UNO Q D1 (RX) → DEN GP0 (TX)
- UNO Q GND → DEN GND
- UNO Q USB → dator (övervakning)
- DEN USB → dator (övervakning)
- PAW USB → dator (övervakning)

---

## 2. Flasha firmware

### 2.1 UNO Q (PRO-45)

```bash
arduino-cli compile --fqbn arduino:unoq:unoq \
  --output-dir /tmp/uno-q-build \
  key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino

arduino-cli upload -p /dev/cu.UNO_Q_PORT \
  --fqbn arduino:unoq:unoq \
  --input-dir /tmp/uno-q-build \
  key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino
```

### 2.2 DEN (PRO-46)

```bash
arduino-cli compile --fqbn rp2040:rp2040:generic_rp2350 \
  --libraries libraries \
  --output-dir /tmp/den-build \
  plc/den-main/den-main.ino

arduino-cli upload -p /dev/cu.DEN_PORT \
  --fqbn rp2040:rp2040:generic_rp2350 \
  --input-dir /tmp/den-build \
  plc/den-main/den-main.ino
```

### 2.3 PAW (PRO-48)

```bash
arduino-cli compile --fqbn rp2040:rp2040:generic_rp2350 \
  --libraries libraries \
  --output-dir /tmp/paw-build \
  id-kort/paw-main/paw-main.ino

arduino-cli upload -p /dev/cu.PAW_PORT \
  --fqbn rp2040:rp2040:generic_rp2350 \
  --input-dir /tmp/paw-build \
  id-kort/paw-main/paw-main.ino
```

---

## 3. Verifiering: UNO Q RNG-nyckelgenerering (PRO-45)

### 3.1 Steg

1. Öppna serial monitor för UNO Q:

   ```bash
   arduino-cli monitor -p /dev/cu.UNO_Q_PORT -c baudrate=115200
   ```

2. Starta UNO Q och leta efter boot-loggar.

3. **Observera:** Om `[PRO-45]` inte visas i boot-loggarna, kontrollera att rätt firmware är installerad.

### 3.2 Förväntad output

```
[PRO-45] Starting key generation...
[PRO-45] Running TRNG health check... OK
[PRO-45] Generating 128-bit AES key from TRNG... OK
[PRO-45] Key generated successfully.
[PRO-45] Key fingerprint (SHA-256[:4]): XXXXXXXXXXXXXXXX
```

### 3.3 Faktiskt resultat (ifyll)

| Fält             | Värde        | Obs |
| ---------------- | ------------ | --- |
| Health check     | PASS / FAIL  |     |
| Nyckellängd      | 16 byte      |     |
| Fingeravtryck    | `__________` |     |
| Nyckelexponering | NEJ / JA     |     |
| Boot-tid         | _____ ms     |     |

### 3.4 Logg (ifyll)

```
[Kopiera relevanta rader från serial monitor här]
```

---

## 4. Verifiering: RNG-felåterhämtning (PRO-45)

### 4.1 Steg

1. Starta UNO Q.
2. Under `[PRO-45] Generating 128-bit AES key...` koppla bort strömmen (eller trigga RNG-fel).
3. Återanslut och övervaka serial output.

### 4.2 Förväntat resultat

```
[PRO-45] TRNG generation failed. Aborting (fail-closed).
[key_authority_event] key_generation_failed: TRNG generation error
```

### 4.3 Faktiskt resultat (ifyll)

| Fält               | Värde        | Obs |
| ------------------ | ------------ | --- |
| RNG-fel detekterat | JA / NEJ     |     |
| Fail-closed        | JA / NEJ     |     |
| Nyckel exporterad  | JA / NEJ     |     |
| State efter fel    | `__________` |     |

---

## 5. Verifiering: USB-distribution till DEN (PRO-46)

### 5.1 Förutsättningar

- UNO Q har en giltig genererad nyckel (från Test 1)
- DEN är ansluten och programmerad
- Båda enheterna är på samma fysiska plats

### 5.2 Steg

1. Öppna serial monitor för UNO Q och DEN (två separata fönster/terminals).
2. På UNO Q: trigga distribution till DEN enligt enhetens gränssnitt.
3. Övervaka båda loggarna.

### 5.3 Förväntad UNO Q-output

```
[PRO-46] Distributing key to PLC via UART...
[PRO-46] Sending handshake... OK
[PRO-46] Sending key data... sent
[PRO-46] Waiting for storage confirmation... OK (hash verified)
[PRO-46] Key successfully distributed to PLC.
```

### 5.4 Förväntad DEN-output

```
[PRO-46] Handshake received.
[PRO-46] CRC verified OK.
[PRO-46] Key stored. Hash sent: XXXXXXXXXXXXXXXX
```

### 5.5 Faktiskt resultat (ifyll)

| Fält                 | Värde       | Obs |
| -------------------- | ----------- | --- |
| Handshake            | PASS / FAIL |     |
| CRC-verifiering      | PASS / FAIL |     |
| Hash-match           | PASS / FAIL |     |
| Nyckel lagrad i SRAM | JA / NEJ    |     |
| K_mac härledd        | JA / NEJ    |     |

### 5.6 Logg (ifyll)

```
UNO Q: _______________________
DEN: _______________________
```

---

## 6. Verifiering: USB-distribution till PAW (PRO-46)

### 6.1 Steg

1. Öppna serial monitor för PAW.
2. På UNO Q: trigga distribution till PAW.
3. Övervaka alla tre loggarna (UNO Q, PAW, och eventuell DEN om den är ansluten).

### 6.2 Förväntad PAW-output

```
[PRO-48] Handshake received.
[PRO-48] CRC verified OK.
[PRO-48] Key stored. Hash sent: XXXXXXXXXXXXXXXX
```

### 6.3 Faktiskt resultat (ifyll)

| Fält                 | Värde        | Obs |
| -------------------- | ------------ | --- |
| Handshake            | PASS / FAIL  |     |
| CRC-verifiering      | PASS / FAIL  |     |
| Hash-match           | PASS / FAIL  |     |
| Nyckel lagrad i SRAM | JA / NEJ     |     |
| keyStored flag       | true / false |     |

### 6.4 Logg (ifyll)

```
UNO Q: _______________________
PAW: _______________________
```

---

## 7. Verifiering: Operatörsbekräftelse (PRO-46)

### 7.1 Steg

1. På UNO Q: begär distribution till valfritt mål.
2. Övervaka serial output: `awaiting button press`.
3. **Vänta** 5 sekunder utan att trycka på knappen (A0).
4. Verifiera att ingen distribution sker.
5. Tryck på knappen (A0).
6. Verifiera att distribution påbörjas.

### 7.2 Förväntat resultat

- Utan knapptryck: timeout, ingen distribution
- Med knapptryck: distribution startar

### 7.3 Faktiskt resultat (ifyll)

| Fält                     | Värde       | Obs |
| ------------------------ | ----------- | --- |
| Knapptryck krävs         | JA / NEJ    |     |
| Timeout utan tryck       | PASS / FAIL |     |
| Distribution efter tryck | PASS / FAIL |     |
| Tidsgräns                | _____ s     |     |

---

## 8. Verifiering: CRC-fel under distribution

### 8.1 Steg

1. Anslut en man-in-the-middle-enhet (t.ex. Arduino med SoftwareSerial) mellan UNO Q och DEN.
2. På UNO Q: begär distribution till DEN.
3. På MiM-enhet: ändra 1 byte i CRC-fältet i key-paketet.
4. Övervaka DEN output.

### 8.2 Förväntat resultat

```
[PRO-46] CRC mismatch! Expected: XXXXXXXX Got: XXXXXXXX
```

### 8.3 Faktiskt resultat (ifyll)

| Fält               | Värde           | Obs |
| ------------------ | --------------- | --- |
| CRC-fel detekterat | PASS / FAIL     |     |
| MSG_ERROR sänd     | PASS / FAIL     |     |
| Nyckel lagrad      | NEJ / JA (fail) |     |
| Buffert rensad     | PASS / FAIL     |     |

---

## 9. Verifiering: Timeout under distribution

### 9.1 Steg

1. På UNO Q: begär distribution till DEN.
2. Koppla loss kabeln under `[PRO-46] Sending key data...`.
3. Vänta 10 sekunder.
4. Återanslut och övervaka UNO Q output.

### 9.2 Förväntat resultat

```
[PRO-46] Timeout waiting for READY response.
[PRO-46] distribution_failed: PLC did not respond
```

### 9.3 Faktiskt resultat (ifyll)

| Fält                | Värde       | Obs |
| ------------------- | ----------- | --- |
| Timeout detekterad  | PASS / FAIL |     |
| Ingen nyckel lagrad | PASS / FAIL |     |
| Buffert rensad      | PASS / FAIL |     |

---

## 10. Verifiering: Signal- och tidsverifiering vid 115200 baud

### 10.1 Steg

1. Anslut oscilloskop till TX/RX-linjen mellan UNO Q och DEN.
2. Starta en distribution (Test 5).
3. Mät signalparametrar.

### 10.2 Förväntade värden

| Parameter           | Förväntat värde | Tolerans |
| ------------------- | --------------- | -------- |
| Bit-tid             | 86.8 µs         | ±2%      |
| Signalnivå HIGH     | ≥ 0.7·Vcc       |          |
| Signalnivå LOW      | ≤ 0.3·Vcc       |          |
| Frame-tid (22 byte) | 1.91 ms         | ±5%      |
| Teckenförluster     | 0               |          |

### 10.3 Faktiskt resultat (ifyll)

| Parameter       | Mänt värde | Avvikelse |
| --------------- | ---------- | --------- |
| Bit-tid         | _____ µs   | _____%    |
| Signalnivå HIGH | _____ V    |           |
| Signalnivå LOW  | _____ V    |           |
| Frame-tid       | _____ ms   | _____%    |
| Teckenförluster | _____      |           |

---

## 11. Sammanfattning av resultat

| Test                          | Pass/Fail | Kräver hårdvaru?                 | Obs |
| ----------------------------- | --------- | -------------------------------- | --- |
| 1: RNG-nyckelgenerering       | _____     | ✅ UNO Q                         |     |
| 2: RNG-felåterhämtning        | _____     | ✅ UNO Q                         |     |
| 3: USB-distribution till DEN  | _____     | ✅ UNO Q + DEN                   |     |
| 4: USB-distribution till PAW  | _____     | ✅ UNO Q + PAW                   |     |
| 5: Operatörsbekräftelse       | _____     | ✅ UNO Q                         |     |
| 6: Signal-/tidsverifiering    | _____     | ✅ UNO Q + DEN/PAW + oscilloskop |     |
| 7: Timeout under distribution | _____     | ✅ UNO Q + DEN                   |     |
| 8: CRC-fel                    | _____     | ✅ UNO Q + DEN + MiM             |     |

---

## 12. Kvarvarande hårdvarubegränsningar

Följande kan endast verifieras på fysisk hårdvara:

1. **STM32U585 RNG-entropi:** Software-mocks kan inte simulera verklig RNG-entropi eller hårdvarufel.
2. **Signalintegritet:** Oscilloskop/mätinstrument krävs för timing- och spänningsverifiering.
3. **Fysisk knapptryckning:** A0-knappen på UNO Q kan endast testas manuellt.
4. **Kabel-/anslutningsrobusthet:** Fysisk koppling/koppling krävs för att verifiera.
5. **Tidsmässig beteende:** Verkliga UART-tider och timeout-beteenden kan avvika från mocks.

---

## 13. Kommandon för snabb referens

```bash
# Lista serialportar
ls -la /dev/cu.* /dev/tty.*

# Monitor UNO Q
arduino-cli monitor -p /dev/cu.UNO_Q_PORT -c baudrate=115200

# Monitor DEN
arduino-cli monitor -p /dev/cu.DEN_PORT -c baudrate=115200

# Monitor PAW
arduino-cli monitor -p /dev/cu.PAW_PORT -c baudrate=115200

# Flasha UNO Q
arduino-cli upload -p /dev/cu.UNO_Q_PORT --fqbn arduino:unoq:unoq --input-dir /tmp/uno-q-build key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino

# Flasha DEN
arduino-cli upload -p /dev/cu.DEN_PORT --fqbn rp2040:rp2040:generic_rp2350 --input-dir /tmp/den-build plc/den-main/den-main.ino

# Flasha PAW
arduino-cli upload -p /dev/cu.PAW_PORT --fqbn rp2040:rp2040:generic_rp2350 --input-dir /tmp/paw-build id-kort/paw-main/paw-main.ino
```
