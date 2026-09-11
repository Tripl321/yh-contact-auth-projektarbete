# PRO-45 & PRO-46 — Fysisk verifieringprotokoll

> **Status:** Planering — ej fysiskt testad än.
> **Gäller:** UNO Q (STM32U585), DEN (RP2350), PAW (Feather RP2350)
> **Firmware:** `key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino`, `plc/den-main/den-main.ino`, `id-kort/paw-main/paw-main.ino`

---

## 1. Testmaskin och förutsättningar

| Komponent | Version/firmware | Obs |
|-----------|------------------|-----|
| UNO Q | Arduino UNO Q (STM32U585 + QRB2210) | `arduino:unoq` |
| DEN | Raspberry Pi Pico 2 (RP2350) | `rp2040:rp2040:generic_rp2350` |
| PAW | Adafruit Feather RP2350 | `rp2040:rp2040:generic_rp2350` |
| Kabel | USB-A → USB-C (UNO Q ↔ dator), USB-C → USB-C (DEN/PAW ↔ dator) | Originalkablar |
| Serial monitor | 115200 baud, 8N1 | `arduino-cli monitor` eller `screen` |

Alla enheter ska vara på samma fysiska plats, med kända COM-portar.

---

## 2. Kabeldragning

```
Dator ─── USB ─── UNO Q (Serial1 D0/D1) ─── USB ─── DEN (Serial1 GP0/GP1)
                                          └── USB ─── PAW (Serial USB)
```

- UNO Q Serial1 (D0/D1) → DEN USB-seriell (GP0=TX, GP1=RX)
- UNO Q USB → dator (för övervakning)
- DEN USB → dator (för övervakning)
- PAW USB → dator (för övervakning)

---

## 3. Test 1: UNO Q RNG-nyckelgenerering (PRO-45)

### 3.1 Förutsättningar
- UNO Q firmware med PRO-45-ändringar är installerad
- `prj.conf` innehåller:
  ```
  CONFIG_HARDWARE_DEVICE_CS_GENERATOR=y
  CONFIG_TEST_RANDOM_GENERATOR=n
  ```
- Serial monitor på 115200 baud är öppen

### 3.2 Steg
1. Starta UNO Q och övervaka serial output.
2. Leta efter `[PRO-45] Starting key generation...`.
3. Verifiera `[PRO-45] Running TRNG health check... OK`.
4. Verifiera `[PRO-45] Generating 128-bit AES key from TRNG... OK`.
5. Verifiera `[PRO-45] Key fingerprint (SHA-256[:4]):` följt av 8 hex-tecken.
6. Notera att **inga** rader innehåller `aesKey` eller `keyHash` i klartext.

### 3.3 Förväntat resultat
- TRNG health check passerar (inga felmeddelanden)
- 16-byte AES-nyckel genereras
- Endast fingeravtryck (SHA-256[:4]) visas i serial output
- `[PRO-45] Key generated successfully.` loggas

### 3.4 Resultatfält
| Fält | Värde |
|------|-------|
| Health check | PASS / FAIL |
| Nyckellängd | 16 byte |
| Fingeravtryck | 8 hex-tecken |
| Nyckelexponering | INTE EXponerad / exponerad |

### 3.5 Fail-closed-kriterium
- Om TRNG health check misslyckas: `keyState` sätts till `ERROR_STATE`, ingen nyckel exporteras, `secureWipeKey()` anropas.

---

## 4. Test 2: RNG-felåterhämtning (PRO-45)

### 4.1 Förutsättningar
- Samma som Test 1
- Möjlighet att simulera RNG-fel (t.ex. genom att koppla bort nätverk/kraft under generering)

### 4.2 Steg
1. Starta UNO Q.
2. Under `[PRO-45] Generating 128-bit AES key...` koppla bort strömmen (eller trigga RNG-fel på annat sätt).
3. Återanslut och övervaka serial output.

### 4.3 Förväntat resultat
- `[PRO-45] TRNG generation failed. Aborting (fail-closed).`
- `keyState` = `ERROR_STATE`
- Ingen nyckel exporteras
- `secureWipeKey()` anropas

### 4.4 Resultatfält
| Fält | Värde |
|------|-------|
| RNG-fel detekterat | JA / NEJ |
| Fail-closed | JA / NEJ |
| Nyckel exporterad | JA / NEJ |

### 4.5 Fail-closed-kriterium
- Vid RNG-fel: ingen nyckel i RAM, ingen export, state = `ERROR_STATE`.

---

## 5. Test 3: USB-nyckeldistribution till DEN (PRO-46)

### 5.1 Förutsättningar
- UNO Q har en giltig genererad nyckel
- DEN är ansluten via USB-seriell
- UNO Q och DEN är på samma fysiska plats
- Serial monitor för båda enheterna är öppen

### 5.2 Steg
1. På UNO Q: begär distribution till `TARGET_PLC` (0x01).
2. Övervaka UNO Q serial output:
   - `[PRO-46] Distributing key to PLC via UART...`
   - `[PRO-46] Sending handshake... OK`
   - `[PRO-46] Sending key data... sent`
   - `[PRO-46] Waiting for storage confirmation... OK (hash verified)`
3. Övervaka DEN serial output:
   - `[PRO-46] Handshake received.`
   - `[PRO-46] CRC verified OK.`
   - `[PRO-46] Key stored. Hash sent: XXXXXXXX`
4. Verifiera att hash från DEN matchar UNO Q:s fingeravtryck.

### 5.3 Förväntat resultat
- Handshake genomförs
- Nyckel (22 byte) överförs
- CRC32 verifieras på DEN
- DEN bekräftar med hash
- UNO Q verifierar hash

### 5.4 Resultatfält
| Fält | Värde |
|------|-------|
| Handshake | PASS / FAIL |
| CRC-verifiering | PASS / FAIL |
| Hash-match | PASS / FAIL |
| Nyckelexponering | INTE exponerad / exponerad |

### 5.5 Fail-closed-kriterium
- Felaktigt CRC: DEN svarar `MSG_ERROR`, ingen nyckel lagras.
- Timeout (>5 s): UNO Q avbryter, ingen nyckel lagras.
- Hash-mismatch: UNO Q loggar fel, ingen nyckel markeras som distribuerad.

---

## 6. Test 4: USB-nyckeldistribution till PAW (PRO-46)

### 6.1 Förutsättningar
- UNO Q har en giltig genererad nyckel
- PAW är ansluten via USB
- Serial monitor för PAW är öppen

### 6.2 Steg
1. På UNO Q: begär distribution till `TARGET_PAW` (0x02).
2. Övervaka UNO Q serial output (samma som Test 3).
3. Övervaka PAW serial output:
   - `[PRO-48] Handshake received.`
   - `[PRO-48] CRC verified OK.`
   - `[PRO-48] Key stored. Hash sent: XXXXXXXX`
4. Verifiera hash-match mellan PAW och UNO Q.

### 6.3 Förväntat resultat
- Identiskt med Test 3, men mål = PAW
- PAW:s `keyStored` = `true` efter distribution

### 6.4 Resultatfält
| Fält | Värde |
|------|-------|
| Handshake | PASS / FAIL |
| CRC-verifiering | PASS / FAIL |
| Hash-match | PASS / FAIL |
| Nyckel lagrad i SRAM | JA / NEJ |

### 6.5 Fail-closed-kriterium
- Samma som Test 3.

---

## 7. Test 5: Operatörsbekräftelse (PRO-46)

### 7.1 Förutsättningar
- UNO Q är redo för distribution
- Knappen (A0) är åtkomlig
- Serial monitor är öppen

### 7.2 Steg
1. På UNO Q: begär distribution till valfritt mål.
2. Övervaka serial output: `awaiting button press`.
3. **Tryck inte** på knappen under 5 sekunder — verifiera att ingen distribution sker.
4. Tryck på knappen (A0).
5. Verifiera att distribution påbörjas.

### 7.3 Förväntat resultat
- Distribution startar endast efter fysisk knapptryckning
- Utan knapptryck: ingen distribution efter 5 s timeout

### 7.4 Resultatfält
| Fält | Värde |
|------|-------|
| Knapptryck krävs | JA / NEJ |
| Timeout utan tryck | PASS / FAIL |
| Distribution efter tryck | PASS / FAIL |

### 7.5 Fail-closed-kriterium
- Om knappen inte trycks: ingen nyckelexport, state förblir `GENERATED`.

---

## 8. Test 6: Signal- och tidsverifiering vid 115200 baud

### 8.1 Förutsättningar
- UNO Q och DEN/PAW är anslutna
- Oscilloskop eller logisk analysator är tillgänglig
- Kabel är original USB-seriell

### 8.2 Steg
1. Anslut oscilloskop till TX/RX-linjen mellan UNO Q och DEN.
2. Starta en distribution (Test 3).
3. Mät:
   - Signalnivåer: HIGH ≥ 0.7·Vcc, LOW ≤ 0.3·Vcc
   - Bit-tid: 1/115200 ≈ 86.8 µs
   - Start/stop-bits: 1 start, 1 stop, ingen parity
   - Total frame-tid för 22-byte key packet: (22 × 10) / 115200 ≈ 1.91 ms
4. Verifiera att det inte finns någon teckenförlust.

### 8.3 Förväntat resultat
- Ren 8N1-signal utan störningar
- Bit-tid inom ±2% av 86.8 µs
- Inga teckenförluster under hela distributionen

### 8.4 Resultatfält
| Fält | Värde |
|------|-------|
| Signalnivå HIGH | ___ V |
| Signalnivå LOW | ___ V |
| Bit-tid | ___ µs |
| Teckenförluster | 0 / ___ |

### 8.5 Fail-closed-kriterium
- Om teckenförlust detekteras: distributionen misslyckas, fail-closed aktiveras.

---

## 9. Test 7: Avbruten USB-överföring (fail-closed)

### 9.1 Förutsättningar
- UNO Q har en giltig genererad nyckel
- DEN är ansluten
- Kabel kan kopplas loss under överföring

### 9.2 Steg
1. På UNO Q: begär distribution till DEN.
2. När `[PRO-46] Sending key data...` visas, koppla loss kabeln.
3. Återanslut efter 1 sekund.
4. Övervaka UNO Q och DEN output.

### 9.3 Förväntat resultat
- UNO Q: `[PRO-46] distribution_failed` efter timeout
- DEN: inget lagrat, `provBuf` nollställt
- Ingen partiell nyckel lagrad

### 9.4 Resultatfält
| Fält | Värde |
|------|-------|
| Distribution avbruten | PASS / FAIL |
| Ingen nyckel lagrad | PASS / FAIL |
| Buffert rensad | PASS / FAIL |

### 9.5 Fail-closed-kriterium
- Vid avbrott: `pollProvisioning()` returnerar `PROV_FAILED`, `memset(provBuf, 0, ...)`, ingen nyckel i SRAM.

---

## 10. Test 8: CRC-fel under distribution

### 10.1 Förutsättningar
- UNO Q har en giltig genererad nyckel
- DEN är ansluten
- Möjlighet att modifiera data på väg (t.ex. med en man-in-the-middle-enhet)

### 10.2 Steg
1. På UNO Q: begär distribution till DEN.
2. Infoga ett CRC-fel i key-paketet (ändra 1 byte i payload).
3. Övervaka DEN output.

### 10.3 Förväntat resultat
- DEN: `[PRO-46] CRC mismatch!`
- DEN svarar med `MSG_ERROR`
- Ingen nyckel lagras

### 10.4 Resultatfält
| Fält | Värde |
|------|-------|
| CRC-fel detekterat | PASS / FAIL |
| MSG_ERROR sänd | PASS / FAIL |
| Nyckel lagrad | NEJ / JA (fail) |

### 10.5 Fail-closed-kriterium
- CRC mismatch: `break` i do-while, `memset(provBuf, 0, ...)`, `PROV_FAILED`.

---

## 11. Sammanfattning: vad som kräver fysisk UNO Q

| Test | Kräver fysisk UNO Q | Kräver fysisk DEN/PAW |
|------|---------------------|------------------------|
| 1: RNG-nyckelgenerering | ✅ Ja | Nej |
| 2: RNG-felåterhämtning | ✅ Ja | Nej |
| 3: USB-distribution till DEN | ✅ Ja | ✅ Ja |
| 4: USB-distribution till PAW | ✅ Ja | ✅ Ja |
| 5: Operatörsbekräftelse | ✅ Ja | Nej |
| 6: Signal-/tidsverifiering | ✅ Ja | ✅ Ja |
| 7: Avbruten distribution | ✅ Ja | ✅ Ja |
| 8: CRC-fel | ✅ Ja | ✅ Ja |

**Obs:** Alla protokolltest (med mocks) körs i Python-sviten. Fysiska test ovan är endast för hårdvaruverifiering.

---

## 12. Kommando för testkörning

```bash
# Softwaretests (körs på dator)
python3 -m pytest tests/test_pro45_key_generation.py -v
python3 -m pytest tests/test_pro46_usb_distribution.py -v
python3 -m pytest tests/ -q
```

Fysiska test kräver manuella steg enligt ovan.
