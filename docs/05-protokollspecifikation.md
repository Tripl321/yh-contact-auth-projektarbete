# 05 — Protokollspecifikation

**PRO-42** | SHALLOT challenge-response protocol over LoRa P2P

## 1. Översikt

SHALLOT-protokollet implementerar en mutual challenge-response autentisering mellan edge enforcement-nod (PLC) och PAW (ID-bricka) över LoRa P2P. Protokollet använder HMAC-SHA256 för meddelandeintegritet och AES-128-CTR för payload-kryptering.

### Roller

| Roll | Hårdvara | Funktion |
|---|---|---|
| Edge Enforcement (PLC) | Pico 2 + Core1262 | Initierar challenge, verifierar response, fattar fail-closed beslut |
| PAW (ID-bricka) | Feather RP2350 + Core1262 | Mottager challenge, beräknar response, visar verdict på e-Paper |

## 2. Paketformat (PRO-81)

Alla SHALLOT-paket har följande wire-format:

```
[Version+MsgType  1B]  bits 7-4 = version (0x1), bits 3-0 = msg type
[SenderID         8B]  unik identifierare per nod
[SeqNum           4B]  big-endian, stigande per nod
[Nonce            8B]  slump från RP2350 hardware RNG
[EncryptedPayload  N]  variabel längd, 0–64 byte
[HMAC             8B]  trunkerad HMAC-SHA256
```

- Header-längd: 21 byte (1 + 8 + 4 + 8)
- Minimipaket: 29 byte (header + HMAC, tom payload)
- Maximipaket: 93 byte (header + 64 byte payload + HMAC)

### Meddelandetyper

| Typ | Värde | Beskrivning |
|---|---|---|
| MSG_CHALLENGE | 0x01 | Edge → PAW: initierar autentisering |
| MSG_RESPONSE | 0x02 | PAW → Edge: svarar med krypterad nonce |
| MSG_SUCCESS | 0x03 | Edge → PAW: autentisering godkänd |
| MSG_FAILURE | 0x04 | Edge → PAW: autentisering nekad |
| MSG_KEY_DIST | 0x05 | Framtida: nyckeldistribution |
| MSG_KEY_ACK | 0x06 | Framtida: nyckelbekräftelse |
| MSG_HEARTBEAT | 0x07 | Framtida: hjärtslag |

## 3. Nyckelderivation

Från en 128-bit master key derivas två sub-nycklar:

```
K_enc = SHA-256(master_key || "ENC")[:16]
K_mac = SHA-256(master_key || "MAC")[:16]
```

- K_enc används för AES-128-CTR kryptering av payload
- K_mac används för HMAC-SHA256 av hela paketet
- Master key är Phase 1 en stub (0x00–0x0F); Phase 2 ersätter med riktig UNO Q-nyckel (PRO-45)

## 4. HMAC-SHA256

- Trunkerad till 8 byte (SHALLOT_HMAC_LEN)
- Scope: Version+MsgType || SenderID || SeqNum || Nonce || EncryptedPayload (alltså ej HMAC-fältet självt)
- Implementation använder RP2350 hardware SHA-256-accelerator (hw_sha256_start/update/finish)
- Konstant-tidsjämförelse för förhindrande av timing-attacker

### Anti-DoS: HMAC före sekvensnummer

HMAC verifieras INNAN sekvensnummer konsumeras. Detta förhindrar en attackerare från att uttömma sekvensnummer-slots med skräppaket, eftersom endast autentiserade paket konsumerar en plats i SeqWhitelist.

## 5. AES-128-CTR

- Keystream genereras genom AES-ECB-encryption av en 128-bit counter-block
- Counter-block layout: [0x00 ×4] || SeqNum(4B) || Nonce(8B)
- Block-counter inkrementeras i de två lägsta byten (counter[14:15])
- AESLib.encryptSingle() används för varje 16-byte block
- XOR mellan keystream och plaintext/ciphertext — symmetrisk operation

## 6. Replay-skydd (SeqWhitelist)

Sliding-window med bitmask-implementation:

- Fönsterstorlek: 10 sekvensnummer
- uint16_t bitmask istället för bool[10] — O(1) operationer
- Första paketet etablerar fönstret
- Paket inom fönstret men redan sett: refuseras
- Paket äldre än fönstret: refuseras
- Paket nyare än fönstret: fönstret skiftas framåt

## 7. Challenge-Response Flöde

### 7.1 Edge-initierat flöde

```
Edge (PLC)                          PAW (ID-bricka)
    |                                    |
    |--- MSG_CHALLENGE (nonce_E) ------->|
    |                                    | Verifiera HMAC
    |                                    | Kontrollera seq (replay)
    |<--- MSG_RESPONSE (enc(nonce_E)) ---|
    | Verifiera HMAC                     |
    | Kontrollera seq (replay)           |
    | Dekryptera payload                  |
    |--- MSG_SUCCESS / MSG_FAILURE ----->|
    |                                    | Visa verdict på e-Paper
```

### 7.2 Felhantering

- HMAC-fel: paket kasseras, inget svar skickas (PAW) eller MSG_FAILURE skickas (Edge)
- Replay: paket kasseras, inget svar skickas
- Timeout: 3 återförsök (Edge), 5 s per försök
- Radio-fel: loggas via Serial, LED blinkar

## 8. Fail-Closed

Edge enforcement-noden fattar ett fail-closed beslut:
- Om något steg i verifieringen misslyckas nekas åtkomst
- LED förblir LOW vid nekad åtkomst
- PAW visar "Access Denied" på e-Paper

## 9. Säkerhetsöverväganden

| Aspekt | Åtgärd |
|---|---|
| Timing-attacker | Konstant-tidsjämförelse av HMAC |
| Replay | SeqWhitelist sliding-window |
| DoS (seq exhaustion) | HMAC före seq-konsumtion |
| Nyckel-läckage | K_enc/K_mac derivas, master key används ej direkt |
| Nonce-kollision | 8 byte hardware RNG per paket |
| Trunkerad HMAC | 8 byte (64-bit) — tillräckligt för LoRa-paket med begränsad bandbredd |

## 10. Framtida arbete

- Phase 2: Ersätt stub-nyckel med riktig UNO Q-nyckeldistribution (PRO-45)
- Flash-persistens av sekvensnummer (MVP: RAM-endast)
- e-Paper-integration i PAW (PRO-57)
- Fysisk end-to-end test (PRO-77)
