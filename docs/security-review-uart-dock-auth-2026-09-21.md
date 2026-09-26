# Säkerhetsgranskning — UART-docka autentisering (PRO-87/84/88/53)

**Datum:** 2026-09-21 | **Status:** Färdig | **Omfattning:** PRO-87 (protokoll), PRO-84 (PAW-responder), PRO-88 (DEN-initierare), PRO-53 (fail-closed watchdog), PRO-98 (blocklist).

## 1. Sammanfattning

Implementeringen av UART-docka autentiseringen är kryptografiskt och arkitektoniskt solid. Alla 551 tester passerar, inklusive KAT-verifierade SHA-256, HMAC-SHA256, CRC32 och Ed25519-implementeringar. Fail-closed-statemaskinen är korrekt: ingen felväg kan nå AUTHENTICATED. Dock finns **en kritisk begränsning** som gör systemet otillgängligt i befintligt läge.

## 2. Verifierade komponenter [K]

### 2.1 UART-ramprotokoll (PRO-87)

`libraries/DenUartProtocol/src/DenUartProtocol.h` (247 rader, header-only, transportfri).

| Kontroll                | Status | Detalj                                                                  |
| ----------------------- | ------ | ----------------------------------------------------------------------- |
| SYNC-ankring (0xAA)     | PASS   | `den_scanner_push` ignorerar skräpbytes fram tills SYNC                 |
| CRC32 (IEEE 802.3, LE)  | PASS   | Pin-kärd: `0xCBF43926`, verifieras mot C-host-kat                       |
| Längd-validering        | PASS   | `LEN > 64` avvisas innan fler byte läses; exakt payload-storlek per typ |
| Typ-validering          | PASS   | Okända typvärde → `DEN_ERR_TYPE`                                        |
| Byte-timeout            | PASS   | 100 ms stall mitt i ram → kassera (`DEN_ERR_TIMEOUT`)                   |
| Resync-budget           | PASS   | Max 64 skräpbytes sedan SYNC (`DEN_ERR_RESYNC`)                         |
| Konstant-tidsjämförelse | PASS   | `den_ct_compare` används (aldrig `memcmp`)                              |
| Transport-fri           | PASS   | Inga `Serial`/`Arduino.h`-beroenden i modulen                           |
| Ingen duplikation       | PASS   | CRC32, jämförelse, framing kördes från delad modul                      |

### 2.2 Kryptografi (PRO-49)

`libraries/ShallotCrypto/src/ShallotCrypto.h` (187 rader, header-only).

| Kontroll               | Status | Detalj                                                 |
| ---------------------- | ------ | ------------------------------------------------------ |
| SHA-256 (FIPS 180-4)   | PASS   | KAT: `sha_empty`, `sha_abc`, `sha_56` matchar referens |
| HMAC-SHA256 (RFC 4231) | PASS   | KAT: tre RFC-fall verifierade                          |
| K_mac-derivning        | PASS   | `SHA-256(master                                        |     | "MAC")[:16]` — enhetligt mellan DEN/PAW/UNO-Q |
| K_enc-derivning        | PASS   | `SHA-256(master                                        |     | "ENC")[:16]` — reserverad                     |
| Fail-closed oversize   | PASS   | Message >64B eller key >64B → zero output              |
| Volatil wipe           | PASS   | `shalot_wipe` använder `volatile uint8_t*`             |
| Ingen memcmp           | PASS   | `den_ct_compare` ägds av DenUartProtocol, återanvänds  |

**KAT-resultat (host-kompilerad C mot verkliga headers):**

```
crc_ref cbf43926
sha_empty e3b0c44...
sha_abc ba7816b...
sha_56 248d6a6...
hmac_rfc1 b0344c6...
hmac_rfc2 5bdcc14...
hmac_rfc3 773ea91...
dev_kmac 99c7117275f487623752e6d5d0eb438f
dev_hmac 782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda
fail_msg 0000000... (32 byte noll)
fail_key 0000000... (32 byte noll)
```

### 2.3 DEN fail-closed statemaskin (PRO-53)

`plc/den-main/den-main.ino` (1048 rader).

Statemaskin: `DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED`

| Övergång                           | Verifierat | Bevis                                                                                                                  |
| ---------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| Boot → DENIED                      | PASS       | `denState = DEN_ST_DENIED` i `setup()`; test_pro53_boot_starts_denied                                                  |
| DENIED → CHALLENGE_SENT            | PASS       | `den_send_challenge()` efter `SESSION_GAP_MS`; test_pro53_state_machine_transitions                                    |
| CHALLENGE_SENT → AUTHENTICATED     | PASS       | Endast komplett giltigt RESPONSE med korrekt HMAC inom 2 s; test_pro53_happy_path_auth_then_denied                     |
| CHALLENGE_SENT → DENIED (alla fel) | PASS       | Timeout, CRC-fel, fel typ, fel storlek, HMAC-mismatch, stale-nonce, disconnect, blocklist — alla → den_fail() → DENIED |
| AUTHENTICATED → DENIED             | PASS       | Efter `SESSION_GAP_MS`; test_pro53_prior_success_not_authorizing                                                       |

**Fail-closed garantier:**

- Ingen felväg transitionerar till AUTHENTICATED (test_pro53_state_machine_transitions)
- ACK är informellt — beslutet tas innan ACK (test_pro53_ack_is_informational)
- PAW-display/e-paper påverkar inte DEN-beslutet (test_pro53_display_does_not_affect_decision)
- All-zero master-nyckel avvisas (PRO-93/PRO-94)
- TRNG-all-zero-nonce → challenge avbruts (fail closed)
- Stale RESPONSE (viscad nonce) → nekat (test_pro53_stale_response_denied)

### 2.4 PAW-responder (PRO-84)

`id-kort/paw-main/paw-main.ino` (1040 rader).

| Kontroll                   | Status | Detalj                                                                                                          |
| -------------------------- | ------ | --------------------------------------------------------------------------------------------------------------- |
| Responder-only             | PASS   | `den_encode(DEN_TYPE_CHALLENGE` saknas i PAW-källan (test_pro84_source_guards)                                  |
| Svarar endast på CHALLENGE | PASS   | Test_pro84_unexpected_type_ignored: HEARTBEAT/ACK/ALARM/RESPONSE ignoreras                                      |
| Fail-closed utan nyckel    | PASS   | PRO-94 gate: `paw_session_key_is_valid` nekar innan HMAC-beräkning (test_pro84_unprovisioned_ignores_challenge) |
| Transport-isolation        | PASS   | Dock (Serial1) och LoRa (SPI1) separata; `paw_session_accept_challenge` tar transport-parameter                 |
| Split-frame-hantering      | PASS   | Test_pro84_split_frames_assemble                                                                                |
| CRC-resync                 | PASS   | Test_pro84_garbage_recovery: skräp + korrupt + giltig → svara endast på giltig                                  |
| E-paper on-blocking        | PASS   | `showStatus()` returnerar omedelbart; `poll()` avslutar asyncronnt med BUSY-timeout-degradering                 |

### 2.5 PAW-session-bibliotek

`libraries/PawSession/src/PawSession.h` (382 rader).

- Session-state hanteras av biblioteket, inte sketch: `PAW_AUTH_WAITING_FOR_KEY → WAITING_FOR_CHALLENGE → COMPUTING_RESPONSE → WAITING_FOR_RESULT → WAITING_FOR_CHALLENGE`
- `paw_session_accept_challenge` nekar om nyckel saknas (`PAW_SESSION_EVENT_NO_KEY`)
- Transport-spårning förhindrar cross-transport confusion: en challenge på en transport blockeras om en annan är pending
- 2.5 s PAW ACK-watchdog (PRO-60): display-endast, påverkar inte DEN-deadline (test_pro58_late_ack_ignored)

### 2.6 E2E-interop (PRO-50)

PAW:s HMAC-svar matchar DEN:s förväntade MAC exakt:

- Testvektor: master=`00..0F`, nonce=`0x10..0x17` → HMAC = `782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda`
- Test_pro84_valid_challenge_response bekräftar att PAW svarar med exakt denna HMAC

### 2.7 USB-provisionering (PRO-46)

`libraries/ProvisioningProtocol/src/ProvisioningProtocol.h` (67 rader).

| Kontroll                                     | Status                                                                |
| -------------------------------------------- | --------------------------------------------------------------------- |
| Handshaking (0xA1 → 0xA2 → 0xA3 → 0xA4/0xA5) | PASS                                                                  |
| CRC32 (big-endian, key-only scope)           | PASS — matchar firmware                                               |
| All-zero-nyckel avvisas                      | PASS — DEN och PAW båda kollar (test_pro47_key_storage)               |
| Timeout → wipe                               | PASS — 10 s timeout, fail-closed                                      |
| Ingen key-material i logg                    | PASS — endast fingerprint (4 byte) skickas tillbaka                   |
| Host-C-kat verifierar                        | PASS — `test_provisioning_vectors.py` kompilerar C-harness mot header |

### 2.8 Ed25519-blocklist (PRO-98)

`libraries/Ed25519/src/Ed25519.h` (23 rader, C-header).

| Kontroll                              | Status                                                   |
| ------------------------------------- | -------------------------------------------------------- |
| RFC 8032 test-vectors                 | PASS — `test_pro98_ed25519_sign_verify`                  |
| Manipulerad signatur nekas            | PASS                                                     |
| Rollback (version < 1) nekas          | PASS                                                     |
| Fel public key nekas                  | PASS                                                     |
| Stulen PAW kan inte signera           | PASS — Ed25519-nyckel aldrig hämtas från master          |
| Blocklist-gate efter HMAC             | PASS — `test_pro98_bad_hmac_never_reaches_gate`          |
| Deny-chain visar aldrig AUTHENTICATED | PASS — `test_pro98_deny_chain_never_shows_authenticated` |
| Källguards mot HMAC-authority         | PASS — `test_pro98_source_guards_ed25519`                |

## 3. Kritiskt fynd: Blockerad blocklist-trust-root [R → BLOCKER]

**Lokalisering:** `plc/den-main/den-main.ino:144-149`

```c
static const uint8_t blocklist_public_key[ED25519_PUBLIC_KEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
```

**Effekt:** Eftersom trust-roten är alla nollor kan ingen Ed25519-signatur någonsin verifieras. `blocklist_valid` förblir 0 för alltid. I `den_on_response()` (rad 890):

```c
if (!blocklist_valid) {
    den_fail(DEN_REASON_BLOCKLISTED);
    return;
}
```

**Resultat:** VARJE komplett, giltig HMAC-autentisering nekas med `DEN_REASON_BLOCKLISTED` (kod 8). UART-docka autentiseringen fungerar inte i befintligt läge — detta är avsiktligt fail-closed (som dokumenteras i docs/17 §11.6), men det är en **production blocker**. Dokumentet självt listar detta som ett öppet stycke:

> `- [ ] Embed production Ed25519 public key in DEN firmware (replace all-zero placeholder)` — docs/17, punkt 11.6

**Åtgärd krävs:** Infoga produktions-Ed25519-offentliga nyckel ( signerad av HSM på UNO Q) innan produktionsflärdning. Detta är en byggtida beslut, inte en kodändring.

## 4. Meduppi fynd

### 4.1 Reason-code för ogiltig nyckel (LOW)

I `den_on_response()` (rad 846-848) saknar nyckel → `den_fail(DEN_REASON_HMAC_MISMATCH)`. Detta lär ut nyckelstatus genom felkoden. Även om reason-codes är icke-hemliga observationskoder, skulle `DEN_REASON_NO_KEY` vara tydligare. Minimalt säkerhetsproblem.

### 4.2 Blocklist-fingeravtryck jämförelse (LOW-MEDIUM)

I `den_on_response()` (rader 900-906) jämförs fingeravtryck mot blocklist med en sekventiell XOR-loop. Detta är inte konstant-tid. Eftersom fingeravtryck är 4 byte och listan max 16 poster, är informationsläcket marginellt, men `paw_session_key_is_valid` har samma mönster (rad 128-134). Rekommenderas: konstant-tidsjämförelse för sekretess-känsliga jämförelser.

### 4.3 E-paper bildfrys (LOW)

Om e-paper blir fast i AUTHENTICATED-stillstand vid strömavbrott (ingen ström för att uppdatera), kan en giltig authentication-indikeras även efter att nyckeln har torkats. Dokumenterat i docs/09 §8 och docs/10 som restrisk. Hårdvarulösning krävs (t.ex. tydlig "låst"-indikator som alltid visas vid boot).

## 5. Ingen PRO-93-dev-key-stubb

Källguards bekräftar att ingen hårdkodad dev-nyckel finns i aktiv firmware:

- `test_pro53_source_guards`: `#warning` saknas, `DEVELOPMENT-ONLY` saknas, `DEN_DEV_KEY` saknas
- `test_pro84_source_guards`: samma kontroller för PAW
- `test_pro47_key_storage`: all-zero master nekas, nyckel lagras endast i SRAM

## 6. Testresultat

```
$ python3 -m pytest tests/ tools/ -q
551 passed in 5.35s
```

Relevanta test-filer:

| Test                            | Antal | Omfattar                                    |
| ------------------------------- | ----- | ------------------------------------------- |
| test_pro87_uart.py              | 24    | UART-protokoll, CRC, scanner, source-guards |
| test_pro88_den.py               | 18+11 | DEN statemaskin + Ed25519-blocklist tests   |
| test_pro84_paw.py               | 33    | PAW-responder, transport-isolation, e-paper |
| test_shallot_crypto_kat.py      | 6     | SHA-256, HMAC, CRC32, K_mac KAT (host-C)    |
| test_provisioning_vectors.py    | 4     | USB-provisionering CRC/byggelse (host-C)    |
| test_pro47_key_storage.py       | 10    | SRAM, wipe, all-zero rejection              |
| test_pro49_key_derivation.py    | 8     | K_mac/K_enc derivning                       |
| test_pro50_hmac_paw.py          | 7     | HMAC-vektorer, interop                      |
| test_pro51_nonce_generation.py  | 6     | 8-byte TRNG-nonce, all-zero rejection       |
| test_pro61_e2e_integration.py   | 8     | E2E-session simulator                       |
| test_pro62_failure_scenarios.py | 10    | Timeout, crash, reconnect                   |
| test_pro94_security_review.py   | 9     | Source-guards, fail-closed                  |
| test_pro95_session.py           | 11    | Session lifetime, grant expiry              |
| test_pro97_breakglass.py        | 20    | Break-glass ceremony, audit                 |
| test_pro98_den_blocklist.py     | 17    | Blocklist signature, revoke, fail-closed    |

## 7. Restrisker som kräver fysisk bänk

| #      | Restrisk                                                                              | Varför simulering inte räcker                             |
| ------ | ------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| H1     | RP2350 TRNG-entropi                                                                   | Mock fångar all-zero men inte svag entropi                |
| H2     | UART-signalintegritet 115200                                                          | Bitfel/jitter finns inte i mock                           |
| H3     | 2 s-deadline mot verkliga klockar                                                     | Interrupt-latens på PAW (RadioLib/e-paper) kan äta budget |
| H4     | PAW svarar ej oprovisionerad                                                          | Mock pinnar logiken; ingen RESPONSE kräver bänk           |
| K1-K6  | SRAM-volatilitet, UF2-inspektion, wipe, nollnyckel-nekande, timeout-clear, trådanalys | Kräver fysisk enhet                                       |
| PRO-63 | Pen-test (side-kanaler, fault injection)                                              | Kräver specialiserad hårdvara                             |

## 8. Slutsats

| Område                                           | Risk           | Status                                                                 |
| ------------------------------------------------ | -------------- | ---------------------------------------------------------------------- |
| UART-protokoll (CRC, framing, scanner)           | Ingen          | PASS                                                                   |
| HMAC-SHA256 + K_mac-derivning                    | Ingen          | PASS                                                                   |
| Fail-closed statemaskin                          | Ingen          | PASS                                                                   |
| PAW-responder (fail-closed, transport-isolation) | Ingen          | PASS                                                                   |
| Ed25519-blocklist logik                          | Ingen (i mock) | PASS                                                                   |
| **Blocklist trust root (all-zeros)**             | **KRITISK**    | **BLOCKER — kräver produktions-nyckel**                                |
| TRNG-entropi                                     | Medel          | H1 — kräver bänk                                                       |
| UART-timing (2 s deadline)                       | Medel          | H3 — kräver bänk                                                       |
| E-paper bildfrys                                 | Låg            | H3/R — hålls utanför auth-väg                                          |
| Provisionerings-sändarauth                       | Medel          | Design-begränsad: CRC + fysisk närvaro, ingen kryptografisk sändarauth |

**Rekommendation:** Systemet är krypto- och protokollmässigt verifierat och korrekt implementerat. För att kunna användas i produktion krävs att produktions-Ed25519-offentliga nyckeln införs in i `den-main.ino:144` — detta är det enda blockövningsområdet. Efter detta är gjort och fysisk bänkverifiering (H1–H7) genomförts, är systemet klart för pen-testning (PRO-63).
