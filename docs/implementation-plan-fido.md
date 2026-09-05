# SHALLOT — FIDO-gated USB Provisioning — Implementation Plan

**Branch:** `vibe/paw-line-corruption-fix-bf5bdb` @ `5035710`
**Date:** 2026-09-04
**Status:** Plan - no broad code changes yet

## 1. Goal

Add FIDO + button-gated, epoch-tagged, one-time-grant USB provisioning without breaking the working LoRa P2P flow. Keep `USB is sole transport` (UART deprecated).

## 2. Ubiquitous language

PAW, Edge enforcement node (PLC), Mama Bear (UNO Q: STM32U585 MCU is authority, QRB2210 MPU is untrusted orchestrator), SHALLOT, key epoch, provisioning fixture (passive USB hub), FIDO session credential.

## 3. Current gaps (audit summary)

*   **No epoch** - `aesKey[16]` overwrite has no version. LoRa HMAC is `HMAC(key, nonce)` only. Replay across epochs possible.
*   **No one-time grant** - `generateKey` and `distributeKey` are idempotent. Same key can be distributed twice. No token consumption.
*   **No pending/active** - `KeyState` is `UNINITIALIZED/GENERATED/DISTRIBUTED_*`. No `PENDING` slot, no old-key retention.
*   **Button OR FIDO, not AND** - `distribute_key_now` bypasses button. MCU trusts MPU `lsusb` presence.
*   **No MCU FIDO verification** - MPU does `hidraw` + `lsusb` VID match, no CTAP2 assertion.
*   **Transport mismatch** - Docs say USB, committed code still `Serial1` (UART). Dirty patch to `Serial` is uncommitted.
*   **Weak nonce** - PLC `LCG` seeded 1. No TRNG.
*   **Replay window** - PLC verifies `echoedNonce` supplied by PAW (`memcpy(currentNonce, echoedNonce)`), so attacker can choose nonce.
*   **No fail-closed RSSI/heartbeat/relay** - Logged only.

## 4. Target state machine

```
IDLE
 -> SESSION_STARTED            (MPU: enter maintenance, recovery code, button sequence)
 -> FIDO_CREDENTIAL_REGISTERED  (MPU registers one Pico FIDO credential for this session)
 -> KEY_GENERATED               (MCU: generate AES-128 + epoch++, needs grant GENERATE_KEY)
 -> PLC_STAGED                  (MCU: stage pending key to PLC, needs grant STAGE_PLC)
 -> PAW_STAGED                  (MCU: stage pending key to PAW, needs grant STAGE_PAW)
 -> BOTH_ACKNOWLEDGED           (both ack epoch+fp via USB)
 -> COMMITTED                   (activate pending -> active, within 10 min monotonic window)
 -> CREDENTIAL_REVOKED -> IDLE

Failure: EXPIRED | CANCELED | FAILED | REQUIRES_NEW_FIDO_SESSION
```

Rules:

*   One `epoch` (uint32 monotonic, starts 1, increments on each `GENERATE_KEY`). Stored in MCU `uint32_t activeEpoch`, `pendingEpoch`, `pendingKey[16]`, `activeKey[16]`.
*   PLC/PAW store `activeKey/activeEpoch` and `pendingKey/pendingEpoch`. New key is `pending` until `COMMIT`.
*   Both must ack same `pendingEpoch` + `fp=SHA256(key)[:4]` within 10 min (MCU `millis()` monotonic, not wall clock). Old key stays active on timeout/fail. Pending invalidated.
*   Every state transition needs a fresh one-time grant: `{op, target, epoch, nonce[16], expiry 60s, grantId[16]}`. Grant consumed after use, replay rejected, wrong op/target/epoch rejected.
*   Generation and each staging need **both** FIDO assertion (UP) **and** fresh button press (not held).

## 5. Interfaces

### 5.1 MCU - Bridge RPC (MPU -> MCU via `/var/run/arduino-router.sock` 115200, `Serial1` is LPUART1, `Serial` is USB CDC)

Keep `provide_safe` for thread safety.

```
uint8_t get_key_state() -> KeyState
String get_key_fingerprint() -> hex SHA256[:4] of activeKey
String get_pending_fingerprint() -> hex of pendingKey

// First vertical slice - placeholder grant
bool request_key_generation(bytes grantToken) -> bool
// grantToken = 16B random + 4B epoch + 1B op + 4B expiry (all checked on MCU)
// Placeholder: grantToken is checked as: expiry > millis(), epoch == expected, op == GENERATE_KEY, token not seen before (replay cache 8 entries), and button LOW was sampled within 2s of call.

bool request_key_distribution(uint8 target, bytes grantToken) -> bool // for STAGE_PLC / STAGE_PAW

// Later slices will replace placeholder with FIDO assertion verification
```

Button primitive: `bool wasFreshPress()` - samples `A0` pull-up: need `HIGH->LOW` edge within 2s window, not `LOW` held. Debounce 50 ms, require release >200 ms before.

### 5.2 USB provisioning (host/MPU -> PLC/PAW via USB CDC 115200, `Serial`)

Keep `0xA1-0xA4` but add epoch:

```
Host -> Dev: 0xA1 target[1] epoch_be4[4] nonce[16]  (22B)  // was 2B
Dev -> Host: 0xA2 deviceId[4] epoch_be4[4]          // echo epoch
Host -> Dev: 0xA3 len[1]=16 key[16] crc32_be4[4] epoch_be4[4] // 26B, CRC over key only (keep), epoch for binding
Dev -> Host: 0xA4 hash4[4] epoch_be4[4]             // 9B, hash = SHA256(key)[:4]
```

PLC/PAW behavior: Verify `epoch == pendingEpoch` expected, store as `pendingKey/pendingEpoch` (do not overwrite `activeKey`), reply `0xA4`. On `COMMIT` (later slice, `0xB4` or Bridge), copy `pending -> active` only if both acked same epoch within window.

### 5.3 LoRa P2P (868 MHz, RadioLib, 0xB1-0xB3)

No change to packet sizes yet, but HMAC input becomes `HMAC-SHA256(activeKey, epoch_be4 || nonce16 || 0xB1)` for challenge and `epoch_be4 || nonce16 || 0xB2` for response. Add `epoch_be4` to challenge packet: `0xB1 nonce16 epoch4` (21B) and response `0xB2 nonce16 epoch4 hmac32` (53B). Keep constant-time compare, add replay cache (last 16 nonces, 60s window) and RSSI gate `if (radio.getRSSI() < -70) discard`.

## 6. Files to change

*   **MAMA BEAR MCU** `key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino` (672 lines) - add `activeKey[16], pendingKey[16], activeEpoch, pendingEpoch, pendingDeadline, grantReplayCache[8][16]`, epoch increment, one-time grant check, button edge, state `PENDING_*`, `COMMIT`/`CANCEL`, fix `Serial1` -> `Serial` for USB (or keep `Serial1` for router and use `Serial` for USB - decide: `Serial` is USB CDC, `Serial1` is LPUART1 router, `Serial2` is usart3 D20/D21 - use `Serial` for USB provisioning, keep `Serial1` for router, do not mix).
*   **MAMA BEAR MPU** `key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py` (740 lines) - keep `BridgeRPC` but fix `recv` to msgpack-unpack one frame, add `generate_grant(op,target,epoch)` helper for placeholder, add FIDO CTAP2 via `fido2` library later, add recovery code verifier (argon2).
*   **PLC** `plc/plc-key-receiver/plc-key-receiver.ino` (632 lines dirty) - add `activeKey/pendingKey`, `activeEpoch/pendingEpoch`, `pendingDeadline`, change `receiveKey()` to USB `Serial` with epoch, add `commitPending()` with 10 min window, fix `generateNonce` to use `analogRead(A0)` + `micros()` hashed or RP2350 `get_rand_32`, fix `verifyResponse` to compare `echoedNonce == currentNonce` and check epoch, add replay cache, RSSI gate, constant-time already OK.
*   **PAW** `id-kort/paw-main/paw-main.ino` (639 lines) + `id-kort/paw-key-receiver/paw-key-receiver.ino` (317 lines) - same epoch/pending split, USB `Serial`, remove `Serial.write(txPacket)` leak on USB (`paw-main:612`), add HMAC context `epoch`.
*   **Docs** `docs/02-arkitektur.md`, `docs/implementation-plan-fido.md` (new), `README.md` - update state diagram, protocol tables, threat model.
*   **Tests** `tests/` - new `test_provisioning.py` (pytest, pyserial mock), `test_lora_hmac.py` (known vectors), `test_replay.py`.

## 7. Risks

*   **USB vs UART mismatch** - Committed code still UART. Flashing dirty `Serial` patch without commit will break CI. Mitigation: Commit USB transport first (already done in `5035710` for docs, now do for code).
*   **Key exposure via debug** - `Serial.printf` nonce/HMAC leaks. Mitigation: Gate debug behind `DEBUG` build flag, never log key/nonce.
*   **TRNG bug** - `RNG_CR` toggle without FIFO drain (`:140`). Mitigation: Disable RNG, delay, drain `RNG_DR` 4 times, re-enable.
*   **Bridge hang** - `BridgeRPC.call` unbounded `recv`. Mitigation: Use `msgpack.Unpacker` with `recv(4096)` one frame and timeout, as in `SHALLOT_MamaBear/app/app.py: mcu_cmd`.
*   **FIDO spoof** - Current `lsusb` VID check is bypass. Mitigation: First slice uses placeholder grant (random token + button), not real FIDO, but enforces one-time + expiry + operation binding on MCU. Real FIDO in slice 3 will use `fido2` CTAP2 `getAssertion` with `challenge = grantToken`.
*   **Epoch rollback** - No monotonic storage. Mitigation: Store `activeEpoch` in `EEPROM` or `flash0` `storage_partition` with wear leveling, but for prototype keep in RAM and document as limitation (power loss resets epoch - acceptable for prototype, not production).

## 8. Tests (mandatory)

*   `test_no_grant_denied` - `request_key_generation` without grant, with held button, with expired grant (expiry < millis), with replayed grant -> all denied, state stays `IDLE`, audit shows `FAILED` no key.
*   `test_wrong_binding` - grant with `op=STAGE_PLC` used for `GENERATE_KEY`, `target=PAW` used for `PLC`, `epoch=99` vs expected `1` -> denied.
*   `test_button_held` - Hold `A0 LOW` for 3s then call `request_key_generation` with valid grant -> denied (needs fresh edge).
*   `test_usb_missing` - Call `STAGE_PLC` when PLC not on hub (timeout 5s) -> `FAILED`, `activeKey` unchanged.
*   `test_one_staged_other_fails` - Stage PLC OK, stage PAW timeout -> `FAILED`, `pendingKey` invalidated, `activeEpoch` still old.
*   `test_interrupted_transfer` - Send `0xA1` then disconnect USB mid-`0xA3` -> no `STORED`, device stays on old epoch.
*   `test_lora_replay` - Record valid `0xB2` response, replay within 30s -> PLC `verifyResponse` rejects (nonce cache), stays fail-closed.
*   `test_lora_invalid_hmac` - Flip one bit in HMAC -> `diff !=0` -> `FAILED`, no `MSG_RESULT 0x01`.
*   `test_audit_no_secrets` - Generate and stage, then grep `audit/provisioning_log.jsonl` for key hex, recovery code, grantToken -> must not appear, only `fp`, `epoch`, `op`, `outcome`.

## 9. Vertical slices

**Slice 1 (this PR):** Add `activeEpoch/pendingEpoch`, `pendingKey`, `grantReplayCache`, `wasFreshPress()`, and `request_key_generation(grant)` with placeholder token check (random 16B + epoch + op + expiry). Keep `distribute_key_now` but gate on `wasFreshPress() && verifyGrant()`. No real FIDO yet. Tests: `test_no_grant_denied`, `test_wrong_binding`, `test_button_held`, `test_audit_no_secrets`.

**Slice 2:** Add `STAGE_PLC/STAGE_PAW` with USB `0xA1` epoch, store as `pending`, require both `0xA4` acks with same epoch, add `COMMIT` with 10 min `millis()` window, `CANCEL/EXPIRE` invalidates pending. Tests: `test_usb_missing`, `test_one_staged_other_fails`, `test_interrupted_transfer`.

**Slice 3:** Replace placeholder with Pico FIDO CTAP2: MPU `fido2` `ClientPin` `getAssertion` with `challenge = grantToken`, MCU verifies `hmac_sha256(fidoRootPubKey, challenge)` or stores `fidoCredentialId` allowlist. Add `SESSION_STARTED` with recovery code verifier. Tests: `test_fido_wrong_origin`, `test_fido_replay`.

**Slice 4:** Add device identity: PLC/PAW generate `P-256` keypair on first boot, store private in flash with RP2350 `get_rand_32` + `OTP` note, MPU allowlist `pubkeyHash`, challenge `sessionNonce || deviceId || role || op || epoch` signed with `mbedtls ecdsa`, MCU verifies. Tests: `test_wrong_device_signature`.

## 10. Deliverables for slice 1

*   Updated `uno-q-key-authority-mcu.ino` with epoch + grant
*   Minimal MPU helper `generate_placeholder_grant()` for tests
*   `tests/test_provisioning.py` with 4 mandatory negative tests
*   Updated `docs/02-arkitektur.md` state diagram (Mermaid) and `docs/threat-model.md`
*   Hardware checklist: USB hub, all three on hub, no UART, button A0, FIDO key not yet required (placeholder)
