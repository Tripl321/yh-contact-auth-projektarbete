# SHALLOT Provisioning v2 — Security Design

**Status:** Draft, awaiting approval. No implementation changes until approved.
**Date:** 2026-09-07 (updated 2026-09-07)
**Scope:** Key provisioning from MAMA BEAR (UNO Q) to PLC and PAW via USB CDC relay through MPU (QRB2210 Linux).

---

## 1. Trust Model

| Component | Trusted with plaintext keys? | Trusted with ciphertext? | Trusted with metadata? |
|-----------|------------------------------|--------------------------|------------------------|
| **MCU (STM32U585)** | Yes — generates, encrypts, stores | Yes | Yes (epoch, target, fingerprint) |
| **MPU (QRB2210 Linux)** | **No** | Yes (relays ciphertext only) | Yes (epoch, target, status, fingerprint) |
| **PLC (RP2350)** | Yes — receives, decrypts, stores | Yes | Yes |
| **PAW (RP2350)** | Yes — receives, decrypts, stores | Yes | Yes |

**MPU is explicitly NOT trusted with plaintext key material.** It relays AES-128-GCM ciphertext from MCU to PLC/PAW via `/dev/ttyACM*`.

**Out of scope (lab prototype):** Physical compromise of the MCU (including flash extraction with debug equipment). The prototype relies on RDP Level 1 readout protection. Physical attacks requiring chip-level forensics are explicitly excluded from the threat model.

---

## 2. Per-Device Bootstrap Secret

### 2.1 What it is

Each device (PLC, PAW) has a **bootstrap secret** — a 32-byte cryptographically random key, unique per device, installed once during manufacturing setup. This secret is the root of trust for the provisioning channel. It is never used directly as an encryption key; it serves only as an input to HMAC-based key derivation.

- **Size:** 32 bytes (256 bits).
- **Uniqueness:** Each PLC and PAW has its own independently generated secret. No two devices share the same bootstrap secret.
- **Purpose:** HMAC/KDF input for deriving per-envelope AES-128-GCM transport keys. Never used directly as a GCM key.

### 2.2 How it is first installed

**One-time setup (per device, before first provisioning):**

1. Device is connected to a **trusted setup workstation** (not MAMA BEAR, not the provisioning fixture).
2. A setup script generates a 32-byte random bootstrap secret using the workstation's CSPRNG.
3. The secret is written to the device's **flash** via USB (using a dedicated setup command).
4. The device stores it in a **persistent flash sector** that survives reboot.
5. The workstation computes `SHA-256(bootstrap_secret)` and records the hash.
6. MAMA BEAR (MCU) stores the **plaintext** 32-byte bootstrap secret per device (see section 2.5).
7. **The workstation must erase its copy of the plaintext secret immediately after installation.** The setup script must securely delete (overwrite with zeros) the secret from RAM and any temporary storage. Only the hash is retained on the workstation for audit purposes.

**Result after setup:**
- Device has the plaintext bootstrap secret in flash.
- MCU has the plaintext bootstrap secret in flash (lab prototype only — see 2.5).
- Workstation has only the hash (for audit). Plaintext is erased.
- No other party has the plaintext secret.

### 2.3 How it is protected

| Platform | Storage | Protection |
|----------|---------|------------|
| **PLC (RP2350)** | Dedicated flash sector (not overlaid by firmware) | Flash protection (RP2350 can disable read/write via debug interface if configured) |
| **PAW (RP2350)** | Same as PLC | Same as PLC |
| **MCU (STM32U585)** | Plaintext 32-byte secrets for PLC and PAW in flash | RDP Level 1 (readout protection, already available) |

**Prototype limitation (explicitly out of scope):** RP2350 flash protection is not permanently locked (no OTP burn). An attacker with physical access and debug equipment could read the bootstrap secret. Physical compromise requiring chip-level forensics is **explicitly excluded** from the prototype threat model. The threat model covers remote attackers and casual unsupervised physical access only.

**Setup workstation requirement:** The plaintext bootstrap secret must be erased from the setup workstation immediately after installation. The setup script must:
- Generate the secret in a stack/heap buffer.
- Write it to the device via USB.
- Overwrite the buffer with zeros (volatile memset).
- Delete any temporary files containing the secret.
- Verify that no copy remains on disk (e.g., no swap, no temp files, no shell history).

### 2.4 Transport key derivation

The bootstrap secret is used as an HMAC/KDF input, not directly as an encryption key. For each provisioning envelope, the AES-128-GCM transport key is derived:

```
transport_key = HMAC-SHA256(bootstrap_secret, "SHALLOT_ENVELOPE_v2" || session_nonce)[0:16]
```

- `bootstrap_secret`: 32 bytes, unique per device, stored in flash (input to HMAC, never used as AES key directly)
- `session_nonce`: 12 bytes, fresh per envelope (from MCU TRNG or entropy)
- `transport_key`: 16 bytes (AES-128-GCM key), unique per envelope due to fresh nonce

This ensures:
- Different devices get different transport keys (different bootstrap secrets).
- Different envelopes for the same device get different transport keys (different nonces).
- Compromise of one transport key does not reveal the bootstrap secret (HMAC is one-way).
- The bootstrap secret itself is never passed to any AES-GCM function.

### 2.5 Bootstrap secret on MCU — lab prototype decision

**Decision:** The MCU stores **plaintext** 32-byte bootstrap secrets for PLC and PAW in flash. This is allowed **only for the lab prototype** under the following conditions:

1. **RDP Level 1 (readout protection) must be active** on the STM32U585. This prevents casual flash readout via debug interface.
2. **Physical compromise of the MCU is explicitly out of scope** for the prototype threat model. An attacker with chip-level forensics equipment could extract the secrets despite RDP.
3. **This is NOT acceptable for production.** The production path must use either:
   - ECDH key agreement (MCU never stores long-term device secrets), or
   - Hardware key wrapping on the STM32U585 SAES peripheral with a master key that never leaves the MCU.
4. The limitation must be documented in the threat model section of the final deliverable.

**Why this is acceptable for the prototype:**
- The prototype threat model excludes invasive physical attacks.
- RDP Level 1 prevents casual readout.
- The alternative (ECDH or SAES key wrapping) requires significantly more implementation work and is deferred to the production track.

---

## 3. MCU-Based Key Wrapping

### 3.1 Construction: AES-128-GCM

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Cipher** | AES-128 | Matches SHALLOT_AES_KEY_SIZE; available on all platforms |
| **Mode** | GCM (NIST SP 800-38D) | Authenticated encryption with AAD |
| **Key** | transport_key (16 bytes) | Per-device, per-envelope derived via HMAC-SHA256 |
| **Nonce** | 12 bytes, unique per envelope | GCM standard nonce size (RFC 5116) |
| **Tag** | 16 bytes | Full GCM tag (not truncated) |
| **Plaintext** | AES_key(16) + CRC32(4) = 20 bytes | Operational key + integrity check |
| **AAD** | target_id(1) + epoch_be4(4) + seq(1) + protocol_version(1) = 7 bytes | Authenticates metadata without encrypting it |

### 3.2 Envelope wire format

```
Offset  Field           Size  Description
0       msg_type         1     0xA3 (SHALLOT_MSG_KEY_DATA)
1       ciphertext_len   1     20 (fixed)
2-21    ciphertext       20    AES-128-GCM encrypted key + CRC32
22-33   nonce            12    Unique per envelope (from MCU entropy)
34-37   epoch            4     Big-endian epoch (also in AAD)
38      seq              1     Sequence number (also in AAD)
39      target_id        1     Target device (also in AAD)
40      version          1     Protocol version (also in AAD)
41-56   tag              16    AES-128-GCM authentication tag
Total:  57 bytes
```

### 3.3 MCU crypto path — alternative B (software AES-128-GCM)

**Decision:** MCU alternative B (software AES-128-GCM in sketch) is selected, **but only if** an established, version-pinned AES-128-GCM implementation can be verified. No custom cryptography will be written.

**Requirements for alternative B:**
1. The implementation must be from an established, audited library (e.g., BearSSL, mbedtls, tinyAES+GCM module).
2. The library version must be pinned and documented.
3. KAT tests must pass on the MCU before any envelope implementation.
4. The implementation must not rely on MCU hardware peripherals (that requires loader rebuild, deferred to production track).

**Direct register access to the STM32U585 AES peripheral (alternative C) is excluded.** Loader rebuild (alternative A) is a production track, deferred.

**Current blocker for MCU:** No AES-GCM symbols are exported via LLEXT to sketches. The Zephyr loader does not compile or link any crypto library. The STM32 HAL CRYP headers exist in the llext-edk but are not compiled. Options to resolve:

- **B-1:** Include BearSSL source in the MCU sketch build. BearSSL is C99, portable to ARM Cortex-M33. This requires adding BearSSL source files to the sketch's compilation. Version-pin: BearSSL as shipped with arduino-pico v6.0.0.
- **B-2:** Include a minimal, established AES-GCM C library (e.g., mbedtls AES-GCM module) as a sketch include. Requires version-pinning and KAT verification.

**If neither B-1 nor B-2 can be verified:** Report as a blocker. Do NOT implement a custom AES-GCM. Do NOT send any keys over USB until the MCU crypto path is proven.

### 3.4 Encryption (MCU side)

```
1. MCU generates AES-128 operational key (TRNG)
2. MCU generates 12-byte nonce (TRNG or entropy)
3. transport_key = HMAC-SHA256(bootstrap_secret, "SHALLOT_ENVELOPE_v2" || nonce)[0:16]
4. AAD = target_id || epoch_be4 || seq || version
5. plaintext = operational_key || CRC32(operational_key || epoch_be4)
6. (ciphertext, tag) = AES-128-GCM-Encrypt(transport_key, nonce, AAD, plaintext)
7. Build envelope frame (57 bytes)
8. Zeroize: transport_key, plaintext
9. Return frame as hex string to MPU via Bridge RPC
```

### 3.5 Relay (MPU side)

```
1. MPU receives hex envelope from MCU via Bridge RPC
2. MPU converts hex to bytes (57 bytes)
3. MPU opens /dev/serial/by-id/<device>
4. MPU writes 57 bytes to serial port
5. MPU reads receipt (0xA4 STORED: hash + epoch, 9 bytes)
6. MPU reports receipt to MCU via Bridge RPC
```

**MPU never sees plaintext.** It handles only ciphertext + metadata.

### 3.6 Decryption (PLC/PAW side)

```
1. Device receives 57-byte frame on Serial
2. Extract: ciphertext, nonce, epoch, seq, target_id, version, tag
3. Build AAD = target_id || epoch_be4 || seq || version
4. transport_key = HMAC-SHA256(bootstrap_secret, "SHALLOT_ENVELOPE_v2" || nonce)[0:16]
5. AES-128-GCM-Decrypt(transport_key, nonce, AAD, ciphertext, tag)
   - br_gcm_check_tag() returns 1 (match) or 0 (mismatch) — constant-time
6. IF tag mismatch:
   - Zeroize: transport_key, ciphertext, all buffers
   - Send error response
   - Return (do NOT use plaintext)
7. IF tag match:
   - Verify CRC32(plaintext[0:16] || epoch_be4) == plaintext[16:20]
   - IF CRC mismatch: zeroize, send error, return
   - Verify epoch freshness (see section 4.5)
   - Stage key as pending (not active)
   - Send 0xA4 STORED (hash + epoch)
   - Zeroize: transport_key, plaintext
```

---

## 4. Nonce/Counter Lifecycle — NOT Reboot-Safe (Explicit)

### 4.1 Nonce generation

Nonces are generated by the MCU for each envelope:
- 12 bytes from MCU TRNG (or `millis()` + `micros()` entropy for prototype)
- **Must be unique per transport_key.** Reusing a nonce with the same key breaks GCM.
- MCU tracks the last used nonce per device in volatile SRAM
- **NOT reboot-safe:** On MCU reboot, the nonce tracking state is lost. If TRNG is functional, fresh nonces are generated after reboot, so nonce reuse is unlikely. If TRNG is NOT functional (e.g., `CONFIG_TEST_RANDOM_GENERATOR` is accidentally enabled), nonce reuse is possible — this is a safety-critical failure that must fail-closed.

### 4.2 Epoch counter — NOT reboot-safe

- 32-bit monotonically increasing counter, stored in MCU SRAM (**volatile**)
- Starts at 0 on boot
- Incremented on each key generation
- **NOT reboot-safe:** On MCU reboot, epoch resets to 0. Devices that were provisioned before the reboot have a higher epoch. This means:
  - After MCU reboot, a new provisioning session starts at epoch 1.
  - Devices must accept epoch 1 as fresh (since their SRAM is also cleared on reboot).
  - If a device has NOT rebooted but the MCU has, the device would reject epoch 1 (stale). This is a known limitation.
  - In practice, all devices are rebooted together with the MCU during a provisioning session.

### 4.3 Sequence number (seq)

- 1 byte, per-provisioning-round
- Used for retry disambiguation (same epoch + seq = idempotent)
- Not a security control — GCM nonce + AAD provide replay protection
- Reset to 0 for each new epoch
- **NOT reboot-safe:** Same as epoch, stored in SRAM.

### 4.4 Replay cache — NOT reboot-safe

**Per-device replay cache (in SRAM):**
- Device stores last accepted `(epoch, seq)` pair
- If a new envelope has the same `(epoch, seq)` as already staged: answer idempotently (resend STORED ack)
- If a new envelope has an older epoch than active: reject
- If a new envelope has a new epoch: accept and stage

**NOT reboot-safe:** On device reboot, the replay cache is cleared. An attacker who captured an old envelope (before the device rebooted) could replay it after the device reboots. The GCM tag would still verify because:
- The bootstrap secret has not changed.
- The nonce, epoch, and seq in the captured envelope are valid.

**This is a known vulnerability.** Section 4.5 defines the authenticated re-provisioning flow to mitigate it.

### 4.5 Authenticated re-provisioning flow (reboot-safe)

**Problem:** After a device reboot, the replay cache is empty. An attacker can replay a captured envelope.

**Solution:** After a device reboot, the device enters a **post-reboot state** where it refuses to accept any envelope until it has completed an authenticated re-provisioning handshake with the MCU.

**Post-reboot state:**
1. On boot, the device sets `active_epoch = 0`, `pending_epoch = 0`, `replay_cache = empty`.
2. The device sets a flag `REQUIRES_REPROVISION = true`.
3. While `REQUIRES_REPROVISION` is true, the device refuses ALL key envelopes (both v1 and v2).
4. The device only accepts a **re-provisioning initiation** message from the MCU.

**Re-provisioning initiation:**
1. MCU sends a `SHALLOT_MSG_REPROVISION` (new message type, e.g., 0xA8) to the device.
2. This message contains:
   - `target_id` (1 byte)
   - `fresh_challenge` (16 bytes, from MCU TRNG)
   - `epoch_be4` (4 bytes, the new epoch)
   - `version` (1 byte, must be 2)
3. This message is authenticated with a GCM tag using the bootstrap secret-derived transport key.
4. The device verifies the tag (GCM with AAD = target_id || epoch_be4 || version).
5. If verified, the device:
   - Clears `REQUIRES_REPROVISION`
   - Sets `expected_epoch = epoch from message`
   - Begins accepting v2 envelopes for this epoch
6. If not verified, the device rejects and stays in `REQUIRES_REPROVISION`.

**Effect:** An attacker cannot replay an old envelope after a device reboot because:
- The device is in `REQUIRES_REPROVISION` state.
- The attacker would need to send a valid `SHALLOT_MSG_REPROVISION` with a correct GCM tag.
- Without the bootstrap secret, the attacker cannot produce a valid tag.
- A captured old `SHALLOT_MSG_REPROVISION` has a different `epoch` — the device would reject it (epoch mismatch with current expected epoch).

**Boot banner:** The device's boot banner (visible on Serial) includes `REQUIRES_REPROVISION: YES/NO` so the operator can verify the state.

---

## 5. Authenticated Metadata (AAD)

### 5.1 Fields

| Field | Size | Bound to | Prevents |
|-------|------|----------|----------|
| `target_id` | 1 byte | Device identity | Wrong-device key delivery (PLC gets PAW's key) |
| `epoch` | 4 bytes (BE) | Key epoch | Downgrade to old epoch |
| `seq` | 1 byte | Retry round | Replay of old retry |
| `version` | 1 byte | Protocol version | Version confusion (but NOT sufficient alone for downgrade protection — see section 6) |

### 5.2 Why each field is in AAD (not just in plaintext)

- **AAD is authenticated but not encrypted.** The device can read these fields before decryption and use them to decide whether to proceed.
- **GCM tag covers AAD + ciphertext.** Modifying any AAD field invalidates the tag.
- This means an attacker cannot change `target_id` from PLC to PAW without breaking the tag.
- This means an attacker cannot change `epoch` from 2 to 1 without breaking the tag.

---

## 6. Explicit Version/Downgrade Handling

### 6.1 Protocol version field

- `version = 1`: Legacy plaintext key-data frame (current 0xA3 format, 27 bytes)
- `version = 2`: AES-128-GCM envelope (57 bytes, this design)

### 6.2 Version in AAD is NOT sufficient for downgrade protection

**The `version` field in AAD alone does NOT prevent downgrade attacks.** An attacker can send a v1 frame (which has no GCM tag and no version authentication) to a device that accepts both v1 and v2. The v1 frame would be processed as a valid plaintext key, bypassing the v2 authentication entirely.

**Therefore, downgrade protection requires BOTH:**
1. `version` in AAD (prevents modifying v2 envelope's version field).
2. **A device-side policy that disables v1 acceptance** after v2 migration.

### 6.3 Device-side version policy

**Migration mode (default after bootstrap secret installation):**
- Device accepts BOTH v1 and v2 frames.
- Used during the transition period when not all devices have bootstrap secrets.

**V2-only mode (after migration complete):**
- Device accepts ONLY v2 frames.
- v1 frames are rejected with an error log.
- This mode is set by writing a persistent flag in flash (e.g., `V2_ONLY = true`).
- Once set, the device cannot be downgraded to accept v1 without:
  - A physical flash erase (which also erases the bootstrap secret), OR
  - An authenticated v2 migration command from the MCU.

**Authenticated migration mode toggle:**
- The MCU can send a `SHALLOT_MSG_SET_V2ONLY` (new message type) authenticated with GCM using the bootstrap secret.
- This prevents an attacker from forcing a device back into v1-accepting mode.

### 6.4 Legacy V1 permanent disable

**After V2 migration:**
- V1 acceptance is **permanently disabled** on each device via an authenticated v2 command.
- The device stores `V2_ONLY = true` in a persistent flash flag.
- No v1 frame is accepted after this flag is set.
- Clearing the flag requires erasing the bootstrap secret (which requires physical access and a new bootstrap setup).

### 6.5 MCU-side version policy

- MCU always sends v2 envelopes when a bootstrap secret is available for the target device.
- If no bootstrap secret is stored for a device, MCU falls back to v1 (with a warning log). This fallback is temporary and only used during initial migration.
- After all devices have bootstrap secrets and have been set to V2_ONLY mode, MCU code paths for v1 are removed.

---

## 7. Security Properties Summary

| Property | How achieved |
|----------|-------------|
| **Confidentiality** | AES-128-GCM encryption of operational key |
| **Integrity** | GCM tag covers ciphertext + AAD |
| **Authentication** | Transport key derived from per-device bootstrap secret; tag verification rejects wrong-key envelopes |
| **Target binding** | `target_id` in AAD — GCM tag breaks if target changed |
| **Epoch binding** | `epoch` in AAD — GCM tag breaks if epoch changed |
| **Seq binding** | `seq` in AAD — GCM tag breaks if seq changed |
| **Version binding** | `version` in AAD — GCM tag breaks if version changed (v2 only) |
| **Downgrade protection** | V2_ONLY persistent flag in flash + authenticated migration toggle (NOT version-in-AAD alone) |
| **Replay protection (within session)** | Nonce uniqueness + epoch monotonicity + device replay cache (SRAM) |
| **Replay protection (after reboot)** | Authenticated re-provisioning flow (section 4.5) — device refuses envelopes until `REQUIRES_REPROVISION` is cleared by authenticated handshake |
| **Constant-time tag check** | `br_gcm_check_tag()` returns uint32_t (1 or 0) |
| **Zeroization** | All sensitive buffers zeroed on both success and failure paths |
| **MPU isolation** | MPU sees only ciphertext + metadata, never plaintext |
| **Bootstrap secret erase** | Setup workstation erases plaintext secret after installation |

---

## 8. Limitations (Prototype)

1. **Bootstrap secret in MCU flash (plaintext):** Allowed for lab prototype with RDP Level 1. Physical compromise explicitly out of scope. NOT acceptable for production.
2. **RP2350 flash not OTP-locked:** Physical attacker with debug equipment can extract bootstrap secret. Out of scope for prototype threat model.
3. **Nonce entropy:** Prototype uses `millis()` + `micros()` — not CSPRNG. MCU TRNG should be used. If TRNG is not functional, this is a fail-closed condition.
4. **No forward secrecy:** If bootstrap secret is compromised, all past and future envelopes are compromised.
5. **SRAM epoch and replay cache are NOT reboot-safe:** Explicitly documented. Mitigated by authenticated re-provisioning flow (section 4.5).
6. **CRC32 in plaintext:** Redundant with GCM tag, but provides an independent integrity check after decryption.
7. **No key rotation of bootstrap secret:** Bootstrap secret is installed once. Rotation requires a new setup session on the trusted workstation.
8. **MCU software AES-GCM (alternative B):** Not hardware-accelerated. Must use an established, version-pinned library. No custom cryptography. If no verified library is available, this is a blocker.
9. **Setup workstation trust:** The setup workstation must be trusted. If the workstation is compromised during bootstrap secret installation, the secret is leaked. The workstation must erase the plaintext secret immediately after installation.

---

## 9. Resolved Decisions

1. **Bootstrap secret size:** 32 bytes (256 bits). Unique per PLC and PAW.
2. **Bootstrap secret usage:** HMAC/KDF input only. AES-128-GCM key derived per envelope via `HMAC-SHA256(bootstrap_secret, label || nonce)[0:16]`.
3. **MCU stores plaintext bootstrap secret:** Allowed for lab prototype only. RDP Level 1 must be active. Physical compromise explicitly out of scope.
4. **MCU crypto path:** Alternative B (software AES-128-GCM) only if an established, version-pinned library can be verified. No custom cryptography. If no library is verified: report blocker. Direct register access excluded. Loader rebuild deferred to production track.
5. **SRAM epoch/replay cache:** NOT reboot-safe. Mitigated by authenticated re-provisioning flow (section 4.5).
6. **Legacy V1:** Permanently disabled after V2 migration via authenticated v2 command setting `V2_ONLY` persistent flag. Version in AAD alone is NOT sufficient for downgrade protection.
7. **Setup workstation:** Must erase plaintext bootstrap secret immediately after installation.

---

## 10. Implementation Plan (After Approval)

1. ~~Pin arduino-pico v6.0.0~~ (done)
2. ~~Create standalone AES-128-GCM known-answer tests for PLC/PAW using BearSSL + NIST test vectors~~ (done, compiles on both targets)
3. Prove MCU crypto path: verify an established AES-128-GCM library compiles and KAT passes on MCU (alternative B). If blocker: report.
4. Implement v2 envelope (replace ShallotEnvelope.h SHA-256 CTR with AES-128-GCM using established library)
5. Implement bootstrap secret storage on PLC/PAW (flash sector)
6. Implement envelope encryption on MCU
7. Implement envelope decryption on PLC/PAW
8. Implement authenticated re-provisioning flow (section 4.5)
9. Implement V2_ONLY persistent flag and authenticated migration toggle
10. Update MPU relay script for v2 envelope
11. End-to-end test with test vectors first, then with generated keys
12. No real keys over USB until all test vectors pass on all three targets
