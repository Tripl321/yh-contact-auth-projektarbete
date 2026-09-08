# SHALLOT Provisioning v2 — Security Design

**Status:** Draft, awaiting approval. No implementation changes until approved.
**Date:** 2026-09-07
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

---

## 2. Per-Device Bootstrap Secret

### 2.1 What it is

Each device (PLC, PAW) has a **bootstrap secret** — a 32-byte random key installed once during manufacturing setup. This secret is the root of trust for the provisioning channel.

### 2.2 How it is first installed

**One-time setup (per device, before first provisioning):**

1. Device is connected to a **trusted setup workstation** (not MAMA BEAR).
2. A setup script generates a 32-byte random bootstrap secret using the workstation's CSPRNG.
3. The secret is written to the device's **flash** via USB (using a dedicated setup command).
4. The device stores it in a **persistent flash sector** that survives reboot.
5. The workstation computes `SHA-256(bootstrap_secret)` and records the hash.
6. MAMA BEAR (MCU) stores only `SHA-256(bootstrap_secret)` per device — the **allowlist entry**.
7. The workstation erases its copy of the plaintext secret.

**Result:**
- Device has the plaintext bootstrap secret in flash.
- MCU has only the hash (for identity verification, not for encryption).
- No other party has the plaintext secret.

### 2.3 How it is protected

| Platform | Storage | Protection |
|----------|---------|------------|
| **PLC (RP2350)** | Dedicated flash sector (not overlaid by firmware) | Flash protection (RP2350 can disable read/write via debug interface if configured) |
| **PAW (RP2350)** | Same as PLC | Same as PLC |
| **MCU (STM32U585)** | Stores only hashes, not plaintext secrets | RDP Level 1 (readout protection, already available) |

**Prototype limitation:** RP2350 flash protection is not permanently locked (no OTP burn). An attacker with physical access and debug equipment could read the bootstrap secret. This is accepted in the prototype threat model (casual physical access only).

### 2.4 Transport key derivation

For each provisioning envelope, the transport key is derived:

```
transport_key = HMAC-SHA256(bootstrap_secret, "SHALLOT_ENVELOPE_v2" || session_nonce)[0:16]
```

- `bootstrap_secret`: 32 bytes, unique per device, stored in flash
- `session_nonce`: 12 bytes, fresh per envelope (from MCU TRNG or entropy)
- `transport_key`: 16 bytes (AES-128 key)

This means:
- MCU must know the bootstrap secret to derive the transport key.
- **Problem:** MCU only stores the hash, not the plaintext secret.

### 2.5 Bootstrap secret on MCU

The MCU must have the plaintext bootstrap secret to encrypt envelopes. Options:

**Option A: MCU stores plaintext bootstrap secrets (prototype)**
- MCU stores plaintext 32-byte secrets for PLC and PAW in flash.
- Protected by RDP Level 1.
- Simple, works for prototype.
- Risk: MCU compromise reveals all device secrets.

**Option B: Mutual key agreement (production)**
- MCU and device perform an ECDH key agreement at provisioning start.
- Bootstrap secret is used only to authenticate the agreement.
- MCU never stores long-term device secrets.
- Requires ECDH on all platforms — more complex.

**Recommendation for prototype:** Option A. Document the limitation. Move to Option B in production.

---

## 3. MCU-Based Key Wrapping

### 3.1 Construction: AES-128-GCM

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Cipher** | AES-128 | Matches SHALLOT_AES_KEY_SIZE; available on all platforms |
| **Mode** | GCM (NIST SP 800-38D) | Authenticated encryption with AAD |
| **Key** | transport_key (16 bytes) | Per-device, per-session derived |
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

### 3.3 Encryption (MCU side)

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

### 3.4 Relay (MPU side)

```
1. MPU receives hex envelope from MCU via Bridge RPC
2. MPU converts hex to bytes (57 bytes)
3. MPU opens /dev/serial/by-id/<device>
4. MPU writes 57 bytes to serial port
5. MPU reads receipt (0xA4 STORED: hash + epoch, 9 bytes)
6. MPU reports receipt to MCU via Bridge RPC
```

**MPU never sees plaintext.** It handles only ciphertext + metadata.

### 3.5 Decryption (PLC/PAW side)

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
   - Verify epoch > active_epoch (freshness)
   - IF stale epoch: zeroize, send error, return
   - Stage key as pending (not active)
   - Send 0xA4 STORED (hash + epoch)
   - Zeroize: transport_key, plaintext
```

---

## 4. Reboot-Safe Nonce/Counter Lifecycle

### 4.1 Nonce generation

Nonces are generated by the MCU for each envelope:
- 12 bytes from MCU TRNG (or `millis()` + `micros()` entropy for prototype)
- **Must be unique per transport_key.** Reusing a nonce with the same key breaks GCM.
- MCU tracks the last used nonce per device in volatile SRAM
- On reboot, MCU's epoch counter resets to 0 — but transport keys are re-derived with fresh nonces, so reboot does not cause nonce reuse as long as TRNG is functional

### 4.2 Epoch counter

- 32-bit monotonically increasing counter, stored in MCU SRAM (volatile)
- Starts at 0 on boot
- Incremented on each key generation
- Devices track `active_epoch` and `pending_epoch` in SRAM
- On device reboot: `active_epoch = 0`, no key stored
- This means a device reboot requires re-provisioning (expected for prototype)

### 4.3 Sequence number (seq)

- 1 byte, per-provisioning-round
- Used for retry disambiguation (same epoch + seq = idempotent)
- Not a security control — GCM nonce + AAD provide replay protection
- Reset to 0 for each new epoch

### 4.4 Replay protection

**Per-device replay cache (in SRAM):**
- Device stores last accepted `(epoch, seq)` pair
- If a new envelope has the same `(epoch, seq)` as already staged: answer idempotently (resend STORED ack)
- If a new envelope has an older epoch than active: reject
- If a new envelope has a new epoch: accept and stage

**GCM tag binds the AAD:** An attacker cannot replay an old envelope with a modified epoch because the GCM tag would not verify.

**Reboot behavior:**
- On device reboot, replay cache is cleared (SRAM volatile)
- An attacker could replay an old envelope after device reboot
- Mitigation: MCU generates fresh nonces, so old envelope's nonce+tag won't match the current bootstrap secret derivation
- **But:** If the bootstrap secret hasn't changed, the old envelope is still valid
- **Acceptable for prototype:** Device reboot requires re-provisioning session. MCU should not send old envelopes after device reboot.

---

## 5. Authenticated Metadata (AAD)

### 5.1 Fields

| Field | Size | Bound to | Prevents |
|-------|------|----------|----------|
| `target_id` | 1 byte | Device identity | Wrong-device key delivery (PLC gets PAW's key) |
| `epoch` | 4 bytes (BE) | Key epoch | Downgrade to old epoch |
| `seq` | 1 byte | Retry round | Replay of old retry |
| `version` | 1 byte | Protocol version | Downgrade to v1 (plaintext) protocol |

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

### 6.2 Device-side version check

1. Device reads `version` byte from frame (offset 40, not encrypted)
2. If `version == 1`: process as legacy plaintext frame (backward compatibility)
3. If `version == 2`: process as GCM envelope
4. If `version` is anything else: reject frame, log error

### 6.3 Downgrade prevention

- GCM tag covers the `version` field (it's in AAD).
- An attacker cannot downgrade a v2 envelope to v1 by changing the version byte — the tag would break.
- An attacker cannot force v1 mode by sending a v1 frame with a v2 key — the device would accept v1, but the MCU would only send v2 envelopes.
- **Transition period:** Both v1 and v2 are accepted during migration. After migration, devices can be configured to reject v1.

### 6.4 MCU-side version policy

- MCU always sends v2 envelopes when a bootstrap secret is available.
- If no bootstrap secret is stored for a device, MCU falls back to v1 (with a warning log).
- This fallback is temporary and should be removed after all devices are bootstrapped.

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
| **Version binding** | `version` in AAD — GCM tag breaks if version changed |
| **Replay protection** | Nonce uniqueness + epoch monotonicity + device replay cache |
| **Downgrade protection** | `version` in AAD — cannot downgrade v2 to v1 without breaking tag |
| **Constant-time tag check** | `br_gcm_check_tag()` returns uint32_t (1 or 0) |
| **Zeroization** | All sensitive buffers zeroed on both success and failure paths |
| **MPU isolation** | MPU sees only ciphertext + metadata, never plaintext |

---

## 8. Limitations (Prototype)

1. **Bootstrap secret in MCU flash (plaintext):** Option A. Not acceptable for production.
2. **RP2350 flash not OTP-locked:** Physical attacker with debug equipment can extract bootstrap secret.
3. **Nonce entropy:** Prototype uses `millis()` + `micros()` — not CSPRNG. MCU TRNG should be used.
4. **No forward secrecy:** If bootstrap secret is compromised, all past and future envelopes are compromised.
5. **Replay after device reboot:** Replay cache is in SRAM (volatile). Acceptable because reboot requires re-provisioning session.
6. **CRC32 in plaintext:** Redundant with GCM tag, but provides an independent integrity check after decryption.
7. **No key rotation of bootstrap secret:** Bootstrap secret is installed once. Rotation requires a new setup session.

---

## 9. Open Questions for Approval

1. **Is Option A (MCU stores plaintext bootstrap secrets) acceptable for the prototype?**
2. **Should the bootstrap secret be 32 bytes or 16 bytes?** (32 bytes proposed, 16 bytes matches AES key size)
3. **Should `version` be a single byte or larger?** (1 byte proposed)
4. **Should the device reject v1 frames after v2 is deployed?** (Configurable proposed)
5. **What is the maximum number of provisioning rounds before a device must be re-bootstrapped?** (No limit proposed for prototype)

---

## 10. Implementation Plan (After Approval)

1. Pin arduino-pico v6.0.0 (verified)
2. Create standalone AES-128-GCM known-answer tests for PLC/PAW using BearSSL + NIST test vectors
3. Prove MCU crypto path: either software AES-GCM compilation or Zephyr crypto activation
4. Implement v2 envelope in ShallotEnvelope.h (replace current SHA-256 CTR)
5. Implement bootstrap secret storage on PLC/PAW (flash sector)
6. Implement envelope encryption on MCU
7. Implement envelope decryption on PLC/PAW
8. Update MPU relay script for v2 envelope
9. End-to-end test with test vectors first, then with generated keys
10. No real keys over USB until all test vectors pass on all three targets
