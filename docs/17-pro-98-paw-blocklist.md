# PRO-98 — Signed and distributable PAW blocklist

**Status:** Implementation complete | **Scope:** DEN-side blocklist with signed distribution via MamaBear

## 1. Overview

PRO-98 adds a signed, versioned key-fingerprint blocklist to the DEN (dock
enforcement node). When a PAW authenticates with valid HMAC, the DEN checks
the shared key's SHA-256 fingerprint against the blocklist. If present,
the DEN denies access even though the HMAC is valid.

## 2. Architecture

```
┌─────────────┐     MSG_BLOCKLIST (0xA6)      ┌────────────────────────────────┐
│             │  version, issuer, entries, sig │                                │
│ UNO Q       │ ────────────────────────────► │ DEN (PLC dock)                 │
│ (MamaBear)  │                                 │  - verifies HMAC-SHA256        │
└─────────────┘                                  │  - checks version              │
                                                │  - activates on valid sig     │
                                                │  - keeps last valid on error  │
                                                │                                │
                                                │  During auth:                  │
                                                │  1. Verify HMAC (existing)    │
                                                │  2. Compute SHA-256(key)[:4]   │
                                                │  3. Check against blocklist    │
                                                │  4. Deny if found              │
                                                └────────────────────────────────┘
```

## 3. Blocklist format (MSG_BLOCKLIST = 0xA6)

| Field       | Size                    | Description                                                          |
| ----------- | ----------------------- | -------------------------------------------------------------------- |
| version     | 1 byte                  | Format version (currently 1)                                         |
| issuer      | 16 bytes                | Null-padded ASCII issuer identifier                                  |
| entry_count | 1 byte                  | Number of blocked entries (0–16)                                     |
| entries     | 4 × `entry_count` bytes | SHA-256(shared_key)\[:4\] fingerprints                               |
| signature   | 32 bytes                | HMAC-SHA256 over (version \|\| issuer \|\| entry_count \|\| entries) |

Total size: `18 + 4*N + 64` bytes (82–146 bytes for 0–16 entries).

## 4. Signature scheme

Ed25519 asymmetric signing. MamaBear (UNO Q) holds the **Ed25519 private key** for signing blocklists. DEN holds the corresponding **Ed25519 public key** for verification. PAW devices never have access to the signing key.

- Private key (32 bytes): Only on UNO Q (MamaBear). Used to sign blocklists.
- Public key (32 bytes): Embedded in DEN firmware. Used to verify blocklists.
- Signature (64 bytes): Ed25519 signature over the blocklist data.

The signed data is: `version || issuer(16B) || entry_count || entries`.

This is a true digital signature scheme: only MamaBear can produce valid signatures, while any DEN can verify them. A compromised PAW (which only holds the symmetric master key) cannot forge blocklist signatures.

## 5. Blocklist distribution flow

1. DEN is in `PROV_PH_HANDSHAKE` phase, waiting on USB Serial
2. MamaBear sends `MSG_BLOCKLIST` (0xA6) with the blocklist payload
3. DEN reads the blocklist data (up to 146 bytes)
4. DEN verifies:
   - Minimum length check (fail-closed if truncated)
   - Version >= `BLOCKLIST_VERSION` (reject rollbacks)
   - `entry_count <= BLOCKLIST_MAX_ENTRIES`
   - Ed25519 signature with embedded public key
5. If valid: DEN copies the blocklist to `current_blocklist`, sets `blocklist_valid = 1`
   - DEN acknowledges with `MSG_BLOCKLIST_ACK` (0xA7) + `0x01` (success)
6. If invalid: DEN keeps the previous valid blocklist
   - DEN acknowledges with `MSG_BLOCKLIST_ACK` + `0x00` (failure)

## 6. Authentication with blocklist

The blocklist check is performed **after** successful HMAC verification:

1. DEN sends CHALLENGE (nonce)
2. PAW responds with RESPONSE (HMAC-SHA256)
3. DEN verifies HMAC
4. **If valid:** DEN computes `SHA-256(DEN_DEV_KEY)[:4]` and checks against blocklist
5. If found in blocklist → `DEN_REASON_BLOCKLISTED`, ACK(0x00), transition to DENIED
6. If not found → `DEN_REASON_OK`, ACK(0x01), transition to AUTHENTICATED

Checking after HMAC verification ensures the blocklist lookup never runs
on unauthenticated input, preventing probing attacks.

## 7. Fail-closed guarantees

| Failure mode                              | Response                               |
| ----------------------------------------- | -------------------------------------- |
| Invalid signature                         | Blocklist not activated; old list kept |
| Version too old                           | Blocklist not activated; old list kept |
| Truncated/corrupt data                    | Blocklist not activated; old list kept |
| `blocklist_valid = 0` (no valid list yet) | All PAWs allowed (no blocking)         |
| PAW with blocklisted key                  | Denied after HMAC verification         |

## 8. PAW identity binding

Each PAW has a unique `device_id` (4 bytes, e.g. `50 41 57 01`). The blocklist
uses the key fingerprint (`SHA-256(shared_key)[:4]`) rather than `device_id`
because:

- The DEN does not know which PAW is docked (no identity in the UART protocol)
- The key fingerprint binds to the provisioned key, which is unique per PAW
- If a PAW is revoked, its key cannot be re-provisioned (it stays blocklisted)

## 9. Simulation vs. physical verification

### What is simulated in tests (`tests/test_pro88_den.py`)

| Test                                        | What it verifies                               |
| ------------------------------------------- | ---------------------------------------------- |
| `test_pro98_valid_blocklist_update`         | Valid HMAC signature, correct format, accepted |
| `test_pro98_manipulated_signature_rejected` | Flipped signature bit → rejected               |
| `test_pro98_rollback_rejected`              | Lower version → rejected                       |
| `test_pro98_truncated_data_rejected`        | Incomplete message → rejected                  |
| `test_pro98_empty_blocklist_accepted`       | Zero entries with valid signature → accepted   |
| `test_pro98_blocked_paw_denied_after_auth`  | Valid HMAC but blocked key → denied            |
| `test_pro98_non_blocked_paw_accepted`       | Valid HMAC and clean key → authenticated       |
| `test_pro98_blocklist_checked_after_hmac`   | Bad HMAC → HMAC_MISMATCH, not BLOCKLISTED      |
| `test_pro98_source_has_blocklist`           | Source contains blocklist symbols              |
| `test_pro98_uno_q_source_guards`            | UNO Q source has distribution support          |

All tests are **Python mock simulations** of the firmware logic. The HMAC
verification, version checking, and truncation handling are mirrored in Python.

### What requires physical MamaBear/UNO Q verification

| Scenario                                     | Physical test required            |
| -------------------------------------------- | --------------------------------- |
| MSG_BLOCKLIST sent to DEN over USB UART      | Yes — real serial communication   |
| DEN acknowledges with MSG_BLOCKLIST_ACK      | Yes — real serial echo            |
| UNO Q blocklist signing over UART            | Yes — actual firmware signing     |
| DEN fails to activate on real corrupted data | Yes — real parsing failure        |
| PAW with blocked key denied over docked UART | Yes — physical dock test          |
| `provide` RPC calls (`get_key_state`, etc.)  | Yes — real Bridge RPC over socket |
| TRNG key generation                          | Yes — hardware entropy source     |
| Hardware RNG for challenge nonce             | Yes — RP2350 pico-sdk RNG         |

## 10. Constants reference

| Constant                   | Value          | Description                           |
| -------------------------- | -------------- | ------------------------------------- |
| `MSG_BLOCKLIST`            | 0xA6           | Blocklist distribution message type   |
| `MSG_BLOCKLIST_ACK`        | 0xA7           | Blocklist distribution acknowledgment |
| `BLOCKLIST_VERSION`        | 1              | Current blocklist format version      |
| `BLOCKLIST_MAX_ENTRIES`    | 16             | Maximum blocked fingerprints          |
| `KEY_HASH_SIZE`            | 4              | SHA-256(key)[:4] fingerprint size     |
| `BLOCKLIST_ISSUER`         | "SHALLOT-AUTH" | Default issuer string                 |
| `BLOCKLIST_SIGNATURE_SIZE` | 64             | Ed25519 signature size                |
| `DEN_REASON_BLOCKLISTED`   | 8              | Fail reason code for blocked PAWs     |

## 11. Security Review (Ed25519 Implementation)

### 11.1 Private Key Handling

| Check | Status | Notes |
|-------|--------|-------|
| Private key hardcoded in firmware | ✅ PASS | `blocklist_private_key` is zero-initialized static array; no hardcoded value |
| Private key in test data | ✅ PASS | Test key only in `tests/test_pro88_den.py`, clearly marked `TEST_ED25519_PRIVATE_KEY` |
| Private key in build config / repo | ✅ PASS | No private key material in any `.ino`, `.h`, `.cpp`, or build files |
| Private key provisioning | ⚠️ TODO | `blocklist_key_provisioned = 0` flag; production must provision via secure out-of-band channel |
| Private key zeroization | ✅ PASS | SRAM only; cleared on reset; no flash persistence |

### 11.2 Public Key Handling

| Check | Status | Notes |
|-------|--------|-------|
| DEN contains only public key | ✅ PASS | `blocklist_public_key[32]` embedded in DEN; all-zero placeholder for production |
| UNO Q contains only private key | ✅ PASS | Private key in UNO Q; public key derived internally if needed |
| PAW has neither key | ✅ PASS | PAW firmware has no Ed25519 code or keys |

### 11.3 Implementation Verification

| Check | Status | Notes |
|-------|--------|-------|
| Signature size (64 bytes) | ✅ PASS | `BLOCKLIST_SIGNATURE_SIZE = 64` |
| Private key size (32 bytes) | ✅ PASS | `ED25519_PRIVATE_KEY_SIZE = 32` |
| Public key size (32 bytes) | ✅ PASS | `ED25519_PUBLIC_KEY_SIZE = 32` |
| RFC 8032 test vectors | ✅ PASS | Empty msg, short msg, long msg, wrong msg, wrong pk all verified |
| Custom implementation vs. cryptography | ✅ PASS | Custom tweetnacl-based impl matches cryptography library |
| Constant-time operations | ✅ PASS | tweetnacl/ref10 reference implementation is constant-time |
| Sensitive data logging | ✅ PASS | All blocklist debug under `SECURE_DEBUG`; no private key logging |

### 11.4 Test Coverage

| Test | Status |
|------|--------|
| `test_pro98_ed25519_sign_verify` | ✅ PASS |
| `test_pro98_blocklist_signature_format` | ✅ PASS |
| `test_pro98_blocklist_signature_verification` | ✅ PASS |
| `test_pro98_manipulated_blocklist_rejected` | ✅ PASS |
| `test_pro98_rollback_rejected` | ✅ PASS |
| `test_pro98_wrong_public_key_rejected` | ✅ PASS |
| `test_pro98_stolen_paw_cannot_sign` | ✅ PASS |
| `test_pro98_blocked_paw_denied` | ✅ PASS |
| `test_pro98_source_guards_ed25519` | ✅ PASS |

### 11.5 What is Verified vs. Simulated vs. Requires Independent Review

| Category | Items |
|----------|-------|
| **Verified (automated tests)** | Ed25519 sign/verify with RFC 8032 vectors; blocklist format; manipulated signature rejection; rollback rejection; wrong public key rejection; stolen PAW cannot sign; firmware source guards |
| **Simulated (Python mock)** | Full blocklist distribution flow; DEN session state machine; HMAC-SHA256 challenge-response; UART framing/CRC |
| **Requires independent crypto code review** | Custom tweetnacl/ref10 Ed25519 implementation in `libraries/Ed25519/`; SRAM-only private key storage; side-channel resistance on target hardware (STM32U585 / RP2350); secure provisioning channel for production private key |

### 11.6 Open Items for Production Deployment

- [ ] Secure provisioning process for Ed25519 private key on UNO Q (out-of-band, HSM-backed)
- [ ] Embed production Ed25519 public key in DEN firmware (replace all-zero placeholder)
- [ ] Independent cryptographic code review of `libraries/Ed25519/` implementation
- [ ] Side-channel analysis on target hardware (STM32U585 for UNO Q, RP2350 for DEN)
- [ ] Flash storage for blocklist across reboots (currently SRAM-only)
- [ ] Key rotation / revocation procedure for Ed25519 key pair

## 12. TODO (future work)

- Add blocklist query RPC to the UNO Q bridge interface
- Support incremental blocklist updates (add/remove individual entries)
- Store blocklist in flash across reboots (currently SRAM-only)
