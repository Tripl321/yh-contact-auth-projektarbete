# 14 — Provisioning v2: Automatic PAW Device-Identity Verification

Status: design v1.0 for review — **no firmware implementation yet**.
Wait for approval before any code changes.

## 1. Goal and non-goals

- **Goal:** Replace the manual e-paper VERIFY-code ceremony with automatic
  PAW device-identity verification. The MCU verifies cryptographically that
  it is provisioning the intended PAW. The operator authorizes the
  provisioning action but does not validate cryptographic values manually.
- **Non-goals:** LoRa transport, multi-device fan-out, key rotation over
  the air, recovery after compromise (re-run the ceremony).
- **Explicitly not revived:** raw-key export, legacy Serial1 provisioning,
  TOFU as a production fallback.

## 2. Roles and trust boundary

| Party | May see | Must never see |
|-------|---------|----------------|
| PAW (Feather RP2350) | Ed25519 identity secret key, session ephemeral secret, wrapped operations key | Other PAWs' identity keys, other sessions' secrets |
| MCU (STM32U585) | PAW Ed25519 public key (pinned), session ephemeral public, wrapped operations key | PAW Ed25519 secret key, other PAWs' material |
| MPU / Bridge (Linux) | Public values only: fingerprints, transcript metadata, audit events | Operational key, KEK, DH shared secret, ephemeral secrets, PAW Ed25519 secret |
| Operator | Provisioning prompt (metadata/metadata only), audit log | Raw keys, crypto internals |

**Hard rule:** MPU code must handle only public fields. A source guard
will enforce the absence of key-named variables in the MPU path (same
enforcement as docs/12-envelope-protocol.md §2).

## 3. Cryptographic primitives

| Function | Algorithm | Purpose |
|----------|-----------|---------|
| Identity signing | Ed25519 (EdDSA on Curve25519) | PAW proves identity to MCU |
| Ephemeral key exchange | X25519 | Session KEK derivation (reuses vetted BearSSL subset) |
| KDF | HKDF-SHA256 | Session KEK from DH shared secret |
| Symmetric wrap | AES-128-GCM | Operations key confidentiality + integrity |
| Hash | SHA-256 | Transcript binding, AAD, fingerprints |
| TRNG | STM32U585 RNG / RP2350 TRNG | Fresh nonces, ephemeral secrets |

### 3.1 Vetted foundation

The X25519, AES-GCM, SHA-256, and HKDF primitives are already vetted
via `libraries/EnvelopeCrypto` (BearSSL subset). On-silicon proof covers
both Feather RP2350 and UNO Q STM32U585 (see VETTING-NOTE.md). The
i15 backend (`ec_c25519_i15.c`) provides Curve25519 scalar multiplication
used by both X25519 and Ed25519.

**Ed25519 gap:** the current vendored subset includes only X25519
functions (key exchange). Ed25519 signing/verification requires adding
BearSSL's Ed25519 wrapper source files to the subset. These files
(`ed25519.c`, `ed25519_internal.h`, plus signature helpers) are part
of the upstream BearSSL distribution under the same LGPL-3.0+ licence
as the current subset. The `ec_c25519_i15.c` and all `i15_*.c` files
are shared — no duplication. Estimated addition: ~2–4 KB flash,
<100 B RAM. Feasibility proven in §7.

## 4. Protocol specification

### 4.1 Key types

- **Identity keypair (long-term):** Each PAW has an Ed25519 keypair
  `(id_sk, id_pk)` generated once at manufacture/provisioning. The
  public key `id_pk` is registered with the MCU and pinned to the
  PAW's `device_id`. The secret key never leaves PAW SRAM.
- **Ephemeral keypair (per session):** Both PAW and MCU generate a
  fresh X25519 keypair per provisioning session. These are ephemeral
  and discarded after the session completes or fails.

### 4.2 Enrolled PAW public key

The MCU stores a table mapping `device_id → id_pk`:

```
trust_root = { device_id_1: id_pk_1, device_id_2: id_pk_2, ... }
```

This table is provisioned at MCU manufacture (or via a separate
secure enrollment workflow described in §5). The MCU verifies that
every incoming `device_id` in E1 matches an entry in `trust_root`.

### 4.3 Message formats

All multi-byte integers big-endian on the wire.

#### E1 `PUBKEY` (77 B)

```
[0xB1][device_id 4][id_pk_pub 32][pub_P 32][nonce_P 8]
```

- `device_id`: 4 bytes, PAW's identity (e.g. `50 41 57 01`)
- `id_pk_pub`: 32 bytes, PAW's Ed25519 **identity** public key
- `pub_P`: 32 bytes, PAW's X25519 ephemeral public key
- `nonce_P`: 8 bytes, fresh random from PAW TRNG

PAW asserts its own `device_id` here so the MCU can bind it into the
trust-root lookup and AAD; the PAW re-checks with its true id at open,
so a swapped E1 fails signature verification.

#### E2 `ENVELOPE` (81 B)

```
[0xB2][epoch 4][pub_M 32][nonce_M 12][ct 16][tag 16]
```

- `epoch`: 4 bytes, MCU monotonic counter (§6)
- `pub_M`: 32 bytes, MCU's X25519 ephemeral public key
- `nonce_M`: 12 bytes, fresh random from MCU TRNG (also GCM IV)
- `ct`, `tag`: 16 bytes each, AES-128-GCM ciphertext and tag

The `ct` wraps the 16-byte operations key under the session KEK with
AAD = transcript (§7).

#### E3 `STORED` (4 B)

`id_pk_pub` fingerprint = SHA-256(id_pk_pub)[0:4]. This confirms to the
MCU that the PAW successfully verified and stored the key. Same
semantics as the legacy `0xA4` confirmation, so MCU verification logic
is unchanged.

#### USB-CDC framing (MPU↔PAW leg)

Self-delimiting hex lines, exact lengths:

```
E1:<len hex>\n
E2:<len hex>\n
E3:<8 hex>\n
RESULT:OK\n   (operator authorizes)
RESULT:FAIL\n (operator rejects)
```

Session control lines (PAW→MPU): `FIXTURE\n`, `ENVELOPE_START\n`,
`CANCEL\n`, `DISP:OK\n`, `DISP:FAIL <reason>\n`.

### 4.4 Protocol transcript (signed by PAW)

The PAW signs the following transcript with its Ed25519 secret key:

```
transcript = DOMAIN || VER || target_id || device_id || epoch_be4
             || id_pk_pub || pub_M || pub_P || nonce_P || nonce_M
```

Where `DOMAIN = "SHALLOT-PV2"` (12 bytes, no NUL), `VER = 0x02`.
Total transcript: 12+1+1+4+4+32+32+32+8+12 = 138 bytes.

The PAW computes `sig = Ed25519_sign(id_sk, transcript)`. The signature
is verified by the MCU using `id_pk_pub` looked up from `trust_root`
by `device_id`. The signature covers both ephemeral public keys, both
nonces, epoch, device binding — any substitution fails verification.

### 4.5 Key schedule

1. `shared = X25519(sec_M, pub_P)` on MCU; `X25519(sec_P, pub_M)` on PAW.
   Both sides compute the same shared secret from their own ephemeral
   secret and the peer's ephemeral public key.
2. Both sides apply the all-zero check (RFC 7748 §6 guidance).
3. `salt = SHA256(transcript)` — transcript-bound, never zero in practice.
4. `KEK = HKDF-SHA256(shared, salt = salt, info = "SHALLOT-PV2/KEK-v1")[0:16]`.
5. `ct, tag = AES-128-GCM-Enc(KEK, IV = nonce_M, pt = operations_key,
   aad = transcript)`.

Salt and info are public values; secrecy rests on `shared` alone. The
transcript commits to all public fields, so a KEK is useless outside
its session.

### 4.6 VERIFY value (retained for audit only)

`VERIFY = hex(SHA256(0xB1 || id_pk_pub || pub_M || pub_P))[0:16]` — 16 hex chars = 64 bits.
This is now an **audit/metadata** value, not a production gate. The
operator may see it on the MPU UI for traceability, but the ceremony
succeeds or fails automatically based on cryptographic verification.

### 4.7 Session completion

On successful E2 open:
1. PAW unwraps `operations_key`.
2. PAW verifies `id_pk_pub` matches the key used in the transcript.
3. PAW stores `operations_key` in SRAM (volatile, wiped on reset).
4. PAW emits E3 = `SHA-256(id_pk_pub)[0:4]`.
5. PAW emits `DISP:OK` (diagnostic UI only — see §8).
6. MCU receives E3, confirms fingerprint matches, logs audit event.

On failure: PAW wipes all session secrets, emits `DISP:FAIL <reason>`,
no E3, no operations key stored.

### 4.8 Epoch (replay + ordering)

- MCU keeps a monotonic `epoch` counter in SRAM, starting at 1, +1 per wrap.
- PAW keeps `lastEpoch` in SRAM and accepts an envelope iff `lastEpoch`
  is none or `epoch > lastEpoch`. Otherwise PAW wipes and aborts.
- On accept, PAW sets `lastEpoch = epoch` only after successful tag
  verification and operations-key unwrap.
- MCU reboot restarts its counter → PAW rejects the next envelope.
  Documented, accepted (operator re-runs ceremony).
- 32-bit wrap out of scope.

## 5. Enrollment

### 5.1 PAW identity key generation

At manufacture (or first secure provisioning), the PAW generates an
Ed25519 identity keypair `(id_sk, id_pk)` using its TRNG. `id_sk` is
written to PAW SRAM only (volatile). On every boot, the PAW re-derives
`id_pk` from `id_sk` if needed; `id_sk` is never written to flash.

**Flash limitation:** RP2350 flash is not a hardware-secure key store.
Physical extraction/cloning of `id_sk` from flash remains a residual
risk pending a secure element. This is explicitly documented in §9.

### 5.2 MCU trust-root registration

The MCU stores `trust_root = { device_id → id_pk }` in its flash or
protected SRAM. Registration options:

- **Option A (manufacture):** id_pk written to MCU during production
  test, verified against PAW via the certificate or manual check.
- **Option B (first ceremony):** The first provisioning session uses
  a pre-shared bootstrap key; subsequent sessions use the verified
  id_pk. Bootstrap keys are single-use and destroyed after first use.
- **Option C (QR code / manual entry):** id_pk hex string printed on
  PAW packaging, manually entered into MCU during provisioning.

Option A is the recommended default. Options B and C are fallbacks for
field re-provisioning.

### 5.3 Replacement and revocation

- **Replacement:** A PAW with a new identity keypair is registered in
  `trust_root` with a new `device_id` or by updating the existing entry
  via the MCU's secure provisioning interface. The old `id_pk` is
  marked revoked and rejected in signature verification.
- **Revocation:** The MCU removes the `device_id` entry from
  `trust_root` or marks it revoked. Any E1 from a revoked device fails
  signature verification immediately. Revoked devices cannot be
  re-enrolled without MCU-side intervention.
- **Audit:** All enrollment, replacement, and revocation events are
  logged to the MPU audit log with `device_id`, `timestamp`, `action`,
  and operator fingerprint/metadata.

## 6. Trust-boundary diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          MPU / Bridge (Linux)                     │
│  May see:  public values, fingerprints, audit metadata            │
│  Never sees: keys, KEK, DH secret, ephemeral secrets              │
│                                                                  │
│  [audit log] ←── fingerprints + metadata only                    │
│       │                                                          │
│  USB-CDC serial                                                   │
│       │                                                          │
├─────┴────────────────────────────────────────────────────────────┤
│                          PAW (RP2350)                             │
│  May see:  id_sk (SRAM only), session ephemeral secret,           │
│            operations_key (SRAM only)                             │
│  Never sees: id_pk is PUBLIC, other PAWs' secrets                 │
│                                                                  │
│  Ed25519_sign(id_sk, transcript) → sig                           │
│  X25519(sec_P, pub_M) → shared                                  │
│  HKDF → KEK, AES-GCM → unwrap operations_key                    │
│  Stores operations_key in SRAM ONLY                               │
│                                                                  │
├─────┬────────────────────────────────────────────────────────────┤
│  USB-CDC serial                                                   │
│       │                                                          │
├─────┴────────────────────────────────────────────────────────────┤
│                    MCU (STM32U585)                                │
│  May see:  trust_root (id_pk table), session ephemeral secret,    │
│            wrapped operations key                                │
│  Never sees: id_sk, PAW's ephemeral secret, operations key after │
│              unwrap is sent to PAW only                           │
│                                                                  │
│  Ed25519_verify(id_pk, transcript, sig) → accept/reject          │
│  X25519(sec_M, pub_P) → shared                                  │
│  HKDF → KEK, AES-GCM → wrap operations_key                      │
│  Epoch counter (monotonic)                                       │
└──────────────────────────────────────────────────────────────────┘
```

**Key observation:** The MPU/Bridge layer is a pure relay for public
values. It can observe, log, and forward, but cannot forge, decrypt,
or impersonate. The cryptographic binding is between PAW and MCU only.

## 7. Library/toolchain feasibility

### 7.1 Feather RP2350 (PAW)

| Resource | Available | Estimated need | Status |
|----------|-----------|----------------|--------|
| Flash | 2 MB | Current build ~66 KB + Ed25519 ~3 KB | ✓ Fits |
| SRAM | 264 KB | Current runtime ~8 KB + Ed25519 ~1 KB | ✓ Fits |
| TRNG | RP2350 hardware TRNG | Verified in existing firmware | ✓ Available |
| Toolchain | PlatformIO / Arduino IDE + earlephilhower | Existing setup | ✓ Available |
| BearSSL Ed25519 | Requires adding source files | ~3 KB flash | Feasible (§7.3) |

**Build size projection:** Current PAW build (103172 B with envelope
phase-2 flag ON) + Ed25519 source (~3 KB) ≈ 106–107 KB. Well within
the 2 MB flash budget.

### 7.2 UNO Q MCU (STM32U585)

| Resource | Available | Estimated need | Status |
|----------|-----------|----------------|--------|
| Flash | ~2 MB (STM32U585) | Current build ~128 KB | ✓ Fits |
| SRAM | ~320 KB | Current runtime ~4 KB | ✓ Fits |
| TRNG | STM32U585 hardware RNG | Verified (RNG_CR register access) | ✓ Available |
| Toolchain | Arduino IDE + ArduinoCore-zephyr | Existing setup | ✓ Available |
| BearSSL Ed25519 | Requires adding source files | ~3 KB flash | Feasible (§7.3) |

**Note:** The MCU's `trust_root` table must fit in flash/SRAM. For a
deployment of up to 256 PAWs, the table is 256 × (4 + 32) = 9216 bytes
— trivially fits in SRAM or flash.

### 7.3 Adding Ed25519 to the BearSSL subset

The current subset vendored from BearSSL 0.6 includes:
- `ec_c25519_i15.c` + `i15_*.c` — Curve25519 scalar multiplication
  (used by X25519 key exchange)

BearSSL's Ed25519 signing/verification is implemented in additional
source files from the upstream BearSSL distribution:
- `ed25519.c` — signature signing
- `ed25519_verify.c` — signature verification
- `ed25519_internal.h` — internal definitions
- `ed25519.h` — public API

These files depend on `ec_c25519_i15.c` and the `i15_*.c` files
already in the subset. They are licensed under LGPL-3.0+ (same as
current subset). The `br_ec_c25519_i15` instance is shared — Ed25519
calls `br_ec_c25519_i15.mul()` internally.

**Verification requirement:** Before adding Ed25519 source files, run
the existing `tests/test_envelope.py` KAT chain (already passing) and
add Ed25519-specific KATs from RFC 8032. The VETTING-NOTE.md process
(host + on-silicon + pinned digests) must be repeated.

### 7.4 Transport layer

The existing transport layer is sufficient:
- **MPU→PAW:** USB-CDC serial with self-delimiting hex lines (existing
  protocol, already tested)
- **MPU↔MCU:** Bridge RPC over internal socket (existing, tested)
- **MCU→PAW:** The MCU produces E2 and sends it to PAW via the same
  serial transport. The PAW parses and opens it.

No transport changes required.

## 8. Operator interaction

### 8.1 Start provisioning

The operator initiates via the MPU UI (button, CLI, or API call). The
MPU sends `ENVELOPE_START` to PAW and begins the protocol.

### 8.2 Authorization

The operator authorizes the provisioning **action** (not the cryptographic
values). The MPU shows:
- `device_id` (4 bytes)
- PAW hardware fingerprint / metadata
- Session transcript summary (epoch, public key fingerprints)
- A request to confirm: "Provision this device?"

A bare "yes" is acceptable because the cryptographic verification is
automatic. The operator is not validating signatures or key material.

### 8.3 Diagnostic UI

The e-paper display remains as **optional diagnostic UI only**. It
may show:
- `AUTHENTICATING` / `AUTHENTICATED` / `FAILED` status icons
- `VERIFY` fingerprint for audit traceability
- `DISP:OK` / `DISP:FAIL` status

No manual code comparison is required. The display is never a
production gate.

### 8.4 Audit

Every event is logged to the MPU audit log:
- `provisioning_start`: `device_id`, `operator_id`, `timestamp`
- `provisioning_success`: `device_id`, `e3_fingerprint`, `timestamp`
- `provisioning_failure`: `device_id`, `reason`, `timestamp`
- `enrollment`: `device_id`, `id_pk_fingerprint`, `operator_id`, `timestamp`
- `revocation`: `device_id`, `operator_id`, `timestamp`

Audit entries store fingerprints/metadata only — never raw keys.

## 9. Threat model and residual-risk table

| Threat | Attack vector | Mitigation | Residual risk |
|--------|---------------|------------|---------------|
| Replay attack | Re-send a captured E1/E2 | Epoch monotonic + transcript-bound AAD + nonce uniqueness | **None** — fresh nonce per session, epoch rejects old envelopes |
| Wrong-device provisioning | Attacker presents a different PAW's E1 | MCU verifies `device_id` against `trust_root`, Ed25519 signature must match `id_pk` for that `device_id` | **None** — only the PAW with the matching Ed25519 private key can produce a valid signature |
| Key substitution | Attacker substitutes `id_pk_pub` or `pub_M` | Both ephemeral public keys bound into transcript and AAD; signature covers the full transcript | **None** — substitution breaks signature verification |
| Tampered envelope | Modify ciphertext in transit | AES-128-GCM tag verification | **None** — any modification breaks the tag |
| Man-in-the-middle (MPU) | MPU relays incorrect values | MPU only relays bytes; cannot forge Ed25519 signatures or decrypt AES-GCM | **None** — MPU lacks Ed25519 secret key and KEK |
| MCU compromise | Attacker reads MCU flash | `trust_root` may be exposed; attacker can impersonate registered PAWs but cannot read PAW secrets | **Medium** — secure-element or flash-encryption mitigates; documented |
| PAW physical extraction | Extract `id_sk` from RP2350 | Volatile SRAM only; boot wipes SRAM | **High** — RP2350 flash is not a hardware-secure key store; physical extraction is possible. **Pending secure element.** |
| Epoch reset (MCU reboot) | MCU reboot resets epoch counter | PAW rejects envelopes with `epoch ≤ lastEpoch`; ceremony must re-run | **Low** — operator inconvenience only, no security breach |
| DoS (repeated envelopes) | Attacker sends many E1s | Epoch increment + rate limiting on MCU | **Low** — each attempt is fast, no state exhaustion |
| Supply chain (compromised PAW at manufacture) | PAW has pre-installed `id_sk` | Manufacturing process controls; verify PAW fingerprint at enrollment | **Medium** — requires physical access at manufacture |
| Audit log tampering | Attacker modifies MPU audit log | Append-only storage, separate host, cryptographic chaining (future) | **Medium** — current audit log is file-based; append-only and off-device storage recommended |

### 9.1 Explicit prototype limitation

**RP2350 flash is not a hardware-secure key store.** The Ed25519 identity
secret key (`id_sk`) resides in PAW SRAM only. A physical attacker with
access to the PAW can extract `id_sk` from flash or SRAM by desoldering
the chip or probing the buses. This means physical extraction/cloning
of a PAW's identity remains a **residual risk** pending the addition of a
secure element (e.g., ATECC608A, SE050) that provides hardware key
storage and Ed25519 signing internally.

This limitation is acceptable for the prototype and initial deployment
where physical access to PAWs is controlled. Production deployment
should migrate to a secure element for `id_sk` storage and signing.

### 9.2 Threat boundary (stated plainly)

The protocol assumes:
- Honest-but-buggy relay (MPU/Bridge): can observe and forward public
  values, cannot forge signatures or decrypt ciphertext.
- Honest operator: authorizes actions, does not validate crypto manually.
- Physical access control: PAWs are in controlled locations.

A malicious MPU operator with shell access can observe all public values
and potentially log them, but cannot forge an Ed25519 signature or decrypt
the AES-GCM wrapped key. A malicious operator who also has physical
access to a PAW can extract `id_sk` (see §9.1). Full compromise with
both shell access and physical access is outside the ceremony's threat
model and belongs to physical access control and off-device audit.

## 10. Fail-closed table

| Event | Behaviour |
|-------|-----------|
| Ed25519 signature verification fails | wipe all session secrets, no E3, `DISP:FAIL`, abort |
| All-zero shared secret | abort before wrap, `DISP:FAIL` |
| Epoch rule violated | wipe, abort, operator re-runs ceremony |
| `device_id` not in `trust_root` | reject E1 immediately, no wrap attempted |
| E2 timeout (no E2 within window) | PAW wipes `sec_P`, aborts, `DISP:FAIL` |
| Display render fails | staged key wiped, never committed, `DISP:FAIL` |
| Operator rejects | abort, nothing committed, audit logged |
| Cancel (in-flight only) | wipe staging/secrets, `DISP:CANCELLED` |
| Any AAD field mismatch | identical to signature failure |
| MCU reboot | PAW rejects next envelope (epoch reset), operator re-runs |

## 11. Test plan

### 11.1 RFC/NIST vectors

- **Ed25519:** RFC 8032 test vectors (all 4 cases: correct, wrong key,
  wrong signature, wrong message). Verified via `tests/test_envelope.py`
  infrastructure. Each vector must pass on host, Feather RP2350 (on-chip),
  and UNO Q STM32U585 (on-chip).
- **X25519:** RFC 7748 §6.1 test vectors (already passing in
  `tests/test_envelope.py`).
- **AES-GCM:** NIST SP 800-38D known-answer tests (already passing).
- **HKDF-SHA256:** RFC 5869 test vectors (already passing).
- **SHA-256:** NIST/FIPS 180-4 test vectors (already passing).

### 11.2 Negative tests

| Test | Description | Expected |
|------|-------------|----------|
| Replay | Re-send a valid E1/E2 from a previous session | Signature/epoch rejects; no key stored |
| Tamper | Flip a bit in E2 ciphertext | Tag verification fails; no key stored |
| Wrong device | E1 with valid format but `device_id` not in `trust_root` | E1 rejected immediately |
| Invalid signature | E1 from a PAW with a different `id_pk` not in `trust_root` | Signature verification fails |
| Revoked device | E1 from a previously revoked PAW | `trust_root` check rejects; no wrap attempted |
| Wrong epoch | E2 with `epoch ≤ lastEpoch` | Epoch rule rejects; PAW aborts |
| All-zero shared | Crafted inputs producing zero DH output | All-zero check catches; abort |
| Timeout | No E2 received within window | PAW wipes `sec_P`, `DISP:FAIL` |
| Degraded render | PAW with display failure | `DISP:FAIL`, no E3, no key stored |
| Operator reject | `RESULT:FAIL` | Key wiped, audit logged |
| Empty trust_root | MCU has no PAW registered | All E1s rejected |
| Duplicate nonce | Same `nonce_P` reused in a different session | Transcript-bound AAD ensures KEK differs; signature still binds |

### 11.3 Test infrastructure

Reuse the existing `tests/_envelope_lib.py` infrastructure:
- `_envelope_lib.py` builds `envelope.so` from `libraries/EnvelopeCrypto`
  and exposes C primitives via ctypes
- `tests/test_envelope.py` drives the golden vector
- Add Ed25519 KAT runner to `tests/test_envelope.py` (or new
  `tests/test_provisioning_v2.py`)
- On-silicon proof follows VETTING-NOTE.md process: host `.so`, Feather
  RP2350 on-chip, UNO Q STM32U585 on-chip

### 11.4 Bench verification

After firmware implementation, repeat the bench record process:
1. Flash PAW with v2 firmware
2. Flash MCU with v2 firmware (flag OFF for production; ON for fixture)
3. Run `envelope_fixture_session` or `envelope_session` from MPU script
4. Verify: automatic success without manual code comparison
5. Verify: all negative cases fail closed

## 12. Phased implementation plan

### Phase 1 — Design review and tooling (week 1)

- [ ] Review this specification
- [ ] Add Ed25519 source files to BearSSL subset
- [ ] Add RFC 8032 KATs to `tests/test_envelope.py`
- [ ] Verify Ed25519 on host + Feather RP2350 + UNO Q STM32U585
- [ ] Update `libraries/EnvelopeCrypto/VETTING-NOTE.md`
- [ ] Update `libraries/EnvelopeCrypto/library.properties`

### Phase 2 — MCU trust-root and verification (week 2)

- [ ] Add `trust_root` table to MCU firmware
- [ ] Implement Ed25519 signature verification on MCU
- [ ] Implement transcript construction and verification
- [ ] Add epoch counter logic
- [ ] Update Bridge RPC to handle v2 messages
- [ ] Update MPU script with v2 protocol handler
- [ ] Test: MCU verifies valid PAW signatures

### Phase 3 — PAW identity and signing (week 3)

- [ ] Add Ed25519 signing to PAW firmware
- [ ] Implement `trust_root` lookup by `device_id`
- [ ] Implement transcript construction and signing
- [ ] Add `id_pk_pub` to E1 message format
- [ ] Update PAW state machine for v2 ceremony
- [ ] Add E3 fingerprint (SHA-256(id_pk_pub)[0:4])
- [ ] Test: PAW signs transcript, MCU verifies

### Phase 4 — Integration and negative testing (week 4)

- [ ] End-to-end v2 ceremony on bench
- [ ] Run all negative tests (§11.2)
- [ ] Verify automatic success without manual code comparison
- [ ] Verify audit logging
- [ ] Verify enrollment and revocation workflows
- [ ] Verify fail-closed behavior for all events in §10

### Phase 5 — Production readiness (week 5, gated)

- [ ] Remove manual e-paper VERIFY ceremony code (mark as diagnostic only)
- [ ] Remove legacy `VERIFY` display as production gate
- [ ] Update docs/12-envelope-protocol.md to mark v0.2 as superseded
- [ ] Remove all raw-key export code paths (Phase 4 gate from
  docs/12-envelope-protocol.md §11)
- [ ] Security review of `trust_root` storage on MCU
- [ ] Document RP2350 flash limitation for production deployment
- [ ] Recommend secure element for production (`id_sk` in hardware)

### Phase 6 — Secure element (future, not in current scope)

- [ ] Integrate ATECC608A or SE050 for `id_sk` storage
- [ ] Move Ed25519 signing to secure element
- [ ] PAW firmware uses I2C/SPI to delegate signing
- [ ] Physical extraction no longer exposes `id_sk`

## 13. Message format summary

| Message | Direction | Size | Content |
|---------|-----------|------|---------|
| E1 `PUBKEY` | PAW→MCU | 77 B | `[0xB1][device_id 4][id_pk_pub 32][pub_P 32][nonce_P 8]` |
| E2 `ENVELOPE` | MCU→PAW | 81 B | `[0xB2][epoch 4][pub_M 32][nonce_M 12][ct 16][tag 16]` |
| E3 `STORED` | PAW→MCU | 4 B | `SHA-256(id_pk_pub)[0:4]` |
| RESULT:OK/FAIL | MPU→PAW | variable | Operator authorization |
| DISP:OK/FAIL | PAW→MPU | variable | Diagnostic status |
| FIXTURE/ENVELOPE_START/CANCEL | MPU→PAW | variable | Session control |

## 14. Changes to existing protocol

- `DOMAIN` changes from `"SHALLOT-ENV1"` to `"SHALLOT-PV2"` (protocol separation).
- `VER` changes from `0x01` to `0x02`.
- E1 format adds `id_pk_pub` (32 bytes) and `pub_P` (32 bytes). E1 length changes from 45 B to 77 B.
- E2 format unchanged (81 B), still carries MCU ephemeral public key.
- Transcript expands to include both ephemeral public keys: 138 bytes (was 106 B).
- E3 changes from 4-byte fingerprint of the unwrapped key to `SHA-256(id_pk_pub)[0:4]` — the PAW's identity fingerprint, confirming the PAW verified and stored the key.
- VERIFY becomes audit/metadata only, not a production gate.
- Ceremony is fully automatic; operator authorizes the action, not the cryptographic values.
