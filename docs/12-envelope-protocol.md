# 12 — Wrapped-key envelope protocol (USB-C provisioning)

Status: spec v0.1 for review. No firmware implements this yet; do not build
against it until the review is approved. Normative test vectors live in
`tests/test_envelope.py` and drive the real C in `libraries/EnvelopeCrypto`.

## 1. Goal and non-goals

- Goal: move a fresh 16-byte operational key from the UNO Q MCU to the PAW
  over USB-CDC such that the MPU (Linux) and the Bridge RPC layer only ever
  handle public values. Raw key bytes exist only in MCU SRAM and PAW SRAM.
- Non-goals: LoRa transport, multi-device fan-out, key rotation over the air,
  recovery after compromise (re-run the full ceremony).

## 2. Roles and trust boundary

| Party | May see | Must never see |
|-------|---------|----------------|
| MCU (STM32U585) | operational key, both e/OCTETS below | — |
| PAW (RP2350) | operational key after open, session secrets | other sessions' secrets |
| MPU / Bridge | pubkeys, nonces, epoch, ct, tag, fingerprints, VERIFY | operational key, KEK, DH shared secret, ephemeral secrets |

MPU code for Phase 2 must handle only the named public fields; a source
guard will enforce the absence of key-named variables in the MPU path.

## 3. Notation and constants

- `DOMAIN = "SHALLOT-ENV1"` (12 ASCII bytes), `VER = 0x01`.
- `target_id`: 1 byte, existing provisioning target (`0x01`/`0x02`).
- `device_id`: 4 bytes, PAW's existing device id (e.g. `50 41 57 01`).
- All multi-byte integers big-endian on the wire.

## 4. Messages (fixed sizes, USB-CDC framing of the 0xA1 family)

E1 PAW→MPU `PUBKEY` (41 B): `[0xB1][pub_P 32][nonce_P 8]`.
PAW generates a fresh `sec_P` (32 B TRNG) and fresh `nonce_P` (8 B TRNG)
per attempt and computes `pub_P = X25519(sec_P)`.

E2 MPU→PAW `ENVELOPE` (81 B):
`[0xB2][epoch 4][pub_M 32][nonce_M 12][ct 16][tag 16]`.
MCU generated fresh `sec_M` (32 B TRNG) and fresh `nonce_M` (12 B TRNG,
also the GCM IV) and assigned `epoch` (§7).

E3 PAW→MPU `STORED`: existing `0xA4` + 4-byte fingerprint of the UNWRAPPED
key — byte-identical semantics to today, so MCU verification is unchanged.

## 5. Key schedule

1. `shared = X25519(sec_M, pub_P)` on MCU; `X25519(sec_P, pub_M)` on PAW.
2. Both sides apply the all-zero check: OR-accumulate the 32 shared bytes in
   a data-independent loop; abort the session if the result is zero
   (RFC 7748 §6 guidance; the library does not do this for you).
3. `KEK = HKDF-SHA256(shared, salt = 32 zero bytes, info = "SHALLOT-ENV1/KEK")[0:16]`.
4. `ct, tag = AES-128-GCM-Enc(KEK, IV = nonce_M, pt = operational_key, aad = AAD)`.

## 6. Associated data (everything public, all bound)

`AAD = DOMAIN || VER || target_id || device_id || epoch_be4 || pub_P ||
pub_M || nonce_P || nonce_M` (106 B fixed).

Effect: any substitution — wrong device, wrong epoch, replayed envelope
under a fresh `nonce_P`, modified pubkey or nonce — breaks tag verification
and the session fails closed. KEK is never used for anything but this wrap;
the operational key is always fresh TRNG output (no key-confusion path).

## 7. Epoch (replay + ordering)

- MCU keeps a monotonic `epoch` counter in SRAM, starting at 1, +1 per wrap.
- PAW keeps `lastEpoch` in SRAM (none until first provision) and accepts an
  envelope iff `lastEpoch` is none or `epoch > lastEpoch`; otherwise it wipes
  and aborts. On accept it sets `lastEpoch = epoch` only after tag verify.
- Consequence (fail-closed direction): an MCU reboot restarts its counter,
  so a previously provisioned PAW rejects the next envelope and the operator
  re-runs the ceremony. Documented, accepted.
- 32-bit wrap is out of scope: at provisioning cadence the space is
  effectively inexhaustible; reaching it requires a new ceremony anyway.

## 8. Operator verification value (≥ 64 bits)

`VERIFY = hex(SHA256(0xB1 || pub_P || pub_M))[0:16]` — 16 hex chars = 64 bits.
Both sides compute it from public values; the MPU UI shows its copy, the PAW
shows its copy, the operator compares before pressing the provision button.

## 9. Confirmation ceremony

Primary (production gate): PAW renders VERIFY on the e-paper; operator
compares with the MPU UI and confirms with the provision button. The e-paper
is currently dead (BUSY stuck HIGH), so this ceremony is NOT yet runnable.

Interim (explicitly incomplete, secured fixture only): TOFU inside a
physically secured fixture + mandatory button press + audit of both
fingerprints. This provides no visual proof against a substituted envelope
and must not be presented as the full ceremony. Restoring the display is a
hard gate for production use.

Rationale for requiring the display: the Feather exposes no other PAW-side
output capable of carrying 64 bits (no buttons besides RESET, LED blinking
cannot carry 64 bits). No non-display confirmation mechanism is specified
because none on current hardware meets the bar.

## 10. Fail-closed table

| Event | Behaviour |
|-------|-----------|
| Tag verify fails (any cause) | wipe KEK/shared/pt, no store, E3 never sent, session aborted |
| All-zero shared secret | abort before wrap (MCU) / before open (PAW) |
| Epoch rule violated | wipe, abort, operator re-runs ceremony |
| Timeout (no E2 within window) | PAW wipes `sec_P`, aborts |
| VERIFY mismatch | operator aborts; nothing stored |
| Any AAD field mismatch | identical to tag failure |

Timeouts, retry limits, and audit-log format are Phase 2 firmware work and
must match this table.

## 11. Next phases (proposal, needs review approval)

- Phase 2: MCU wrap + PAW open firmware behind a compile flag; MPU
  public-fields-only relay with source guard; fixture end-to-end with
  button + audit; display restoration in parallel.
- Phase 3: production ceremony on restored e-paper; negative bench (tamper,
  replay, wrong-device, wrong-epoch rigs); audit review.
- Phase 4: remove legacy raw-key USB path only after Phase 3 sign-off.
