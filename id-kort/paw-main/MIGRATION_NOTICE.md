# Migration Notice — paw-main.ino DEPRECATED

**Status:** Deprecated as of PRO-52. Replaced by `id-kort/paw-challenge-response/paw-challenge-response.ino`.

## Why deprecated

`paw-main.ino` was the Phase 0 PAW implementation:

- Software SHA-256 (no hardware acceleration)
- 32-byte HMAC (full digest, not truncated to 8 bytes)
- Direct master key usage (no K_enc/K_mac derivation)
- No replay protection (no SeqWhitelist)
- No AES-CTR encryption of payload
- No constant-time comparison

## Replacement

`paw-challenge-response/paw-challenge-response.ino` is the PRO-52 implementation:

- Hardware SHA-256 (RP2350 accelerator via hw_sha256_*)
- 8-byte truncated HMAC-SHA256
- Key derivation: K_enc = SHA-256(master_key || "ENC")[:16], K_mac = SHA-256(master_key || "MAC")[:16]
- SeqWhitelist sliding-window replay protection (uint16_t bitmask)
- AES-128-CTR payload encryption
- Constant-time HMAC comparison
- Anti-DoS: HMAC verified before sequence number consumption

## What remains

- e-Paper driver integration (PRO-57) — `display_status()` is a placeholder in the new code
- Real key distribution via UNO Q (PRO-45) — stub key 0x00-0x0F in Phase 1
