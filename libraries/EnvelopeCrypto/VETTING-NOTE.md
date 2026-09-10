# EnvelopeCrypto — vetting note (Phase 0)

Upstream: BearSSL 0.6, Thomas Pornin (MIT). Full licence in
`LICENSE.upstream-bearssl.txt`. Subset frozen 2026-09-10; do not add files
without re-running `tests/test_envelope.py` AND the on-chip KAT probes.

## Verdict

| Candidate | Result | Reason |
|-----------|--------|--------|
| Arduino `Crypto` 0.4.0 (Curve25519/AES-GCM) | REJECTED | Fails RFC 7748 §6.1: sec `77076d…92c2a` yields pub `785b3e9f…`, expected `8520f009…` — on host AND on-chip. Non-RFC scalar handling; cannot interoperate. Do not use for the envelope. |
| This BearSSL subset | ACCEPTED | All KAT green on host, Feather RP2350 on-chip, and UNO Q STM32U585 on-chip (table below). |

## On-silicon proof (2026-09-10, `kat_run` digest chain)

| KAT | Expected | Host (.so) | Feather RP2350 | UNO Q STM32U585 |
|-----|----------|------------|----------------|-----------------|
| SHA256("abc") | `ba7816bf…f20015ad` | PASS | PASS | PASS |
| X25519 pub RFC 7748 §6.1 | `8520f009…9b4e6a` | PASS | PASS ret=1 | PASS |
| X25519 shared RFC 7748 §6.1 | `4a5d9d5b…e161742` | PASS | PASS ret=1 | PASS |
| AES-GCM empty (NIST) | `58e2fcce…7455a` | PASS | PASS | PASS |
| AES-GCM ct (NIST case 2) | `0388dace…2fe78` | PASS | PASS | PASS |
| AES-GCM tag (NIST case 2) | `ab6e47d4…bddf` | PASS | PASS | PASS |
| AES-GCM tamper reject | open=0 | PASS | PASS | PASS |
| HKDF-SHA256 RFC 5869 #1 | `3cb25f25…851865` | PASS | PASS | PASS |

Full digests are pinned in `tests/test_envelope.py`; any byte change fails CI.

## Build notes (keep)

- Feather: a stale `Crypto`-contaminated build failed with a VFP register-args
  ABI mismatch. Clean rebuild from this subset only: OK (66836-byte UF2).
- UNO Q: build hit a HAL RNG macro name collision; worked around in the probe.
  KAT green after. Phase 2 firmware must re-check this when wiring TRNG input.
- UNO Q `kat_run` returns the digest chain as one `;`-joined string because the
  Bridge RPC layer panics on `int8` return types — probe-side constraint only,
  not a crypto finding.

## Subset contents and why

- `ec_c25519_i15.c`, `i15_*.c`, `ccopy.c`: X25519 (constant-time i15 backend).
- `aes_ct.c`, `aes_ct_ctr.c`, `aes_ct_enc.c`, `gcm.c`, `ghash_ctmul.c`:
  AES-128-GCM (constant-time AES + GHASH). `aes_ct_cbcenc.c` is unused by the
  GCM path and kept only to preserve the vetted file set byte-for-byte.
- `sha2small.c`, `hmac.c`, `hkdf.c`: SHA-256, HMAC, HKDF.
- `dec32be.c`, `enc32be.c`, `inner.h`, `config.h`, `inc/*.h`: codec helpers,
  internals, public headers.

## API contract for Phase 2 firmware

- `br_ec_c25519_i15.mul(G, 32, sec, 32, BR_EC_curve25519)` clamps the scalar
  internally (proven by the RFC vector passing on raw TRNG-shaped input).
- The implementation does NOT reject low-order/all-zero DH output — the
  caller MUST apply the all-zero shared-secret check from
  `docs/12-envelope-protocol.md` before wrapping or storing.
- `br_gcm_check_tag` returns non-zero on verify success; treat any other
  return as fatal, wipe, abort (no retries with the same nonce).
