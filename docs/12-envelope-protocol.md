# 12 — Wrapped-key envelope protocol (USB-C provisioning)

Status: spec v0.2 approved for Phase 2 fixture builds. Phase 2 firmware is
feature-flagged (`ENVELOPE_PHASE2`, default OFF) and fixture-only: no
production operational key is provisioned until the e-paper ceremony works
(§9). Normative test vectors live in `tests/test_envelope.py` and drive the
real C in `libraries/EnvelopeCrypto`.

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

## 4. Messages (fixed sizes)

Binary codec (MCU-internal, `envelope.h`, golden vector in
`tests/test_envelope.py`):

E1 `PUBKEY` (45 B): `[0xB1][device_id 4][pub_P 32][nonce_P 8]`.
PAW generates a fresh `sec_P` (32 B TRNG) and fresh `nonce_P` (8 B TRNG)
per attempt and computes `pub_P = X25519(sec_P)`. The PAW asserts its own
`device_id` here so the MCU can bind it into the AAD; the PAW re-checks
with its true id at open, so a swapped E1 fails the tag.

E2 `ENVELOPE` (81 B):
`[0xB2][epoch 4][pub_M 32][nonce_M 12][ct 16][tag 16]`.
MCU generated fresh `sec_M` (32 B TRNG) and fresh `nonce_M` (12 B TRNG,
also the GCM IV) and assigned `epoch` (§7).

E3 `STORED`: the 4-byte fingerprint of the UNWRAPPED key — same semantics
as the legacy `0xA4` confirmation, so MCU verification logic is unchanged.

USB-CDC framing (MPU↔device leg): self-delimiting hex lines, exact lengths,
so binary frames survive a log-sharing stream:
`E1:<90 hex>\n`, `E2:<162 hex>\n`, `E3:<8 hex>\n`, `VERIFY:<16 hex>\n`.
Session control lines: `FIXTURE\n` (arm fixture mode), `ENVELOPE_START\n`
(begin attempt), `CANCEL\n` (abort in-flight session only, never a
committed key), `RESULT:OK` / `RESULT:FAIL` (MPU→PAW operator verdict
after comparing VERIFY values). Display gate lines (PAW→MPU):
`DISP:OK` (glass render completed, key committed, E3 follows),
`DISP:FAIL <reason>` (render failed, nothing committed, no E3).
Anything else on the line channel is ignored.

## 5. Key schedule

1. `shared = X25519(sec_M, pub_P)` on MCU; `X25519(sec_P, pub_M)` on PAW.
2. Both sides apply the all-zero check: OR-accumulate the 32 shared bytes in
   a data-independent loop; abort the session if the result is zero
   (RFC 7748 §6 guidance; the library does not do this for you).
3. `salt = SHA256(AAD)` (32 B) — the salt is the hash of the session
   transcript as fixed in §6, so every session binds a distinct salt derived
   from both nonces, both pubkeys, epoch, and device binding. No zero salt.
4. `KEK = HKDF-SHA256(shared, salt = salt, info = "SHALLOT-ENV1/KEK-v2")[0:16]`.
   The `-v2` label is a distinct protocol label: KEKs derived under the old
   v0.1 parameters (zero salt, `.../KEK` label) never collide with v0.2 KEKs.
5. `ct, tag = AES-128-GCM-Enc(KEK, IV = nonce_M, pt = operational_key, aad = AAD)`.

Salt and info are public values; secrecy rests on `shared` alone. Because the
salt commits to the full transcript, a KEK is useless outside its session.

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

Primary and only production ceremony: PAW renders the full 16-hex VERIFY
on the e-paper after a verified open; the operator compares with the MPU
UI and confirms. The value stays on glass until the session completes
(RESULT:OK → VERIFIED screen), expires, or is cancelled — never replaced
by icons alone, never truncated. E3 is emitted only after the render
completes, so the MPU can only confirm a ceremony the operator could see.
RESULT:FAIL wipes the committed key and shows REJECTED. A failed render
fails the ceremony closed (DISP:FAIL, nothing committed, no E3) and never
falls back to TOFU.

Proof-of-reading: after the automatic string match, the MPU prompts for
the LAST 4 glass chars before env_confirm. A bare OK is rubber-stampable;
typing the chars proves the operator actually read the glass. Empty line
or 3 strikes aborts with RESULT:FAIL.

Operator failure matrix (all fail closed):
- Honest FAIL on a valid session: key wiped both sides (PAW wipe plus an
  orphaned MCU wrap whose key nobody retains), re-run costs ~1 min.
  Availability loss only; audit shows match + operator abort.
- Honest or malicious OK on a MISMATCHED session: impossible through the
  tooling — the automatic compare sends RESULT:FAIL before any verdict
  is accepted. A log pairing mismatch with OK can therefore never occur
  honestly; its presence alone is an incident.
- Honest OK on a valid but MISRENDERED session: key is legitimate
  (crypto consistent), record slightly untrue. Bounded by the glyph
  confusability floor (tests) and the proof-of-reading prompt.
- Malicious FAIL (sabotage): availability only, detectable as a pattern.
- Threat boundary, stated plainly: the ceremony assumes an honest-but-
  buggy relay and operator. A malicious MPU operator with shell access
  can fake both displays consistently; that residual belongs to physical
  access control and append-only off-device audit, not to this protocol.
  Duress-FAIL (silent alert on coerced approval) is a future production
  option, not specified here.

Test-only fixture flow (never a production fallback): inside a physically
secured fixture, with the build flag on and the fixture interlock engaged,
an operator may run the envelope without the visual check for bring-up and
regression testing only. Fixture runs must use test keys, must be labelled
`TEST-ONLY` in the audit log, and their keys must never leave the fixture.
Any proposal to use the fixture flow outside the fixture is rejected by this
spec — restore the display instead.

Rationale for requiring the display: the Feather exposes no other PAW-side
output capable of carrying 64 bits (no buttons besides RESET, LED blinking
cannot carry 64 bits). No non-display confirmation mechanism is specified
because none on current hardware meets the bar.

## 10. Fail-closed table

| Event | Behaviour |
|-------|-----------|
| Tag verify fails (any cause) | wipe KEK/shared/pt, no store, E3 never sent, session aborted, glass REJECTED |
| All-zero shared secret | abort before wrap (MCU) / before open (PAW), glass REJECTED |
| Epoch rule violated | wipe, abort, operator re-runs ceremony, glass REJECTED |
| Timeout (no E2 within window) | PAW wipes `sec_P`, aborts, glass TIMED OUT |
| Display render fails or times out | staged key wiped, never committed, E3 never sent, `DISP:FAIL`, no TOFU fallback |
| Operator rejects (RESULT:FAIL) | committed key wiped, glass REJECTED |
| Cancel (in-flight only) | wipe staging/secrets, glass CANCELLED, committed keys untouched |
| VERIFY mismatch | operator aborts; MPU sends RESULT:FAIL; PAW wipes, glass REJECTED |
| Any AAD field mismatch | identical to tag failure |

Timeouts, retry limits, and audit-log format are Phase 2 firmware work and
must match this table.

## 11. Phases (binding order)

- Phase 2 (in progress): MCU wrap + PAW open firmware behind
  `ENVELOPE_PHASE2` (default OFF); MPU public-fields-only relay with source
  guard; fixture end-to-end with TEST-ONLY keys + audit; display restoration
  in parallel. Flag on is allowed in the fixture only. Fixture mode latches
  from the confirm button at boot where present, otherwise from the audited
  `env_fixture_arm` operator RPC (the bench UNO Q has no button); SRAM-only,
  reboot clears. The fixture flow wraps fresh TEST-ONLY keys, so arming
  without a button cannot expose production material.
- Phase 3: production ceremony on restored e-paper; negative bench (tamper,
  replay, wrong-device, wrong-epoch rigs); audit review.
- Phase 4 (gate, before any non-fixture enablement): remove all remaining
  raw-key export code paths (raw UART key sender, any Bridge/MPU key
  handling — including the closed PR #15 line, which must never be merged),
  then re-verify. Phase 2 MUST NOT be enabled outside fixtures while any
  raw-key export path still exists in the tree.
