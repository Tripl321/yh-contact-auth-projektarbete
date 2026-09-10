# 13 — Display restoration + Phase 2 hardware proofs (bench record)

Date: 2026-09-10. Bench: mamabear (Feather `...AE5E` on ttyACM1, UNO Q via
openocd). Both devices restored to live firmware afterwards (MCU backup
`535604750cd7b9b8`, PAW `lora-paw-restore.uf2`).

## 1. E-paper BUSY-stuck diagnosis: panel electrically absent

Symptom: BUSY stuck HIGH with plain `INPUT` (no pull).

Probe (`/tmp/epdprobe`, kept off-tree as a bench tool): for each
RST {25=D25, 27=A1} × BUSY {7=D7, 29=A3} — BUSY to `INPUT_PULLDOWN`, pulse
RST, sample 400 ms. Then minimal init + update trigger per DC {24, 26} ×
CS {5, 24} watching BUSY.

Result (all pairs): `idle=LOW high_ms=0 maxrun=0`; init/update trigger
produced `went_high=0` on every DC/CS combo.

Conclusion: nothing drives either BUSY candidate — the lines float (the
old "stuck HIGH" was a floating input, not a driven panel). The panel is
electrically absent: unseated HAT/FPC, or missing VCC/GND. This is NOT a
firmware pin-mapping issue, so no pin mapping was changed: paw-main keeps
A0/A1/A3 until the panel answers the probe.

Physical checklist (needs hands on the bench):
1. Reseat the e-paper HAT on the Feather header and the FPC in its
   connector (locking bar closed).
2. Verify panel VCC LED / 3V3 present.
3. Re-run: flash `/tmp/epdprobe.uf2` (or rebuild `epdprobe.ino`), open
   USB serial 115200, send `r`, expect `high_ms>0` on the true RST×BUSY
   pair. Only then unify the in-tree mappings (README vs docs/04 vs
   paw-main disagree on DC/CS — the probe result decides, not the docs).

## 2. Phase 2 PAW envelope: proven on hardware

Flashed flag-ON PAW build (103172 B). USB serial 115200:
- `ENVELOPE_START` without `FIXTURE` → `Refused: fixture not armed` ✓
- `FIXTURE` + `ENVELOPE_START` → one `E1:<90 hex>` line (93 chars) ✓
- Fresh `sec_P`/`nonce_P` per attempt: three consecutive E1s all distinct ✓
- No E2 within 10 s → `E2 timeout` abort, no E3 ✓
- Full open: hardware E1 wrapped off-device (vetted C mirror, op key
  `D0..DF`) → E2 line sent → PAW replied `E3:7cf56de7` and
  `VERIFY:f84886c079c7f621`, both byte-identical to the mirror's
  expectation, plus `TEST-ONLY key stored` ✓

## 3. Phase 2 MCU envelope: deny-side proven, positive path needs a button

Flashed flag-ON MCU build (128400 B), rebooted WITHOUT the confirm button:
- `env_fixture_armed` → `false` ✓
- `env_wrap(<valid E1>:2)` → `""` (refused, nothing wrapped) ✓
- `env_confirm` → `false`; `get_key_fingerprint` → `00000000` ✓

Positive wrap (real `env_wrap` → E2 → PAW open → `env_confirm` true) needs
the confirm button held at MCU boot to latch fixture mode. That step needs
hands on the bench and is the only remaining Phase 2 hardware proof.
