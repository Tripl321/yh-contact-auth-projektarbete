# 13 — Display restoration + Phase 2 hardware proofs (bench record)

Date: 2026-09-10. Bench: mamabear (Feather `...AE5E` on ttyACM1, UNO Q via
openocd). Both devices restored to live firmware afterwards (MCU backup
`535604750cd7b9b8`, PAW `lora-paw-restore.uf2`).

## 1. E-paper diagnosis: panel alive, BUSY/RST found, CS wire missing

History: PRO-29 (Sep 9) verified the panel on CS=5/DC=26/RST=27/BUSY=29
with visible output. Sep 10: BUSY=29 floats dead; something changed on the
bench between the two dates.

Probe (`/tmp/epdprobe`, off-tree bench tool, commands r/c/t/b/n/d over
115200 baud USB serial) established on 2026-09-10 over ~10 flashes:

- Wide sweep (all free GPIOs, INPUT_PULLDOWN): only GPIO2/3 (I2C pull-ups)
  and GPIO8 (LoRa RESET pull-up, matches README D8) idle HIGH. GPIO7/29
  (all documented BUSY pins) float LOW — nothing there.
- DRAIN (5 s pulldown, kills passive charge): GPIO5 stays HIGH = actively
  driven. First GPIO27-LOW transition releases GPIO5 to LOW permanently
  (repeatable): panel BUSY → GPIO5, panel RST → GPIO27. The output stage
  works (releases on reset), so the panel is powered and alive.
- SPI search with BUSY=5/RST=27 over CS × DC {24,26,29,28,12–21,2,3,4,6,9}:
  30+ combos, all silent (no BUSY response to init + update trigger).
  DIN=23/CLK=22 trusted from PRO-29.

Conclusion: HAT BUSY is on Feather D5 and HAT RST on A1, but HAT CS is NOT
on any tried pin — its wire is most likely dangling/loose (panel never
selected, hence deaf), and Feather D5 must NEVER be driven as CS output
again: all current firmware (paw-main + old probes) drives GPIO5 as CS,
fighting the BUSY output and wedging the panel HIGH. That contention is
the "BUSY stuck HIGH" symptom, not a dead panel.

Needed hands on the bench (nothing more can be done remotely):
1. Look at the 8 HAT→Feather wires; report/confirm each landing. Prime
   suspect: HAT CS dangling or mis-landed; HAT BUSY on D5; HAT RST on A1.
2. Reseat HAT/FPC, verify 3V3, power-cycle the Feather (USB unplug 10 s —
   unwedges the controller fully).
3. Re-flash the probe (`/tmp/epdprobe.uf2` on mamabear, or rebuild
   `/tmp/epdprobe/epdprobe.ino`), send `d`: a correct CS shows
   `saw_high=1` + multi-second `busy_ms`. Only then unify the pin docs
   (README vs docs/04 vs paw-main vs architektur-02 all disagree) and fix
   paw-main (BUSY A3→D5, CS off GPIO5, DC/RST per probe result).

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
