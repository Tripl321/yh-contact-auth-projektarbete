# 13 — Display restoration + Phase 2 hardware proofs (bench record)

Date: 2026-09-10. Bench: mamabear (Feather `...AE5E` on ttyACM1, UNO Q via
openocd). Both devices restored to live firmware afterwards (MCU backup
`535604750cd7b9b8`, PAW `lora-paw-restore.uf2`).

## 1. E-paper recovery: wiring confirmed, panel executes (2026-09-10 pm)

Manual continuity (PAW unpowered) confirms HAT CS→D5/GPIO5,
HAT BUSY→A3/GPIO29 — the PRO-29 mapping
(SCK=22, MOSI=23, CS=5, DC=26, RST=27, BUSY=29). PAW firmware already
uses exactly this mapping: NO firmware pin change was needed.

Probe (`/tmp/epdprobe`, off-tree bench tool) ran ~10 flashes that morning
and wrongly concluded BUSY=GPIO5. The known-good PRO-29 B V2 sequence
(white clear → black checker + red border/text, `pro-29-epaper-bringup`
branch) was then flashed and run on current wiring — panel EXECUTES and
completes (BUSY HIGH after trigger, idle after 2800 ms, textbook). Full
USB log kept in bench `/tmp/pro29log.txt`.
USER ACTION: visually confirm white flash then checker + red border/text
on the glass; only the human at the bench can close this loop.

Why the morning pointed at GPIO5 (probe flaw analysis — read before
trusting `/tmp/epdprobe` output):
- F1 wrong oracle: a healthy SSD1681 shows NOTHING on BUSY from a reset
  pulse alone, so Phase A silence on GPIO29 was correct behavior
  misread as "absent". Plain INPUT floats HIGH ("stuck HIGH" in paw-main);
  INPUT_PULLDOWN reads LOW ("silent" in the probe) — same loose wire,
  opposite readings. The BUSY wire was intermittent that morning;
  reseating restored it (continuity + working sequence prove it now).
- F2 single-sample attribution: one coupling coincidence (27→5) was
  over-weighted; the toggle test correctly rejected a hard short but the
  earlier result was kept anyway.
- F3 driving candidate pins that may be panel OUTPUTs (GPIO5 as CS)
  risks contention/wedging the DUT mid-diagnosis. Never drive a pin any
  live hypothesis assigns as output.
- F4 first-coherent-story lock-in: DisplayFind silence should have killed
  the BUSY=5 theory instead of widening the CS search.
- Open (mechanism unexplained, recovery-irrelevant): GPIO5 read actively
  HIGH through a 5 s pulldown drain that morning, released once by a
  GPIO27-LOW. Leading hypothesis is a HAT CS pull-up plus an unresolved
  release path; NOT investigated further once continuity + the working
  sequence decided the matter.

Superseded by the recovery above — kept as a record of the wrong turn:
the "electrically absent" verdict and the CS-dangling theory were
artefacts of F1–F4, not of the hardware.

## 2. E-paper root cause found: wrong update mode 0xC7 vs 0xF7 (2026-09-10 pm)

The panel was never broken. paw-main's driver (inherited from the B V1
`epaper-status-display.ino`) triggers updates with 0x22/0xC7/0x20, but the
B V2 panel needs the official 0x22/0xF7/0x20 full update (PRO-29 verified
2.8 s completions with 0xF7). With 0xC7 the V2 controller starts BUSY and
never finishes — the historic "BUSY stuck HIGH / dead display" (issue
#11). begin()/reset/SPI were always fine, which is why every probe of
wiring/pins contradicted itself.

Fixed in paw-main `displayFrame()` (+`clear()`): 0xF7 update mode, red
plane (0x26) cleared to 0x00 for strictly black-on-white ceremony frames,
RAM counters (0x4E/0x4F) rewound before every staging (PRO-29 proven
symptom: frames landing outside RAM are silently lost), SPI kept at the
verified 400 kHz. First cold double-render after the fix: E3 + DISP:OK at
36.7 s (bounds: DISP 60 s, MPU E3 75 s).

## 3. Phase 2 PAW envelope: proven on hardware

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
