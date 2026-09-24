# Flash-logg DEN + PAW — 2026-09-23

Till mainline (bort från pre-pivot-firmware ~2–9 sep). Fylldes i av agenten
utifrån bygg- och flashutdata; banderoller verifierade mot logg.

## DEN (Pico 2)

| Fält | Värde |
|---|---|
| Källa | `plc/den-main/den-main.ino` @ `68f517e` + ocommitade PRO-98-pinndocs (orörda) |
| UF2 (först) | `build/den-main.ino.uf2` → sparad som `build/den-main-unpinned-6e21c63a.uf2`, sha256 `6e21c63a0643490923ad70eea19fc614ae199f3384afc540ab4476c8550cfbc7` |
| UF2 (nu) | `build/den-main-TESTROOT.ino.uf2`, sha256 `ed24d5520aa5b2be6eb4245f0a8d9698edd8c862fb9b02b93fb336bb6e634c69` |
| TESTROOT-extra | `-DSHALLOT_BLOCKLIST_PUBKEY=<repots testnyckel>` (TEST-ONLY, aldrig produktion) |
| Flashmetod | Först: BOOTSEL + kopiering på Mac. Sedan: fjärr picotool (`1200bps-touch` → BOOTSEL, `load -v -x`, verifierad OK). |
| Banner/bevis | Bootbanner formellt ofångad (skrivs före USB-enumerering); ersättande bevis: `device_id DEN\x01` i binärt handskak + PRO-53-loop (`CHALLENGE`/`code 6`) + provision GRANTED `be45cb26` + signerad tom lista accepterad → live code 0. Gamla banderoller (`PLC Complete Firmware`, epoch-rader) borta. |
| Status nu | Nyckel + signerad tom lista lagrade (SRAM); code 0-cykling mot PAW. |

## PAW (Feather RP2350)

| Fält | Värde |
|---|---|
| Källa | `id-kort/paw-main/paw-main.ino` (+ `epd_words.h`, genererad Helvetica Bold-bitmap) @ `68f517e` + LUT-fix (3 nollrader), UX-spårning, A-glyf, Helvetica-ord |
| UF2-kedja | LUTFIX `833b1ba5…` → UXFIX `a6fae040…` → FONT `1a743d0c…` → **FONT2 (nu) `dd2e1165dcaa8a743ce1b26ac1ddd65d263e916106bafcca4ac70c4a1f2528eb`** |
| Flashmetod | Fjärr picotool genomgående (`1200bps-touch` → BOOTSEL, `load -v -x`, verifierad OK). Inget fysiskt knapptryck behövdes efter första DEN-flashen. |
| Banner/bevis | Fångad boot: `SHALLOT PAW Main Firmware`, `Feather RP2350`, `[PRO-57] e-Paper initialized.` Panel synbekräftad av operatör i alla tre tillstånd (prickar / X+FAILED / bock+AUTHENTICATED). |
| Status nu | Rätt nyckel provisionerad (`be45cb26`); code 0-cykling; panel visar AUTHENTICATED stabilt. |

## Panelbuggar funna och åtgärdade längs vägen

1. **LUT-trunkering:** `WF_FULL_1IN54` saknade 3 nollrader (138/159 värden) → korrupt vågform, svag spökbild. Fix: tabell identisk med referensen (byte-verifierad).
2. **Per-challenge-flimmer:** `AUTHENTICATING` vid varje challenge → full refresh var 3:e s. Fix: display visar senaste utfall + identisk status hoppas över.
3. **A-glyf == O-glyf:** tvärslå saknades → "AUTHENTICATED" lästes som "O...". Fix: en byte.
4. **5x7 för liten:** ersatt med Helvetica Bold-bitmaps (21 pt, genererade offline, verifierade mått/täckning). FAILED fick ord (visade förut bara X).
