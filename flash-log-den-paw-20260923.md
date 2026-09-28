# Flash-logg DEN + PAW — 2026-09-23

Till mainline (bort från pre-pivot-firmware ~2–9 sep). Fylldes i av agenten
utifrån bygg- och flashutdata; banderoller verifierade mot logg.

## DEN (Pico 2 W — hårdvara! firmware byggd för plain Pico 2 `rpipico2`)

> Hårdvarufynd 2026-09-24: kortet är en **Pico 2 W**, inte plain Pico 2.
> Konsekvens: det finns **ingen GPIO-LED** — onboard-LED sitter på
> WL_GPIO0 (CYW43439) och all `LED_BUILTIN`(=GPIO25, på W = wireless SPI CS)
> i firmwaren går ingenstans synligt (ofarligt medan WiFi är oanvänt).
> Källor: Pico 2 W-datasheetet (WL_GPIO0 → user LED), pico-sdk `pico2_w.h`
> ("no PICO_DEFAULT_LED_PIN - LED is on Wireless chip").

| Fält           | Värde                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Källa          | `plc/den-main/den-main.ino` @ `68f517e` + ocommitade PRO-98-pinndocs (orörda)                                                                                                                                                                                                                                                                                                                                                                       |
| UF2 (först)    | `build/den-main.ino.uf2` → sparad som `build/den-main-unpinned-6e21c63a.uf2`, sha256 `6e21c63a0643490923ad70eea19fc614ae199f3384afc540ab4476c8550cfbc7`                                                                                                                                                                                                                                                                                             |
| UF2 (nu)       | `build/den-main-TESTROOT-W.ino.uf2`, sha256 `ca7ef4fd9680059c4379cf3590c19b7af644c6c7890f4e490f6cae59d55c04e0`                                                                                                                                                                                                                                                                                                                                      |
| TESTROOT-extra | `-DSHALLOT_BLOCKLIST_PUBKEY=<repots testnyckel>` (TEST-ONLY, aldrig produktion)                                                                                                                                                                                                                                                                                                                                                                     |
| W-anpassning   | fqbn `rp2040:rp2040:rpipico2w` + `-DPICO_CYW43_SUPPORTED=1 -DCYW43_PIN_WL_DYNAMIC=1` (krävs för länkning; `--clean` vid flaggbyte p.g.a. cache). **Ingen källkodsändring**: befintlig `digitalWrite(LED_BUILTIN)` driver WL_GPIO0 via kärnans CYW43-auto-init (inget WiFi-bibliotek, ingen association — chipet strömsätts men ingen radio startas). USB-identitet bytt till `2e8a:f00f` (portnummer kan skifta — identifiera på nytt efter flash). |
| LED verifierad | Operatör bekräftade grön LED tänd i chatt 2026-09-24 (BG ARM-blinktest + grant-HIGH).                                                                                                                                                                                                                                                                                                                                                               |
| Flashmetod     | Först: BOOTSEL + kopiering på Mac. Sedan: fjärr picotool (`1200bps-touch` → BOOTSEL, `load -v -x`, verifierad OK).                                                                                                                                                                                                                                                                                                                                  |
| Banner/bevis   | Bootbanner formellt ofångad (skrivs före USB-enumerering); ersättande bevis: `device_id DEN\x01` i binärt handskak + PRO-53-loop (`CHALLENGE`/`code 6`) + provision GRANTED `be45cb26` + signerad tom lista accepterad → live code 0. Gamla banderoller (`PLC Complete Firmware`, epoch-rader) borta.                                                                                                                                               |
| Status nu      | Nyckel + signerad tom lista lagrade (SRAM); code 0-cykling mot PAW.                                                                                                                                                                                                                                                                                                                                                                                 |

## PAW (Feather RP2350)

| Fält         | Värde                                                                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Källa        | `id-kort/paw-main/paw-main.ino` (+ `epd_words.h`, genererad Helvetica Bold-bitmap) @ `68f517e` + LUT-fix (3 nollrader), UX-spårning, A-glyf, Helvetica-ord                                 |
| UF2-kedja    | LUTFIX `833b1ba5…` → UXFIX `a6fae040…` → FONT `1a743d0c…` → FONT2 `dd2e1165…` → BEAR `ce98aa67…` → BADGE `76c038da…` → **BADGE-SER (nu) `a13a3e7f8fd64b9bd8272e221e6cbaccfdb35d7ea7b378a130352172c83cc493`** (2026-09-24: display-övergångar serialiserade — begäran under pågående refresh buffras som `_pending` och commitas av `poll()` vid idle; rotorsak bänkfynd "blinkar men byter inte läge": panelens RAM är låst under refresh så mittpå-sända ramar tappades, och dedup mot `_shown` (satt vid begäran) frös tappade ramar permanent. Regressionstest: `test_pro11_epd_mid_refresh_request_is_buffered_not_lost`)                                              |
| Flashmetod   | Fjärr picotool genomgående (`1200bps-touch` → BOOTSEL, `load -v -x`, verifierad OK). Inget fysiskt knapptryck behövdes efter första DEN-flashen.                                           |
| Banner/bevis | Fångad boot: `SHALLOT PAW Main Firmware`, `Feather RP2350`, `[PRO-57] e-Paper initialized.` Panel synbekräftad av operatör i alla tre tillstånd (prickar / X+FAILED / bock+AUTHENTICATED). |
| Status nu    | BADGE-SER-flashad (badge + serialiserade display-övergångar); nyckel raderad av omflashningen — nästa record-demo-körning omprovisionerar. Synbekräftelse av bear→verdict-transitioner väntar. |

## Panelbuggar funna och åtgärdade längs vägen

1. **LUT-trunkering:** `WF_FULL_1IN54` saknade 3 nollrader (138/159 värden) → korrupt vågform, svag spökbild. Fix: tabell identisk med referensen (byte-verifierad).
2. **Per-challenge-flimmer:** `AUTHENTICATING` vid varje challenge → full refresh var 3:e s. Fix: display visar senaste utfall + identisk status hoppas över.
3. **A-glyf == O-glyf:** tvärslå saknades → "AUTHENTICATED" lästes som "O...". Fix: en byte.
4. **5x7 för liten:** ersatt med Helvetica Bold-bitmaps (21 pt, genererade offline, verifierade mått/täckning). FAILED fick ord (visade förut bara X).
