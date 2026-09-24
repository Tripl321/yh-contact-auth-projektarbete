# Flash-checklista: DEN + PAW till aktuell mainline

**Status:** Utkast 2026-09-23 | Syfte: byta båda korten från pre-pivot-firmware
(~2–9 sep 2026, `plc-key-receiver`/`paw-key-receiver`-eran) till aktuell
mainline (`plc/den-main`, `id-kort/paw-main`). Bakgrund: enheternas
faktiska banderoller matchade inte repokoden (epoch-protokoll som inte
finns i trädet).

**Regler:** flasha ett kort i taget (koppla ur det andra — förväxling är
det vanligaste felet här). CLI:t kan inte flasha; allt nedan är manuellt.
Ändra inga befintliga docs eller äldre firmwaremappar tills bänken är
verifierad.

## 0. Förutsättningar (en gång)

- [ ] Repot är på avsedd commit. Spara den:
  ```sh
  git rev-parse --short HEAD
  ```
  Skriv hashen i loggtabellen nedan (kolumn Källa).
- [ ] Kabel: USB-datakabel (inte ren laddkabel) till Macen.
- [ ] Verktyg, välj A eller B:
  - **A — arduino-cli:** `arduino-cli core list` ska visa `rp2040:rp2040`
    (Earle Philhower). Saknas den:
    ```sh
    arduino-cli core install rp2040:rp2040
    ```
    samt bibliotek (krävs enligt `docs/13 §3`):
    ```sh
    arduino-cli lib install "Crypto@0.4.0"
    ```
  - **B — Arduino IDE:** installera boardpaketet för RP2350
    (Pico 2 + Adafruit Feather RP2350) samt biblioteket `Crypto@0.4.0`.
    Använd samma fqbn som i steg 1/2 nedan.

## 1. DEN (Pico 2) — kompilera

```sh
arduino-cli compile \
  --fqbn rp2040:rp2040:rpipico2 \
  --libraries libraries \
  --output-dir build \
  plc/den-main/den-main.ino
```

(Samma kommando som `docs/13 §3`; `shallot build den --dry-run` visar
varianten utan `--libraries`.)

- [ ] Kompilering lyckas utan fel.
- [ ] Lista utdata och spara **faktiskt UF2-namn**:
  ```sh
  ls -la build/*.uf2
  ```
  Förväntat mönster: `build/den-main.ino.uf2` — bekräfta med `ls`,
  gissa aldrig.

## 2. DEN — flasha via BOOTSEL

1. Koppla **ur PAW** från Macen (endast DEN inkopplad).
2. Håll inne **BOOTSEL** på Pico 2, koppla in USB, släpp knappen.
3. En USB-volym dyker upp (t.ex. `RPI-RP2` — spara faktiskt namn).
4. Kopiera UF2-filen till volymen. Kortet startar om automatiskt.
5. Vänta ~5 s.

## 3. DEN — verifiera banner + spara

```sh
shallot bench identify --timeout 10
```

- [ ] Porten identifieras som **DEN** (inte längre gissning).
- [ ] Monitor visar repo-firmwarens bootrader (jämför exakt):
  ```
  [DEN] docked UART auth ready (PRO-53/PRO-46/PRO-94)
  [PRO-98] Blocklist trust root PINNED (Ed25519)
  [DEN] BOOT locked (DENIED); break-glass cleared (fail-closed)
  ```
  (`unpinned`-varianten är också giltig boot — notera vilken du ser.)
- [ ] **Gamla** rader (`PLC Complete Firmware`, `Handshake received epoch`,
      `Resynced past`) förekommer **inte** längre.
- [ ] Spara utdraget: kopiera banderollen till loggtabellen nedan.

## 4. PAW (Feather RP2350) — kompilera

Koppla ur DEN, koppla in PAW. Sedan:

```sh
arduino-cli compile \
  --fqbn rp2040:rp2040:adafruit_feather_rp2350_hstx \
  --build-property build.extra_flags=-DARDUINO_USB_CDC_ONLY \
  --libraries libraries \
  --output-dir build \
  id-kort/paw-main/paw-main.ino
```

(fqbn + extra_flags från `shallot build paw --dry-run`.)

- [ ] Kompilering lyckas utan fel.
- [ ] Spara **faktiskt UF2-namn** (`ls -la build/*.uf2`,
      förväntat `build/paw-main.ino.uf2` — bekräfta).

## 5. PAW — flasha via BOOTSEL

1. Endast PAW inkopplad.
2. BOOTSEL-håll + USB i (Feather: håll BOOT, tryck RESET, släpp) tills
   USB-volymen syns (spara faktiskt volymnamn).
3. Kopiera UF2-filen. Kortet startar om automatiskt.
4. Vänta ~5 s (e-paper-init tar några sekunder).

## 6. PAW — verifiera banner + spara

```sh
shallot bench identify --timeout 10
```

- [ ] Porten identifieras som **PAW**.
- [ ] Monitor visar repo-firmwarens bootrader (jämför exakt):
  ```
  ============================================
  SHALLOT PAW Main Firmware
  Hardware: Adafruit Feather RP2350
  Components: Core1262 LoRa + e-Paper
  ============================================
  [PRO-57] Initializing e-Paper...
  [PRO-57] e-Paper initialized.
  [PRO-28] SPI1 initialized for Core1262.
  [PRO-58] Initializing RadioLib SX1262 LoRa...
  [PRO-58] RadioLib SX1262 initialized successfully.
  [PRO-48] Key reception via loop poll (non-blocking)...
  ```
  Notera avvikelse: `e-Paper initialization FAILED (degraded mode)` eller
  `LoRa initialization FAILED` är giltig boot men ska noteras (relevant
  för PNL-1/H7 senare).
- [ ] **Gamla** rader (`PAW Key Receiver (PRO-48)` som banner,
      epoch-rader) förekommer **inte** längre.
- [ ] Spara utdraget i loggtabellen nedan.

## 7. Flash-logg (fyll i — detta är spårbarheten)

Spara som ny fil i repots rot, t.ex.
`flash-log-den-paw-20260923T000000Z.md` (datum = verkligt datum):

| Enhet | Källa (.ino + commit) | UF2-filnamn | Datum (UTC) | Banner (första raderna) |
|---|---|---|---|---|
| DEN | `plc/den-main/den-main.ino` @ `<hash>` | `<från ls>` | `<datum>` | `[DEN] docked UART auth ready …` |
| PAW | `id-kort/paw-main/paw-main.ino` @ `<hash>` | `<från ls>` | `<datum>` | `SHALLOT PAW Main Firmware` … |

Tomma fält = steget är inte gjort. Ingen rad utan banner.

## 8. Överlämning till verifiering

När steg 0–7 är klara och båda korten sitter i Macen igen, meddela
agenten. Då verifieras i ordning (med sparade loggar):

1. `shallot bench identify` → DEN + PAW på repo-firmware.
2. Provisionering av testnycklar från Macen (CLI-protokollet stämmer
   mot repo-firmware; fingerprint-match är beviset).
3. K1: bryt strömmen → omstart utan nyckel → nekad auth utan ny
   ceremoni, allt loggat till `bench-verify.jsonl`.
