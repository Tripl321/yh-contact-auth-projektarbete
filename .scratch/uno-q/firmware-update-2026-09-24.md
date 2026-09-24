# Firmware-uppdatering Arduino UNO Q — research 2026-09-24

Uppdrag: "Hur löser man nya firmwaret för Arduino UNO Q?" — kartlagt mot
**endast primärkällor** (docs.arduino.cc, arduino.cc, officiella Arduino-repon
på GitHub, Arduinos officiella paket-/image-index). `.scratch/uno-q/REFS`
fanns inte vid researchtillfället; källförteckningen nedan ersätter den.

Bänkkontext som utgick ifrån: UNO Q på `/dev/ttyACM0` (udev-regel
`99-arduino-uno-q.rules`), "UNO Q core 0.8.2 (0.9.0 troligen senast)",
"Arduino Bridge for UNO Q 0.0.7 (0.0.8 troligen senast)". **Obs: inga av de
två benämningarna matchar någon officiell artefakt — se avsnitt 5.**

## 1. Sammanfattning (allt nedan verifierat i primärkälla)

| Komponent | Senaste version | Datum | Publicerad av |
|---|---|---|---|
| MCU-core (Zephyr), plattform "Arduino Q Boards" (UNO Q + VENTUNO Q) | **1.0.0** | 2026-09-02 | Boards Manager, `arduino:zephyr` |
| MCU-core, senaste plattform med enbart UNO Q ("Arduino UNO Q Board") | **0.90.0** | 2026-07-27 | Boards Manager, `arduino:zephyr` |
| Linux-image (MPU, Debian 13 "trixie") | **20260528-558** (kernel 7.0.0-g122c2c22d838) | 2026-05-28 (versionsträng) | `downloads.arduino.cc/debian-im/Stable/info.json` |
| Bridge-bibliotek för sketch-sidan, `Arduino_RouterBridge` | **0.4.3** | 2026-06-23 | Library Manager + `arduino-libraries/Arduino_RouterBridge` |
| Bridge-tjänst på kortet (Linux-sidan), `arduino-router` | **v0.10.0** | 2026-08-11 | `arduino/arduino-router` (ingår i Linux-imagen) |
| Python-bibliotek `arduino-router-bridge-py` | **v0.5.0** | 2026-09-08 | `arduino/arduino-router-bridge-py` |
| Uppdateringsverktyg `arduino-flasher-cli` | **v0.5.4** | 2026-09-23 | `arduino/arduino-flasher-cli` |
| Arduino App Lab | **0.10.0** (tagg `al-0.10.0`) | 2026-08-18 | `arduino/arduino-app-lab` |

"NYA FIRMWARET" för UNO Q består av tre separata saker som uppdateras
var för sig:

1. **MCU-sidans core** (STM32U585, kör Zephyr + Arduino-sketcher) — installeras
   i Arduino IDE:s Boards Manager, inte på kortet förrän du laddar en sketch.
2. **MPU-sidans Debian-OS-image** (Qualcomm QRB2210, hela Linux-systemet) —
   flashas till kortet via App Lab eller `arduino-flasher-cli` (EDL-läge).
3. **Bridge-komponenter** (library i IDE/tjänst på kortet) — library via
   Library Manager; tjänsten `arduino-router` ingår i OS-imagen.

## 2. Uppdateringsväg steg för steg

### 2a. MCU-core (Arduino IDE / arduino-cli)

- Öppna **Boards Manager** (IDE 2.x) och sök `Zephyr`. Installera/uppdatera
  plattformen — från 1.0.0 heter den **"Arduino Q Boards"** (innehåller både
  UNO Q och VENTUNO Q); tidigare namn: "Arduino UNO Q Board".
  Källa: [ArduinoCore-zephyr README](https://github.com/arduino/ArduinoCore-zephyr)
  ("Install the *'Arduino Zephyr Boards'* platform (or the *'Arduino Uno Q
  Board'* platform if you have an Arduino UNO Q)").
- UNO Q-plattformarna finns i Arduinos **default-index**
  (`https://downloads.arduino.cc/packages/package_index.json`) — ingen extra
  Boards Manager-URL krävs. Verifierat: indexet listar 0.51.0 → 0.90.0 under
  namnet "Arduino UNO Q Board" samt 1.0.0 under "Arduino Q Boards".
- Notera: [UNO Q-user-manualens](https://docs.arduino.cc/tutorials/uno-q/user-manual/)
  felsökningslänk till `package_zephyr_index.json` gäller coren "Arduino Zephyr
  Boards (llext)" — jag verifierade att det indexet **inte** innehåller UNO Q;
  håll dig till default-indexet.
- CLI-ekvivalent (finns på bänkhost): `arduino-cli core update-index` följt av
  `arduino-cli core upgrade arduino:zephyr` (plattforms-ID `arduino:zephyr`
  enligt indexets `architecture`-fält).
- Ingen "Burn Bootloader"-utfasning dokumenteras för UNO Q: Zephyr-loader-
  artikeln listar UNO Q **inte** som berörd board
  ([Help Center](https://support.arduino.cc/hc/en-us/articles/29180434600476)).

### 2b. Bridge-biblioteket (sketch-sida)

- **Library Manager** i IDE: sök `Arduino_RouterBridge` → uppdatera till
  **0.4.3**. Biblioteket är INTE bundled i core-paketet (jag listade
  ArduinoCore-zephyrs `libraries/`: ingen RouterBridge där) — det installeras
  separat. Källa: [arduino-libraries/Arduino_RouterBridge](https://github.com/arduino-libraries/Arduino_RouterBridge)
  samt [Library Manager-indexet](https://downloads.arduino.cc/libraries/library_index.json).
- Python-sidan (`arduino-router-bridge-py` 0.5.0) används för appar som körs
  på Linux-sidan och uppdateras med appar/imagen, inte via IDE.

### 2c. Linux-imagen (MPU) — två officiella vägar

**Väg 1 — Arduino App Lab (rekommenderas om kortet svarar):** Settings →
**Operating system** → **Flash Board**. kryssruta "Preserve user data"
behåller `userdata`-partitionen (`/home/arduino`).
Källa: [Flash a Linux Image](https://docs.arduino.cc/software/app-lab/configure/flash/).

**Väg 2 — Arduino Flasher CLI (om kortet inte syns i App Lab):**

1. **EDL-läge först**: kort urkopplat, kortslut de två EDL-pinnarna med
   jumperkabel, koppla in USB-C. (EDL = Emergency Download Mode, USB VID
   `05c6` PID `9008`; driftläge är VID `2341` PID `0078` enligt
   [user manual](https://docs.arduino.cc/tutorials/uno-q/user-manual/).)
2. Ladda ner verktyget från
   [arduino.cc/en/software → Arduino Flasher CLI](https://www.arduino.cc/en/software/)
   (välj rätt arkitektur; senaste release v0.5.4, 2026-09-23).
3. Kör (dokumenterat kommando):
   ```bash
   ./arduino-flasher-cli flash latest          # senaste Debian-image
   ./arduino-flasher-cli flash unoq            # samma, per README
   ./arduino-flasher-cli flash unoq --version 20260407-523   # specifik version
   ./arduino-flasher-cli flash unoq --preserve-user          # behåll /home/arduino
   ./arduino-flasher-cli flash unoq --temp-dir /path/to/dir  # ~8 GB temp krävs
   ```
   Imagen är ca 1 GB, nedladdning + flash tar flera minuter.
4. Verktyget läser sitt release-index från
   `https://downloads.arduino.cc/debian-im/Stable/info.json` (och
   `ubuntu-im` för VENTUNO Q) — källkod:
   [`arduino-flasher-cli/internal/registry/http_client.go`](https://github.com/arduino/arduino-flasher-cli).
   `arduino-flasher-cli list` visar tillgängliga versioner.
5. Efter lyckad flash: koppla ur, ta bort EDL-jumpern, koppla in igen.

**Linux-host-krav (bänken kör udev-regel, dvs Linux):** utan udev-regel för
EDL (VID `05c6`, PID `9008`) hänger flashern på "Waiting for EDL device".
Officiella regler i
[user manual, Linux Host Setup](https://docs.arduino.cc/tutorials/uno-q/user-manual/)
(skriver `/etc/udev/rules.d/60-Arduino-UNO-Q.rules` med BÅDA lägesparen
`2341:0078` + `05c6:9008`).

### 2d. Arduino App Lab (verktyget, ej kortet)

App Lab **uppdaterar sig själv** ("you should get the latest release
automatically next time you open the software") — release notes för 0.10.0
(2026-08-12 dokumenterat, GitHub-release `al-0.10.0` publicerad 2026-08-18):
[docs release notes](https://docs.arduino.cc/software/app-lab/release-notes/release-0-10),
[github.com/arduino/arduino-app-lab](https://github.com/arduino/arduino-app-lab/releases/latest).

## 3. Rollback / downgrade — JA för alla tre, med förbehåll

- **Core**: alla publicerade versioner (0.51.0, 0.52.0, 0.53.0, 0.53.1,
  0.54.1, 0.55.0, 0.55.2, 0.56.0, 0.90.0, 1.0.0) ligger kvar i
  [package_index.json](https://downloads.arduino.cc/packages/package_index.json)
  → valfri äldre version kan installeras i Boards Manager. Verifierat.
- **Bridge-bibliotek**: alla versioner 0.1.0 → 0.4.3 kvar i
  [library_index.json](https://downloads.arduino.cc/libraries/library_index.json).
  Verifierat.
- **Linux-image**: samtliga 8 publicerade releaser (20250807-136 →
  20260528-558) är nedladdningsbara från
  [debian-im/Stable/info.json](https://downloads.arduino.cc/debian-im/Stable/info.json)
  och flasher-cli har explicit `--version`-flagga ("Version of the image to
  download") + `flash path/to/local/image` för lokal image. Verifierat i
  [flash.go](https://github.com/arduino/arduino-flasher-cli/blob/main/cmd/arduino-flasher-cli/flash/flash.go).
  Förbehåll: omflashen skriver om **hela OS:et**; utan `--preserve-user`
  raderas all lagrad data.
- **Okänt**: huruvida core-uppdatering rör MCU-bootloader/loadern på UNO Q
  är inte dokumenterat i någon primärkälla jag nått (loader-artikeln listar
  inte UNO Q). Sätt inga domslut om detta.

## 4. Risker för delad/lånad bänkbricka (per AGENTS.md bänkdisciplin)

1. **Dataförlust (irreversibelt):** flash av Linux-image raderar hela OS:et
   och all data om `--preserve-user` inte anges. På delad hårdvara kan annans
   arbete sitta i `/home/arduino` — kontrollera med operatören FÖRE flash
   (AGENTS.md "operatörens svar gäller"). Ta backup om möjligt.
2. **EDL-läge är lågnivå-återställning:** kräver fysisk kortslutning av
   EDL-pinnar; fel jumperhantering kan böja stift. Porten `/dev/ttyACM0`
   försvinner helt (ny USB-identitet `05c6:9008`) — efter proceduren gäller
   AGENTS.md §2: ingen port återanvänds utan ny identifiering.
3. **Bänkens udev-regel är overifierad:** bänken har
   `99-arduino-uno-q.rules` (prefix 99) men officiell regel är
   `60-Arduino-UNO-Q.rules` och måste täcka **båda** paren `2341:0078` +
   `05c6:9008`. Okänt om bänkens regel täcker EDL — verifiera med
   `cat /etc/udev/rules.d/99-arduino-uno-q.rules` innan EDL-flash.
4. **Versionspara bridge-komponenter:** sketch-sidans bibliotek
   (`Arduino_RouterBridge`), Linux-sidans tjänst (`arduino-router`) och
   coren utvecklas i separata repo utan dokumenterad versionsmatris —
   uppdateras ena sidan enbart kan RPC/Bridge gå sönder. Efter uppdatering:
   ladda Blink + ett Bridge-exempel och verifiera med logg (AGENTS.md §4).
5. **App Lab auto-uppdaterar sig själv** — verktygsbeteendet på bänken kan
   ändras utan beslut; anteckna App Lab-version i loggen vid varje pass.

## 5. Bänkens angivna versioner stämmer inte — ÅTERVÄRDERA FÖRE ÅTGÄRD

Enligt AGENTS.md §1 ("hårdvaruidentitet ska verifieras med kommando och
output före åtgärd ... minne från tidigare pass gäller aldrig") gäller:

- **"UNO Q core 0.8.2" finns inte officiellt.** Publicerade core-versioner
  är 0.51.0 → 0.56.0, 0.90.0, 1.0.0 (källa: package_index.json + repo-
  releaser). "0.9.0 troligen senast" är dessutom inaktuellt: senast är
  **1.0.0** (2026-09-02). "0.8.2" kan vara felskrivning/minnesbild —
  OKÄNT tills verifierat.
- **"Arduino Bridge for UNO Q 0.0.7/0.0.8" matchar ingen officiell
  komponent.** GitHub-kodsökning på exakta strängen ger 0 träff i Arduinos
  organisation. Officiella bridge-artefakter: `Arduino_RouterBridge` 0.4.3
  (library), `arduino-router` v0.10.0 (tjänst på kortet),
  `arduino-router-bridge-py` v0.5.0. (Närmaste "0.0.7" i officiella indexet
  är toolen `scripting-tools` 0.0.7 i corens beroenden — den heter dock
  inte "Bridge".) OKÄNT vad bänken avsåg — verifiera.

Verifieringskommandon att köra och logga (med klockslag) på bänkhosten innan
någon uppdatering:

```bash
arduino-cli version
arduino-cli core list          # förväntat: arduino:zephyr <version> "Arduino UNO Q Board"/"Arduino Q Boards"
arduino-cli lib list           # leta Arduino_RouterBridge <version>
cat /etc/udev/rules.d/99-arduino-uno-q.rules
udevadm info -a -n /dev/ttyACM0 | grep -E 'idVendor|idProduct'   # driftläge: 2341/0078
```

På kortet (Linux-sidan) via App Lab Settings eller ADB: image-version och
router-tjänstens version; exakt kommando/filsökväg för image-version på
kortet är **okänt** i primärkällorna — använd App Lab Settings som källa.

## 6. Källor

- Produkt/docs: https://docs.arduino.cc/hardware/uno-q •
  https://docs.arduino.cc/tutorials/uno-q/user-manual/
  (källa till core-installation, udev/EDL USB-ID:n, bridge-översikt)
- Flash-guide (App Lab + CLI, EDL-steg, flaggor, felsökning):
  https://docs.arduino.cc/software/app-lab/configure/flash/
- Boards Manager-index: https://downloads.arduino.cc/packages/package_index.json
  (core-versioner) • https://downloads.arduino.cc/packages/package_zephyr_index.json
  (innehåller INTE UNO Q)
- Core-repo: https://github.com/arduino/ArduinoCore-zephyr (releases 1.0.0
  2026-09-02, 0.90.0 2026-07-27; README-installation)
- Bridge-bibliotek: https://github.com/arduino-libraries/Arduino_RouterBridge
  (releases, senast 0.4.3) •
  https://downloads.arduino.cc/libraries/library_index.json
- Router-tjänst: https://github.com/arduino/arduino-router (senast v0.10.0) •
  https://github.com/arduino/arduino-router-bridge-py (senast v0.5.0)
- Flasher-verktyg: https://github.com/arduino/arduino-flasher-cli (README +
  releases senast v0.5.4; index-URL:er i `internal/registry/http_client.go`)
- Image-index (senaste + alla äldre):
  https://downloads.arduino.cc/debian-im/Stable/info.json
- App Lab: https://github.com/arduino/arduino-app-lab (releases senast
  al-0.10.0) • release notes
  https://docs.arduino.cc/software/app-lab/release-notes/release-0-10
- Zephyr-loader (UNO Q ej med i listan):
  https://support.arduino.cc/hc/en-us/articles/29180434600476
- Varianter/produktsida: https://store.arduino.cc/pages/uno-q (UNO Q 2GB/4GB)

*Dokumentet redovisar endast vad som är verifierbart i ovanstående
primärkällor per 2026-09-24. Allt övrigt är markerat OKÄNT — inget antaget.*
