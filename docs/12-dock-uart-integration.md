# 12 — Docked UART integration record (PRO-52)

**Status:** Genomförd 2026-09-09 på bänk (Pico 2 + Feather RP2350, MamaBear-värd).
Firmware: DEN `plc/den-main` (main), PAW `paw-main` + e-paper-timeoutfix (PR #10).

## Koppling (verifierad med GPIO-loopback båda håll: 18/18 + 22/22 PASS)

| Från | Till |
|---|---|
| DEN GPIO0 (TX) | PAW GPIO1 (RX) |
| DEN GPIO1 (RX) | PAW GPIO0 (TX) |
| GND | GND |

115200 baud båda håll. Färskare Dupont-kablar krävdes — en nearly-avbrottad
ledare släpper igenom likström men korrumperar UART-kanter (fragment,
en lyckad frame, sedan tystnad).

## Happy path

16/16 cykler `CHALLENGE(16B) → RESPONSE(32B HMAC) → AUTHENTICATED + ACK(0x01)`
i följd, båda loggarna samstämmiga. Interop med dev-nyckel bevisad.

## Fail-closed (alla verifierade på hårdvara)

| Fall | Beteende |
|---|---|
| PAW tyst (BOOTSEL) | DEN `FAILED: timeout` var ~3:e sekund (2 s deadline + 1 s gap) |
| Korrupt CRC (en bit flippad) | DEN `parse error`, 39/39 sessioner, noll grants |
| Fel nyckel (en bit) | DEN `hmac mismatch`, 40/40 sessioner, noll grants |
| PAW utan motpart i 45 s | Noll osponsrade sändningar (responder-only) |

## Kända bänkrestriktioner (ej protokollfel)

- E-paper-panelen svarar inte (BUSY fast HIGH): PR #10 håller noden vid liv
  (`[EPD] BUSY timeout, continuing degraded`), visuell display overifierbar.
- Oprovisionerad PAW blockerar 10 s per varv i provisioneringsväntan +
  varje displayanrop kan stalla loopen: äkta firmware svarar för sent för
  DEN:s 2 s-fönster. Se issue #11 (non-blocking provisionering +
  display-frikoppling). Enhetstester + snabba testbyggen bevisar
  dock-protokollet fullt ut under tiden.
- LoRa-radio på PAW initierar ej (`-2`, ur scope; påverkar ej UART).

## Kommandon (repeterbarhet)

```bash
# Bygg (från reporot)
arduino-cli compile --fqbn rp2040:rp2040:rpipico2 \
  --library libraries/DenUartProtocol --output-dir build-den plc/den-main/den-main.ino
arduino-cli compile --fqbn rp2040:rp2040:adafruit_feather_rp2350_hstx \
  --build-property build.extra_flags="-DARDUINO_USB_CDC_ONLY" \
  --library libraries/DenUartProtocol --output-dir build-paw id-kort/paw-main/paw-main.ino
# Flash: 1200-bps-touch -> RPI-RP2 mass storage -> kopiera UF2 -> auto-reboot
python3 -c "import serial,time; p=serial.Serial('/dev/serial/by-id/<board>',1200); time.sleep(1.5)"
# Monitor: 115200 baud på respektive USB-serieport
```

## Fysiska lärdomar

- Verifiera varje flash med bootkontroll (en FAT-kopia korrumperades tyst
  under arbetet; upptäcktes via utebliven radioinit).
- `/tmp` på värden städas aggressivt — mellanlagra UF2:er utanför `/tmp`.
