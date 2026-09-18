# DEN docked UART auth (PRO-53)

DEN-side session master for the PAW↔DEN docked UART link
(`docs/11-dockat-uart-protokoll.md`). Pico 2 (RP2350).

- **Transport: UART (Serial1 @115200, TX=GPIO0, RX=GPIO1)**
  — the current and only in-scope transport.
  LoRa is explicitly out of scope.
- **State machine: `DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED`**
  fail-closed across the full session lifecycle.
  Every error leaves/returns DEN to DENIED.
- Flow per session: `CHALLENGE(8B TRNG nonce)` → wait ≤2000 ms →
  `RESPONSE(32B HMAC)` → constant-time verify → `ACK(0x01/0x00)` +
  `AUTHENTICATED (code 0)` / `FAILED (code N)` log.
  ACK is informational; the access decision is made before ACK
  and never depends on it.
- **USB serial reason codes** (non-secret, integers 0–11) make the
  DEN decision observable without exposing secrets. Codes 9–11 belong
  to the break-glass flow (PRO-97, se nedan).
- PAW display/UI and other peripherals do not alter the DEN
  decision or deadline.
- No hardcoded keys: PRO-93 removed the bring-up dev key; DEN starts
  unprovisioned and denies until PRO-46 provisioning completes.
- Framing/CRC/parser: shared `libraries/DenUartProtocol` (no duplication).
- Ed25519 blocklist verify: `libraries/Ed25519` adapter over the
  rweather Crypto library (see `docs/13-pro-53-fail-closed.md`).
- See `docs/13-pro-53-fail-closed.md` for the full specification,
  state machine diagram, threat model, and hardware acceptance record.

## Build

```bash
# One-time: Ed25519 adapter dependency (tested v0.4.0)
arduino-cli lib install "Crypto@0.4.0"

arduino-cli compile \
  --fqbn rp2040:rp2040:rpipico2 \
  --libraries libraries \
  --output-dir build \
  plc/den-main/den-main.ino
```

## Upload (UF2 drag-and-drop)

1. Hold BOOTSEL + connect USB (Pico 2) — an `RPI-RP2` drive appears.
2. Copy `build/den-main.ino.uf2` onto it; the board reboots.
3. Monitor USB logs at 115200 baud:
   ```bash
   arduino-cli monitor -p /dev/ttyACM0 -c baudrate=115200
   ```

## Break-glass service mode (PRO-97)

Kortlivat, lokalt serviceläge för definierade åtgärder vid övervakad
återställning — inte generell upplåsning av det underliggande systemet
och aldrig en ersättning för nödstopp eller annan fysisk processäkerhet.
Skapar aldrig permanent bypass: ingen flash, inga persistenta flaggor,
ordinarie auth-väg orörd.

Definierade åtgärder i beviljat läge: `BG STATUS` (skrivskyddad
flaggavläsning + audit-dump, varje anrop loggas) och `BG ABORT`
(återlåsning). Allt annat nekas och loggas utan verkan.

Ceremoni (USB-konsol, fysisk närvaro krävs):
1. `BG ARM` (endast från vilande DENIED, ingen provisionering pågår) —
   DEN drar färsk 4-byte ticket ur TRNG, visar den, beväpnar i 60 s.
2. `BG CONFIRM <8 hex>` inom fönstret — korrekt ticket ger beviljat
   serviceläge i 120 s med larm (snabb LED-blink + banner + kod 10).
3. `BG ABORT` återlåser i förtid. Fönsterutgång, felaktig inmatning och
   omstart återlåser alltid (SRAM-tillstånd dör med strömmen).

Tvåpersonsmodell (fysisk, operativ procedur för prototypen): operatör A
vid DEN-konsolen beväpnar och läser ticketen; operatör B bekräftar med
ticketen via fysisk överlämning. Firmwaren kräver en färsk ticket men
kan inte skilja personer åt eller bevisa en överlämning; proceduren och
auditloggen bär den garantin.

Synlighet: varje användning är synlig och spårbar — larmbanner vid
beviljande, LED-blink under fönstret, `[AUDIT]`-rader (seq/tid/händelse)
för arm/beviljande/nekande/status/avslut. Auditringen är SRAM (16
poster, äldst skrivs över) — konsolsidan måste fånga den.

Audit: SRAM-ring (16 poster, sekvensnr + tid + händelse) + läsbara
`[AUDIT]`-rader över USB — konsolsidan måste fånga dem (flyktiga).

Säkerhetsantaganden: två operatörer enligt procedur (firmwaren kräver
en färsk ticket men kan inte tekniskt upprätthålla eller bevisa två
skilda operatörer); USB-konsol = fysisk närvaro (fjärrangripare utan
lokal USB når inte ceremonin); inmatning ekas aldrig (tråden bär även
nyckelmaterial).

Restrisker: en ensam operatör vid konsolen kan utföra båda stegen
(procedur + audit täcker, firmware hindrar inte); audit ringen skriver
över äldst vid >16 händelser och försvinner vid omstart; delad tråd med
PRO-46/PRO-98 — konsolen parsar endast strikta ASCII-rader i viloläge;
ingen tvångskod (duress); 120 s-fönstret är en medveten avvägning
mellan servicebarhet och exponering.

## Bench checks (no PAW needed)

- **Negative loopback:** jumper TX0↔RX1. DEN receives its own
  CHALLENGE back → `FAILED:unexpected type (code 2)`, ACK 0x00.
  Proves fail-closed deny.
- **Silence:** nothing connected → `FAILED:timeout (code 1)` every ~3 s.
- **Live session:** needs PAW firmware (PRO-84):
  `AUTHENTICATED (code 0)` + ACK 0x01.

## Tests

```bash
python3 -m pytest tests/test_pro88_den.py tests/test_pro87_uart.py -v
# 17 + 24 = 41 tests
python3 -m pytest tests/ -q
# 102 tests total
```

Out of scope here: LoRa, e-paper, pogo-dock mechanics (PRO-85), PAW firmware.
