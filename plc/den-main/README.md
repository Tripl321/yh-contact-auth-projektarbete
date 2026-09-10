# DEN docked UART auth (PRO-53)

DEN-side session master for the PAW↔DEN docked UART link
(`docs/11-dockat-uart-protokoll.md`). Pico 2 (RP2350).

- **Transport: UART (Serial1 @115200, TX=GPIO0, RX=GPIO1)**
  — the current and only in-scope transport.
  LoRa is explicitly out of scope.
- **State machine: `DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED`**
  fail-closed across the full session lifecycle.
  Every error leaves/returns DEN to DENIED.
- Flow per session: `CHALLENGE(16B TRNG nonce)` → wait ≤2000 ms →
  `RESPONSE(32B HMAC)` → constant-time verify → `ACK(0x01/0x00)` +
  `AUTHENTICATED (code 0)` / `FAILED (code N)` log.
  ACK is informational; the access decision is made before ACK
  and never depends on it.
- **USB serial reason codes** (non-secret, integers 0–7) make the
  DEN decision observable without exposing secrets.
- PAW display/UI and other peripherals do not alter the DEN
  decision or deadline.
- Development shared key (`DEN_DEV_KEY` 00..0F) is bring-up only and
  `#warning`-marked — replace with the provisioned key before production.
- Framing/CRC/parser: shared `libraries/DenUartProtocol` (no duplication).
- See `docs/13-pro-53-fail-closed.md` for the full specification,
  state machine diagram, threat model, and hardware acceptance record.

## Build

```bash
arduino-cli compile \
  --fqbn rp2040:rp2040:rpipico2 \
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
