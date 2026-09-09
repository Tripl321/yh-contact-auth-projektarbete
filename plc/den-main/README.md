# DEN docked UART auth (PRO-88)

DEN-side session master for the PAW↔DEN docked UART link
(`docs/11-dockat-uart-protokoll.md`). Pico 2 (RP2350).

- Transport: **Serial1 @115200, TX=GPIO0, RX=GPIO1** (UART0 defaults —
  no pin remap). USB Serial is logs only.
- Flow per session: `CHALLENGE(16B TRNG nonce)` → wait ≤2000 ms →
  `RESPONSE(32B HMAC)` → constant-time verify → `ACK(0x01/0x00)` +
  `AUTHENTICATED` / `FAILED` log. Every failure fails closed.
- Development shared key (`DEN_DEV_KEY` 00..0F) is bring-up only and
  `#warning`-marked — replace with the provisioned key before production.
- Framing/CRC/parser: shared `libraries/DenUartProtocol` (no duplication).

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
   (Replace `/dev/ttyACM0` with the Pico 2 port.)

## Bench checks (no PAW needed)

- **Negative loopback:** jumper TX0↔RX1. DEN receives its own CHALLENGE
  back → `FAILED: unexpected type`, ACK 0x00. Proves fail-closed deny.
- **Silence:** nothing connected → `FAILED: timeout` every ~3 s.
- **Live session:** needs PAW firmware (PRO-84): `AUTHENTICATED` + ACK 0x01.

Out of scope here: LoRa, e-paper, pogo-dock mechanics (PRO-85), PAW firmware.
