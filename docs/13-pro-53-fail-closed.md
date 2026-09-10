# 13 — PRO-53 Fail-Closed Watchdog (DEN UART Authentication)

Status: spec v1.0 approved. Implementation and hardware acceptance
complete. UART is the current and only in-scope transport for
DEN↔PAW docked authentication. **LoRa is explicitly out of scope.**

## 1. State machine

```
┌──────────┐  gap(ms)  ┌──────────────────────┐  valid HMAC  ┌───────────────┐
│          │──────────▶│                      │─────────────▶│               │
│  DENIED  │           │   CHALLENGE_SENT     │              │  AUTHENTICATED │
│          │◀──────────│  await RESPONSE ≤2s  │              │               │
│ (initial,│  timeout/ │                      │   timeout /  │  (brief       │
│  after   │  any fail │  DEN_ST_CHALLENGE_SENT│  hmac/parse │   confirmation)│
│  reset,  │  │        │                      │  │           │               │
│  disc,)  │  │        └──────────────────────┘  │           └───────┬───────┘
└──────────┘  │                                    │               │
              │  den_fail()                        │  gap(ms)      │
              │  (all errors → DENIED)             │               │
              │                                    │               │
              └────────────────────────────────────┘               │
              DEN_ST_DENIED                                        │
              DEN_ST_AUTHENTICATED ────────────────────────────────┘
```

### States

| State | Meaning | Transition to |
|-------|---------|---------------|
| `DENIED` | Initial after boot/reset/disconnect/malformed/session complete. Waits gap, then sends CHALLENGE. | `CHALLENGE_SENT` (after gap) |
| `CHALLENGE_SENT` | Challenge sent, awaiting RESPONSE. Deadline = 2 s from CHALLENGE transmission. | `AUTHENTICATED` (valid HMAC) or `DENIED` (any error) |
| `AUTHENTICATED` | HMAC verified. Brief confirmation. ACK already sent. | `DENIED` (after gap) |

### Transition rules

| From | Trigger | To | Notes |
|------|---------|----|-------|
| DENIED | `millis() - stateAt ≥ SESSION_GAP_MS` | CHALLENGE_SENT | Automatic; sends CHALLENGE |
| CHALLENGE_SENT | Valid RESPONSE, HMAC matches | AUTHENTICATED | Access granted; ACK sent |
| CHALLENGE_SENT | Timeout (≥ 2 s) | DENIED | `den_fail(REASON_TIMEOUT)` |
| CHALLENGE_SENT | CRC error, parse error, unexpected type, invalid size | DENIED | `den_fail(REASON_PARSE_ERROR/UNEXPECTED_TYPE/INVALID_SIZE)` |
| CHALLENGE_SENT | HMAC mismatch | DENIED | `den_fail(REASON_HMAC_MISMATCH)` |
| CHALLENGE_SENT | PAW disconnect (no bytes > 3 s) | DENIED | `den_fail(REASON_DISCONNECT)` |
| CHALLENGE_SENT | Stale response (nonce wiped) | DENIED | `den_fail(REASON_STALE_RESPONSE)` |
| AUTHENTICATED | `millis() - stateAt ≥ SESSION_GAP_MS` | DENIED | Session complete; new session requires fresh challenge |

**All errors fail closed.** No error path transitions to AUTHENTICATED.

### Design invariants

1. **DEN starts in DENIED.** After boot, reset, disconnect, malformed input, or session expiry, DEN is always DENIED.
2. **Only a complete, valid RESPONSE for the current CHALLENGE** may transition DEN to AUTHENTICATED.
3. **The response deadline is exactly 2 seconds** from CHALLENGE transmission.
4. **Prior successful sessions do not remain valid.** After the session gap, DEN returns to DENIED; a new challenge is required.
5. **ACK is informational.** The access decision is made before ACK and never depends on it.
6. **PAW display/UI and other peripherals** do not alter the DEN decision or deadline.
7. **Authentication status is observable over USB serial** with non-secret reason codes (integers 0–7).

## 2. Reason codes (non-secret, observable over USB serial)

| Code | Name | Meaning |
|------|------|---------|
| 0 | OK | Authenticated |
| 1 | TIMEOUT | Response deadline exceeded |
| 2 | UNEXPECTED_TYPE | Frame type ≠ RESPONSE |
| 3 | INVALID_SIZE | Payload length mismatch |
| 4 | PARSE_ERROR | CRC, length, type, or resync failure |
| 5 | HMAC_MISMATCH | Constant-time compare failed |
| 6 | DISCONNECT | PAW UART disconnect detected |
| 7 | STALE_RESPONSE | Response for a prior (wiped) nonce |

## 3. Hardware acceptance record

### Wiring (unchanged, current DEN↔PAW UART)

| Signal | DEN (Pico 2) | PAW (Feather RP2350) | Note |
|--------|-------------|---------------------|------|
| UART TX | GPIO0 (UART0 TX) | GPIO1 (UART0 RX) | Serial1 |
| UART RX | GPIO1 (UART0 RX) | GPIO0 (UART0 TX) | Serial1 |
| GND | GND | GND | Common ground |
| Baud | 115200 | 115200 | Fixed |

### Acceptance tests (bench)

1. **Negative loopback** (TX0↔RX1 jumper): DEN receives its own CHALLENGE back → `FAILED:unexpected type (code 2)`, ACK 0x00. Proves fail-closed deny. ✓
2. **Silence** (nothing connected): `FAILED:timeout (code 1)` every ~3 s. ✓
3. **Live session** (with PAW firmware PRO-84): `AUTHENTICATED (code 0)`, ACK 0x01. ✓
4. **State transitions verified** via USB serial log: `DENIED` → `CHALLENGE_SENT` → `AUTHENTICATED` → `DENIED`. ✓
5. **Timeout**: response after 2 s → `DENIED` with code 1. ✓
6. **Malformed frame**: CRC error → `DENIED` with code 4. ✓
7. **HMAC mismatch**: wrong key → `DENIED` with code 5. ✓
8. **Disconnect**: no bytes for 3 s → `DENIED` with code 6. ✓
9. **Prior session not authorizing**: after session gap, new challenge required. ✓
10. **Display/UI does not affect decision**: no e-paper/display code in DEN firmware. ✓

### Bench commands

```bash
# Compile DEN firmware
arduino-cli compile \
  --fqbn rp2040:rp2040:rpipico2 \
  --output-dir build \
  plc/den-main/den-main.ino

# Upload (hold BOOTSEL + connect USB, copy UF2)
# Monitor USB logs
arduino-cli monitor -p /dev/ttyACM0 -c baudrate=115200

# Run Python tests
python3 -m pytest tests/test_pro88_den.py tests/test_pro87_uart.py -v
```

## 4. Build and test results

```
$ python3 -m pytest tests/test_pro88_den.py tests/test_pro87_uart.py -v
...
17 passed (test_pro88_den.py)
24 passed (test_pro87_uart.py)
41 passed total
```

Full suite: **102 tests passing**.

```
$ python3 -m pytest tests/ -q
102 passed in 0.11s
```

## 5. Transport scope

**Current transport: UART (Serial1) over pogo-pins/USB-C dock.**

LoRa is explicitly out of scope. This is documented in:
- `docs/00-scope.md` — LoRa-radiofeldsökning är explicit ur scope
- `docs/architecture-pivot-2026-09-09.md` — kontaktbaserad primärtransport
- `docs/11-dockat-uart-protokoll.md` — UART protokolldefinition
- `docs/13-pro-53-fail-closed` — PRO-53 fail-closed watchdog (this document)

## 6. What changed from the previous implementation

| Aspect | Before (PRO-88) | After (PRO-53) |
|--------|-----------------|----------------|
| States | `GAP`, `WAIT` | `DENIED`, `CHALLENGE_SENT`, `AUTHENTICATED` |
| Initial state | `DEN_ST_GAP` | `DEN_ST_DENIED` |
| Fail transitions | `DEN_ST_GAP` | `DEN_ST_DENIED` |
| Success transition | `DEN_ST_GAP` (immediate) | `DEN_ST_AUTHENTICATED` → `DEN_ST_DENIED` |
| Reason codes | String labels | Enum `DenReason` with USB-observable integer codes |
| Disconnect detection | None | `!Serial1.available()` for > 3 s → `DENIED` |
| Stale response check | None | All-zero nonce → `DENIED` |
| PAW display/UI | Not addressed | Explicitly excluded from DEN decision |
| ACK semantics | Not addressed | Explicitly informational |

## 7. Residual risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Development shared key (`DEN_DEV_KEY`) | Bring-up only; not production | `#warning`-marked; must be replaced with provisioned key |
| No hardware secure element | `id_sk` extraction possible | Future: secure element (ATECC608A/SE050) |
| UART byte-level timeout only | Fast byte-level stall handled; no session-level keepalive | 2 s session deadline covers this |
| MCU reboot resets epoch counter | PAW rejects next envelope | Operator re-runs ceremony; documented |

## 8. LoRa status

**LoRa is out of scope.** No LoRa behavior is present in the DEN firmware, the PAW UART responder, or the protocol. The architecture pivot (2026-09-09) designates UART as the primary transport. LoRa TX-only alarm channel remains a future consideration for a separate task, not part of PRO-53.