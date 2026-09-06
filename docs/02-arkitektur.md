# Systemarkitektur — SHALLOT

> Status: Uppdaterad 2026-09-04 | Vecka: 1 | Linear: PRO-31 + PRO-45 + PRO-46

## 1. Oeversikt

Systemet bestaar av tre noder:

| Nod | Haardvara | Roll |
|-----|---------|------|
| PAW (Portable Authentication Wearable) | Adafruit Feather RP2350 + Core1262 + e-Paper | Baerbar ID-bricka, skickar autentiseringsbegaran |
| Edge enforcement-nod | Raspberry Pi Pico 2 (RP2350A) + Core1262 | Verifierar autentisering, fattar fail-closed-beslut |
| Air-gapped provisioneringshubb (Mama Bear) | Arduino UNO Q | Genererar och distribuerar AES-128-nycklar via USB (single source of truth) |

> **Beslut 2026-09-04 - USB istället för UART:** Alla tidigare referenser till UART (Serial1, D0/D1) för nyckeldistribution är föråldrade. Nyckeldistribution sker nu **enbart via USB** (USB CDC). Alla tre noder ansluts via USB-hubb. Detta beslut ersätter UART-arkitekturen fullständigt.

## 2. Databussdiagram

```mermaid
graph TD
    subgraph USB Provisioning Fixture
        MamaBear[MAMA BEAR\nSTM32U585 MCU] -->|USB CDC| PLCC[PLC\nRP2350]
        MamaBear -->|USB CDC| PAWW[PAW\nFeather RP2350]
    end
    
    PLCC -->|LoRa 868MHz| PAWW
    
    style MamaBear fill:#ff69b4,stroke:#333
    style PLCC fill:#90EE90,stroke:#333
    style PAWW fill:#90EE90,stroke:#333
```

## 3. Kommunikation

### 3.1 USB Provisioning Protocol

**Transport:** USB CDC via passive hub (MCU ↔ Devices)

| Message | Direction | Format | Size | Description |
|---------|-----------|--------|------|-------------|
| Handshake | MCU → Device | `0xA1 + target_id + epoch_be4` | 6B | Initiate key distribution |
| Ready | Device → MCU | `0xA2 + device_id[4] + epoch_be4` | 9B | Device acknowledges, echoes epoch |
| Key Data | MCU → Device | `0xA3 + len + key[16] + crc32 + epoch_be4` | 26B | Pending key with CRC and epoch |
| Stored | Device → MCU | `0xA4 + hash[4] + epoch_be4` | 9B | Device confirms storage with fingerprint |
| Commit | MCU → Device | `0xA6 + target_id + epoch_be4` | 6B | Activate pending → active key |
| Cancel | MCU → Device | `0xA7 + target_id + epoch_be4` | 6B | Discard pending key |
| Error | Device → MCU | `0xA5` | 1B | Distribution failed |

**CRC32:** Accidental corruption check only (not authentication).
**Epoch:** 4-byte big-endian, monotonically increasing.
**Target IDs:** PLC = 0x01, PAW = 0x02.

### 3.2 LoRa P2P Authentication Protocol (868 MHz)

| Message | Direction | Format | Size | Description |
|---------|-----------|--------|------|-------------|
| Challenge | PLC → PAW | `0xB1 + nonce[16] + epoch_be4` | 21B | Fresh challenge with epoch context |
| Response | PAW → PLC | `0xB2 + nonce[16] + epoch_be4 + hmac[32]` | 53B | HMAC-SHA256(key, epoch\|\|nonce) |
| Result | PLC → PAW | `0xB3 + result(0x01/0x00)` | 2B | Auth success/failure |

**HMAC Input:** `SHA256(key, epoch_be4 || nonce || message_type)` - binds response to epoch and message type.
**Replay Protection:** PLC maintains nonce cache (last 16 nonces, 60s window).
**RSSI Gate:** PLC discards packets with RSSI < -70 dBm (fail-closed).

## 4. State Machine — Key Rotation

```mermaid
stateDiagram-v2
    [*] --> IDLE: Startup
    
    IDLE --> SESSION_STARTED: MPU enters maintenance mode
    SESSION_STARTED --> FIDO_CREDENTIAL_REGISTERED: Register Pico FIDO session credential
    FIDO_CREDENTIAL_REGISTERED --> KEY_GENERATED: MCU generates key + epoch++ (requires grant + button)
    KEY_GENERATED --> PLC_STAGED: Distribute to PLC via USB (requires grant + button)
    KEY_GENERATED --> PAW_STAGED: Distribute to PAW via USB (requires grant + button)
    PLC_STAGED --> BOTH_ACKNOWLEDGED: PAW also staged
    PAW_STAGED --> BOTH_ACKNOWLEDGED: PLC also staged
    BOTH_ACKNOWLEDGED --> COMMITTED: Both ack same epoch, MCU sends COMMIT via USB
    COMMITTED --> CREDENTIAL_REVOKED: Revoke Pico FIDO credential
    CREDENTIAL_REVOKED --> IDLE: Return to idle
    
    KEY_GENERATED --> EXPIRED: Pending deadline (10 min) elapsed
    PLC_STAGED --> EXPIRED: Pending deadline elapsed
    PAW_STAGED --> EXPIRED: Pending deadline elapsed
    BOTH_ACKNOWLEDGED --> EXPIRED: Commit deadline elapsed
    
    KEY_GENERATED --> CANCELED: Operator cancel
    PLC_STAGED --> CANCELED: Operator cancel  
    PAW_STAGED --> CANCELED: Operator cancel
    BOTH_ACKNOWLEDGED --> CANCELED: Operator cancel
    
    KEY_GENERATED --> FAILED: Distribution error
    PLC_STAGED --> FAILED: Distribution error
    PAW_STAGED --> FAILED: Distribution error
    
    EXPIRED --> IDLE: Clean up pending
    CANCELED --> IDLE: Clean up pending
    FAILED --> IDLE: Clean up pending
    FAILED --> REQUIRES_NEW_FIDO_SESSION: FIDO error
    
    note right of KEY_GENERATED
        Key stored as PENDING on MCU
        Devices have no pending yet
    end note
    
    note right of BOTH_ACKNOWLEDGED
        Both devices have pending key
        MCU verifies same epoch + fingerprint
        COMMIT promotes pending → active
    end note
```

**Epoch Management:**
- `activeEpoch`: Currently active operational key
- `pendingEpoch`: Next epoch being staged (activeEpoch + 1)
- `pendingDeadlineMs`: 10-minute window for staging both devices
- **Rollback Protection:** Epoch must be monotonically increasing

## 5. Fail-closed-princip

Relay OFF som standard. Autentisering kraevs foer att slaa paa. Trigger foer OFF:
- Heartbeat-timeout > 5 s
- Svag RSSI (< -70 dBm)
- Ogiltig signatur / HMAC
- Replay-detektering (nonce cache)
- Utgaangen epoch-nyckel
- Missing/expired grant authorization
- Missing fresh button press

## 6. Security Boundaries

### 6.1 Trust Model

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED COMPUTE BASE                       │
│  ┌─────────────────────┐                                    │
│  │  STM32U585 MCU      │  ◄── Key Generation (TRNG)         │
│  │  (UNO Q)            │  ◄── Grant Verification            │
│  │                     │  ◄── Epoch State Management         │
│  │                     │  ◄── Button Edge Detection          │
│  └─────────────────────┘                                    │
│         ▲                                                     │
│         │ USB CDC (Key Material)                             │
│         ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              UNTRUSTED ORCHESTRATION                 │   │
│  │  Qualcomm QRB2210 MPU (Linux)                         │   │
│  │  - Bridge RPC coordination                           │   │
│  │  - FIDO2/WebAuthn session management                 │   │
│  │  - USB device detection                               │   │
│  │  - Audit logging (NO KEY MATERIAL)                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
        ▲           ▲
        │ USB       │ USB
        ▼           ▼
┌──────────────┐ ┌──────────────┐
│    PLC        │ │    PAW        │
│  (RP2350)     │ │ (Feather RP2350)│
└──────────────┘ └──────────────┘
        ▲           ▲
        └─── LoRa P2P ───┘
```

### 6.2 Threat Model (Updated 2026-09-04)

**In Scope:**
- ✅ Remote attackers (network-based)
- ✅ Casual or brief unsupervised physical access
- ✅ Replay attacks (LoRa messages, grant tokens)
- ✅ Spoofing attacks (device identity, FIDO assertions)
- ✅ Accidental key rotation (missing button, wrong grant)
- ✅ Cloned device identifiers (mitigated by challenge-response)
- ✅ Compromised MPU-side orchestration (MCU still enforces)
- ✅ USB transport security (epoch binding, hash verification)

**Out of Scope (Prototype):**
- ❌ Invasive chip extraction
- ❌ Theft-grade hardware forensics
- ❌ Tamper-evident enclosure design
- ❌ Sophisticated side-channel attacks
- ❌ Supply chain attacks on hardware

**Defence in Depth:**
1. **Physical:** Button edge detection prevents accidental/forced authorization
2. **Cryptographic:** One-time grants, HMAC, epoch binding, FIDO2 UP requirement
3. **Protocol:** USB message integrity (CRC), LoRa replay protection, RSSI gating
4. **Temporal:** Grant expiry (60s), pending window (10min), nonce cache
5. **Audit:** Complete logging of operations without secrets
6. **Separation:** MPU never sees key material, MCU is single source of truth

**Remaining Limitations (Prototype):**
- USB hub is passive (no cryptographic protection)
- Epoch stored in RAM only (power loss resets to 0)
- Keys stored in volatile SRAM (power loss = fail-closed but requires re-provisioning)
- No permanent device identity keys yet (slice 4)
- No production firmware signing yet
- FIDO2 implementation uses placeholder (slice 3)
