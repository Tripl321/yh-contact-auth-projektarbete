# SHALLOT — Threat Model and Limitations

**Document:** SHALLOT-THREAT-001  
**Version:** 1.0  
**Date:** 2026-09-05  
**Classification:** Internal - Security Sensitive  

## 1. Purpose

This document defines the threat model for SHALLOT, documenting what the prototype is designed to protect against, what it explicitly does not protect against, and the current limitations of the implementation.

## 2. Threat Model Overview

### 2.1 System Components

| Component | Role | Security Boundary | Trust Level |
|-----------|------|-------------------|-------------|
| MAMA BEAR MCU | Key generation, epoch management, authorization enforcement | STM32U585 hardware | **Trusted** (High) |
| MAMA BEAR MPU | Orchestration, FIDO2 coordination, audit logging | QRB2210 Linux | **Untrusted** (Medium) |
| PLC | Edge enforcement, LoRa challenge, HMAC verification | RP2350A hardware | **Semi-Trusted** (Medium) |
| PAW | Portable authentication, HMAC response, status display | Feather RP2350 hardware | **Semi-Trusted** (Medium) |
| USB Hub | Passive connectivity between devices | Hardware hub | **Untrusted** (Low) |
| Pico FIDO Key | User presence authentication | FIDO2 hardware token | **Trusted** (Medium) |

### 2.2 Data Classification

| Data Type | Storage Location | Protection Level | Exposure Risk |
|-----------|------------------|------------------|---------------|
| AES-128 operational key | MCU SRAM, PLC SRAM, PAW SRAM | **Critical** | Power loss = key loss, but fail-closed |
| Pending key material | MCU SRAM, PLC/PAW SRAM during staging | **Critical** | Atomic activation required |
| Hardware TRNG output | STM32U585 RNG registers | **Critical** | TRNG health check before use |
| Device private identity keys | PLC/PAW flash (future) | **Critical** | Currently simulated with deterministic seeds |
| FIDO2 session credential | Pico FIDO token | **High** | Revoked after session, one-time use |
| Grant tokens | MCU grant cache, MPU memory | **High** | 60s expiry, one-time use, operation-bound |
| Key fingerprints (SHA-256[:4]) | MCU/MPU/PLC/PAW memory, audit logs | **Medium** | No secret material, but can be correlated |
| Audit log entries | MPU file system | **Medium** | No secrets, but operational metadata |
| LoRa nonces | PLC/PAW memory | **Medium** | Replay protection via cache |
| Epoch counters | MCU/MPU/PLC/PAW memory | **Low** | Monotonic, but stored in RAM only |

## 3. Threat Actors

### 3.1 In Scope (Addressed by Design)

#### TA-1: Remote Attacker
- **Capabilities:** Network access, passive/active interception
- **Resources:** Standard computing hardware, off-the-shelf tools
- **Motivation:** Gain unauthorized access, disrupt operations
- **Attack Surface:** LoRa RF, USB (when connected to untrusted hosts)

#### TA-2: Opportunistic Physical Attacker
- **Capabilities:** Brief unsupervised physical access (< 5 minutes)
- **Resources:** Standard tools, no specialized hardware
- **Motivation:** Theft of service, disruption, data exfiltration
- **Attack Surface:** USB ports, buttons, exposed hardware

#### TA-3: Compromised Orchestration Host
- **Capabilities:** Full control of MPU (QRB2210 Linux)
- **Resources:** Malware, exploit code
- **Motivation:** Bypass authorization, extract keys, manipulate provisioning
- **Attack Surface:** Bridge RPC, MPU applications

### 3.2 Out of Scope (Explicit Non-Goals)

#### TA-OOS-1: Invasive Physical Attacker
- **Capabilities:** Chip extraction, hardware modification, invasive probing
- **Resources:** Specialized equipment, forensic tools, physical access > 30 minutes
- **Mitigation:** Out of scope for prototype. Production would require hardware security modules, tamper-resistant enclosures.

#### TA-OOS-2: Nation-State Actor
- **Capabilities:** Advanced persistent threats, supply chain attacks, side-channel expertise
- **Resources:** Significant funding, custom hardware, zero-day exploits
- **Mitigation:** Out of scope for prototype. Production would require certified hardware, formal verification, supply chain controls.

#### TA-OOS-3: Theft-Grade Forensic Analysis
- **Capabilities:** Memory forensics, power analysis, fault injection
- **Resources:** Laboratory equipment, expert knowledge
- **Mitigation:** Out of scope for prototype. Keys stored in volatile SRAM (power loss = key loss).

## 4. Attack Vectors and Mitigations

### 4.1 In Scope - Mitigated

#### AV-01: Replay Attacks
- **Vector:** Replay LoRa challenge/response, replay grant tokens, replay FIDO2 assertions
- **Mitigation:**
  - LoRa: Nonce cache (last 16 nonces, 60s window), epoch binding in HMAC
  - Grants: One-time use cache (8 entries), expiry (60s max)
  - FIDO2: Operation/target/epoch/challenge binding, sign count verification
- **Residual Risk:** **Low** - Cache size limits protection window; epoch rollback possible on power loss

#### AV-02: Spoofing Attacks
- **Vector:** Impersonate PLC/PAW, impersonate MAMA BEAR, spoof FIDO2 device
- **Mitigation:**
  - Device identity: P-256 challenge-response with allowlist of public key hashes (Slice 4)
  - MAMA BEAR: Single source of truth, STM32U585 hardware TRNG
  - FIDO2: Session credentials bound to specific operation/target/epoch
- **Residual Risk:** **Medium** - Device identity currently uses mock signatures; production requires real ECDSA

#### AV-03: Cloned Device Identifiers
- **Vector:** Copy static device IDs, use cloned PAW/PLC
- **Mitigation:**
  - Device identity challenge-response with cryptographic signatures
  - Allowlist of expected device public key hashes on MCU
  - Fresh challenge for each provisioning session
- **Residual Risk:** **Medium** - Mock signatures can be reverse-engineered; production requires real cryptography

#### AV-04: Missing Accountability
- **Vector:** Undetected key provisioning, unauthorized operations without trace
- **Mitigation:**
  - Audit logging: All operations logged with timestamp, operation, target, epoch, outcome
  - No secrets in logs: Only fingerprints, not keys or full nonces
  - FIDO2 assertions: User presence (UP) required for all sensitive operations
  - Button confirmation: Fresh physical press required on MAMA BEAR
- **Residual Risk:** **Low** - Logs could be tampered if MPU compromised; production requires signed audit logs

#### AV-05: Authorization Bypass
- **Vector:** Access without FIDO2, access without button press, reuse old grants
- **Mitigation:**
  - Both FIDO2 assertion AND button press required for all sensitive operations
  - Grants: One-time use, operation-bound, target-bound, epoch-bound, expiry (60s)
  - Button: HIGH→LOW edge detection with 200ms release check, 50ms debounce, 2s window
  - No generic "authenticated" state - each grant authorizes exactly one action
- **Residual Risk:** **Low** - Held button detection prevents some bypass attempts

#### AV-06: Key Extraction
- **Vector:** Read keys from device memory, extract via debug interfaces, memory dump
- **Mitigation:**
  - Keys stored in volatile SRAM (power loss = key loss, fail-closed)
  - No secret-returning USB/serial commands
  - Constant-time comparison for HMAC verification
  - Explicit key zeroization on error/rejection
- **Residual Risk:** **Medium** - Debug interfaces may still be accessible; production requires debug lock

#### AV-07: Accidental Key Rotation
- **Vector:** Button pressed accidentally, wrong grant used, stale epoch
- **Mitigation:**
  - Button edge detection prevents held button
  - Grant binding prevents wrong operation/target/epoch
  - Epoch monotonic increase enforcement
  - Pending window (10min) with deadline expiry
- **Residual Risk:** **Low** - 200ms release requirement prevents rapid accidental presses

#### AV-08: Man-in-the-Middle on USB
- **Vector:** Intercept/modify USB messages between MAMA BEAR and PLC/PAW
- **Mitigation:**
  - CRC32 on key data (accidental corruption check)
  - Epoch binding in all USB messages
  - Device identity verification before key release
  - Atomic activation (both devices or neither)
- **Residual Risk:** **High** - USB hub is passive and untrusted; CRC32 not cryptographic authentication

#### AV-09: LoRa Signal Interception/Injection
- **Vector:** Capture/replay LoRa packets, inject forged packets
- **Mitigation:**
  - HMAC-SHA256 authentication of all LoRa messages
  - Fresh nonces with epoch context
  - Constant-time HMAC verification
  - RSSI gating (discard < -70 dBm)
  - Replay protection via nonce cache
- **Residual Risk:** **Low** - Strong cryptographic protection; RSSI gate prevents weak signal attacks

#### AV-10: Compromised MPU Orchestration
- **Vector:** Malicious MPU software, compromised Linux system
- **Mitigation:**
  - MCU is single source of truth for key material
  - MPU never sees keys in clear
  - Bridge RPC limited to status queries and grant-based requests
  - MCU enforces all authorization (button + grant + epoch + operation)
- **Residual Risk:** **Low** - MPU compromise cannot generate or distribute keys without MCU cooperation

### 4.2 Out of Scope - Not Mitigated

#### AV-OOS-01: Hardware Forensics
- **Vector:** Memory extraction from powered devices, flash dumping
- **Impact:** Full key recovery, device cloning
- **Status:** Out of scope for prototype

#### AV-OOS-02: Side-Channel Attacks
- **Vector:** Power analysis, timing attacks, EM emissions
- **Impact:** Key extraction, operation inference
- **Status:** Out of scope for prototype

#### AV-OOS-03: Supply Chain Attacks
- **Vector:** Malicious hardware, backdoored firmware, compromised libraries
- **Impact:** Full system compromise
- **Status:** Out of scope for prototype

#### AV-OOS-04: Denial of Service
- **Vector:** RF jamming, USB flooding, resource exhaustion
- **Impact:** System unavailability
- **Status:** Partially addressed (fail-closed behavior), but full DoS protection out of scope

## 5. Security Boundaries

### 5.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED COMPUTE BASE                       │
│  ┌─────────────────────┐                                    │
│  │  STM32U585 MCU      │  ◄── Key Generation (TRNG)         │
│  │  (UNO Q)            │  ◄── Grant Verification            │
│  │                     │  ◄── Epoch State Management         │
│  │                     │  ◄── Button Edge Detection          │
│  │                     │  ◄── Device Identity Verification  │
│  └─────────────────────┘                                    │
│         ▲                                                     │
│         │ USB CDC (Key Material + Identity Challenges)      │
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
        └─── LoRa P2P (868 MHz, HMAC-SHA256)───┘
```

### 5.2 Data Flow Boundaries

**Key Material (Critical)**
- Generated: STM32U585 TRNG → MCU SRAM only
- Transmitted: MCU → PLC/PAW via USB (encrypted by protocol design, not by transport)
- Stored: PLC/PAW SRAM (pending until COMMIT), MCU SRAM (active)
- **Never**: MPU memory, USB hub, host computer, logs, debug output

**Authorization Artifacts (High)**
- Generated: MPU (grants) with FIDO2 binding
- Verified: MCU (grants + button)
- Stored: MCU grant cache (8 entries, volatile)
- **Never**: Persistent storage, logs, multiple reuse

**Audit Data (Medium)**
- Generated: MPU based on MCU notifications
- Stored: MPU file system (JSONL)
- Contains: Timestamps, operation types, targets, epochs, fingerprints, outcomes
- **Never**: Key material, full nonces, grants, recovery codes

## 6. Current Implementation Limitations

### 6.1 Prototype-Only Limitations

| Limitation | Impact | Production Requirement |
|------------|--------|------------------------|
| Keys stored in volatile SRAM | Power loss = key loss, requires re-provisioning | Non-volatile secure storage with anti-tamper |
| Epoch stored in RAM only | Power loss resets epoch to 0 | EEPROM/flash storage with wear leveling |
| Device identity uses mock P-256 | Signatures can be forged if seed algorithm known | Real ECDSA P-256 with hardware-backed keys |
| USB hub is passive (no crypto) | Man-in-the-middle possible on USB | Hardware-secured USB hub or point-to-point connections |
| FIDO2 library dependency | Real FIDO2 requires `fido2` Python package | Pre-installed libraries or fallback to other FIDO2 methods |
| No firmware signing | Malicious firmware could be flashed | Signed firmware with secure boot |
| Debug interfaces may be open | Potential for invasive attacks | Production debug lock with sacrificial testing |
| No tamper-evident enclosure | Physical attacks not detected | Tamper-evident/tamper-resistant enclosure design |

### 6.2 Known Weaknesses

| Weakness | Description | Impact | Mitigation Status |
|----------|-------------|--------|-------------------|
| CRC32 for integrity | Not cryptographic, can be forged | Accidental corruption only | Acceptable for prototype (documented limitation) |
| Linear congruential PRNG for PLC nonce | Predictable if state known | Nonce prediction possible | Acceptable for prototype; RP2350 TRNG upgrade planned |
| Mock device identity signatures | Deterministic from device ID | Impersonation possible if algorithm reverse-engineered | Prototype only; real ECDSA for production (Slice 4) |
| Grant cache limited to 8 entries | Old grants could be replayed after cache overflow | Grant replay after 8 new grants | Acceptable for prototype; increase cache or use better replay prevention |
| Button detection software-only | Could potentially be bypassed via hardware | Button bypass possible | Acceptable for prototype; hardware button monitoring for production |
| USB transport unencrypted | Passive interception possible | Key material exposure on USB | USB hub is trusted for prototype; documented limitation |

### 6.3 Unimplemented Security Features

| Feature | Status | Priority | Planned Slice |
|---------|--------|----------|----------------|
| Real ECDSA P-256 signatures | Mock implementation | High | Slice 4 (code complete, needs library) |
| Hardware-backed key storage | Not implemented | Medium | Future production |
| Signed firmware updates | Not implemented | Medium | Future production |
| Secure debug lock | Not implemented | Medium | Future production |
| Hardware RNG on RP2350 | Uses LCG fallback | Low | Future optimization |
| Argon2 for recovery code | SHA-256 with pepper only | Medium | Slice 3 enhancement |
| Signed audit logs | Not implemented | Low | Future enhancement |
| Rate limiting on authorization | Not implemented | Low | Future enhancement |

## 7. Defense in Depth Analysis

### 7.1 Physical Layer
- **Held Button Detection:** 200ms release requirement prevents held button bypass
- **Fresh Press Detection:** HIGH→LOW edge with 50ms debounce, 2s window
- **Hardware Button:** Physical user presence required on MAMA BEAR

### 7.2 Protocol Layer
- **Epoch Binding:** All messages include epoch to prevent cross-epoch confusion
- **Operation Binding:** Grants bound to specific operations (GENERATE_KEY, STAGE_PLC, etc.)
- **Target Binding:** Grants and operations bound to specific target devices
- **Expiry:** Grants valid for 60s maximum, one-time use
- **Replay Prevention:** Grant cache (8 entries), nonce cache (16 entries)

### 7.3 Cryptographic Layer
- **HMAC-SHA256:** LoRa message authentication, constant-time verification
- **TRNG:** STM32U585 hardware RNG with health check for key generation
- **Device Identity:** Mock P-256 signatures with allowlist verification
- **CRC32:** Accidental corruption detection (not authentication)

### 7.4 Authorization Layer
- **Dual Authorization:** FIDO2 assertion (UP) + physical button press required
- **Operation Specificity:** Each grant authorizes exactly one operation
- **Temporal Constraints:** 60s grant expiry, 10min pending window
- **State Machine:** Fail-closed behavior on any error/timeout

### 7.5 Audit Layer
- **Complete Logging:** All operations logged with metadata
- **No Secrets:** Audit logs contain no key material, grants, or full nonces
- **Operation Context:** Each log entry includes operation, target, epoch, outcome

## 8. Security Claims

### 8.1 Positive Claims (What SHALLOT Protects Against)

✅ **Replay Attacks:** LoRa messages, grant tokens, FIDO2 assertions are protected against replay within their validity windows

✅ **Cloned Static IDs:** Device identity challenge-response prevents simple cloning of device identifiers

✅ **Accidental Key Rotation:** Button edge detection, grant binding, and epoch verification prevent accidental key changes

✅ **Missing Accountability:** Audit logging captures all provisioning events with context

✅ **Compromised Orchestration:** MCU enforcement means MPU compromise cannot bypass key generation/distribution requirements

✅ **Lost/Stolen Authenticator:** Session credentials are one-time use, automatically revoked, and require physical presence

✅ **Authorization Specificity:** Each approval is for exactly one operation/target/epoch, cannot be reused

### 8.2 Negative Claims (What SHALLOT Does NOT Protect Against)

❌ **Invasive Hardware Attacks:** Chip extraction, memory forensics, fault injection

❌ **Sophisticated Side-Channel Attacks:** Power analysis, timing attacks, EM emissions

❌ **Supply Chain Attacks:** Malicious hardware, backdoored firmware

❌ **Man-in-the-Middle on USB:** Passive USB hub allows interception (CRC32 is not cryptographic)

❌ **Hardware Cloning with Full Access:** If attacker has physical access and specialized equipment, device secrets could be extracted

❌ **Denial of Service:** RF jamming, USB flooding can disrupt operations

## 9. Recommendations for Production Deployment

### 9.1 Critical for Production
1. **Replace mock device identity with real ECDSA P-256** using hardware-backed keys
2. **Implement non-volatile secure storage** for keys and epoch counters
3. **Add firmware signing and secure boot** to prevent unauthorized firmware
4. **Implement hardware debug lock** with sacrificial testing on production hardware
5. **Use signed audit logs** to prevent tampering with operational records
6. **Add rate limiting** on all authorization endpoints

### 9.2 Recommended for Production
1. **Hardware-backed TRNG** on all devices (not just MCU)
2. **Tamper-evident enclosures** for all hardware components
3. **Secure USB hub** with cryptographic protection or point-to-point connections
4. **Production recovery code management** with proper Argon2 hashing
5. **Hardware security modules** for critical key storage
6. **Formal security review** of all cryptographic implementations

### 9.3 Nice-to-Have
1. **Hardware watchdog timers** for fail-closed behavior on hangs
2. **Secure element chips** for key storage on PLC/PAW
3. **Physical tamper detection** with zeroization on tamper
4. **Hardware RNG on RP2350** devices
5. **Larger replay caches** for better protection against old grant replay

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-09-05 | SHALLOT Team | Initial version |

**Reviewers:**  
**Approvals:**