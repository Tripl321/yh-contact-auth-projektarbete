# SHALLOT — Simulated, Incomplete, and Unsafe Items

**Document:** SHALLOT-SIU-001  
**Version:** 1.0  
**Date:** 2026-09-05  
**Classification:** Internal - Must Read Before Deployment  

> **⚠️ WARNING: This prototype contains simulated security components that are NOT suitable for production use. Do NOT deploy in environments where security is required without addressing all items in this document.**

## 1. Purpose

This document explicitly lists all components of SHALLOT that are:
- **Simulated** (mock implementations that appear secure but are not)
- **Incomplete** (partially implemented, missing critical functionality)
- **Unsafe** (known to be vulnerable or insufficient for real security)

**This document must be reviewed and all items addressed before ANY production deployment.**

## 2. Simulated Components (Mock Security)

### 2.1 Device Identity (Slice 4)

| Component | Location | Simulation Details | Security Impact | Production Requirement |
|-----------|----------|-------------------|-----------------|------------------------|
| P-256 ECDSA signatures | PLC/PAW/MCU firmware | Uses SHA-256(deviceSeed + message) as mock signature | **CRITICAL**: Signatures can be forged by anyone who knows the algorithm | Real ECDSA P-256 with hardware-backed private keys |
| Device private keys | PLC/PAW firmware | Stored as plain seed derived from device ID | **CRITICAL**: Private key material in plaintext, derived deterministically | Hardware-backed secure key storage with true TRNG |
| Device public keys | PLC/PAW firmware | Created as mock uncompressed format (0x04 + x + y) where x and y are copies of private seed | **HIGH**: Public keys are not valid ECDSA points, allowlist matching is based on predictable hashes | Real ECDSA key generation and proper public key format |
| Device allowlist verification | MCU firmware | Computes expected hashes from known device ID seeds | **HIGH**: Allowlist can be bypassed if attacker knows the seed derivation algorithm | Allowlist of real public key hashes from provisioned devices |

**Simulation Algorithm:**
```c
// On devices (mock P-256):
sha256(devicePrivateKey, 32, devicePublicKeyHash);
// devicePrivateKey = seed (from deviceId)

// On MCU (mock verification):
// Compute expected hash from known seed ("PLC\x01" or "PAW\x01")
// Compare with received deviceHash
```

**Attack Vector:** An attacker who reverse-engineers the seed derivation algorithm can compute valid device hashes and forge signatures for any operation/target/epoch combination.

### 2.2 FIDO2 Session Credentials

| Component | Location | Simulation Details | Security Impact | Production Requirement |
|-----------|----------|-------------------|-----------------|------------------------|
| FIDO2 library dependency | MPU Python script | Falls back to placeholder if `fido2` library not installed | **HIGH**: Without real FIDO2, grants are just random bytes with no hardware security | Install `fido2` library: `pip install fido2` |
| Session credential registration | MPU `Fido2SessionManager` | Creates mock credential ID if library unavailable | **HIGH**: Mock credentials provide no real user presence verification | Use real `fido2.client.Fido2Client.register()` |
| Session credential revocation | MPU `Fido2SessionManager` | Only resets internal state, does not delete from device | **MEDIUM**: Session credentials persist on device after "revocation" | Use real credential deletion if supported by device |
| User presence (UP) requirement | MPU FIDO2 calls | Uses `user_verification='discouraged'` | **MEDIUM**: No PIN/UV, but still requires user touch on device | Acceptable for prototype; consider UV for production |

**Simulation Fallback:**
```python
# If fido2 library not available:
self.session_credential_id = secrets.token_bytes(32)
# This is just random bytes, not a real FIDO2 credential
```

**Attack Vector:** If `fido2` library is not installed, an attacker can bypass FIDO2 security entirely. The system falls back to placeholder grants that only require button press.

### 2.3 Recovery Code Verification

| Component | Location | Simulation Details | Security Impact | Production Requirement |
|-----------|----------|-------------------|-----------------|------------------------|
| Recovery code format check | MPU `verify_recovery_code()` | Only checks length (≥16) and alphanumeric format | **CRITICAL**: Any 16+ character alphanumeric string is accepted | Proper verification against stored Argon2 hash |
| Recovery code hashing | MPU `hash_recovery_code()` | Uses SHA-256(recovery_code + pepper) | **HIGH**: SHA-256 is too fast for password verification, vulnerable to brute force | Use Argon2 with proper parameters |
| Recovery code storage | MPU audit logging | Stores hash of recovery code in audit | **MEDIUM**: Hash is stored, but if hashing is weak, recovery code could be brute forced | Store only Argon2 hash with proper salt and parameters |

**Simulation Implementation:**
```python
def verify_recovery_code(recovery_code):
    if not recovery_code or len(recovery_code) < 16:
        return False
    if not recovery_code.isalnum():
        return False
    return True  # Accepts ANY alphanumeric string >= 16 chars!
```

**Attack Vector:** An attacker can use ANY 16+ character alphanumeric string as a recovery code. The system provides no real verification.

## 3. Incomplete Components

### 3.1 Hardware Security

| Component | Location | Missing Functionality | Security Impact | Completion Requirement |
|-----------|----------|----------------------|-----------------|------------------------|
| Debug interface protection | All devices | No protection against debug access | **HIGH**: Debug interfaces may allow memory dump, firmware extraction | Implement debug lock with sacrificial testing |
| Secure key storage | PLC/PAW firmware | Keys stored in volatile SRAM, not protected from memory access | **HIGH**: Memory dump can extract keys | Hardware-backed secure key storage |
| Epoch persistence | All devices | Epoch counters stored in RAM only, lost on power cycle | **MEDIUM**: Power loss resets epoch to 0, allowing epoch rollback | Store epoch in EEPROM/flash with wear leveling |
| Firmware signing | All devices | No signature verification on firmware updates | **HIGH**: Malicious firmware could be flashed | Implement signed firmware with secure boot |
| Hardware RNG on RP2350 | PLC/PAW firmware | Uses LCG for nonce generation when TRNG not available | **MEDIUM**: Predictable nonces if state known | Use hardware TRNG or proper PRNG |

### 3.2 Protocol Security

| Component | Location | Missing Functionality | Security Impact | Completion Requirement |
|-----------|----------|----------------------|-----------------|------------------------|
| USB transport authentication | MCU/PLC/PAW | No cryptographic authentication on USB messages | **CRITICAL**: Man-in-the-middle possible on USB hub | Add HMAC or signature on USB messages |
| USB message encryption | MCU/PLC/PAW | All USB messages sent in clear | **CRITICAL**: Key material visible on USB bus | Add encryption for key data on USB |
| LoRa encryption | PLC/PAW | LoRa messages only authenticated, not encrypted | **MEDIUM**: Message content visible to eavesdroppers | Add encryption for LoRa messages |
| Replay cache size | PLC firmware | Nonce cache limited to 16 entries | **LOW**: Old nonces can be replayed after cache overflow | Increase cache size or use better replay prevention |
| Grant cache size | MCU firmware | Grant replay cache limited to 8 entries | **LOW**: Old grants can be replayed after cache overflow | Increase cache size or use better replay prevention |

### 3.3 FIDO2 Implementation

| Component | Location | Missing Functionality | Security Impact | Completion Requirement |
|-----------|----------|----------------------|-----------------|------------------------|
| Real FIDO2 credential deletion | MPU | Session credential revocation does not delete from device | **MEDIUM**: Credentials persist on device after session end | Implement real credential deletion |
| FIDO2 device presence verification | MPU | Uses simple `lsusb` check for device detection | **LOW**: Could be bypassed | Use proper FIDO2 device verification |
| FIDO2 challenge binding | MPU | Challenge includes operation/target/epoch, but not full context | **LOW**: Binding could be stronger | Review and strengthen challenge binding |

## 4. Unsafe Components

### 4.1 Known Vulnerabilities

| Component | Location | Vulnerability | Impact | Fix |
|-----------|----------|--------------|--------|-----|
| CRC32 for integrity | All firmware | CRC32 is not cryptographic, can be forged | **HIGH**: Accidental corruption detection only, not authentication | Replace with HMAC or signature for security-critical data |
| Linear Congruential Generator (LCG) | PLC firmware | `simpleRandState = simpleRandState * 1664525 + 1013904223` | **HIGH**: Predictable if state known | Use hardware TRNG or cryptographic PRNG |
| Software-only button detection | MCU firmware | Button state read via `digitalRead(A0)` | **MEDIUM**: Could be bypassed via hardware manipulation | Add hardware monitoring for button |
| Serial debug output | All firmware | Key material, nonces, hashes logged to Serial | **HIGH**: Secrets exposed in debug logs | Remove all secret logging, use DEBUG build flag |
| Memory zeroization | All firmware | Uses `memset()` and `volatile` for key wiping | **LOW**: Compiler may optimize away, not guaranteed on power loss | Use platform-specific secure zeroization |

### 4.2 Potential Vulnerabilities

| Component | Location | Potential Issue | Impact | Investigation Required |
|-----------|----------|----------------|--------|------------------------|
| MessagePack RPC parsing | MPU BridgeRPC | No explicit length checks on all inputs | **MEDIUM**: Could lead to buffer overflow | Add explicit length checks, use safe parsing |
| USB message parsing | All firmware | No length checks before `readBytes()` | **MEDIUM**: Could lead to buffer overflow | Add explicit length checks before all reads |
| Millis() rollover | All firmware | Uses `millis()` for timeouts, which rolls over after ~50 days | **LOW**: Could cause unexpected behavior | Use unsigned math for comparisons, handle rollover |
| String formatting | MCU firmware | Uses custom `printHex()` due to Zephyr limitations | **LOW**: Potential buffer overflow in hex formatting | Add bounds checking to printHex |

## 5. Environment-Specific Issues

### 5.1 Prototype-Only Assumptions

| Assumption | Risk | Production Consideration |
|------------|------|---------------------------|
| USB hub is trusted | USB messages not authenticated/encrypted | Use secure USB hub or point-to-point connections |
| Physical access is supervised | Device identity mock signatures acceptable | Implement real device identity for unsupervised use |
| Power loss is acceptable | Keys stored in volatile SRAM | Implement persistent secure storage |
| Debug interfaces accessible | Acceptable for development | Disable debug interfaces for production |

### 5.2 Dependency Issues

| Dependency | Issue | Risk | Resolution |
|------------|-------|------|------------|
| `fido2` Python library | Optional dependency, may not be installed | FIDO2 security bypassed | Document as requirement, provide fallback warning |
| Arduino Core for STM32U585 | May not have hardware TRNG enabled | TRNG health check may fail | Add prj.conf with `CONFIG_HARDWARE_DEVICE_CS_GENERATOR=y` |
| RadioLib | Uses software SPI for some configurations | Potential timing issues | Test with actual hardware, use hardware SPI where available |
| GxEPD2 | Large library, may have memory issues on RP2350 | Display instability | Test memory usage, consider display optimizations |

## 6. Test Coverage Gaps

### 6.1 Missing Tests

| Test Category | Missing Tests | Risk | Priority |
|---------------|---------------|------|----------|
| Device identity | Real ECDSA signature verification | Mock signatures not tested | High |
| FIDO2 | Real `fido2` library integration | Placeholder not tested | High |
| USB transport | Man-in-the-middle on USB | Cannot test without secure hub | Medium |
| Hardware security | Debug interface access | Requires specialized hardware | Medium |
| Side channels | Power analysis, timing | Requires specialized equipment | Low |
| Long-duration | Millis() rollover after 50 days | Hard to test | Low |

### 6.2 Inadequate Tests

| Test Category | Issue | Risk | Improvement |
|---------------|-------|------|-------------|
| Device identity | Only tests mock signature computation | Mock may not match real implementation | Add tests for real ECDSA when available |
| FIDO2 | Only tests placeholder behavior | May not catch real FIDO2 issues | Add tests with real FIDO2 device |
| LoRa | Tests with mock RadioLib | May not catch real RF issues | Add hardware-in-loop LoRa tests |
| Button detection | Software-only tests | May not catch hardware issues | Add hardware button tests |

## 7. Checklist for Safe Use

Before using SHALLOT in ANY environment where security matters:

- [ ] ✅ **DO NOT USE IN PRODUCTION** - This is a prototype with known simulated security
- [ ] ✅ Review and understand all items in this document
- [ ] ✅ Review the Threat Model document (`11-threat-model-limitations.md`)
- [ ] ✅ Ensure all devices are running the correct firmware versions
- [ ] ✅ Verify `fido2` library is installed if relying on FIDO2 security: `pip show fido2`
- [ ] ✅ Understand that device identity verification uses mock signatures
- [ ] ✅ Understand that recovery code verification accepts ANY alphanumeric string
- [ ] ✅ Understand that USB transport has no cryptographic protection
- [ ] ✅ Understand that keys are stored in volatile SRAM (lost on power cycle)
- [ ] ✅ Implement physical security for all devices
- [ ] ✅ Implement network/RF security for LoRa communications
- [ ] ✅ Have a plan for key re-provisioning after power loss
- [ ] ✅ Monitor audit logs regularly for suspicious activity

## 8. Summary: What MUST Be Fixed Before Production

### Critical (Must Fix)
1. ✅ **Device Identity**: Replace mock P-256 signatures with real ECDSA
2. ✅ **USB Transport**: Add cryptographic authentication and encryption for USB messages
3. ✅ **FIDO2**: Ensure `fido2` library is available and used for all FIDO2 operations
4. ✅ **Recovery Code**: Implement proper Argon2-based recovery code verification
5. ✅ **Secure Storage**: Implement non-volatile secure storage for keys and epoch
6. ✅ **Firmware Signing**: Add signed firmware with secure boot
7. ✅ **Debug Protection**: Implement debug lock to prevent unauthorized access

### High Priority (Should Fix)
1. ✅ **Hardware RNG**: Use hardware TRNG on all devices
2. ✅ **FIDO2 Credential Deletion**: Implement real credential deletion on session end
3. ✅ **Replay Cache**: Increase cache sizes or implement better replay prevention
4. ✅ **Error Handling**: Add comprehensive error handling and logging
5. ✅ **Input Validation**: Add explicit length checks on all inputs

### Medium Priority (Nice to Fix)
1. ✅ **LoRa Encryption**: Add encryption in addition to authentication
2. ✅ **Signed Audit Logs**: Add cryptographic signatures to audit log entries
3. ✅ **Rate Limiting**: Add rate limiting on all authorization endpoints
4. ✅ **Hardware Button**: Add hardware-level button monitoring

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-09-05 | SHALLOT Team | Initial version |

**Reviewers:**  
**Approvals:**  

---

**By reading this document, you acknowledge that SHALLOT contains simulated security components and is NOT suitable for production use without addressing all critical and high priority items listed above.**

**This prototype is for research, development, and demonstration purposes only.**