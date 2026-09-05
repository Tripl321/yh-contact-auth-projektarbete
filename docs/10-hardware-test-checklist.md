# SHALLOT — Hardware Test Checklist for USB Fixture

**Document:** SHALLOT-HW-TEST-001  
**Version:** 1.0  
**Date:** 2026-09-05  
**Status:** Draft  

## 1. Purpose

This checklist ensures that the three-device USB provisioning fixture is properly configured and all hardware components are functioning correctly before and after firmware updates.

## 2. Test Environment

### Required Hardware
- [ ] MAMA BEAR: Arduino UNO Q (STM32U585 + QRB2210 MPU)
- [ ] PLC: Raspberry Pi Pico 2 (RP2350A) + Core1262-868M LoRa module
- [ ] PAW: Adafruit Feather RP2350 + Core1262-868M + 1.54" e-Paper
- [ ] Passive USB 2.0/3.0 hub with sufficient power (3+ ports recommended)
- [ ] USB-C cables (3x, high-quality, shielded)
- [ ] USB-A to USB-C adapters (if needed for hub compatibility)
- [ ] 5V power supply for USB hub (if hub requires external power)
- [ ] Pico FIDO key (Raspberry Pi Pico with FIDO2 firmware) - for Slice 3

### Required Software
- [ ] Arduino IDE with boards support:
  - [ ] Arduino UNO Q (STM32U585) support
  - [ ] Raspberry Pi Pico (RP2040) support (earlephilhower core)
  - [ ] Adafruit Feather RP2350 support
- [ ] `fido2` Python library (for Slice 3 real FIDO2): `pip install fido2`
- [ ] `pytest` for running test suite: `pip install pytest`
- [ ] RadioLib library for LoRa
- [ ] GxEPD2 library for e-Paper (PAW only)

## 3. Pre-Test Setup

### Physical Setup
1. **USB Hub Configuration**
   - [ ] Connect USB hub to power source
   - [ ] Ensure hub has sufficient power for all three devices
   - [ ] Verify hub supports USB 2.0+ (no USB 1.1 only hubs)
   - [ ] Check hub has dedicated power for each port (not bus-powered only)

2. **Device Connections**
   - [ ] Connect MAMA BEAR to USB hub port 1
   - [ ] Connect PLC to USB hub port 2
   - [ ] Connect PAW to USB hub port 3
   - [ ] Connect USB hub to host computer (for monitoring/firmware updates)
   - [ ] Verify all USB connections are secure (no loose connectors)

3. **Device Power**
   - [ ] Ensure all devices power up correctly
   - [ ] Check LED indicators on all devices
   - [ ] Verify no power cycling or brown-out conditions

## 4. Individual Device Tests

### 4.1 MAMA BEAR (UNO Q)

**Firmware Verification**
- [ ] STM32U585 MCU firmware flashed with `uno-q-key-authority-mcu.ino`
- [ ] QRB2210 MPU running `uno-q-key-authority-mpu.py`
- [ ] Arduino Bridge service running on MPU
- [ ] Bridge RPC socket available at `/var/run/arduino-router.sock`

**Hardware Checks**
- [ ] Confirmation button (A0) functional and not stuck
- [ ] Status LED functional
- [ ] USB CDC enumeration successful (`ttyACM*` or `/dev/ttyGS0`)
- [ ] Internal UART bridge between MCU and MPU functional

**Functional Tests**
- [ ] Serial monitor shows "SHALLOT — UNO Q Key Authority" on boot
- [ ] Button press detected (HIGH→LOW edge) - LED should respond
- [ ] Bridge RPC responds to `get_key_state` queries
- [ ] Grant-based key generation works with button press
- [ ] USB serial communication with PLC/PAW functional

### 4.2 PLC (Raspberry Pi Pico 2)

**Firmware Verification**
- [ ] Firmware flashed with `plc-key-receiver/plc-key-receiver.ino`
- [ ] Correct board selection: Raspberry Pi Pico 2 (RP2350A)

**Hardware Checks**
- [ ] Core1262 LoRa module properly connected via SPI1
- [ ] SPI1 pins: SCK=GP10, MOSI=GP11, MISO=GP12, CS=GP9
- [ ] LoRa control pins: BUSY=GP6, RESET=GP8, DIO1=GP21
- [ ] USB enumeration successful
- [ ] Built-in LED functional

**Functional Tests**
- [ ] Serial monitor shows "SHALLOT — PLC Complete Firmware" on boot
- [ ] USB handshake with MAMA BEAR successful (0xA1→0xA2)
- [ ] Key reception via USB works (0xA3 message)
- [ ] LoRa initialization successful (868 MHz)
- [ ] Challenge generation and transmission works
- [ ] HMAC verification successful with correct key
- [ ] RSSI gating functional (discards < -70 dBm)
- [ ] COMMIT message handling works (0xA6)
- [ ] Identity challenge response works (0xB4→0xB5)

### 4.3 PAW (Adafruit Feather RP2350)

**Firmware Verification**
- [ ] Firmware flashed with `paw-main/paw-main.ino`
- [ ] Correct board selection: Adafruit Feather RP2350

**Hardware Checks**
- [ ] Core1262 LoRa module properly connected via SPI1
- [ ] SPI1 pins: SCK=D10/GP10, MOSI=D11/GP11, MISO=D24/GP24, CS=D9/GP9
- [ ] LoRa control pins: BUSY=D7/GP7, RESET=D4/GP4, DIO1=A2/GP28
- [ ] e-Paper display properly connected via SPI0
- [ ] SPI0 pins: CS=5/GP5, DC=A0/GP26, RST=A1/GP27, BUSY=D25/GP25
- [ ] USB enumeration successful
- [ ] Built-in LED functional

**Functional Tests**
- [ ] Serial monitor shows "SHALLOT PAW Main Firmware" on boot
- [ ] e-Paper initialization successful
- [ ] Status icons display correctly (AUTHENTICATING, AUTHENTICATED, FAILED)
- [ ] USB handshake with MAMA BEAR successful (0xA1→0xA2)
- [ ] Key reception via USB works (0xA3 message)
- [ ] LoRa initialization successful (868 MHz)
- [ ] Challenge reception and HMAC response works
- [ ] Result message handling works (0xB3)
- [ ] COMMIT message handling works (0xA6)
- [ ] Identity challenge response works (0xB4→0xB5)

## 5. USB Fixture Integration Tests

### 5.1 Basic Connectivity
- [ ] All three devices enumerated on USB hub simultaneously
- [ ] Each device has unique serial port identifier
- [ ] No USB enumeration conflicts or errors
- [ ] Host can communicate with all three devices via their serial ports

### 5.2 Provisioning Flow
- [ ] MAMA BEAR detects all devices on USB hub
- [ ] Session start with recovery code works
- [ ] FIDO2 session credential registration works (Slice 3)
- [ ] Grant-based key generation works with button press
- [ ] Key distribution to PLC via USB successful
- [ ] Device identity verification for PLC works
- [ ] Key distribution to PAW via USB successful
- [ ] Device identity verification for PAW works
- [ ] Both devices acknowledge same epoch and fingerprint
- [ ] COMMIT message sent to both devices
- [ ] Both devices respond with COMMIT acknowledgment
- [ ] Key activation successful on both devices
- [ ] FIDO2 session credential revocation works

### 5.3 LoRa Authentication Flow
- [ ] PLC sends challenge to PAW over LoRa (868 MHz)
- [ ] PAW receives challenge and computes HMAC response
- [ ] PLC verifies HMAC and sends result
- [ ] PAW displays correct status on e-Paper
- [ ] PLC indicates authentication success/failure
- [ ] RSSI values within expected range (> -70 dBm)
- [ ] No LoRa packet loss or corruption

### 5.4 Negative Tests
- [ ] Disconnect PLC during provisioning → fail-closed, PAW unchanged
- [ ] Disconnect PAW during provisioning → fail-closed, PLC unchanged
- [ ] Disconnect USB hub mid-transfer → no partial activation
- [ ] Send wrong epoch → device rejects
- [ ] Send corrupted key data → CRC mismatch, device rejects
- [ ] Replay old challenge → nonce cache rejects
- [ ] Invalid HMAC → authentication fails
- [ ] Wrong device identity → identity verification fails

## 6. Environmental Tests

### 6.1 RF Environment
- [ ] Test in open area (minimal RF interference)
- [ ] Test in typical indoor environment
- [ ] Test with LoRa frequency: 868.0 MHz
- [ ] Test with LoRa settings: BW=125kHz, SF=9, CR=5
- [ ] Verify signal strength between devices
- [ ] Test at various distances (0.5m, 1m, 5m, 10m)

### 6.2 Power Tests
- [ ] Test with USB hub powered from host only
- [ ] Test with externally powered USB hub
- [ ] Test with battery power (if applicable)
- [ ] Verify stable operation during power fluctuations
- [ ] Check for proper fail-closed behavior on power loss

### 6.3 Temperature Tests
- [ ] Test at room temperature (20-25°C)
- [ ] Test at elevated temperature (40-50°C) if possible
- [ ] Check for stable operation across temperature range
- [ ] Verify no thermal throttling or performance degradation

## 7. Security Tests

### 7.1 Physical Security
- [ ] Verify button on MAMA BEAR cannot be held down to bypass fresh press detection
- [ ] Verify button requires >200ms release between presses
- [ ] Verify 50ms debounce works correctly
- [ ] Verify 2s window for button press detection

### 7.2 Device Identity
- [ ] Verify PLC cannot impersonate PAW
- [ ] Verify PAW cannot impersonate PLC
- [ ] Verify device with wrong public key hash is rejected
- [ ] Verify signature cannot be replayed across different operations
- [ ] Verify signature cannot be replayed across different epochs

### 7.3 FIDO2 Security (Slice 3)
- [ ] Verify FIDO2 device presence required
- [ ] Verify user touch required (UP)
- [ ] Verify assertion bound to operation
- [ ] Verify assertion bound to target
- [ ] Verify assertion bound to epoch
- [ ] Verify assertion cannot be replayed
- [ ] Verify session credential automatically revoked

## 8. Test Results Log

| Test | Date | Tester | Result | Notes |
|------|------|--------|--------|-------|
| Individual Device Tests | | | | |
| USB Fixture Integration | | | | |
| Environmental Tests | | | | |
| Security Tests | | | | |

## 9. Troubleshooting Guide

### Common Issues

**USB Enumeration Failures**
- Check USB cable quality
- Try different USB ports on hub
- Verify hub has sufficient power
- Check for driver issues on host

**LoRa Communication Failures**
- Verify same frequency (868.0 MHz)
- Check antenna connections
- Verify SPI connections
- Check for RF interference
- Ensure devices are within range

**Device Identity Failures**
- Verify device firmware has correct device ID
- Check allowlist on MCU matches device hashes
- Verify challenge-response protocol timing
- Ensure no man-in-the-middle on USB

**FIDO2 Failures**
- Verify `fido2` library installed: `pip show fido2`
- Check Pico FIDO device firmware updated
- Verify device detected: `lsusb` should show Pico
- Check user touch detected properly

## 10. Sign-Off

**Test Suite Completion**
- [ ] All individual device tests passed
- [ ] All integration tests passed
- [ ] All environmental tests passed
- [ ] All security tests passed
- [ ] All negative tests passed

**Approvals**
- [ ] Operator training completed
- [ ] Hardware setup verified
- [ ] Software version confirmed
- [ ] Test results reviewed

**Test Lead:** ___________________  **Date:** _________  
**Technical Reviewer:** _____________  **Date:** _________