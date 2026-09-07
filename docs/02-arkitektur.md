# Arkitektur - SHALLOT

## 1. Systemöversikt

SHALLOT implementerar ett säkert, fail-closed autentiseringsystem med HMAC-SHA256 och LoRa P2P-kommunikation.

### 1.1 Nodöversikt

**UNO Q - Air-gapped Provisioning Hub**
- Roll: Trust root, nyckelgenerering och distribution
- Hårdvara: Arduino UNO Q (STM32U585)
- Funktioner: AES-128 nyckelgenerering via TRNG, USB nyckeldistribution

**Edge Enforcement Node (PLC)**
- Roll: Autentiseringsbeslut och åtkomstkontroll
- Hårdvara: Raspberry Pi Pico 2 (RP2350) + Waveshare Core1262
- Funktioner: 128-bit nonce, HMAC-SHA256 verifiering, LoRa kommunikation

**PAW - ID-bricka**
- Roll: Användarautentisering
- Hårdvara: Adafruit Feather RP2350 + Core1262 + e-Paper
- Funktioner: HMAC-SHA256 beräkning, LoRa, e-Paper statusdisplay

## 2. Databussdiagram

### 2.1 Edge Enforcement Node - SPI1

RP2350 -> Core1262
SPI1_SCK (GPIO10) -> SCK
SPI1_MOSI (GPIO11) -> MOSI
SPI1_MISO (GPIO24) -> MISO
GPIO9 -> CS
GPIO4 -> RESET
GPIO7 -> BUSY
GPIO28 -> DIO1

### 2.2 PAW - SPI Configuration

Core1262 LoRa module SPI1:
- SCK = D10 GPIO10
- MOSI = D11 GPIO11
- MISO = D24 GPIO24
- CS = D9 GPIO9
- RESET = pin 4 GPIO4
- BUSY = pin 7 GPIO7
- DIO1 = A2 GPIO28

e-Paper display SPI0:
- DIN = MO GPIO23
- CLK = SCK GPIO22
- CS = D5 GPIO5
- DC = A0 GPIO26
- RST = A1 GPIO27
- BUSY = A3 GPIO29

CRITICAL: GPIO4 is SPI0 MISO, NOT SPI1 MISO. SPI1.setRX(4) causes runtime panic.

## 3. Kommunikation

### 3.1 LoRa P2P Protocol

Radio Configuration:
- Frequency: 868.1 MHz EU ISM-band
- Bandwidth: 125 kHz
- Spreading Factor: 7
- Coding Rate: 4/5
- Transmit Power: 20 dBm
- Sync Word: 0x12
- Timeout: 5000 ms
- Retry Policy: 3 attempts

### 3.2 Packet Format

Frame Layout 40 bytes:
- Byte 0: Version 4 bits + Message Type 4 bits
- Byte 1-4: Sequence Number 32 bits
- Byte 5-20: Nonce 128 bits
- Byte 21-31: Payload 11 bytes
- Byte 32-39: HMAC-SHA256 8 bytes truncated

Message Types:
- 0x01: CHALLENGE
- 0x02: RESPONSE
- 0x03: SUCCESS
- 0x04: FAILURE
- 0x05: KEY_DIST
- 0x06: KEY_ACK
- 0x07: HEARTBEAT

## 4. Fail-Closed Princip

Definition: Systemet nekar åtkomst som default och kräver explicit autentisering.

Implementation:
- Hardware: Watchdog timer, Timeout 5000 ms, Default DENY
- Software: Valid HMAC required, Invalid = DENY, Timeout = DENY
- Protocol: No default-open state, All communication requires valid session

Fail-Closed Scenarios:
- Invalid HMAC -> DENY
- Timeout -> DENY
- Packet loss 3 retries -> DENY
- Watchdog trigger -> DENY

## 5. UNO Q Architecture Three-Layer Model

### 5.1 Layer 1: MCU STM32U585
- Function: Key generation, secure storage, UART key distribution
- Security: No MPU involvement with key material

### 5.2 Layer 2: MPU QRB2210/Linux
- Function: Orchestration UI, audit log, validation
- Security: Never touches key material

### 5.3 Layer 3: Bridge RPC
- Function: Communication between Layer 1 and Layer 2
- Security: Status and confirmation messages only
- Protocol: MessagePack RPC

### 5.4 Key Decisions

1. TRNG on STM32U585: Minimal attack surface, physical entropy
2. UART Distribution: Most reliable for breadboard
3. Physical Confirmation: Button press required
4. Audit Log: Stores key fingerprints SHA-256[:4] only

## 6. Säkerhetsarkitektur

### 6.1 Trust Model
- Trust Root: UNO Q MCU
- Trusted: Edge/PAW
- Untrusted: External

### 6.2 Security Boundaries
- Air-Gap: UNO Q physically isolated
- Key Material: Never leaves MCU layer
- Communication: LoRa P2P with HMAC-SHA256
- Display: Privacy masking - no personal information

---
*Document: 02-arkitektur.md | Version: 1.0 | Date: 2026-09-07 | Author: Johannes Oleras*