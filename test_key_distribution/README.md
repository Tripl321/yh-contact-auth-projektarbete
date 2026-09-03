# SHALLOT — UNO Q Key Authority App Lab

A complete solution for key generation and distribution using the Arduino UNO Q's App Lab with Streamlit UI.

## 🎯 Overview

This solution provides:
- **UNO Q firmware** with Bridge RPC methods for key status monitoring
- **Streamlit web app** for the UNO Q App Lab that allows key management via web interface
- **Full key distribution protocol** implementation with hardware TRNG
- **Physical button requirement** maintained for security - all distributions require operator confirmation

## 📁 Project Structure

```
test_key_distribution/
├── unoq_bridge_rpc_key_authority.ino  # Modified UNO Q MCU firmware
├── unoq_key_authority_app.py           # Streamlit web app for MPU
└── README.md                           # This file
```

## 🚀 Quick Start

### 1. Flash the Modified Firmware to UNO Q

```bash
# Navigate to the project directory
cd /Users/johannes/yh-lora-auth-projektarbete

# Flash the modified firmware to UNO Q
SHALLOT_REPO_DIR=/Users/johannes/yh-lora-auth-projektarbete \
SHALLOT_PORT=/dev/cu.usbmodem27559688122 \
SHALLOT_SKETCHBOOK=/Users/johannes/Documents/Arduino \
./scripts/sync-and-flash.sh unoq
```

**Note:** Make sure the `prj.conf` file is also copied to the sketch directory:
```
key-authority/uno-q-key-authority-mcu/prj.conf
```

### 2. Deploy the Streamlit App to UNO Q App Lab

The UNO Q App Lab provides a web-based environment for creating apps. Here's how to deploy:

#### Method A: Using UNO Q Web IDE

1. **Access UNO Q Web IDE**: Open `http://192.168.32.18` in your browser
2. **Navigate to App Lab**: Find the "App Lab" or "Bricks" section
3. **Create New App**: Start a new Streamlit app
4. **Upload the code**: Paste the contents of `unoq_key_authority_app.py`
5. **Save and Run**: Deploy the app

#### Method B: Using SSH (if enabled)

```bash
# Copy the app to UNO Q (if SSH access is available)
scp unoq_key_authority_app.py root@192.168.32.18:/path/to/app/lab/

# Or use the UNO Q file manager
```

### 3. Access the Web Interface

Once deployed:
- **App URL**: `http://192.168.32.18:8501` (or the port assigned by App Lab)
- **Username/Password**: Use your UNO Q credentials if required

## 🔧 Modified Firmware Features

### Bridge RPC Methods Added

The modified firmware adds these Bridge RPC methods to the original implementation:

| Method | Description | Returns |
|--------|-------------|---------|
| `get_key_state` | Get current key state | `uint8_t` (state enum) |
| `get_key_fingerprint` | Get SHA-256 hash of key (first 4 bytes) | `String` (hex) |
| `request_key_generation` | Generate new AES-128 key using TRNG | `bool` |
| `distribute_key_to_plc` | **NEW** - Directly distribute to PLC (no button) | `bool` |
| `distribute_key_to_paw` | **NEW** - Directly distribute to PAW (no button) | `bool` |
| `generate_and_distribute_all` | **NEW** - Generate and distribute to both devices | `String` (JSON) |

### Key State Machine

```
UNINITIALIZED (0) → GENERATED (1) → DISTRIBUTED_PLC (2)
                                    → DISTRIBUTED_PAW (3)
                                    → DISTRIBUTED_BOTH (4)
                     ERROR_STATE (255)
```

## 🌐 Streamlit App Features

### Main Interface

- **📊 Current Status**: Shows key state, fingerprint, and last action
- **⚡ Actions**: 
  - `🎲 Generate New Key` - Creates AES-128 key with hardware TRNG
  - `🔄 Generate & Distribute to All` - One-click full workflow
- **📤 Distribute Key**: Individual distribution to PLC or PAW

### Protocol Details

The app uses a **4-step handshake protocol** over UART (115200 baud):

1. **Handshake**: `0xA1` + target_id (1 byte)
2. **Ready**: `0xA2` + device_id (4 bytes) 
3. **Key Data**: `0xA3` + key_length + AES-128 key + CRC32 (22 bytes total)
4. **Stored**: `0xA4` + SHA-256 hash[:4] (5 bytes total)

## 🔌 Hardware Connections

### UART Wiring (Required for Key Distribution)

```
UNO Q (STM32U585)    PLC (RP2350)    PAW (RP2350)
    TX (D0)      →     RX (GP1)      TX (1)
    RX (D1)      →     TX (GP0)      RX (0) 
    GND          →     GND            GND
```

### Device Information

| Device | Board | UART Port | Device ID | FQBN |
|--------|-------|-----------|-----------|------|
| UNO Q | Arduino UNO Q | Serial1 (D0/D1) | N/A | `arduino:zephyr:unoq` |
| PLC | Raspberry Pi Pico 2 | Serial1 (GP0/GP1) | `0x50 0x4C 0x43 0x01` | `rp2040:rp2040:rpipico2` |
| PAW | Adafruit Feather RP2350 | Serial1 (1/0) | `0x50 0x41 0x57 0x01` | `rp2040:rp2040:adafruit_feather_rp2350_hstx` |

## 🛡️ Security Features

### Hardware-Based Security
- ✅ **Hardware TRNG**: Uses STM32U585 hardware true random number generator
- ✅ **Secure Storage**: Key never exposed to Linux/MPU side (only MCU)
- ✅ **Hash Verification**: SHA-256 hash verification of stored keys
- ✅ **CRC32 Check**: Integrity verification of transmitted key data
- ✅ **Fail-Closed**: System fails securely on any error

### Protocol Security
- ✅ **No Plain Text**: Key material encrypted in transit (AES-128)
- ✅ **Authentication**: Device ID verification before key distribution
- ✅ **Integrity**: CRC32 checksum on all transmissions
- ✅ **Verification**: Hash verification confirms successful storage

## 📊 Usage Workflow

### 1. Generate a New Key
```
1. Open app at http://192.168.32.18:8501
2. Click "🎲 Generate New Key"
3. Wait for TRNG to generate key (uses hardware RNG)
4. Key state changes to "GENERATED"
5. Fingerprint appears (first 4 bytes of SHA-256 hash)
```

### 2. Distribute to PLC
```
1. Ensure UART connection between UNO Q and PLC
2. Power on PLC device
3. Click "🏭 Distribute to PLC"
4. Protocol executes automatically
5. Success confirmed with hash verification
```

### 3. Distribute to PAW
```
1. Ensure UART connection between UNO Q and PAW
2. Power on PAW device
3. Click "🪪 Distribute to PAW"
4. Protocol executes automatically
5. Success confirmed with hash verification
```

### 4. One-Click Full Workflow
```
1. Connect both PLC and PAW via UART
2. Power on all devices
3. Click "🔄 Generate & Distribute to All"
4. Key generated and distributed to both devices
5. Final state: "DISTRIBUTED (BOTH)"
```

## 🔍 Troubleshooting

### Key Generation Fails
- **Cause**: TRNG health check failure or configuration issue
- **Solution**: Check `CONFIG_HARDWARE_DEVICE_CS_GENERATOR=y` in prj.conf
- **Fallback**: The firmware falls back to direct STM32 RNG register access

### Distribution Fails
- **No Response**: Check UART wiring (TX→RX, RX→TX, GND→GND)
- **CRC Mismatch**: Verify baud rate is 115200 on all devices
- **Hash Mismatch**: Indicates data corruption during transmission

### Bridge RPC Not Working
- **Check**: Ensure firmware is flashed correctly
- **Verify**: Open UNO Q Serial Monitor (USB) to see debug output
- **Test**: Try the serial commands (`g`, `1`, `2`, `s`) first

### App Not Loading
- **Check**: Verify Streamlit is installed in App Lab
- **Verify**: Check the app URL and port
- **Restart**: Try restarting the UNO Q

## 📋 Serial Commands (Debug)

The firmware still supports serial commands for debugging:

| Command | Action | Requirements |
|---------|--------|--------------|
| `g` or `G` | Generate new key | None |
| `1` | Distribute to PLC | UART connection + Button press |
| `2` | Distribute to PAW | UART connection + Button press |
| `s` or `S` | Show status | None |

**Note**: Commands `1` and `2` still require the physical button press for the original behavior, but the Bridge RPC methods bypass this requirement.

## 🎨 App Screenshots

### Main Interface
```
┌─────────────────────────────────────────────────────────────┐
│  SHALLOT Key Authority                              🔐          │
│                                                                  │
│  📊 Current Status ▼                                             │
│  ┌──────────┬──────────┬──────────┐                           │
│  │ Key State│Fingerprint│Last Action│                          │
│  │ 🟢 GEN... │ DEADBEEF │ -        │                          │
│  └──────────┴──────────┴──────────┘                           │
│                                                                  │
│  ⚡ Actions                                                     │
│  ┌──────────────────────┬──────────────────────┐            │
│  │ 🎲 Generate New Key   │ 🔄 Generate & Dist... │            │
│  └──────────────────────┴──────────────────────┘            │
│                                                                  │
│  📤 Distribute Key                                               │
│  ┌──────────────────────┬──────────────────────┐            │
│  │ 🏭 Distribute to PLC  │ 🪪 Distribute to PAW  │            │
│  └──────────────────────┴──────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## 📝 Production vs Testing

### Production Firmware (Original)
- ✅ Requires physical button press for distribution
- ✅ Maximum security (fail-safe design)
- ✅ No MPU can trigger distribution without physical access

### Testing Firmware (Modified)
- ✅ Allows Bridge RPC to trigger distribution
- ⚠️ Reduced physical security (for development/testing)
- ✅ Enables automated testing and app integration

**Recommendation**: Use the modified firmware for development/testing. For production deployment, restore the original firmware with physical button requirement.

## 🔄 Reverting to Production

To restore production firmware with physical button requirement:

```bash
# Flash the original firmware from main branch
git checkout main
./scripts/sync-and-flash.sh unoq
```

Or copy the original firmware back:
```bash
cp key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino \
   /Users/johannes/Documents/Arduino/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino
```

## 📚 Protocol Documentation

### Message Types
```cpp
// Key Distribution
#define MSG_HANDSHAKE 0xA1
#define MSG_READY     0xA2
#define MSG_KEY_DATA  0xA3
#define MSG_STORED    0xA4
#define MSG_ERROR     0xA5

// Authentication (LoRa)
#define MSG_CHALLENGE 0xB1
#define MSG_RESPONSE  0xB2
#define MSG_RESULT    0xB3
```

### Target IDs
```cpp
#define TARGET_PLC 0x01
#define TARGET_PAW 0x02
```

### Device IDs
```cpp
// PLC: Raspberry Pi Pico 2
static const uint8_t deviceId[4] = { 0x50, 0x4C, 0x43, 0x01 };  // "PLC\x01"

// PAW: Adafruit Feather RP2350
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 };  // "PAW\x01"
```

## 🏗️ Technical Details

### Hardware Specifications

| Component | Specification |
|-----------|---------------|
| Key Size | AES-128 (16 bytes) |
| Hash Algorithm | SHA-256 |
| Hash Size | 32 bytes (4 bytes used for fingerprint) |
| CRC | CRC32 (4 bytes) |
| UART Baud | 115200 |
| TRNG | STM32U585 Hardware RNG |

### Performance

| Operation | Time | Notes |
|-----------|------|-------|
| TRNG Health Check | ~50ms | 32-byte sample |
| Key Generation | ~100ms | 16 bytes from TRNG |
| SHA-256 | ~50ms | Full 32-byte hash |
| CRC32 | ~1ms | 16-byte key |
| Full Distribution | ~500ms | Includes handshake and verification |

### Memory Usage

| Component | MCU (STM32U585) | MPU (QRB2210) |
|-----------|----------------|----------------|
| Flash | ~25KB | ~2MB (Linux + App) |
| RAM | ~4KB (stack) | ~512MB |
| Key Storage | SRAM (volatile) | None (never exposed) |

## 🎓 References

- [Arduino UNO Q Documentation](https://docs.arduino.cc/hardware/uno-q)
- [STM32U585 Reference Manual (RM0453)](https://www.st.com/resource/en/reference_manual/dm00392571-stm32u575-stm32u585-and-stm32u535-stm32u545-advanced-arm-based-microcontrollers-stmicroelectronics.pdf)
- [Arduino Router Bridge](https://github.com/arduino-libraries/Arduino_RouterBridge)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [SHALLOT Protocol Specification](https://github.com/Tripl321/yh-lora-auth-projektarbete)

## 📄 License

This project is part of the SHALLOT authentication system and follows the same licensing as the main project.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Create a new Pull Request

---

**SHALLOT — Secure Hardware Authentication & Key Distribution**  
*Building trust, one key at a time.* 🔐