/*
 * SHALLOT PAW Main Firmware
 * Target: Adafruit Feather RP2350 + Core1262-868M + 1.54" 3-color e-Paper
 * 
 * Full PAW firmware combining:
 *   - PRO-48: Key reception from UNO Q (paw-key-receiver.ino)
 *   - PRO-50: HMAC-SHA256 challenge-response
 *   - PRO-57: e-Paper status display (via GxEPD2 3-color driver)
 *   - PRO-58: LoRa P2P communication with PLC (RadioLib SX1262)
 *
 * Hardware pin mapping (Feather RP2350 silkscreen labels):
 *   USB (Mama Bear/host): via USB-C hub (UART TX->1, RX->0 deprecated 2026-09-04)
 *   LoRa (SPI1):   SCK=D10, MOSI=D11, MISO=D24, CS=D9, BUSY=pin7, RESET=pin4, DIO1=A2
 *   e-Paper (SPI0):CS=5, DC=A0(GPIO26), RST=A1(GPIO27), BUSY=D25(GPIO25)
 *                   SPI0 MO(GP23) -> DIN, SPI0 SCK(GP22) -> CLK
 *
 * e-Paper panel: Waveshare 1.54" 3-färg B/W/R (GDEH0154Z90, SSD1682).
 * Korrekt drivare är GxEPD2_3C/GxEPD2_154_Z90c; B/W-drivaren (D67) lämnar
 * röda planet oskrivet -> röd bakgrund. Full refresh ~14 s.
 *
 * Architecture (USB - UART deprecated 2026-09-04):
 *   1. Wait for key from UNO Q at startup via USB (was Serial)
 *   2. Initialize LoRa (SX1262 on SPI1) and e-Paper (SPI0)
 *   3. Listen for challenge (nonce) from PLC over LoRa
 *   4. Compute HMAC-SHA256(key, nonce) and transmit response
 *   5. Update e-Paper with privacy-compliant authentication status icons
 *
 * Privacy: e-Paper shows ONLY status icons (no text, no PII)
 *   States: AUTHENTICATING, AUTHENTICATED, FAILED
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <GxEPD2_3C.h>

enum EpdStatus {
    EPD_STATUS_AUTHENTICATING = 0,
    EPD_STATUS_AUTHENTICATED  = 1,
    EPD_STATUS_FAILED         = 2,
    EPD_STATUS_BLANK          = 3
};

// =============================================================
// Configuration
// =============================================================

// LoRa settings (868 MHz EU band)
#define LORA_FREQUENCY        868.0
#define LORA_BANDWIDTH        125.0
#define LORA_SPREADING_FACTOR 9
#define LORA_CODING_RATE      5
#define LORA_PREAMBLE_LENGTH  8
#define LORA_SYNC_WORD        0x12
#define LORA_OUTPUT_POWER     14

// Timeouts
#define KEY_DISTRIBUTION_TIMEOUT 10000  // ms
#define CHALLENGE_TIMEOUT        30000  // ms

// =============================================================
// Pin Definitions
// =============================================================

// --- LoRa Core1262 (SPI1) ---
#define LORA_SCK_PIN     10
#define LORA_MOSI_PIN    11
#define LORA_MISO_PIN    24
#define LORA_CS_PIN      9
#define LORA_BUSY_PIN    7
#define LORA_RESET_PIN   4
#define LORA_DIO1_PIN    A2

// --- e-Paper (SPI0) via GxEPD2 ---
// CS=5, DC=A0(26), RST=A1(27), BUSY=D25(25)

// --- UART to UNO Q ---
// Hardware Serial: TX->1, RX->0

#undef LED_BUILTIN
#define LED_BUILTIN 6

// =============================================================
// SPI1 Instance for Core1262
// =============================================================
SPIClassRP2040 loraSPI(spi1, LORA_MISO_PIN, LORA_CS_PIN, LORA_SCK_PIN, LORA_MOSI_PIN);

// =============================================================
// RadioLib SX1262 Module
// =============================================================
SX1262 radio = new Module(LORA_CS_PIN, LORA_DIO1_PIN, LORA_RESET_PIN, LORA_BUSY_PIN, loraSPI);

static volatile bool loraPacketReceived = false;

#if defined(ESP8266) || defined(ESP32)
  ICACHE_RAM_ATTR
#endif
static void setLoRaFlag(void) {
    loraPacketReceived = true;
}

// =============================================================
// Protocol Message Types
// =============================================================

#define MSG_HANDSHAKE    0xA1
#define MSG_READY        0xA2
#define MSG_KEY_DATA     0xA3
#define MSG_STORED       0xA4
#define MSG_ERROR        0xA5
#define MSG_COMMIT       0xA6
#define MSG_CANCEL       0xA7

#define MSG_CHALLENGE    0xB1
#define MSG_RESPONSE     0xB2
#define MSG_RESULT       0xB3

// Device identity challenge-response messages (Slice 4)
#define MSG_ID_CHALLENGE  0xB4
#define MSG_ID_RESPONSE   0xB5

#define TARGET_PAW       0x02
#define TARGET_PLC       0x01

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE     16
#define KEY_HASH_SIZE     4
#define CHALLENGE_SIZE    16
#define HMAC_SIZE         32

// =============================================================
// e-Paper via GxEPD2
// =============================================================

// Waveshare 1.54" 3-color B/W/R panel (GDEH0154Z90, SSD1682), 200x200.
// Uses GxEPD2_3C tricolor driver so the red plane is always written white.
// Full refresh takes ~14s; GxEPD2 uses timed waits (BUSY may not be wired).
GxEPD2_3C<GxEPD2_154_Z90c, GxEPD2_154_Z90c::HEIGHT> display(
  GxEPD2_154_Z90c(5, 26, 27, 25)  // CS, DC, RST, BUSY
);

void epdInit() {
    display.init(0, true, 2, false);  // serial_diag, initial, reset_duration, pulldown_rst
    display.setRotation(0);
}

static EpdStatus lastShownStatus = EPD_STATUS_BLANK;
static bool hasShownResult = false;

void epdShowStatus(EpdStatus status) {
    // Avoid redundant full refreshes (the 3-color panel flickers and blocks
    // ~14s per refresh). Only redraw when the displayed status actually changes.
    if (status == lastShownStatus) {
        return;
    }
    // Once a definitive result (AUTHENTICATED/FAILED) has been shown, don't
    // bounce back to the AUTHENTICATING splash on background timeouts or
    // repeat challenges.
    if (status == EPD_STATUS_AUTHENTICATING && hasShownResult) {
        return;
    }
    if (status == EPD_STATUS_AUTHENTICATED || status == EPD_STATUS_FAILED) {
        hasShownResult = true;
    }
    lastShownStatus = status;

    // Restore the screen buffer to full window (necessary after powerOff)
    display.setFullWindow();
    display.firstPage();
    do {
        display.fillScreen(GxEPD_WHITE);

        int cx = 100, cy = 100, r = 50;

        display.drawRect(4, 4, 192, 192, GxEPD_BLACK);

        switch (status) {
            case EPD_STATUS_AUTHENTICATING:
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                display.fillCircle(cx, cy - r / 2, r / 5, GxEPD_BLACK);
                display.fillCircle(cx - r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
                display.fillCircle(cx + r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
                break;

            case EPD_STATUS_AUTHENTICATED: {
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                int s = r * 2 / 3;
                display.drawLine(cx - s, cy, cx - s / 4, cy + s / 2, GxEPD_BLACK);
                display.drawLine(cx - s / 4, cy + s / 2, cx + s, cy - s / 2, GxEPD_BLACK);
                break;
            }

            case EPD_STATUS_FAILED: {
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                int s = r * 2 / 3;
                display.drawLine(cx - s, cy - s, cx + s, cy + s, GxEPD_BLACK);
                display.drawLine(cx - s, cy + s, cx + s, cy - s, GxEPD_BLACK);
                break;
            }

            default:
                break;
        }
    } while (display.nextPage());
}

// =============================================================
// Key Storage
// =============================================================

static uint8_t aesKey[AES_KEY_SIZE];
static bool keyStored = false;
static uint32_t activeEpoch = 0;
static uint32_t pendingEpoch = 0;
static uint8_t pendingKey[AES_KEY_SIZE];
static bool pendingValid = false;
static uint32_t pendingDeadlineMs = 0;
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 }; // "PAW\x01"

// =============================================================
// Device Identity (Slice 4) - P-256 ECDSA
// =============================================================

// P-256 curve parameters (secp256r1 / prime256v1)
#define P256_PRIVATE_KEY_SIZE  32
#define P256_PUBLIC_KEY_SIZE   65  // Uncompressed: 0x04 + x[32] + y[32] = 65 bytes
#define P256_SIGNATURE_SIZE    64  // r[32] + s[32]
#define SHA256_HASH_SIZE      32

// Device identity storage
static uint8_t devicePrivateKey[P256_PRIVATE_KEY_SIZE];
static uint8_t devicePublicKey[P256_PUBLIC_KEY_SIZE];
static bool deviceIdentityGenerated = false;
static uint8_t devicePublicKeyHash[SHA256_HASH_SIZE];

// Generate deterministic P-256 keypair from device-specific seed
static void generateDeviceIdentity() {
  if (deviceIdentityGenerated) return;
  
  // For prototype: use deviceId as seed (deterministic for testing)
  uint8_t seed[32];
  memset(seed, 0, 32);
  memcpy(seed, deviceId, 4);
  
  // Generate private key from seed
  memcpy(devicePrivateKey, seed, P256_PRIVATE_KEY_SIZE);
  
  // Compute public key hash
  sha256(devicePrivateKey, P256_PRIVATE_KEY_SIZE, devicePublicKeyHash);
  
  // Create mock public key (uncompressed format: 0x04 + x + y)
  devicePublicKey[0] = 0x04;
  memcpy(&devicePublicKey[1], devicePrivateKey, 32);
  memcpy(&devicePublicKey[33], devicePrivateKey, 32);
  
  deviceIdentityGenerated = true;
}

// Sign a message using device identity (mock for prototype)
static void signWithDeviceKey(const uint8_t* message, size_t msgLen, uint8_t* signature) {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  
  // Mock signature: SHA-256(privateKey + message)
  uint8_t input[P256_PRIVATE_KEY_SIZE + msgLen];
  memcpy(input, devicePrivateKey, P256_PRIVATE_KEY_SIZE);
  memcpy(&input[P256_PRIVATE_KEY_SIZE], message, msgLen);
  sha256(input, sizeof(input), signature);
  
  // Duplicate hash to fill 64-byte signature
  memcpy(&signature[32], signature, 32);
}

// =============================================================
// SHA-256 Implementation
// =============================================================

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x)  (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x)  (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

void sha256(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t paddedLen = ((len + 9 + 63) / 64) * 64;
    uint8_t* msg = (uint8_t*)calloc(paddedLen, 1);
    if (!msg) return;
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bitLen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        msg[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;
    }

    for (size_t blk = 0; blk < paddedLen; blk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)msg[blk + i * 4] << 24)
                 | ((uint32_t)msg[blk + i * 4 + 1] << 16)
                 | ((uint32_t)msg[blk + i * 4 + 2] << 8)
                 | ((uint32_t)msg[blk + i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            w[i] = SHA256_SIG1(w[i - 2]) + w[i - 7] + SHA256_SIG0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + SHA256_EP1(e) + SHA256_CH(e, f, g) + sha256_k[i] + w[i];
            uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = h[i] & 0xFF;
    }

    free(msg);
}

// =============================================================
// CRC32 Implementation
// =============================================================

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// =============================================================
// Identity Challenge-Response Protocol (Slice 4)
// =============================================================

// Handle identity challenge from MCU
// MCU sends: MSG_ID_CHALLENGE(0xB4) + challenge[32] + operation[1] + target[1] + epoch[4]
// Device responds: MSG_ID_RESPONSE(0xB5) + signature[64] + devicePubKeyHash[4]
static bool handleIdentityChallenge() {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  
  // Total message: 1 (msgType) + 32 (challenge) + 1 (operation) + 1 (target) + 4 (epoch) = 39 bytes
  if (Serial.available() < 39) return false;
  
  int peek = Serial.peek();
  if (peek != MSG_ID_CHALLENGE) return false;
  
  // Read challenge message
  uint8_t msgType = Serial.read();
  if (msgType != MSG_ID_CHALLENGE) return false;
  
  uint8_t challenge[32];
  uint8_t operation;
  uint8_t target;
  uint32_t epoch;
  
  // Read exactly 32 bytes for challenge
  size_t bytesRead = Serial.readBytes((char*)challenge, 32);
  if (bytesRead != 32) return false;
  
  operation = Serial.read();
  target = Serial.read();
  epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) |
          ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
  
  // Create message to sign: challenge + operation + target + epoch
  uint8_t signInput[32 + 1 + 1 + 4];
  memcpy(signInput, challenge, 32);
  signInput[32] = operation;
  signInput[33] = target;
  signInput[34] = (epoch >> 24) & 0xFF;
  signInput[35] = (epoch >> 16) & 0xFF;
  signInput[36] = (epoch >> 8) & 0xFF;
  signInput[37] = epoch & 0xFF;
  
  // Sign the message
  uint8_t signature[P256_SIGNATURE_SIZE];
  signWithDeviceKey(signInput, sizeof(signInput), signature);
  
  // Send response
  Serial.write(MSG_ID_RESPONSE);
  Serial.write(signature, P256_SIGNATURE_SIZE);
  Serial.write(devicePublicKeyHash, KEY_HASH_SIZE);
  Serial.flush();
  
  Serial.println("[PRO-48] Identity challenge response sent");
  return true;
}

// =============================================================
// HMAC-SHA256 Implementation (PRO-50)
// =============================================================

#define HMAC_BLOCK_SIZE 64

void hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t* mac) {
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t innerHash[32];
    uint8_t outerHash[32];

    memset(k_ipad, 0x36, HMAC_BLOCK_SIZE);
    memset(k_opad, 0x5C, HMAC_BLOCK_SIZE);

    for (size_t i = 0; i < keyLen; i++) {
        if (i < HMAC_BLOCK_SIZE) {
            k_ipad[i] ^= key[i];
            k_opad[i] ^= key[i];
        }
    }

    uint8_t* innerMsg = (uint8_t*)calloc(HMAC_BLOCK_SIZE + msgLen, 1);
    if (!innerMsg) { memset(mac, 0, 32); return; }
    memcpy(innerMsg, k_ipad, HMAC_BLOCK_SIZE);
    memcpy(innerMsg + HMAC_BLOCK_SIZE, msg, msgLen);
    sha256(innerMsg, HMAC_BLOCK_SIZE + msgLen, innerHash);

    uint8_t outerMsg[HMAC_BLOCK_SIZE + 32];
    memcpy(outerMsg, k_opad, HMAC_BLOCK_SIZE);
    memcpy(outerMsg + HMAC_BLOCK_SIZE, innerHash, 32);
    sha256(outerMsg, sizeof(outerMsg), outerHash);

    memcpy(mac, outerHash, 32);

    memset(k_ipad, 0, HMAC_BLOCK_SIZE);
    memset(k_opad, 0, HMAC_BLOCK_SIZE);
    memset(innerHash, 0, 32);
    memset(outerHash, 0, 32);
    memset(innerMsg, 0, HMAC_BLOCK_SIZE + msgLen);
    free(innerMsg);
    memset(outerMsg, 0, sizeof(outerMsg));
}

// =============================================================
// Key Reception from UNO Q (PRO-48)
// =============================================================

bool receiveKeyFromUNOQ() {
    uint32_t timeoutStart = millis();

    Serial.println("[PRO-48] Waiting for key distribution from UNO Q (USB epoch-tagged)...");

    uint32_t stagedEpoch = 0;
    while (millis() - timeoutStart < KEY_DISTRIBUTION_TIMEOUT) {
        if (Serial.available() >= 1) {
            int peek = Serial.peek();
            // Check for identity challenge first (Slice 4)
            if (peek == MSG_ID_CHALLENGE) {
                handleIdentityChallenge();
                continue;  // Continue waiting for handshake
            }
        }
        if (Serial.available() >= 6) {
            uint8_t msgType = Serial.read();
            uint8_t targetId = Serial.read();
            uint32_t epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
            if (msgType == MSG_HANDSHAKE && targetId == TARGET_PAW) {
                Serial.print("[PRO-48] Handshake received epoch "); Serial.println(epoch);
                if (epoch <= activeEpoch) { Serial.println("[PRO-48] Epoch not newer - reject"); return false; }
                stagedEpoch = epoch;
                break;
            }
        }
    }
    if (stagedEpoch == 0) {
        Serial.println("[PRO-48] Timeout waiting for handshake.");
        return false;
    }

    Serial.print("[PRO-48] Sending READY epoch "); Serial.println(stagedEpoch);
    Serial.write(MSG_READY);
    Serial.write(deviceId, 4);
    Serial.write((stagedEpoch >> 24) & 0xFF);
    Serial.write((stagedEpoch >> 16) & 0xFF);
    Serial.write((stagedEpoch >> 8) & 0xFF);
    Serial.write(stagedEpoch & 0xFF);
    Serial.flush();

    timeoutStart = millis();
    while (Serial.available() < 26 && millis() - timeoutStart < KEY_DISTRIBUTION_TIMEOUT) {
        // Check for identity challenge while waiting (Slice 4)
        if (Serial.available() >= 1) {
            int peek = Serial.peek();
            if (peek == MSG_ID_CHALLENGE) {
                handleIdentityChallenge();
            }
        }
        delay(1);
    }
    if (Serial.available() < 26) {
        Serial.println("[PRO-48] Timeout waiting for key data.");
        return false;
    }

    // Check for identity challenge before reading key data (Slice 4)
    if (Serial.peek() == MSG_ID_CHALLENGE) {
        handleIdentityChallenge();
    }

    uint8_t msgType = Serial.read();
    if (msgType != MSG_KEY_DATA) {
        Serial.printf("[PRO-48] Expected KEY_DATA, got 0x%02X\n", msgType);
        return false;
    }

    uint8_t receivedKeyLen = Serial.read();
    if (receivedKeyLen != AES_KEY_SIZE) {
        Serial.printf("[PRO-48] Unexpected key length: %d\n", receivedKeyLen);
        return false;
    }

    uint8_t receivedKey[AES_KEY_SIZE];
    Serial.readBytes(receivedKey, AES_KEY_SIZE);

    uint32_t receivedCrc = ((uint32_t)Serial.read() << 24)
                         | ((uint32_t)Serial.read() << 16)
                         | ((uint32_t)Serial.read() << 8)
                         | ((uint32_t)Serial.read());
    uint32_t receivedEpoch = ((uint32_t)Serial.read() << 24)
                           | ((uint32_t)Serial.read() << 16)
                           | ((uint32_t)Serial.read() << 8)
                           | ((uint32_t)Serial.read());
    if (receivedEpoch != stagedEpoch) {
        Serial.printf("[PRO-48] Epoch mismatch staged %lu got %lu\n", (unsigned long)stagedEpoch, (unsigned long)receivedEpoch);
        Serial.write(MSG_ERROR);
        return false;
    }

    uint32_t computedCrc = crc32(receivedKey, AES_KEY_SIZE);
    if (computedCrc != receivedCrc) {
        Serial.printf("[PRO-48] CRC mismatch! Expected: %08X Got: %08X\n", computedCrc, receivedCrc);
        Serial.write(MSG_ERROR);
        memset(receivedKey, 0, AES_KEY_SIZE);
        return false;
    }
    Serial.println("[PRO-48] CRC verified OK.");

    memcpy(pendingKey, receivedKey, AES_KEY_SIZE);
    pendingEpoch = stagedEpoch;
    pendingValid = true;
    pendingDeadlineMs = millis() + 600000;
    memset(receivedKey, 0, AES_KEY_SIZE);

    uint8_t fullHash[32];
    sha256(pendingKey, AES_KEY_SIZE, fullHash);
    uint8_t keyHash[KEY_HASH_SIZE];
    memcpy(keyHash, fullHash, KEY_HASH_SIZE);

    Serial.write(MSG_STORED);
    Serial.write(keyHash, KEY_HASH_SIZE);
    Serial.write((pendingEpoch >> 24) & 0xFF);
    Serial.write((pendingEpoch >> 16) & 0xFF);
    Serial.write((pendingEpoch >> 8) & 0xFF);
    Serial.write(pendingEpoch & 0xFF);
    Serial.flush();

    Serial.print("[PRO-48] Pending key stored epoch "); Serial.print(pendingEpoch); Serial.print(" hash ");
    for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
    Serial.println();

    memset(fullHash, 0, 32);
    return true;
}

// =============================================================
// Authentication State Machine
// =============================================================

enum AuthState {
    STATE_WAITING_FOR_KEY,
    STATE_WAITING_FOR_CHALLENGE,
    STATE_COMPUTING_RESPONSE,
    STATE_WAITING_FOR_RESULT
};

static AuthState currentState = STATE_WAITING_FOR_KEY;
static bool loraInitialized = false;

// =============================================================
// Setup
// =============================================================

void setup() {
    Serial.begin(115200); while(!Serial) delay(10);

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    delay(2000);

    Serial.println("============================================");
    Serial.println("SHALLOT PAW Main Firmware");
    Serial.println("Hardware: Adafruit Feather RP2350");
    Serial.println("Components: Core1262 LoRa + e-Paper");
    Serial.println("============================================");

    Serial.println("[PRO-57] Initializing e-Paper (GxEPD2)...");
    epdInit();
    Serial.println("[PRO-57] e-Paper initialized.");
    epdShowStatus(EPD_STATUS_AUTHENTICATING);

    loraSPI.begin();
    Serial.println("[PRO-28] SPI1 initialized for Core1262.");

    Serial.println("[PRO-58] Initializing RadioLib SX1262 LoRa...");
    int state = radio.begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SPREADING_FACTOR,
                            LORA_CODING_RATE, LORA_SYNC_WORD, LORA_OUTPUT_POWER,
                            LORA_PREAMBLE_LENGTH);

    if (state == RADIOLIB_ERR_NONE) {
        Serial.println("[PRO-58] RadioLib SX1262 initialized successfully.");
        loraInitialized = true;
        radio.setDio1Action(setLoRaFlag);
        radio.startReceive();
    } else {
        Serial.printf("[PRO-58] LoRa initialization FAILED, code: %d\n", state);
    }

    Serial.println("[PRO-48] Starting key reception...");

    if (receiveKeyFromUNOQ()) {
        currentState = STATE_WAITING_FOR_CHALLENGE;
        Serial.println("[PRO-48] Key received successfully.");
        digitalWrite(LED_BUILTIN, HIGH);
        epdShowStatus(EPD_STATUS_AUTHENTICATING);
    } else {
        Serial.println("[PRO-48] Key reception FAILED / Waiting...");
        currentState = STATE_WAITING_FOR_KEY;
        epdShowStatus(EPD_STATUS_FAILED);
    }
}

// =============================================================
// Loop
// =============================================================

void loop() {
    static uint32_t lastChallengeTime = 0;
    static uint8_t challenge[CHALLENGE_SIZE];
    static uint32_t challengeEpoch = 0;
    static uint8_t response[HMAC_SIZE];
    static uint8_t rxBuffer[64];

    if (loraInitialized && loraPacketReceived) {
        loraPacketReceived = false;

        size_t rxLen = radio.getPacketLength();
        if (rxLen > sizeof(rxBuffer)) rxLen = sizeof(rxBuffer);

        int state = radio.readData(rxBuffer, rxLen);
        if (state == RADIOLIB_ERR_NONE && rxLen > 0) {
            uint8_t msgType = rxBuffer[0];
            Serial.printf("[LoRa RX] Type: 0x%02X, Length: %u bytes, RSSI: %.1f dBm, SNR: %.1f dB\n",
                          msgType, (unsigned)rxLen, radio.getRSSI(), radio.getSNR());

            // RSSI gate and epoch check
            if (msgType == MSG_CHALLENGE && rxLen >= (1 + CHALLENGE_SIZE + 4)) {
                float rssi = radio.getRSSI();
                if (rssi < -70.0) {
                    Serial.printf("[PRO-50] RSSI %.1f too weak, discard\n", rssi);
                    radio.startReceive();
                    return;
                }
                uint32_t epoch = ((uint32_t)rxBuffer[1+CHALLENGE_SIZE] << 24) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+1] << 16) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+2] << 8) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+3]);
                if (epoch != activeEpoch) {
                    Serial.printf("[PRO-50] Epoch mismatch got %lu expected %lu\n", (unsigned long)epoch, (unsigned long)activeEpoch);
                    radio.startReceive();
                    return;
                }
                Serial.println("[PRO-50] Challenge received from PLC over LoRa");
                memcpy(challenge, rxBuffer + 1, CHALLENGE_SIZE);
                challengeEpoch = epoch;
                lastChallengeTime = millis();
                currentState = STATE_COMPUTING_RESPONSE;
                epdShowStatus(EPD_STATUS_AUTHENTICATING);

                Serial.print("[PRO-50] Challenge nonce: ");
                for (int i = 0; i < CHALLENGE_SIZE; i++) Serial.printf("%02X", challenge[i]);
                Serial.println();
            }
            else if (msgType == MSG_RESULT && rxLen >= 2) {
                uint8_t result = rxBuffer[1];
                if (result == 0x01) {
                    Serial.println("[PRO-50] Authentication SUCCESS (LoRa)");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epdShowStatus(EPD_STATUS_AUTHENTICATED);
                    for (int i = 0; i < 5; i++) {
                        digitalWrite(LED_BUILTIN, HIGH); delay(100);
                        digitalWrite(LED_BUILTIN, LOW); delay(100);
                    }
                } else {
                    Serial.println("[PRO-50] Authentication FAILED (LoRa)");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epdShowStatus(EPD_STATUS_FAILED);
                    for (int i = 0; i < 10; i++) {
                        digitalWrite(LED_BUILTIN, HIGH); delay(50);
                        digitalWrite(LED_BUILTIN, LOW); delay(50);
                    }
                }
            }
        }
        radio.startReceive();
    }

    // Handle identity challenge via USB (Slice 4) - must come before COMMIT handling
    if (Serial.available() >= 1) {
        int peek = Serial.peek();
        if (peek == MSG_ID_CHALLENGE) {
            handleIdentityChallenge();
        }
    }

    // Handle pending commit via USB (6B: type + target + epoch_be4, or 5B legacy)
    if (pendingValid && Serial.available() >= 5) {
        int peek = Serial.peek();
        if (peek == MSG_COMMIT || peek == MSG_CANCEL) {
            uint8_t msg = Serial.read();
            uint32_t epoch = 0;
            
            // Check if there's a target ID byte (6-byte format)
            if (Serial.available() >= 5) { // At least 5 more bytes = target + epoch
                uint8_t targetId = Serial.read();
                // Only process if this message is for us or broadcast
                if (targetId != TARGET_PAW && targetId != 0xFF) {
                    // Not for us, skip the rest
                    while (Serial.available() > 0 && Serial.peek() != MSG_COMMIT && Serial.peek() != MSG_CANCEL) {
                        Serial.read();
                    }
                    return; // Wait for next message
                }
                epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
            } else if (Serial.available() >= 4) { // Legacy 5-byte format
                epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
            } else {
                // Not enough bytes, wait
                return;
            }
            
            if (msg == MSG_COMMIT) {
                if (pendingValid && pendingEpoch == epoch && millis() < pendingDeadlineMs) {
                    memcpy(aesKey, pendingKey, AES_KEY_SIZE);
                    activeEpoch = pendingEpoch;
                    keyStored = true;
                    Serial.print("[PRO-48] Committed epoch "); Serial.println(activeEpoch);
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    digitalWrite(LED_BUILTIN, HIGH);
                    epdShowStatus(EPD_STATUS_AUTHENTICATING);
                    
                    // Send acknowledgment back to MCU
                    uint8_t fullHash[32];
                    sha256(aesKey, AES_KEY_SIZE, fullHash);
                    uint8_t ackHash[KEY_HASH_SIZE];
                    memcpy(ackHash, fullHash, KEY_HASH_SIZE);
                    Serial.write(MSG_STORED);
                    Serial.write(ackHash, KEY_HASH_SIZE);
                    Serial.write((activeEpoch >> 24) & 0xFF);
                    Serial.write((activeEpoch >> 16) & 0xFF);
                    Serial.write((activeEpoch >> 8) & 0xFF);
                    Serial.write(activeEpoch & 0xFF);
                    Serial.flush();
                    memset(fullHash, 0, 32);
                    Serial.println("[PRO-48] Sent COMMIT acknowledgment");
                } else {
                    Serial.println("[PRO-48] Commit failed");
                }
            } else {
                memset(pendingKey, 0, AES_KEY_SIZE);
                pendingValid = false;
                pendingEpoch = 0;
                Serial.println("[PRO-48] Pending canceled");
            }
        }
    }
    if (pendingValid && millis() > pendingDeadlineMs) {
        Serial.println("[PRO-48] Pending expired");
        memset(pendingKey, 0, AES_KEY_SIZE);
        pendingValid = false;
        pendingEpoch = 0;
    }

    switch (currentState) {
        case STATE_WAITING_FOR_KEY:
            if (receiveKeyFromUNOQ()) {
                Serial.print("[PRO-48] Pending stored epoch "); Serial.print(pendingEpoch); Serial.println(" waiting for COMMIT");
                // Stay in WAITING_FOR_KEY until COMMIT, but show authenticating
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_WAITING_FOR_CHALLENGE:
            if (lastChallengeTime > 0 && (millis() - lastChallengeTime > CHALLENGE_TIMEOUT)) {
                lastChallengeTime = 0;
                Serial.println("[PRO-50] Challenge timeout.");
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_COMPUTING_RESPONSE:
            if (keyStored) {
                uint8_t hmacInput[4 + CHALLENGE_SIZE];
                hmacInput[0] = (challengeEpoch >> 24) & 0xFF;
                hmacInput[1] = (challengeEpoch >> 16) & 0xFF;
                hmacInput[2] = (challengeEpoch >> 8) & 0xFF;
                hmacInput[3] = challengeEpoch & 0xFF;
                memcpy(hmacInput+4, challenge, CHALLENGE_SIZE);
                hmac_sha256(aesKey, AES_KEY_SIZE, hmacInput, 4+CHALLENGE_SIZE, response);
                memset(hmacInput, 0, sizeof(hmacInput));

                Serial.print("[PRO-50] HMAC Response computed epoch "); Serial.print(challengeEpoch); Serial.print(" : ");
                for (int i = 0; i < HMAC_SIZE; i++) Serial.printf("%02X", response[i]);
                Serial.println();

                uint8_t txPacket[1 + CHALLENGE_SIZE + 4 + HMAC_SIZE];
                txPacket[0] = MSG_RESPONSE;
                memcpy(txPacket + 1, challenge, CHALLENGE_SIZE);
                txPacket[1+CHALLENGE_SIZE] = (challengeEpoch >> 24) & 0xFF;
                txPacket[1+CHALLENGE_SIZE+1] = (challengeEpoch >> 16) & 0xFF;
                txPacket[1+CHALLENGE_SIZE+2] = (challengeEpoch >> 8) & 0xFF;
                txPacket[1+CHALLENGE_SIZE+3] = challengeEpoch & 0xFF;
                memcpy(txPacket + 1 + CHALLENGE_SIZE + 4, response, HMAC_SIZE);

                if (loraInitialized) {
                    int txState = radio.transmit(txPacket, sizeof(txPacket));
                    if (txState == RADIOLIB_ERR_NONE) {
                        Serial.println("[PRO-50] Response sent over LoRa to PLC.");
                    } else {
                        Serial.printf("[PRO-50] LoRa transmit error: %d\n", txState);
                    }
                    radio.startReceive();
                }

                // Removed Serial.write leak over USB (was HMAC exposure)

                currentState = STATE_WAITING_FOR_RESULT;
                memset(challenge, 0, CHALLENGE_SIZE);
            } else {
                Serial.println("[PRO-50] ERROR: No key stored!");
                currentState = STATE_WAITING_FOR_KEY;
                epdShowStatus(EPD_STATUS_FAILED);
            }
            break;

        case STATE_WAITING_FOR_RESULT:
            break;
    }

    static uint32_t lastHeartbeat = 0;
    if (millis() - lastHeartbeat > 1000) {
        lastHeartbeat = millis();
        if (keyStored) {
            digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
        } else {
            digitalWrite(LED_BUILTIN, (millis() / 200) % 2);
        }
    }

    delay(10);
}
