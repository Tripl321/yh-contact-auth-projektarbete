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
#include <ShallotEpd.h>  // PAW status display driver (owns GxEPD2, EpdStatus)
#include <ShallotLoRaProtocol.h>  // Shared PAW/PLC protocol (types, lengths, timeouts)

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

// Timeouts: see SHALLOT_KEY_DIST_TIMEOUT_MS / SHALLOT_CHALLENGE_TIMEOUT_MS
// in ShallotLoRaProtocol.h (shared with PLC).

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
// Protocol Message Types — see ShallotLoRaProtocol.h
// (SHALLOT_MSG_*, SHALLOT_TARGET_*, shared with PLC)
// =============================================================

// =============================================================
// e-Paper status display — see libraries/ShallotEpd (driver owns the
// GxEPD2 panel, status modes, refresh guards and test mode).
// PAW logic only calls epdInit() / epdShowStatus() / epdTestCycle().
// =============================================================

// =============================================================
// Key Storage
//
// Lifecycle: staged as pending (validated) -> committed to active on
// COMMIT -> pending wiped. Expiry/cancel/replacement wipe pending.
// Only status icons and the 4-byte fingerprint ever leave the device;
// the key bytes are never exposed.
// =============================================================

static uint8_t aesKey[SHALLOT_AES_KEY_SIZE];
static bool keyStored = false;
static uint32_t activeEpoch = 0;
static uint32_t pendingEpoch = 0;
static uint8_t pendingKey[SHALLOT_AES_KEY_SIZE];
static bool pendingValid = false;
static uint32_t pendingDeadlineMs = 0;
static uint8_t pendingSeq = 0;
static inline void secureWipePending() {
  volatile uint8_t* k = (volatile uint8_t*)pendingKey;
  for (uint8_t i = 0; i < SHALLOT_AES_KEY_SIZE; i++) k[i] = 0;
  pendingValid = false;
  pendingEpoch = 0;
  pendingDeadlineMs = 0;
  pendingSeq = 0;
}
// Device ID: SHALLOT_DEVICE_ID_PAW from ShallotLoRaProtocol.h ("PAW\x01")

// =============================================================
// Device Identity (Slice 4) - P-256 ECDSA
// =============================================================

// P-256 curve parameters (secp256r1 / prime256v1)
// Sizes: SHALLOT_P256_* / SHALLOT_SHA256_SIZE in ShallotLoRaProtocol.h

// Device identity storage
static uint8_t devicePrivateKey[SHALLOT_P256_PRIVATE_KEY_SIZE];
static uint8_t devicePublicKey[SHALLOT_P256_PUBLIC_KEY_SIZE];
static bool deviceIdentityGenerated = false;
static uint8_t devicePublicKeyHash[SHALLOT_SHA256_SIZE];

// Generate deterministic P-256 keypair from device-specific seed
static void generateDeviceIdentity() {
  if (deviceIdentityGenerated) return;
  
  // For prototype: use SHALLOT_DEVICE_ID_PAW as seed (deterministic for testing)
  uint8_t seed[32];
  memset(seed, 0, 32);
  memcpy(seed, SHALLOT_DEVICE_ID_PAW, 4);
  
  // Generate private key from seed
  memcpy(devicePrivateKey, seed, SHALLOT_P256_PRIVATE_KEY_SIZE);
  
  // Compute public key hash
  sha256(devicePrivateKey, SHALLOT_P256_PRIVATE_KEY_SIZE, devicePublicKeyHash);
  
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
  uint8_t input[SHALLOT_P256_PRIVATE_KEY_SIZE + msgLen];
  memcpy(input, devicePrivateKey, SHALLOT_P256_PRIVATE_KEY_SIZE);
  memcpy(&input[SHALLOT_P256_PRIVATE_KEY_SIZE], message, msgLen);
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
// MCU sends: SHALLOT_MSG_ID_CHALLENGE(0xB4) + challenge[32] + operation[1] + target[1] + epoch[4]
// Device responds: SHALLOT_MSG_ID_RESPONSE(0xB5) + signature[64] + devicePubKeyHash[4]
static bool handleIdentityChallenge() {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  
  // Total message: see SHALLOT_ID_CHALLENGE_FRAME_LEN in ShallotLoRaProtocol.h
  if (Serial.available() < SHALLOT_ID_CHALLENGE_FRAME_LEN) return false;
  
  int peek = Serial.peek();
  if (peek != SHALLOT_MSG_ID_CHALLENGE) return false;
  
  // Read challenge message
  uint8_t msgType = Serial.read();
  if (msgType != SHALLOT_MSG_ID_CHALLENGE) return false;
  
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
  uint8_t signature[SHALLOT_P256_SIGNATURE_SIZE];
  signWithDeviceKey(signInput, sizeof(signInput), signature);
  
  // Send response
  Serial.write(SHALLOT_MSG_ID_RESPONSE);
  Serial.write(signature, SHALLOT_P256_SIGNATURE_SIZE);
  Serial.write(devicePublicKeyHash, SHALLOT_KEY_HASH_SIZE);
  Serial.flush();
  
  Serial.println("[PRO-48] Identity challenge response sent");
  return true;
}

// =============================================================
// HMAC-SHA256 Implementation (PRO-50)
// (Block size SHALLOT_HMAC_BLOCK_SIZE, see ShallotLoRaProtocol.h)
// =============================================================

void hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t* mac) {
    uint8_t k_ipad[SHALLOT_HMAC_BLOCK_SIZE];
    uint8_t k_opad[SHALLOT_HMAC_BLOCK_SIZE];
    uint8_t innerHash[32];
    uint8_t outerHash[32];

    memset(k_ipad, 0x36, SHALLOT_HMAC_BLOCK_SIZE);
    memset(k_opad, 0x5C, SHALLOT_HMAC_BLOCK_SIZE);

    for (size_t i = 0; i < keyLen; i++) {
        if (i < SHALLOT_HMAC_BLOCK_SIZE) {
            k_ipad[i] ^= key[i];
            k_opad[i] ^= key[i];
        }
    }

    uint8_t* innerMsg = (uint8_t*)calloc(SHALLOT_HMAC_BLOCK_SIZE + msgLen, 1);
    if (!innerMsg) { memset(mac, 0, 32); return; }
    memcpy(innerMsg, k_ipad, SHALLOT_HMAC_BLOCK_SIZE);
    memcpy(innerMsg + SHALLOT_HMAC_BLOCK_SIZE, msg, msgLen);
    sha256(innerMsg, SHALLOT_HMAC_BLOCK_SIZE + msgLen, innerHash);

    uint8_t outerMsg[SHALLOT_HMAC_BLOCK_SIZE + 32];
    memcpy(outerMsg, k_opad, SHALLOT_HMAC_BLOCK_SIZE);
    memcpy(outerMsg + SHALLOT_HMAC_BLOCK_SIZE, innerHash, 32);
    sha256(outerMsg, sizeof(outerMsg), outerHash);

    memcpy(mac, outerHash, 32);

    memset(k_ipad, 0, SHALLOT_HMAC_BLOCK_SIZE);
    memset(k_opad, 0, SHALLOT_HMAC_BLOCK_SIZE);
    memset(innerHash, 0, 32);
    memset(outerHash, 0, 32);
    memset(innerMsg, 0, SHALLOT_HMAC_BLOCK_SIZE + msgLen);
    free(innerMsg);
    memset(outerMsg, 0, sizeof(outerMsg));
}

// Encrypted key envelope (must be after sha256, crc32, hmac_sha256 definitions)
#include <ShallotEnvelope.h>

// =============================================================
// Key Reception from UNO Q (PRO-48)
// =============================================================

// Live pending round identity: epoch = session, seq = UNO Q retry counter.
// A repeated frame with matching (epoch, seq) is answered idempotently.
// (pendingSeq itself lives with the key-storage state above.)

static void sendReadyFrame(uint32_t epoch) {
    Serial.print("[PRO-48] Sending READY epoch "); Serial.println(epoch);
    Serial.write(SHALLOT_MSG_READY);
    Serial.write(SHALLOT_DEVICE_ID_PAW, 4);
    uint8_t epochBe[4];
    shallot_put_be32(epochBe, epoch);
    Serial.write(epochBe, 4);
    Serial.flush();
}

// Stage CRC-verified key bytes as pending and acknowledge with STORED.
// The key is validated before storage: zero/degenerate values are refused
// (fail-closed) and leave any live pending round untouched.
// Returns true when staged (STORED sent), false when refused.
// Safe to repeat for the same round (idempotent resend).
static bool stagePendingKey(const uint8_t* key, uint32_t epoch, uint8_t seq) {
    if (!shallot_key_looks_valid(key)) {
        Serial.println("[PRO-48] Refusing to stage degenerate key (fail-closed).");
        return false;
    }
    memcpy(pendingKey, key, SHALLOT_AES_KEY_SIZE);
    pendingEpoch = epoch;
    pendingSeq = seq;
    pendingValid = true;
    pendingDeadlineMs = millis() + 600000;

    uint8_t fullHash[32];
    sha256(pendingKey, SHALLOT_AES_KEY_SIZE, fullHash);
    uint8_t keyHash[SHALLOT_KEY_HASH_SIZE];
    memcpy(keyHash, fullHash, SHALLOT_KEY_HASH_SIZE);
    memset(fullHash, 0, 32);

    Serial.write(SHALLOT_MSG_STORED);
    Serial.write(keyHash, SHALLOT_KEY_HASH_SIZE);
    uint8_t epochBe[4];
    shallot_put_be32(epochBe, epoch);
    Serial.write(epochBe, 4);
    Serial.flush();

    Serial.print("[PRO-48] Pending key stored epoch "); Serial.print(epoch); Serial.print(" hash ");
    for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
    Serial.println();
    return true;
}

// Acknowledge the ACTIVE key with STORED + fingerprint (hash only).
// Callers must ensure keyStored is true; sends no key material.
static void sendCommitAck() {
    uint8_t fullHash[32];
    sha256(aesKey, SHALLOT_AES_KEY_SIZE, fullHash);
    uint8_t ackHash[SHALLOT_KEY_HASH_SIZE];
    memcpy(ackHash, fullHash, SHALLOT_KEY_HASH_SIZE);
    memset(fullHash, 0, 32);
    Serial.write(SHALLOT_MSG_STORED);
    Serial.write(ackHash, SHALLOT_KEY_HASH_SIZE);
    uint8_t epochBe[4];
    shallot_put_be32(epochBe, activeEpoch);
    Serial.write(epochBe, 4);
    Serial.flush();
    Serial.println("[PRO-48] Sent COMMIT acknowledgment");
}

bool receiveKeyFromUNOQ() {
    uint32_t timeoutStart = millis();
    uint32_t resyncSkips = 0;

    Serial.println("[PRO-48] Waiting for key distribution from UNO Q (USB epoch-tagged)...");

    uint32_t stagedEpoch = 0;
    uint8_t stagedSeq = 0;

    // Step 1: scan for a HANDSHAKE frame. Stray bytes are dropped one at a
    // time (bounded resync); a KEY_DATA frame matching the live pending
    // round is answered idempotently (covers a lost STORED frame).
    while (millis() - timeoutStart < SHALLOT_KEY_DIST_TIMEOUT_MS) {
        pawFeedWatchdog();  // this wait may legitimately take ~10 s
        if (Serial.available() >= 1) {
            int peek = Serial.peek();
            if (peek == SHALLOT_MSG_ID_CHALLENGE) {
                // Wait for complete identity challenge frame
                if (Serial.available() >= SHALLOT_ID_CHALLENGE_FRAME_LEN) {
                    handleIdentityChallenge();
                    // Reset timeout after handling challenge
                    timeoutStart = millis();
                    continue;
                }
                // Not enough bytes yet, keep waiting
                delay(1);
                continue;
            }
            if (peek == SHALLOT_MSG_KEY_DATA) {
                if (Serial.available() < SHALLOT_KD_KEY_DATA_LEN) {
                    delay(1);  // partial frame: wait for the rest
                    continue;
                }
                uint8_t frame[SHALLOT_KD_KEY_DATA_LEN];
                for (uint8_t i = 0; i < SHALLOT_KD_KEY_DATA_LEN; i++) frame[i] = (uint8_t)Serial.read();
                uint32_t e = shallot_get_be32(&frame[22]);
                if (pendingValid && frame[1] == SHALLOT_AES_KEY_SIZE &&
                    e == pendingEpoch && frame[26] == pendingSeq &&
                    crc32(&frame[2], SHALLOT_AES_KEY_SIZE) == shallot_get_be32(&frame[18])) {
                    if (!stagePendingKey(&frame[2], e, frame[26])) {
                        memset(frame, 0, sizeof(frame));
                        continue;  // refused: staged round untouched, await retry
                    }
                    memset(frame, 0, sizeof(frame));
                    return true;
                }
                Serial.println("[PRO-48] Foreign key-data frame dropped.");
                memset(frame, 0, sizeof(frame));
                continue;
            }
            if (peek == SHALLOT_MSG_HANDSHAKE) {
                if (Serial.available() < SHALLOT_KD_HANDSHAKE_LEN) {
                    delay(1);  // partial frame: wait for the rest
                    continue;
                }
                uint8_t frame[SHALLOT_KD_HANDSHAKE_LEN];
                for (uint8_t i = 0; i < SHALLOT_KD_HANDSHAKE_LEN; i++) frame[i] = (uint8_t)Serial.read();
                uint8_t target = frame[1];
                uint32_t epoch = shallot_get_be32(&frame[2]);
                uint8_t seq = frame[6];
                memset(frame, 0, sizeof(frame));
                if (target != SHALLOT_TARGET_PAW) {
                    Serial.println("[PRO-48] Handshake for another target; dropped.");
                    continue;
                }
                bool fresh = (epoch > activeEpoch);
                bool retry = (pendingValid && epoch == pendingEpoch);
                if (!fresh && !retry) {
                    Serial.println("[PRO-48] Stale handshake epoch - reject");
                    return false;
                }
                Serial.print("[PRO-48] Handshake received epoch "); Serial.print(epoch);
                Serial.print(" seq "); Serial.println(seq);
                stagedEpoch = epoch;
                stagedSeq = seq;
                break;
            }
            // Stray byte: drop it (bounded resync after partial messages).
            if (resyncSkips < SHALLOT_KD_MAX_RESYNC_SKIPS) {
                Serial.read();
                resyncSkips++;
            } else {
                Serial.println("[PRO-48] Resync budget exhausted waiting for handshake.");
                return false;
            }
        }
        delay(1);
    }
    if (stagedEpoch == 0) {
        Serial.println("[PRO-48] Timeout waiting for handshake.");
        if (resyncSkips > 0) {
            Serial.print("[PRO-48] Resynced past ");
            Serial.print(resyncSkips);
            Serial.println(" stray bytes.");
        }
        return false;
    }

    sendReadyFrame(stagedEpoch);

    // Step 2: scan for the KEY_DATA frame. Validation failures resume
    // scanning (resync) instead of aborting: UNO Q retries the same
    // (epoch, seq), so a corrupt first attempt still converges.
    // Identity challenges (0xB4) are served inline as before.
    timeoutStart = millis();
    resyncSkips = 0;
    while (millis() - timeoutStart < SHALLOT_KEY_DIST_TIMEOUT_MS) {
        pawFeedWatchdog();  // this wait may legitimately take ~10 s
        if (Serial.available() >= 1) {
            int peek = Serial.peek();
            if (peek == SHALLOT_MSG_ID_CHALLENGE) {
                // Wait for complete identity challenge frame
                if (Serial.available() >= SHALLOT_ID_CHALLENGE_FRAME_LEN) {
                    handleIdentityChallenge();
                    // Reset timeout after handling challenge
                    timeoutStart = millis();
                    continue;
                }
                // Not enough bytes yet, keep waiting
                delay(1);
                continue;
            }
            if (peek == SHALLOT_MSG_KEY_DATA) {
                if (Serial.available() < SHALLOT_KD_KEY_DATA_LEN) {
                    delay(1);  // partial frame: wait for the rest
                    continue;
                }
                uint8_t frame[SHALLOT_KD_KEY_DATA_LEN];
                for (uint8_t i = 0; i < SHALLOT_KD_KEY_DATA_LEN; i++) frame[i] = (uint8_t)Serial.read();
                if (frame[1] != SHALLOT_AES_KEY_SIZE) {
                    Serial.println("[PRO-48] Bad key-data length; resyncing.");
                    memset(frame, 0, sizeof(frame));
                    continue;
                }
                uint32_t receivedEpoch = shallot_get_be32(&frame[22]);
                uint8_t receivedSeq = frame[26];
                if (receivedEpoch != stagedEpoch || receivedSeq != stagedSeq) {
                    Serial.println("[PRO-48] Key-data from another round; dropped.");
                    memset(frame, 0, sizeof(frame));
                    continue;
                }
                uint32_t receivedCrc = shallot_get_be32(&frame[18]);
                uint32_t computedCrc = crc32(&frame[2], SHALLOT_AES_KEY_SIZE);
                if (computedCrc != receivedCrc) {
                    Serial.println("[PRO-48] CRC mismatch; waiting for retry.");
                    Serial.write(SHALLOT_MSG_ERROR);
                    memset(frame, 0, sizeof(frame));
                    continue;
                }
                Serial.println("[PRO-48] CRC verified OK.");
                if (!stagePendingKey(&frame[2], stagedEpoch, stagedSeq)) {
                    Serial.write(SHALLOT_MSG_ERROR);
                    memset(frame, 0, sizeof(frame));
                    continue;  // refused: keep waiting for a valid retry
                }
                memset(frame, 0, sizeof(frame));
                return true;
            }
            // Stray byte: drop it (bounded resync after partial messages).
            if (resyncSkips < SHALLOT_KD_MAX_RESYNC_SKIPS) {
                Serial.read();
                resyncSkips++;
            } else {
                Serial.println("[PRO-48] Resync budget exhausted waiting for key data.");
                return false;
            }
        }
        delay(1);
    }
    Serial.println("[PRO-48] Timeout waiting for key data.");
    if (resyncSkips > 0) {
        Serial.print("[PRO-48] Resynced past ");
        Serial.print(resyncSkips);
        Serial.println(" stray bytes.");
    }
    return false;
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
// Watchdog and radio recovery
//
// Hardware watchdog (RP2350, max ~8.3 s): 8000 ms timeout, fed on every
// healthy loop pass, inside blocking key-reception waits, and from the
// e-paper busy callback during panel refreshes. Any true lockup reboots
// into the single fail-closed boot path below (no key in SRAM).
// Radio errors are counted; exhaustion tears the radio down and runs
// the same initLoRa() path again (fail-closed: nothing is processed
// while the radio is down).
// =============================================================

#define PAW_WDT_TIMEOUT_MS 8000
#define PAW_RADIO_MAX_CONSEC_ERRORS 3
#define PAW_RADIO_REINIT_RETRY_MS 10000

static uint8_t radioConsecErrors = 0;
static uint32_t lastRadioReinitMs = 0;

static inline void pawFeedWatchdog() {
    rp2040.wdt_reset();
}

// Watchdog self-test (physical test plan, doc 15). Boot-window only:
// shortens the timeout and blocks WITHOUT feeding, so the resulting
// reset exercises exactly the same path as a real lockup trip (reboot,
// WDT log line, fail-closed boot with empty SRAM). Reachable only with
// physical USB access inside the 2 s boot window; effect equals a power
// cycle, which needs no console at all.
static void wdtSelfTest() {
    Serial.println("[WDT] Self-test: 100 ms timeout, blocking 5 s without feed...");
    Serial.flush();
    rp2040.wdt_begin(100);
    delay(5000);  // no feed: guaranteed trip
    Serial.println("[WDT] ERROR: watchdog did not fire!");
}

// Initializes the LoRa radio. Safe to call for first init and for
// recovery re-init (clears the error budget on success).
void initLoRa() {
    Serial.println("[PRO-58] Initializing RadioLib SX1262 LoRa...");
    int state = radio.begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SPREADING_FACTOR,
                            LORA_CODING_RATE, LORA_SYNC_WORD, LORA_OUTPUT_POWER,
                            LORA_PREAMBLE_LENGTH);

    if (state == RADIOLIB_ERR_NONE) {
        Serial.println("[PRO-58] RadioLib SX1262 initialized successfully.");
        loraInitialized = true;
        radioConsecErrors = 0;
        radio.setDio1Action(setLoRaFlag);
        radio.startReceive();
    } else {
        Serial.printf("[PRO-58] LoRa initialization FAILED, code: %d\n", state);
        loraInitialized = false;
        lastRadioReinitMs = millis();
    }
}

static void noteRadioError() {
    if (++radioConsecErrors >= PAW_RADIO_MAX_CONSEC_ERRORS) {
        radioConsecErrors = 0;
        loraInitialized = false;
        lastRadioReinitMs = millis();
        Serial.println("[PRO-58] Radio error budget exhausted; reinitializing (fail-closed).");
        initLoRa();
    }
}

static inline void noteRadioOk() {
    radioConsecErrors = 0;
}

// =============================================================
// Setup
// =============================================================

void setup() {
    Serial.begin(115200);
    rp2040.wdt_begin(PAW_WDT_TIMEOUT_MS);
    while (!Serial) {
        delay(10);
        rp2040.wdt_reset();
    }

    // Fail-closed boot: SRAM holds no key after power loss. State this
    // explicitly (belt-and-braces alongside BSS zero-init) so nothing
    // below can run on stale key material. A watchdog reboot lands here
    // too, so recovery always starts unauthenticated.
    memset(aesKey, 0, SHALLOT_AES_KEY_SIZE);
    keyStored = false;
    activeEpoch = 0;
    secureWipePending();

    if (rp2040.getResetReason() == rp2040.WDT_RESET) {
        Serial.println("[WDT] Rebooted by watchdog; starting unauthenticated (fail-closed).");
    }
    pawFeedWatchdog();

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
    Serial.println("[PRO-57] Press 't' (display test) or 'w' (watchdog self-test) within 2s...");
    int testKey = epdPollTestRequest(2000);
    if (testKey == 't' || testKey == 'T') {
        Serial.println("[PRO-57] Display test mode: cycling all states.");
        epdTestCycle();
    } else if (testKey == 'w' || testKey == 'W') {
        wdtSelfTest();
    }
    epdShowStatus(EPD_STATUS_AUTHENTICATING);

    loraSPI.begin();
    Serial.println("[PRO-28] SPI1 initialized for Core1262.");

    initLoRa();
    pawFeedWatchdog();

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
    static uint8_t challenge[SHALLOT_CHALLENGE_SIZE];
    static uint32_t challengeEpoch = 0;
    static uint8_t response[SHALLOT_HMAC_SIZE];
    static uint8_t rxBuffer[64];

    pawFeedWatchdog();  // healthy loop pass: the last line of defense is fed here

    // Recovery: a dead radio is re-initialized on a throttle (fail-closed
    // meanwhile — nothing is processed while loraInitialized is false).
    if (!loraInitialized && millis() - lastRadioReinitMs >= PAW_RADIO_REINIT_RETRY_MS) {
        initLoRa();
    }

    if (loraInitialized && loraPacketReceived) {
        loraPacketReceived = false;

        size_t rxLen = radio.getPacketLength();
        if (rxLen > sizeof(rxBuffer)) rxLen = sizeof(rxBuffer);

        int state = radio.readData(rxBuffer, rxLen);
        if (state != RADIOLIB_ERR_NONE) {
            Serial.printf("[PRO-58] LoRa read error: %d\n", state);
            noteRadioError();
            radio.startReceive();
        } else if (rxLen > 0) {
            noteRadioOk();  // a clean read proves the radio path is alive
            uint8_t msgType = rxBuffer[0];
            Serial.printf("[LoRa RX] Type: 0x%02X, Length: %u bytes, RSSI: %.1f dBm, SNR: %.1f dB\n",
                          msgType, (unsigned)rxLen, radio.getRSSI(), radio.getSNR());

            // RSSI gate and epoch check (shared validators, fail-closed)
            if (shallot_check_challenge_packet(msgType, rxLen) == SHALLOT_PROTO_OK) {
                float rssi = radio.getRSSI();
                if (!shallot_rssi_ok(rssi)) {
                    Serial.printf("[PRO-50] RSSI %.1f too weak, discard\n", rssi);
                    radio.startReceive();
                    return;
                }
                uint32_t epoch = ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE] << 24) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+1] << 16) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+2] << 8) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+3]);
                if (shallot_check_epoch(epoch, activeEpoch) != SHALLOT_PROTO_OK) {
                    Serial.printf("[PRO-50] Epoch mismatch got %lu expected %lu\n", (unsigned long)epoch, (unsigned long)activeEpoch);
                    radio.startReceive();
                    return;
                }
                Serial.println("[PRO-50] Challenge received from PLC over LoRa");
                memcpy(challenge, rxBuffer + 1, SHALLOT_CHALLENGE_SIZE);
                challengeEpoch = epoch;
                lastChallengeTime = millis();
                currentState = STATE_COMPUTING_RESPONSE;
                epdShowStatus(EPD_STATUS_AUTHENTICATING);

                Serial.print("[PRO-50] Challenge nonce: ");
                for (int i = 0; i < SHALLOT_CHALLENGE_SIZE; i++) Serial.printf("%02X", challenge[i]);
                Serial.println();
            }
            else if (shallot_check_result_packet(msgType, rxLen) == SHALLOT_PROTO_OK) {
                uint8_t result = rxBuffer[1];
                if (result == SHALLOT_RESULT_SUCCESS) {
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
        if (peek == SHALLOT_MSG_ID_CHALLENGE) {
            handleIdentityChallenge();
        }
    }

    // Handle pending commit via USB (6B: type + target + epoch_be4, or 5B legacy).
    // A COMMIT for the already-active epoch is answered idempotently (covers
    // a lost ack without touching key state).
    if (Serial.available() >= 5) {
        int peek = Serial.peek();
        if (peek == SHALLOT_MSG_COMMIT || peek == SHALLOT_MSG_CANCEL) {
            uint8_t msg = Serial.read();
            uint32_t epoch = 0;
            
            // Check if there's a target ID byte (6-byte format)
            if (Serial.available() >= 5) { // At least 5 more bytes = target + epoch
                uint8_t targetId = Serial.read();
                // Only process if this message is for us or broadcast
                if (targetId != SHALLOT_TARGET_PAW && targetId != 0xFF) {
                    // Not for us, skip the rest
                    while (Serial.available() > 0 && Serial.peek() != SHALLOT_MSG_COMMIT && Serial.peek() != SHALLOT_MSG_CANCEL) {
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
            
            if (msg == SHALLOT_MSG_COMMIT) {
                if (pendingValid && pendingEpoch == epoch && millis() < pendingDeadlineMs &&
                    shallot_key_looks_valid(pendingKey)) {
                    memcpy(aesKey, pendingKey, SHALLOT_AES_KEY_SIZE);
                    activeEpoch = pendingEpoch;
                    keyStored = true;
                    secureWipePending();  // temp key data must not linger after replacement
                    Serial.print("[PRO-48] Committed epoch "); Serial.println(activeEpoch);
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    digitalWrite(LED_BUILTIN, HIGH);
                    epdShowStatus(EPD_STATUS_AUTHENTICATING);

                    sendCommitAck();
                } else if (keyStored && epoch == activeEpoch) {
                    // Duplicate COMMIT after a lost ack: already active, resend ack only.
                    Serial.println("[PRO-48] Duplicate COMMIT for active epoch; resending ack");
                    sendCommitAck();
                } else {
                    Serial.println("[PRO-48] Commit failed");
                }
            } else if (pendingValid) {
                secureWipePending();
                Serial.println("[PRO-48] Pending canceled");
            } else {
                Serial.println("[PRO-48] Cancel ignored (no pending)");
            }
        }
    }
    if (pendingValid && millis() > pendingDeadlineMs) {
        Serial.println("[PRO-48] Pending expired");
        secureWipePending();
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
            if (lastChallengeTime > 0 && (millis() - lastChallengeTime > SHALLOT_CHALLENGE_TIMEOUT_MS)) {
                lastChallengeTime = 0;
                Serial.println("[PRO-50] Challenge timeout.");
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_COMPUTING_RESPONSE:
            if (keyStored) {
                uint8_t hmacInput[4 + SHALLOT_CHALLENGE_SIZE];
                hmacInput[0] = (challengeEpoch >> 24) & 0xFF;
                hmacInput[1] = (challengeEpoch >> 16) & 0xFF;
                hmacInput[2] = (challengeEpoch >> 8) & 0xFF;
                hmacInput[3] = challengeEpoch & 0xFF;
                memcpy(hmacInput+4, challenge, SHALLOT_CHALLENGE_SIZE);
                hmac_sha256(aesKey, SHALLOT_AES_KEY_SIZE, hmacInput, 4+SHALLOT_CHALLENGE_SIZE, response);
                memset(hmacInput, 0, sizeof(hmacInput));

                Serial.print("[PRO-50] HMAC Response computed epoch "); Serial.print(challengeEpoch); Serial.print(" : ");
                for (int i = 0; i < SHALLOT_HMAC_SIZE; i++) Serial.printf("%02X", response[i]);
                Serial.println();

                uint8_t txPacket[SHALLOT_LORA_RESPONSE_LEN];
                txPacket[0] = SHALLOT_MSG_RESPONSE;
                memcpy(txPacket + 1, challenge, SHALLOT_CHALLENGE_SIZE);
                txPacket[1+SHALLOT_CHALLENGE_SIZE] = (challengeEpoch >> 24) & 0xFF;
                txPacket[1+SHALLOT_CHALLENGE_SIZE+1] = (challengeEpoch >> 16) & 0xFF;
                txPacket[1+SHALLOT_CHALLENGE_SIZE+2] = (challengeEpoch >> 8) & 0xFF;
                txPacket[1+SHALLOT_CHALLENGE_SIZE+3] = challengeEpoch & 0xFF;
                memcpy(txPacket + 1 + SHALLOT_CHALLENGE_SIZE + 4, response, SHALLOT_HMAC_SIZE);

                if (loraInitialized) {
                    int txState = radio.transmit(txPacket, sizeof(txPacket));
                    if (txState == RADIOLIB_ERR_NONE) {
                        Serial.println("[PRO-50] Response sent over LoRa to PLC.");
                        noteRadioOk();
                    } else {
                        Serial.printf("[PRO-50] LoRa transmit error: %d\n", txState);
                        noteRadioError();
                    }
                    radio.startReceive();
                }

                // Removed Serial.write leak over USB (was HMAC exposure)

                currentState = STATE_WAITING_FOR_RESULT;
                memset(challenge, 0, SHALLOT_CHALLENGE_SIZE);
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
