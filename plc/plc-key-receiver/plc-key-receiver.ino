/*
 * SHALLOT — PLC Complete Firmware (PRO-47 + PRO-49 + PRO-51 + PRO-52)
 * Edge enforcement node: Raspberry Pi Pico 2 (RP2350A) + Core1262-868M
 *
 * Complete implementation:
 *   - PRO-47: Key reception from UNO Q via USB (was UART, deprecated 2026-09-04)
 *   - PRO-51: Nonce generation (16-byte random)
 *   - PRO-52: Challenge-response protocol over LoRa P2P
 *   - PRO-49: HMAC-SHA256 verification of PAW responses
 *
 * Distribution protocol (matches UNO Q MCU firmware) - now via USB CDC:
 *   UNO Q -> PLC:  MSG_HANDSHAKE (0xA1) + target_id (1 byte)  [USB]
 *   PLC -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes)     [USB]
 *   UNO Q -> PLC:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4) [USB]
 *   PLC -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes)  [USB]
 *
 * Authentication protocol (LoRa P2P with PAW):
 *   PLC -> PAW:   MSG_CHALLENGE (0xB1) + nonce (16 bytes)
 *   PAW -> PLC:   MSG_RESPONSE (0xB2) + HMAC-SHA256(key, nonce) (32 bytes)
 *   PLC -> PAW:   MSG_RESULT (0xB3) + result (0x01=success, 0x00=failed)
 *
 * Key storage:
 *   The key is stored in volatile SRAM. On power loss the key
 *   is gone — this is intentional for a prototype (fail-closed on reboot).
 *
 * Hardware:
 *   Raspberry Pi Pico 2 (RP2350A)
 *   USB: Serial (USB CDC) — connected via USB hub to host/Mama Bear (UART GP0/GP1 deprecated)
 *   Core1262-868M: SPI1 (GP10=CLK, GP11=MOSI, GP12=MISO, GP9=CS,
 *                  GP6=BUSY, GP8=RESET, GP21=DIO1) — for LoRa
 *
 * Core: arduino-pico (earlephilhower) or rp2040:rp2040
 *
 * Linear: PRO-47 (key storage), PRO-49 (HMAC verification),
 *         PRO-51 (nonce generation), PRO-52 (challenge-response)
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

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
#define CHALLENGE_INTERVAL        5000   // ms between challenges
#define CHALLENGE_RESPONSE_TIMEOUT 30000 // ms before re-issuing a stale challenge
#define UART_BAUD                115200

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE     16
#define KEY_HASH_SIZE     4
#define CHALLENGE_SIZE    16  // Nonce size
#define HMAC_SIZE         32  // HMAC-SHA256 output

// =============================================================
// Protocol Message Types
// =============================================================

// Key distribution (UART)
#define MSG_HANDSHAKE    0xA1
#define MSG_READY        0xA2
#define MSG_KEY_DATA     0xA3
#define MSG_STORED       0xA4
#define MSG_ERROR        0xA5
#define MSG_COMMIT       0xA6
#define MSG_CANCEL       0xA7

// Authentication protocol (LoRa)
#define MSG_CHALLENGE    0xB1
#define MSG_RESPONSE     0xB2
#define MSG_RESULT       0xB3

// Target IDs
#define TARGET_PLC       0x01
#define TARGET_PAW       0x02

// =============================================================
// Pin Definitions
// =============================================================

// SPI1 Pin Definitions for Core1262
#define SPI1_SCK_PIN   10  // GP10 (physical pin 14)
#define SPI1_MOSI_PIN  11  // GP11 (physical pin 15)
#define SPI1_MISO_PIN  12  // GP12 (physical pin 16) = SPI1 MISO
#define LORA_CS_PIN     9   // GP9 (physical pin 12, software CS)
#define LORA_BUSY_PIN   6   // GP6 (physical pin 9)
#define LORA_RESET_PIN  8   // GP8 (physical pin 11)
#define LORA_DIO1_PIN   21  // GP21 (physical pin 27)

// =============================================================
// SPI1 Instance for Core1262
// =============================================================
SPIClassRP2040 loraSPI(spi1, SPI1_MISO_PIN, LORA_CS_PIN, SPI1_SCK_PIN, SPI1_MOSI_PIN);

// =============================================================
// RadioLib SX1262 Module
// =============================================================
SX1262 radio = new Module(LORA_CS_PIN, LORA_DIO1_PIN, LORA_RESET_PIN, LORA_BUSY_PIN, loraSPI);

// Interrupt flag for received LoRa packets
static volatile bool loraPacketReceived = false;

#if defined(ESP8266) || defined(ESP32)
  ICACHE_RAM_ATTR
#endif
static void setLoRaFlag(void) {
    loraPacketReceived = true;
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
static inline void secureWipePending() {
  memset(pendingKey, 0, AES_KEY_SIZE);
  pendingValid = false;
  pendingEpoch = 0;
  pendingDeadlineMs = 0;
}
static const uint8_t deviceId[4] = { 0x50, 0x4C, 0x43, 0x01 };  // "PLC\x01"

// =============================================================
// Device Identity (Slice 4) - P-256 ECDSA
// =============================================================

// P-256 curve parameters (secp256r1 / prime256v1)
// Using compressed public key format for storage (33 bytes: 0x02/0x03 + x[32])
#define P256_PRIVATE_KEY_SIZE  32
#define P256_PUBLIC_KEY_SIZE   65  // Uncompressed: 0x04 + x[32] + y[32] = 65 bytes
#define P256_COMPRESSED_PUB_SIZE 33  // Compressed: 0x02/0x03 + x[32]
#define P256_SIGNATURE_SIZE    64  // r[32] + s[32]
#define SHA256_HASH_SIZE      32  // SHA-256 produces 32-byte hash

// Device identity storage
static uint8_t devicePrivateKey[P256_PRIVATE_KEY_SIZE];
static uint8_t devicePublicKey[P256_PUBLIC_KEY_SIZE];
static bool deviceIdentityGenerated = false;
static uint8_t devicePublicKeyHash[SHA256_HASH_SIZE];  // SHA-256 of public key

// Generate deterministic P-256 keypair from device-specific seed
// For prototype: use deviceId as seed; for production: use RP2350 flash OTP + TRNG
static void generateDeviceIdentity() {
  if (deviceIdentityGenerated) return;
  
  Serial.println("[PRO-48] Generating P-256 device identity...");
  
  // For prototype: use deviceId as seed (deterministic for testing)
  // In production: use RP2350 unique ID + TRNG
  uint8_t seed[32];
  memset(seed, 0, 32);
  memcpy(seed, deviceId, 4);
  
  // Generate private key from seed (for testing - deterministic)
  // In production: use proper ECDSA key generation with TRNG
  memcpy(devicePrivateKey, seed, P256_PRIVATE_KEY_SIZE);
  
  // For prototype: compute public key as hash of private key (not real ECDSA)
  // This is a placeholder - real implementation would use ECDSA
  sha256(devicePrivateKey, P256_PRIVATE_KEY_SIZE, devicePublicKeyHash);
  
  // Create mock public key (uncompressed format: 0x04 + x + y)
  devicePublicKey[0] = 0x04;  // Uncompressed point
  memcpy(&devicePublicKey[1], devicePrivateKey, 32);  // x coordinate
  memcpy(&devicePublicKey[33], devicePrivateKey, 32); // y coordinate (mock)
  
  deviceIdentityGenerated = true;
  
  Serial.print("[PRO-48] Device identity generated. Pubkey hash: ");
  for (int i = 0; i < 4; i++) Serial.printf("%02X", devicePublicKeyHash[i]);
  Serial.println("...");
}

// Get device public key hash (first 4 bytes for identification)
static void getDevicePublicKeyHash(uint8_t* hashOut) {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  memcpy(hashOut, devicePublicKeyHash, KEY_HASH_SIZE);
}

// Sign a message using device identity (placeholder - mock signature for prototype)
// Real implementation would use ECDSA P-256 with proper signing
// For prototype: returns SHA-256 of (privateKey + message) as mock signature
static void signWithDeviceKey(const uint8_t* message, size_t msgLen, uint8_t* signature) {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  
  // Mock signature: SHA-256(privateKey + message)
  uint8_t input[P256_PRIVATE_KEY_SIZE + msgLen];
  memcpy(input, devicePrivateKey, P256_PRIVATE_KEY_SIZE);
  memcpy(&input[P256_PRIVATE_KEY_SIZE], message, msgLen);
  sha256(input, sizeof(input), signature);
  
  // For prototype: duplicate hash to fill 64-byte signature
  memcpy(&signature[32], signature, 32);
}

// =============================================================
// Identity Challenge-Response Protocol
// =============================================================

// Handle identity challenge from MCU
// MCU sends: MSG_ID_CHALLENGE(0xB4) + challenge[32] + operation[1] + target[1] + epoch[4]
// Device responds: MSG_ID_RESPONSE(0xB5) + signature[64] + devicePubKeyHash[4]
#define MSG_ID_CHALLENGE  0xB4
#define MSG_ID_RESPONSE   0xB5

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
  Serial.write(devicePublicKeyHash, KEY_HASH_SIZE);  // First 4 bytes of pubkey hash
  Serial.flush();
  
  Serial.println("[PRO-48] Identity challenge response sent");
  return true;
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
// HMAC-SHA256 Implementation (PRO-49)
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
// Nonce Generation (PRO-51)
// =============================================================

uint32_t simpleRandState = 1;

void generateNonce(uint8_t* nonce, size_t size) {
  if (size > 16) size = 16;
  for (size_t i = 0; i < size; i++) {
    simpleRandState = simpleRandState * 1664525 + 1013904223;
    nonce[i] = (uint8_t)(simpleRandState >> 16);
  }
}

// =============================================================
// Key Reception Protocol (PRO-47)
// =============================================================

bool receiveKey() {
  uint32_t timeoutStart = millis();
  const uint32_t TIMEOUT_MS = 10000;

  Serial.println("[PRO-47] Waiting for key distribution from UNO Q (USB, epoch-tagged)...");

  // Step 1: Wait for handshake 0xA1 target[1] epoch_be4[4] (6B)
  uint32_t stagedEpoch = 0;
  while (millis() - timeoutStart < TIMEOUT_MS) {
    // Check for identity challenge first (Slice 4) - may need up to 39 bytes
    if (Serial.available() >= 1) {
      int peek = Serial.peek();
      if (peek == MSG_ID_CHALLENGE) {
        // Wait for complete identity challenge frame
        if (Serial.available() >= 39) {
          handleIdentityChallenge();
          // Reset timeout after handling challenge
          timeoutStart = millis();
          continue;
        }
        // Not enough bytes yet, keep waiting
        delay(1);
        continue;
      }
    }
    // Proceed with handshake only if we have enough AND first byte is not identity
    if (Serial.available() >= 6) {
      uint8_t msgType = Serial.read();
      uint8_t targetId = Serial.read();
      uint32_t epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
      if (msgType == MSG_HANDSHAKE && targetId == TARGET_PLC) {
        Serial.print("[PRO-47] Handshake received epoch "); Serial.println(epoch);
        stagedEpoch = epoch;
        // Reject if epoch not newer than active
        if (stagedEpoch <= activeEpoch) {
          Serial.println("[PRO-47] Epoch not newer than active - reject");
          return false;
        }
        break;
      } else {
        Serial.printf("[PRO-47] Unexpected message: 0x%02X target: 0x%02X epoch %lu\n", msgType, targetId, (unsigned long)epoch);
        return false;
      }
    }
    delay(1);
  }
  if (stagedEpoch == 0) {
    Serial.println("[PRO-47] Timeout waiting for handshake.");
    return false;
  }

  // Step 2: Send READY + device ID + epoch (9B)
  Serial.print("[PRO-47] Sending READY epoch "); Serial.println(stagedEpoch);
  Serial.write(MSG_READY);
  Serial.write(deviceId, 4);
  Serial.write((stagedEpoch >> 24) & 0xFF);
  Serial.write((stagedEpoch >> 16) & 0xFF);
  Serial.write((stagedEpoch >> 8) & 0xFF);
  Serial.write(stagedEpoch & 0xFF);
  Serial.flush();

  // Step 3: Wait for key data 0xA3 len key16 crc4 epoch4 = 26B
  // But first, handle any identity challenges (0xB4) which may arrive at any time
  timeoutStart = millis();
  while (millis() - timeoutStart < TIMEOUT_MS) {
    // Check for identity challenge first (Slice 4) - may need up to 39 bytes
    if (Serial.available() >= 1) {
      int peek = Serial.peek();
      if (peek == MSG_ID_CHALLENGE) {
        // Wait for complete identity challenge frame
        if (Serial.available() >= 39) {
          handleIdentityChallenge();
          // Reset timeout after handling challenge
          timeoutStart = millis();
          continue;
        }
        // Not enough bytes yet, keep waiting
        delay(1);
        continue;
      }
    }
    // Proceed with key data only if we have enough AND first byte is not identity
    if (Serial.available() >= 26) {
      break;
    }
    delay(1);
  }
  if (Serial.available() < 26) {
    Serial.println("[PRO-47] Timeout waiting for key data.");
    return false;
  }

  uint8_t msgType = Serial.read();
  if (msgType != MSG_KEY_DATA) {
    Serial.printf("[PRO-47] Expected KEY_DATA, got 0x%02X\n", msgType);
    return false;
  }

  uint8_t receivedKeyLen = Serial.read();
  if (receivedKeyLen != AES_KEY_SIZE) {
    Serial.printf("[PRO-47] Unexpected key length: %d\n", receivedKeyLen);
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
    Serial.printf("[PRO-47] Epoch mismatch staged %lu got %lu\n", (unsigned long)stagedEpoch, (unsigned long)receivedEpoch);
    Serial.write(MSG_ERROR);
    return false;
  }

  uint32_t computedCrc = crc32(receivedKey, AES_KEY_SIZE);
  if (computedCrc != receivedCrc) {
    Serial.printf("[PRO-47] CRC mismatch! Expected: %08X Got: %08X\n",
                   computedCrc, receivedCrc);
    Serial.write(MSG_ERROR);
    return false;
  }
  Serial.println("[PRO-47] CRC verified OK.");

  // Store as pending, not active (second slice)
  memcpy(pendingKey, receivedKey, AES_KEY_SIZE);
  pendingEpoch = stagedEpoch;
  pendingValid = true;
  pendingDeadlineMs = millis() + 600000;
  memset(receivedKey, 0, AES_KEY_SIZE);

  uint8_t fullHash[32];
  sha256(pendingKey, AES_KEY_SIZE, fullHash);
  uint8_t pendingHashLocal[KEY_HASH_SIZE];
  memcpy(pendingHashLocal, fullHash, KEY_HASH_SIZE);

  Serial.write(MSG_STORED);
  Serial.write(pendingHashLocal, KEY_HASH_SIZE);
  Serial.write((pendingEpoch >> 24) & 0xFF);
  Serial.write((pendingEpoch >> 16) & 0xFF);
  Serial.write((pendingEpoch >> 8) & 0xFF);
  Serial.write(pendingEpoch & 0xFF);
  Serial.flush();

  Serial.print("[PRO-47] Pending hash sent: ");
  for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", pendingHashLocal[i]);
  Serial.println();

  memset(fullHash, 0, 32);
  return true;
}

// =============================================================
// API
// =============================================================

bool isKeyStored() {
  return keyStored;
}

const uint8_t* getStoredKey() {
  return keyStored ? aesKey : nullptr;
}

bool isPendingValid() {
  return pendingValid && pendingEpoch != 0 && millis() < pendingDeadlineMs;
}

bool commitPending(uint32_t epoch) {
  if (!pendingValid || pendingEpoch != epoch) {
    Serial.println("[PRO-47] Commit failed: no pending or epoch mismatch");
    return false;
  }
  if (millis() > pendingDeadlineMs) {
    Serial.println("[PRO-47] Commit failed: deadline expired");
    secureWipePending();
    pendingValid = false;
    return false;
  }
  memcpy(aesKey, pendingKey, AES_KEY_SIZE);
  activeEpoch = pendingEpoch;
  keyStored = true;
  // Keep pending for audit but mark as committed
  Serial.print("[PRO-47] Committed epoch "); Serial.println(activeEpoch);
  return true;
}

void checkPendingExpiry() {
  if (pendingValid && millis() > pendingDeadlineMs) {
    Serial.println("[PRO-47] Pending expired, wiping");
    memset(pendingKey, 0, AES_KEY_SIZE);
    pendingValid = false;
    pendingEpoch = 0;
  }
}

// =============================================================
// Challenge-Response Protocol (PRO-52)
// =============================================================

static bool loraInitialized = false;
static uint8_t currentNonce[CHALLENGE_SIZE];
static uint32_t lastChallengeTime = 0;
static bool awaitingResponse = false;

bool sendChallenge() {
  if (!keyStored) {
    Serial.println("[PRO-52] Cannot send challenge: no key stored.");
    return false;
  }
  if (!loraInitialized) {
    Serial.println("[PRO-52] LoRa not initialized.");
    return false;
  }

  generateNonce(currentNonce, CHALLENGE_SIZE);

  Serial.print("[PRO-51] Generated nonce: ");
  for (int i = 0; i < CHALLENGE_SIZE; i++) Serial.printf("%02X", currentNonce[i]);
  Serial.print(" epoch "); Serial.println(activeEpoch);
  Serial.println();

  uint8_t txPacket[1 + CHALLENGE_SIZE + 4];
  txPacket[0] = MSG_CHALLENGE;
  memcpy(txPacket + 1, currentNonce, CHALLENGE_SIZE);
  txPacket[1+CHALLENGE_SIZE] = (activeEpoch >> 24) & 0xFF;
  txPacket[1+CHALLENGE_SIZE+1] = (activeEpoch >> 16) & 0xFF;
  txPacket[1+CHALLENGE_SIZE+2] = (activeEpoch >> 8) & 0xFF;
  txPacket[1+CHALLENGE_SIZE+3] = activeEpoch & 0xFF;

  int txState = radio.transmit(txPacket, sizeof(txPacket));
  if (txState == RADIOLIB_ERR_NONE) {
    Serial.println("[PRO-52] Challenge sent over LoRa to PAW.");
    awaitingResponse = true;
    lastChallengeTime = millis();
    return true;
  } else {
    Serial.printf("[PRO-52] LoRa transmit error: %d\n", txState);
    return false;
  }
}

bool verifyResponse(const uint8_t* echoedNonce, uint32_t echoedEpoch,
                    const uint8_t* response,
                    size_t responseLen) {
  if (!keyStored) {
    Serial.println("[PRO-49] Cannot verify: no key stored.");
    return false;
  }
  if (responseLen != HMAC_SIZE) {
    Serial.printf("[PRO-49] Invalid response length: %u (expected %u)\n",
                  responseLen, HMAC_SIZE);
    return false;
  }
  if (echoedEpoch != activeEpoch) {
    Serial.printf("[PRO-49] Epoch mismatch expected %lu got %lu\n", (unsigned long)activeEpoch, (unsigned long)echoedEpoch);
    return false;
  }
  // Constant-time nonce check (prevent attacker-chosen nonce)
  volatile uint8_t nonceDiff = 0;
  for (int i=0;i<CHALLENGE_SIZE;i++) nonceDiff |= echoedNonce[i] ^ currentNonce[i];
  if (nonceDiff != 0) {
    Serial.println("[PRO-49] Nonce mismatch (replay or wrong challenge)");
    return false;
  }

  uint8_t hmacInput[4 + CHALLENGE_SIZE];
  hmacInput[0] = (activeEpoch >> 24) & 0xFF;
  hmacInput[1] = (activeEpoch >> 16) & 0xFF;
  hmacInput[2] = (activeEpoch >> 8) & 0xFF;
  hmacInput[3] = activeEpoch & 0xFF;
  memcpy(hmacInput+4, echoedNonce, CHALLENGE_SIZE);
  uint8_t expectedHmac[HMAC_SIZE];
  hmac_sha256(aesKey, AES_KEY_SIZE, hmacInput, 4+CHALLENGE_SIZE, expectedHmac);

  volatile uint8_t diff = 0;
  for (size_t i = 0; i < HMAC_SIZE; i++) {
    diff |= response[i] ^ expectedHmac[i];
  }

  memset(expectedHmac, 0, HMAC_SIZE);
  memset(hmacInput, 0, sizeof(hmacInput));

  if (diff != 0) {
    Serial.println("[PRO-49] HMAC verification FAILED.");
    return false;
  }

  Serial.println("[PRO-49] HMAC verification SUCCESS.");
  return true;
}

// =============================================================
// Setup and Loop
// =============================================================

// Initializes the LoRa radio. Safe to call once a key is available
// (either at boot via UART key distribution, or later via USB injection).
void initLoRa() {
  if (loraInitialized) return;
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
}

void setup() {
  Serial.begin(115200); while(!Serial) delay(10);

  loraSPI.setSCK(SPI1_SCK_PIN);
  loraSPI.setTX(SPI1_MOSI_PIN);
  loraSPI.setRX(SPI1_MISO_PIN);
  loraSPI.begin();
  Serial.println("[PRO-27] SPI1 initialized for Core1262.");

  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — PLC Complete Firmware");
  Serial.println("Hardware: Raspberry Pi Pico 2 (RP2350A)");
  Serial.println("Components: Core1262 LoRa");
  Serial.println("============================================");
  Serial.println("Waiting for UNO Q key distribution...");
  Serial.println();

  if (receiveKey()) {
    Serial.println("[PRO-47] Key distribution successful.");
    digitalWrite(LED_BUILTIN, HIGH);
  } else {
    Serial.println("[PRO-47] Key distribution failed. No key stored.");
    for (int i = 0; i < 10; i++) {
      digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
      delay(200);
    }
  }

  if (keyStored) {
    initLoRa();
  }
}

void loop() {
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

      // RSSI fail-closed gate
      float rssi = radio.getRSSI();
      if (rssi < -70.0) {
        Serial.printf("[PRO-52] RSSI %.1f dBm too weak, discard\n", rssi);
        radio.startReceive();
        return;
      }
      if (msgType == MSG_RESPONSE && rxLen >= (1 + CHALLENGE_SIZE + 4 + HMAC_SIZE)) {
        Serial.println("[PRO-52] Response received from PAW over LoRa");

        // Response: 0xB2 || nonce[16] || epoch_be4[4] || hmac[32] = 53B
        const uint8_t* echoedNonce = rxBuffer + 1;
        uint32_t echoedEpoch = ((uint32_t)rxBuffer[1+CHALLENGE_SIZE] << 24) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+1] << 16) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+2] << 8) | ((uint32_t)rxBuffer[1+CHALLENGE_SIZE+3]);
        const uint8_t* responseHmac = rxBuffer + 1 + CHALLENGE_SIZE + 4;

        bool verified = verifyResponse(echoedNonce, echoedEpoch, responseHmac, HMAC_SIZE);

        awaitingResponse = false;
        lastChallengeTime = millis();

        uint8_t resultPacket[2];
        resultPacket[0] = MSG_RESULT;
        resultPacket[1] = verified ? 0x01 : 0x00;

        int txState = radio.transmit(resultPacket, sizeof(resultPacket));
        if (txState == RADIOLIB_ERR_NONE) {
          Serial.print("[PRO-52] Result sent to PAW: ");
          Serial.println(verified ? "SUCCESS" : "FAILED");
        } else {
          Serial.printf("[PRO-52] Failed to send result: %d\n", txState);
        }

        if (verified) {
          for (int i = 0; i < 5; i++) {
            digitalWrite(LED_BUILTIN, HIGH);
            delay(100);
            digitalWrite(LED_BUILTIN, LOW);
            delay(100);
          }
        } else {
          for (int i = 0; i < 10; i++) {
            digitalWrite(LED_BUILTIN, HIGH);
            delay(50);
            digitalWrite(LED_BUILTIN, LOW);
            delay(50);
          }
        }
      }
    }
    radio.startReceive();
  }

  if (keyStored && loraInitialized) {
    bool stale = awaitingResponse &&
                 (millis() - lastChallengeTime >= CHALLENGE_RESPONSE_TIMEOUT);
    if (stale) {
      awaitingResponse = false;
      Serial.println("[PRO-52] Challenge response timed out; re-issuing.");
    }
    if (!awaitingResponse && millis() - lastChallengeTime >= CHALLENGE_INTERVAL) {
      sendChallenge();
    }
  }

  // Handle identity challenge via USB (Slice 4) - check first, regardless of key state
  if (Serial.available() >= 1) {
    int peek = Serial.peek();
    if (peek == MSG_ID_CHALLENGE) {
      handleIdentityChallenge();
    }
  }

  if (!keyStored) {
    if (Serial.available() >= 2) {
      if (receiveKey()) {
        // Key received via USB (was UART) - init LoRa now
        if (!loraInitialized) initLoRa();
      }
    }
  } else if (keyStored && !loraInitialized) {
    initLoRa();
  }

  // Handle pending commit/cancel via USB (6B: type + target + epoch_be4, or 5B legacy)
  if (pendingValid && Serial.available() >= 5) {
    int peek = Serial.peek();
    if (peek == MSG_COMMIT || peek == MSG_CANCEL) {
      uint8_t msg = Serial.read();
      uint32_t epoch = 0;
      
      // Check if there's a target ID byte (6-byte format)
      if (Serial.available() >= 5) { // At least 5 more bytes = target + epoch
        uint8_t targetId = Serial.read();
        // Only process if this message is for us or broadcast
        if (targetId != TARGET_PLC && targetId != 0xFF) {
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
        if (commitPending(epoch)) {
          Serial.print("[PRO-47] Committed pending epoch "); Serial.println(epoch);
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
          // Clear the hash to prevent memory leakage
          memset(fullHash, 0, 32);
          Serial.println("[PRO-47] Sent COMMIT acknowledgment");
        } else {
          Serial.println("[PRO-47] Commit failed");
        }
      } else {
        secureWipePending();
        Serial.println("[PRO-47] Pending canceled");
      }
    }
  }
  checkPendingExpiry();

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
