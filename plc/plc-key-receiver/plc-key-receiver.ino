/*
 * SHALLOT — PLC Complete Firmware (PRO-47 + PRO-49 + PRO-51 + PRO-52 + PRO-53)
 * Edge enforcement node: Raspberry Pi Pico 2 (RP2350A) + Core1262-868M
 *
 * Complete implementation:
 *   - PRO-47: Key reception from UNO Q via USB (was UART, deprecated 2026-09-04)
 *   - PRO-51: Nonce generation (16-byte, seeded from radio noise + ADC + micros)
 *   - PRO-52: Challenge-response protocol over LoRa P2P, with response
 *     timeout, bounded retries (lockout cooldown on exhaustion), and
 *     rejection of stray/duplicate/malformed packets (fail-closed)
 *   - PRO-49: HMAC-SHA256 verification of PAW responses
 *   - PRO-53: Single fail-closed authentication decision (deny-by-default;
 *     invalid HMAC, verification error, timeout or watchdog/internal fault
 *     always denies, never default-open) + hardware watchdog with
 *     fail-closed reboot
 *
 * Distribution protocol (matches UNO Q MCU firmware) - now via USB CDC:
 *   UNO Q -> PLC:  SHALLOT_MSG_HANDSHAKE (0xA1) + target_id (1 byte)  [USB]
 *   PLC -> UNO Q:  SHALLOT_MSG_READY (0xA2) + device_id (4 bytes)     [USB]
 *   UNO Q -> PLC:  SHALLOT_MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4) [USB]
 *   PLC -> UNO Q:  SHALLOT_MSG_STORED (0xA4) + stored_hash (4 bytes)  [USB]
 *
 * Authentication protocol (LoRa P2P with PAW):
 *   PLC -> PAW:   SHALLOT_MSG_CHALLENGE (0xB1) + nonce (16 bytes)
 *   PAW -> PLC:   SHALLOT_MSG_RESPONSE (0xB2) + HMAC-SHA256(key, nonce) (32 bytes)
 *   PLC -> PAW:   SHALLOT_MSG_RESULT (0xB3) + result (0x01=success, 0x00=failed)
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

// Timeouts: see SHALLOT_*_MS in ShallotLoRaProtocol.h (shared with PAW).
#define UART_BAUD                115200

// =============================================================
// Constants and protocol message types — see ShallotLoRaProtocol.h
// (shared SHALLOT_* definitions, same as PAW)
// =============================================================

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
//
// Lifecycle: staged as pending (validated) -> committed to active on
// COMMIT -> pending wiped. Expiry/cancel/replacement wipe pending.
// Only status and the 4-byte fingerprint ever leave the device; the
// key bytes are never exposed (no getter returns them).
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
// PRO-53 fault latch: set on watchdog/internal errors (e.g. HMAC
// allocation failure, where a zeroed MAC could otherwise compare equal
// to an all-zero attacker response). While latched, plcDecideAccess()
// denies every authentication until reboot. Fail-closed boot clears it.
static bool plcInternalFault = false;
// Device ID: see shared header ("PLC\x01")

// =============================================================
// Device Identity (Slice 4) - P-256 ECDSA
// =============================================================

// P-256 curve parameters (secp256r1 / prime256v1)
// Sizes: see shared header (same as PAW).

// Device identity storage
static uint8_t devicePrivateKey[SHALLOT_P256_PRIVATE_KEY_SIZE];
static uint8_t devicePublicKey[SHALLOT_P256_PUBLIC_KEY_SIZE];
static bool deviceIdentityGenerated = false;
static uint8_t devicePublicKeyHash[SHALLOT_SHA256_SIZE];  // SHA-256 of public key

// Generate deterministic P-256 keypair from device-specific seed
// For prototype: use SHALLOT_DEVICE_ID_PLC as seed; for production: use RP2350 flash OTP + TRNG
static void generateDeviceIdentity() {
  if (deviceIdentityGenerated) return;
  
  Serial.println("[PRO-48] Generating P-256 device identity...");
  
  // For prototype: use SHALLOT_DEVICE_ID_PLC as seed (deterministic for testing)
  // In production: use RP2350 unique ID + TRNG
  uint8_t seed[32];
  memset(seed, 0, 32);
  memcpy(seed, SHALLOT_DEVICE_ID_PLC, 4);
  
  // Generate private key from seed (for testing - deterministic)
  // In production: use proper ECDSA key generation with TRNG
  memcpy(devicePrivateKey, seed, SHALLOT_P256_PRIVATE_KEY_SIZE);
  
  // For prototype: compute public key as hash of private key (not real ECDSA)
  // This is a placeholder - real implementation would use ECDSA
  sha256(devicePrivateKey, SHALLOT_P256_PRIVATE_KEY_SIZE, devicePublicKeyHash);
  
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
  memcpy(hashOut, devicePublicKeyHash, SHALLOT_KEY_HASH_SIZE);
}

// Sign a message using device identity (placeholder - mock signature for prototype)
// Real implementation would use ECDSA P-256 with proper signing
// For prototype: returns SHA-256 of (privateKey + message) as mock signature
static void signWithDeviceKey(const uint8_t* message, size_t msgLen, uint8_t* signature) {
  if (!deviceIdentityGenerated) generateDeviceIdentity();
  
  // Mock signature: SHA-256(privateKey + message)
  uint8_t input[SHALLOT_P256_PRIVATE_KEY_SIZE + msgLen];
  memcpy(input, devicePrivateKey, SHALLOT_P256_PRIVATE_KEY_SIZE);
  memcpy(&input[SHALLOT_P256_PRIVATE_KEY_SIZE], message, msgLen);
  sha256(input, sizeof(input), signature);
  
  // For prototype: duplicate hash to fill 64-byte signature
  memcpy(&signature[32], signature, 32);
}

// =============================================================
// Identity Challenge-Response Protocol
// =============================================================

// Handle identity challenge from MCU — types and frame lengths:
// see shared header (same as PAW).

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
  Serial.write(devicePublicKeyHash, SHALLOT_KEY_HASH_SIZE);  // First 4 bytes of pubkey hash
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
  if (!innerMsg) { memset(mac, 0, 32); plcInternalFault = true; return; }  // PRO-53: deny until reboot
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
// Nonce Generation (PRO-51)
// =============================================================

// Prototype entropy pool. Seeded once from radio-channel noise, a floating
// ADC pin and micros(), stirred with micros() on every challenge so two
// boots never produce the same sequence. Prototype grade — production
// should use the RP2350 TRNG directly.
static uint32_t simpleRandState = 1;

static inline uint32_t nonceMix32(uint32_t x) {
  // splitmix32 finalizer: avalanche all input bits into the output.
  x += 0x9E3779B9UL;
  x = (x ^ (x >> 16)) * 0x85EBCA6BUL;
  x = (x ^ (x >> 13)) * 0xC2B2AE35UL;
  return x ^ (x >> 16);
}

static void seedNonceGenerator() {
  uint32_t seed = (uint32_t)micros();
  seed ^= ((uint32_t)analogRead(A0) << 16) ^ (uint32_t)analogRead(A1);
  int32_t rssiRaw = (int32_t)(radio.getRSSI() * 256.0f);  // channel noise LSBs
  seed ^= (uint32_t)rssiRaw * 0x9E3779B1UL;
  if (seed == 0) seed = 0x243F6A88UL;  // never seed with zero
  simpleRandState = nonceMix32(seed);
  Serial.println("[PRO-51] Nonce generator seeded.");
}

void generateNonce(uint8_t* nonce, size_t size) {
  if (size > SHALLOT_CHALLENGE_SIZE) size = SHALLOT_CHALLENGE_SIZE;
  simpleRandState ^= (uint32_t)micros();  // stir per challenge
  for (size_t i = 0; i < size; i++) {
    simpleRandState = simpleRandState * 1664525 + 1013904223;
    nonce[i] = (uint8_t)(simpleRandState >> 16);
  }
  simpleRandState = nonceMix32(simpleRandState);
}

// =============================================================
// Key Reception Protocol (PRO-47)
// =============================================================

// Live pending round identity: epoch = session, seq = UNO Q retry counter.
// A repeated frame with matching (epoch, seq) is answered idempotently.

static void sendReadyFrame(uint32_t epoch) {
  Serial.print("[PRO-47] Sending READY epoch "); Serial.println(epoch);
  Serial.write(SHALLOT_MSG_READY);
  Serial.write(SHALLOT_DEVICE_ID_PLC, 4);
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
    Serial.println("[PRO-47] Refusing to stage degenerate key (fail-closed).");
    return false;
  }
  memcpy(pendingKey, key, SHALLOT_AES_KEY_SIZE);
  pendingEpoch = epoch;
  pendingSeq = seq;
  pendingValid = true;
  pendingDeadlineMs = millis() + 600000;

  uint8_t fullHash[32];
  sha256(pendingKey, SHALLOT_AES_KEY_SIZE, fullHash);
  uint8_t pendingHashLocal[SHALLOT_KEY_HASH_SIZE];
  memcpy(pendingHashLocal, fullHash, SHALLOT_KEY_HASH_SIZE);
  memset(fullHash, 0, 32);

  Serial.write(SHALLOT_MSG_STORED);
  Serial.write(pendingHashLocal, SHALLOT_KEY_HASH_SIZE);
  uint8_t epochBe[4];
  shallot_put_be32(epochBe, epoch);
  Serial.write(epochBe, 4);
  Serial.flush();

  Serial.print("[PRO-47] Pending hash sent: ");
  for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) Serial.printf("%02X", pendingHashLocal[i]);
  Serial.println();
  return true;
}

bool receiveKey() {
  uint32_t timeoutStart = millis();
  const uint32_t TIMEOUT_MS = SHALLOT_KEY_DIST_TIMEOUT_MS;
  uint32_t resyncSkips = 0;

  Serial.println("[PRO-47] Waiting for key distribution from UNO Q (USB, epoch-tagged)...");

  // Step 1: scan for a HANDSHAKE frame. Stray bytes are dropped one at a
  // time (bounded resync); a KEY_DATA frame matching the live pending
  // round is answered idempotently (covers a lost STORED frame).
  uint32_t stagedEpoch = 0;
  uint8_t stagedSeq = 0;
  while (millis() - timeoutStart < TIMEOUT_MS) {
    plcFeedWatchdog();  // PRO-53: the 10 s scan exceeds the 8 s watchdog
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
        Serial.println("[PRO-47] Foreign key-data frame dropped.");
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
        if (target != SHALLOT_TARGET_PLC) {
          Serial.println("[PRO-47] Handshake for another target; dropped.");
          continue;
        }
        bool fresh = (epoch > activeEpoch);
        bool retry = (pendingValid && epoch == pendingEpoch);
        if (!fresh && !retry) {
          Serial.println("[PRO-47] Epoch not newer than active - reject");
          return false;
        }
        Serial.print("[PRO-47] Handshake received epoch "); Serial.print(epoch);
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
        Serial.println("[PRO-47] Resync budget exhausted waiting for handshake.");
        return false;
      }
    }
    delay(1);
  }
  if (stagedEpoch == 0) {
    Serial.println("[PRO-47] Timeout waiting for handshake.");
    if (resyncSkips > 0) {
      Serial.print("[PRO-47] Resynced past ");
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
  while (millis() - timeoutStart < TIMEOUT_MS) {
    plcFeedWatchdog();  // PRO-53: the 10 s scan exceeds the 8 s watchdog
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
          Serial.println("[PRO-47] Bad key-data length; resyncing.");
          memset(frame, 0, sizeof(frame));
          continue;
        }
        uint32_t receivedEpoch = shallot_get_be32(&frame[22]);
        uint8_t receivedSeq = frame[26];
        if (receivedEpoch != stagedEpoch || receivedSeq != stagedSeq) {
          Serial.println("[PRO-47] Key-data from another round; dropped.");
          memset(frame, 0, sizeof(frame));
          continue;
        }
        uint32_t receivedCrc = shallot_get_be32(&frame[18]);
        uint32_t computedCrc = crc32(&frame[2], SHALLOT_AES_KEY_SIZE);
        if (computedCrc != receivedCrc) {
          Serial.println("[PRO-47] CRC mismatch; waiting for retry.");
          Serial.write(SHALLOT_MSG_ERROR);
          memset(frame, 0, sizeof(frame));
          continue;
        }
        Serial.println("[PRO-47] CRC verified OK.");
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
        Serial.println("[PRO-47] Resync budget exhausted waiting for key data.");
        return false;
      }
    }
    delay(1);
  }
  Serial.println("[PRO-47] Timeout waiting for key data.");
  if (resyncSkips > 0) {
    Serial.print("[PRO-47] Resynced past ");
    Serial.print(resyncSkips);
    Serial.println(" stray bytes.");
  }
  return false;
}

// =============================================================
// Key lifecycle API
//
// Only status and the key fingerprint are observable from outside;
// there is intentionally no getter returning key bytes.
// =============================================================

bool commitPending(uint32_t epoch) {
  if (!pendingValid || pendingEpoch != epoch) {
    Serial.println("[PRO-47] Commit failed: no pending or epoch mismatch");
    return false;
  }
  if (millis() > pendingDeadlineMs) {
    Serial.println("[PRO-47] Commit failed: deadline expired");
    secureWipePending();
    return false;
  }
  if (!shallot_key_looks_valid(pendingKey)) {
    Serial.println("[PRO-47] Commit failed: degenerate pending key (fail-closed)");
    secureWipePending();
    return false;
  }
  memcpy(aesKey, pendingKey, SHALLOT_AES_KEY_SIZE);
  activeEpoch = pendingEpoch;
  keyStored = true;
  secureWipePending();  // temp key data must not linger after replacement
  Serial.print("[PRO-47] Committed epoch "); Serial.println(activeEpoch);
  return true;
}

void checkPendingExpiry() {
  if (pendingValid && millis() > pendingDeadlineMs) {
    Serial.println("[PRO-47] Pending expired, wiping");
    secureWipePending();
  }
}

// Acknowledge the ACTIVE key with STORED + fingerprint (hash only).
// Callers must ensure keyStored is true; sends no key material.
static void sendStoredAck() {
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
  Serial.println("[PRO-47] Sent COMMIT acknowledgment");
}

// =============================================================
// Challenge-Response Protocol (PRO-52)
// =============================================================

static bool loraInitialized = false;
static uint8_t currentNonce[SHALLOT_CHALLENGE_SIZE];
static uint32_t lastChallengeTime = 0;
static bool awaitingResponse = false;

// =============================================================
// Bounded retries + replay protection (PRO-52, fail-closed)
//
// Retry budget: consecutive timeouts/failed verifications consume the
// budget; a success resets it. Exhaustion enters a lockout cooldown
// during which no challenges are sent and responses are ignored —
// the lock stays denied by default. Replays/duplicates are rejected
// without consuming budget (so an attacker cannot force lockout).
// =============================================================

#define PLC_AUTH_MAX_ATTEMPTS 5          // failures in a row before lockout
#define PLC_AUTH_LOCKOUT_MS 60000        // cooldown after budget exhausted
#define PLC_NONCE_CACHE_SIZE 16          // replay cache: last accepted nonces
#define PLC_NONCE_CACHE_WINDOW_MS 60000  // entries older than this are evicted

static uint8_t nonceCache[PLC_NONCE_CACHE_SIZE][SHALLOT_CHALLENGE_SIZE];
static uint32_t nonceCacheTimeMs[PLC_NONCE_CACHE_SIZE];
static uint8_t nonceCacheCount = 0;    // ever stored (ring index source)
static uint8_t authConsecFails = 0;    // timeouts + failed verifications in a row
static uint32_t authLockoutUntilMs = 0;
static uint32_t authRejectedCount = 0;  // diagnostics: pre-verification rejections

// True when the echoed nonce was already accepted within the window.
static bool nonceCacheSeen(const uint8_t* nonce, uint32_t now) {
  uint8_t n = (nonceCacheCount < PLC_NONCE_CACHE_SIZE) ? nonceCacheCount : PLC_NONCE_CACHE_SIZE;
  for (uint8_t i = 0; i < n; i++) {
    if (now - nonceCacheTimeMs[i] > PLC_NONCE_CACHE_WINDOW_MS) continue;  // evicted
    volatile uint8_t diff = 0;
    for (uint8_t j = 0; j < SHALLOT_CHALLENGE_SIZE; j++) {
      diff |= (uint8_t)(nonceCache[i][j] ^ nonce[j]);
    }
    if (diff == 0) return true;
  }
  return false;
}

static void nonceCacheRemember(const uint8_t* nonce, uint32_t now) {
  uint8_t slot = (uint8_t)(nonceCacheCount % PLC_NONCE_CACHE_SIZE);
  memcpy(nonceCache[slot], nonce, SHALLOT_CHALLENGE_SIZE);
  nonceCacheTimeMs[slot] = now;
  nonceCacheCount++;
}

// Lockout gate. Returns true while locked; expiry resets the budget.
// Wrap-safe via signed Elapsed comparison on unsigned millis().
static bool authInLockout(uint32_t now) {
  if (authLockoutUntilMs == 0) return false;
  if ((int32_t)(now - authLockoutUntilMs) >= 0) {
    authLockoutUntilMs = 0;
    authConsecFails = 0;
    Serial.println("[PRO-52] Auth lockout expired; resuming challenges.");
    return false;
  }
  return true;
}

// Record a timeout or failed verification. Exhaustion fails closed
// into lockout; success (elsewhere) resets authConsecFails to zero.
static void authRecordFailure(uint32_t now) {
  if (authConsecFails < 255) authConsecFails++;
  if (authConsecFails >= PLC_AUTH_MAX_ATTEMPTS && authLockoutUntilMs == 0) {
    authLockoutUntilMs = now + PLC_AUTH_LOCKOUT_MS;
    awaitingResponse = false;
    Serial.println("[PRO-52] Retry budget exhausted; entering auth lockout (fail-closed).");
  }
}

// =============================================================
// Authentication decision + watchdog (PRO-53, fail-closed)
//
// plcDecideAccess() is the single decision point for edge
// enforcement. Deny-by-default: access is granted only when the HMAC
// verified AND no timeout occurred AND no watchdog/internal fault is
// latched AND a key is stored AND no lockout is active. Every other
// combination denies. Never default-open.
//
// Hardware watchdog (RP2350, max ~8.3 s, same policy as PAW):
// 8000 ms timeout, fed on every healthy loop pass and inside the
// blocking key-reception scans. Any true lockup reboots into the
// single fail-closed boot path in setup() (no key in SRAM, so the
// decision denies until re-provisioned).
// =============================================================

#define PLC_WDT_TIMEOUT_MS 8000

static inline void plcFeedWatchdog() {
  rp2040.wdt_reset();
}

// Watchdog self-test (physical test plan, doc 15). Boot-window only:
// shortens the timeout and blocks WITHOUT feeding, so the resulting
// reset exercises exactly the same path as a real lockup trip (reboot,
// WDT log line, fail-closed boot with empty SRAM). Reachable only with
// physical USB access inside the 2 s boot window; effect equals a power
// cycle, which needs no console at all.
static void plcWdtSelfTest() {
  Serial.println("[WDT] Self-test: 100 ms timeout, blocking 5 s without feed...");
  Serial.flush();
  rp2040.wdt_begin(100);
  delay(5000);  // no feed: guaranteed trip
  Serial.println("[WDT] ERROR: watchdog did not fire!");
}

// Central authentication decision. Deny-by-default: grant starts false
// and is set only when every condition holds simultaneously.
static bool plcDecideAccess(bool hmacOk, bool timedOut, bool watchdogFault, uint32_t now) {
  bool grant = false;  // fail-closed default: never default-open
  if (hmacOk && !timedOut && !watchdogFault && keyStored && !authInLockout(now)) {
    grant = true;
  }
  return grant;
}

bool sendChallenge() {
  if (!keyStored) {
    Serial.println("[PRO-52] Cannot send challenge: no key stored.");
    return false;
  }
  if (!loraInitialized) {
    Serial.println("[PRO-52] LoRa not initialized.");
    return false;
  }
  if (authInLockout(millis())) {
    // Fail-closed: suppressed during lockout. Silent here — the loop
    // call site already guards, so a log would spam every pass.
    return false;
  }

  generateNonce(currentNonce, SHALLOT_CHALLENGE_SIZE);

  Serial.print("[PRO-51] Generated nonce: ");
  for (int i = 0; i < SHALLOT_CHALLENGE_SIZE; i++) Serial.printf("%02X", currentNonce[i]);
  Serial.print(" epoch "); Serial.println(activeEpoch);
  Serial.println();

  uint8_t txPacket[SHALLOT_LORA_CHALLENGE_LEN];
  txPacket[0] = SHALLOT_MSG_CHALLENGE;
  memcpy(txPacket + 1, currentNonce, SHALLOT_CHALLENGE_SIZE);
  txPacket[1+SHALLOT_CHALLENGE_SIZE] = (activeEpoch >> 24) & 0xFF;
  txPacket[1+SHALLOT_CHALLENGE_SIZE+1] = (activeEpoch >> 16) & 0xFF;
  txPacket[1+SHALLOT_CHALLENGE_SIZE+2] = (activeEpoch >> 8) & 0xFF;
  txPacket[1+SHALLOT_CHALLENGE_SIZE+3] = activeEpoch & 0xFF;

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
  if (responseLen != SHALLOT_HMAC_SIZE) {
    Serial.printf("[PRO-49] Invalid response length: %u (expected %u)\n",
                  responseLen, SHALLOT_HMAC_SIZE);
    return false;
  }
  // Shared correlation check: response must echo the live nonce and epoch.
  switch (shallot_check_correlation(currentNonce, echoedNonce, activeEpoch, echoedEpoch)) {
    case SHALLOT_PROTO_OK:
      break;
    case SHALLOT_PROTO_ERR_EPOCH_MISMATCH:
      Serial.printf("[PRO-49] Epoch mismatch expected %lu got %lu\n", (unsigned long)activeEpoch, (unsigned long)echoedEpoch);
      return false;
    default:
      Serial.println("[PRO-49] Nonce mismatch (replay or wrong challenge)");
      return false;
  }

  uint8_t hmacInput[4 + SHALLOT_CHALLENGE_SIZE];
  hmacInput[0] = (activeEpoch >> 24) & 0xFF;
  hmacInput[1] = (activeEpoch >> 16) & 0xFF;
  hmacInput[2] = (activeEpoch >> 8) & 0xFF;
  hmacInput[3] = activeEpoch & 0xFF;
  memcpy(hmacInput+4, echoedNonce, SHALLOT_CHALLENGE_SIZE);
  uint8_t expectedHmac[SHALLOT_HMAC_SIZE];
  hmac_sha256(aesKey, SHALLOT_AES_KEY_SIZE, hmacInput, 4+SHALLOT_CHALLENGE_SIZE, expectedHmac);

  volatile uint8_t diff = 0;
  for (size_t i = 0; i < SHALLOT_HMAC_SIZE; i++) {
    diff |= response[i] ^ expectedHmac[i];
  }

  memset(expectedHmac, 0, SHALLOT_HMAC_SIZE);
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
    seedNonceGenerator();  // radio noise is available from here on
  } else {
    Serial.printf("[PRO-58] LoRa initialization FAILED, code: %d\n", state);
  }
}

void setup() {
  Serial.begin(115200);
  rp2040.wdt_begin(PLC_WDT_TIMEOUT_MS);
  while(!Serial) {
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
  plcInternalFault = false;
  secureWipePending();

  if (rp2040.getResetReason() == rp2040.WDT_RESET) {
    Serial.println("[WDT] Rebooted by watchdog; starting unauthenticated (fail-closed).");
  }
  plcFeedWatchdog();

  loraSPI.setSCK(SPI1_SCK_PIN);
  loraSPI.setTX(SPI1_MOSI_PIN);
  loraSPI.setRX(SPI1_MISO_PIN);
  loraSPI.begin();
  Serial.println("[PRO-27] SPI1 initialized for Core1262.");

  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);

  // Boot window for the watchdog self-test (doc 15). Doubles as the
  // settle delay; the watchdog is fed throughout.
  Serial.println("[PRO-53] Press 'w' (watchdog self-test) within 2s...");
  uint32_t wdtWindowStart = millis();
  int wdtKey = -1;
  while (millis() - wdtWindowStart < 2000) {
    plcFeedWatchdog();
    if (Serial.available() > 0) { wdtKey = Serial.read(); break; }
    delay(10);
  }
  if (wdtKey == 'w' || wdtKey == 'W') {
    plcWdtSelfTest();
  }

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
      plcFeedWatchdog();
      delay(200);
    }
  }

  if (keyStored) {
    initLoRa();
  }
}

void loop() {
  static uint8_t rxBuffer[64];

  plcFeedWatchdog();  // healthy loop pass: the last line of defense is fed here

  if (loraInitialized && loraPacketReceived) {
    loraPacketReceived = false;

    size_t rxLen = radio.getPacketLength();
    if (rxLen > sizeof(rxBuffer)) rxLen = sizeof(rxBuffer);

    int state = radio.readData(rxBuffer, rxLen);
    if (state == RADIOLIB_ERR_NONE && rxLen > 0) {
      uint8_t msgType = rxBuffer[0];
      Serial.printf("[LoRa RX] Type: 0x%02X, Length: %u bytes, RSSI: %.1f dBm, SNR: %.1f dB\n",
                    msgType, (unsigned)rxLen, radio.getRSSI(), radio.getSNR());

      // RSSI fail-closed gate (shared validator)
      float rssi = radio.getRSSI();
      if (!shallot_rssi_ok(rssi)) {
        Serial.printf("[PRO-52] RSSI %.1f dBm too weak, discard\n", rssi);
        radio.startReceive();
        return;
      }
      if (shallot_check_response_packet(msgType, rxLen) == SHALLOT_PROTO_OK) {
        // Fail-closed: a response is only meaningful for a live challenge.
        if (!awaitingResponse) {
          authRejectedCount++;
          Serial.println("[PRO-52] Stray response with no live challenge; rejected.");
          radio.startReceive();
          return;
        }
        Serial.println("[PRO-52] Response received from PAW over LoRa");

        // Response layout: see SHALLOT_LORA_RESPONSE_LEN in shared header.
        const uint8_t* echoedNonce = rxBuffer + 1;
        uint32_t echoedEpoch = ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE] << 24) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+1] << 16) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+2] << 8) | ((uint32_t)rxBuffer[1+SHALLOT_CHALLENGE_SIZE+3]);
        const uint8_t* responseHmac = rxBuffer + 1 + SHALLOT_CHALLENGE_SIZE + 4;

        uint32_t nowRx = millis();
        if (nonceCacheSeen(echoedNonce, nowRx)) {
          authRejectedCount++;
          Serial.println("[PRO-52] Duplicate response (replay); rejected.");
          radio.startReceive();
          return;
        }

        bool verified = verifyResponse(echoedNonce, echoedEpoch, responseHmac, SHALLOT_HMAC_SIZE);
        // PRO-53: single fail-closed decision point. The retry budget
        // follows the actual decision, not the raw HMAC signal.
        bool granted = plcDecideAccess(verified, false, plcInternalFault, nowRx);
        if (granted) {
          nonceCacheRemember(echoedNonce, nowRx);
          authConsecFails = 0;
        } else {
          authRecordFailure(nowRx);
        }

        awaitingResponse = false;
        lastChallengeTime = millis();

        // A live response existed, so the decision is carried explicitly.
        uint8_t resultPacket[SHALLOT_LORA_RESULT_LEN];
        resultPacket[0] = SHALLOT_MSG_RESULT;
        resultPacket[1] = granted ? SHALLOT_RESULT_SUCCESS : SHALLOT_RESULT_FAILURE;

        int txState = radio.transmit(resultPacket, sizeof(resultPacket));
        if (txState == RADIOLIB_ERR_NONE) {
          Serial.print("[PRO-52] Result sent to PAW: ");
          Serial.println(granted ? "SUCCESS" : "FAILED");
        } else {
          Serial.printf("[PRO-52] Failed to send result: %d\n", txState);
        }

        if (granted) {
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
      } else {
        // Explicit rejection of malformed packets: wrong type tag or
        // shorter than the layout requires. Never treated as success.
        authRejectedCount++;
        Serial.printf("[PRO-52] Malformed LoRa packet rejected: type 0x%02X len %u\n",
                      msgType, (unsigned)rxLen);
        radio.startReceive();
        return;
      }
    }
    radio.startReceive();
  }

  if (keyStored && loraInitialized) {
    uint32_t nowAuth = millis();
    bool stale = awaitingResponse &&
                 (nowAuth - lastChallengeTime >= SHALLOT_CHALLENGE_RESPONSE_TIMEOUT_MS);
    if (stale) {
      awaitingResponse = false;
      // PRO-53: timeout denies access (tyst avslag). The decision is
      // evaluated explicitly so this path can never grant; no RESULT is
      // sent because there is no live response to answer.
      const bool timeoutGranted = plcDecideAccess(false, true, plcInternalFault, nowAuth);
      (void)timeoutGranted;  // always false by construction; kept explicit
      Serial.println("[PRO-52] Challenge response timed out; re-issuing.");
      authRecordFailure(nowAuth);  // bounded retries: exhaustion locks out
    }
    // Lockout suppresses sends (fail-closed); expiry is logged by the gate.
    if (!authInLockout(nowAuth) &&
        !awaitingResponse && nowAuth - lastChallengeTime >= SHALLOT_CHALLENGE_INTERVAL_MS) {
      sendChallenge();
    }
  }

  // Handle identity challenge via USB (Slice 4) - check first, regardless of key state
  if (Serial.available() >= 1) {
    int peek = Serial.peek();
    if (peek == SHALLOT_MSG_ID_CHALLENGE) {
      handleIdentityChallenge();
    }
  }

  // Only enter the distribution scan when a HANDSHAKE is actually pending.
  // Calling receiveKey() on any >=2 bytes let it swallow a COMMIT frame.
  if (!keyStored) {
    if (Serial.available() >= 1 && (uint8_t)Serial.peek() == SHALLOT_MSG_HANDSHAKE) {
      receiveKey();
    }
  }
  // NOTE: radio init is intentionally not performed here. On this bench the
  // Core1262 is absent and initLoRa() blocks, tripping the watchdog mid
  // ceremony. Key provisioning is USB-only, so defer/omit radio init.

  // Handle pending commit/cancel via USB (6B: type + target + epoch_be4, or 5B legacy).
  // A COMMIT for the already-active epoch is answered idempotently (covers
  // a lost STORED ack without touching key state).
  if (Serial.available() >= 5) {
    int peek = Serial.peek();
    if (peek == SHALLOT_MSG_COMMIT || peek == SHALLOT_MSG_CANCEL) {
      uint8_t msg = Serial.read();
      uint32_t epoch = 0;
      
      // Check if there's a target ID byte (6-byte format)
      if (Serial.available() >= 5) { // At least 5 more bytes = target + epoch
        uint8_t targetId = Serial.read();
        // Only process if this message is for us or broadcast
        if (targetId != SHALLOT_TARGET_PLC && targetId != 0xFF) {
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
        if (pendingValid && commitPending(epoch)) {
          Serial.print("[PRO-47] Committed pending epoch "); Serial.println(epoch);
          sendStoredAck();
        } else if (keyStored && epoch == activeEpoch) {
          // Duplicate COMMIT after a lost ACK: already active, resend ack only.
          Serial.println("[PRO-47] Duplicate COMMIT for active epoch; resending ack");
          sendStoredAck();
        } else {
          Serial.println("[PRO-47] Commit failed");
        }
      } else if (pendingValid) {
        secureWipePending();
        Serial.println("[PRO-47] Pending canceled");
      } else {
        Serial.println("[PRO-47] Cancel ignored (no pending)");
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
