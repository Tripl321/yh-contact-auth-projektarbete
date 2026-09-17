/*
 * SHALLOT — PAW Key Receiver Firmware (PRO-48)
 * ID-bricka: Adafruit Feather RP2350
 *
 * Role in key distribution:
 *   Receives AES-128 key from UNO Q via USB (was UART, deprecated 2026-09-04),
 *   stores in RP2350 SRAM, returns SHA-256 hash for verification.
 *
 * Distribution protocol (matches UNO Q MCU firmware) - now via USB CDC:
 *   UNO Q -> PAW:  MSG_HANDSHAKE (0xA1) + target_id (1 byte)  [USB]
 *   PAW -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes)     [USB]
 *   UNO Q -> PAW:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4) [USB]
 *   PAW -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes)  [USB]
 *
 * Key storage:
 *   Volatile SRAM (same approach as PLC). Key lost on power cycle.
 *
 * Hardware:
 *   Adafruit Feather RP2350
 *   USB: Serial (USB CDC) — connected via USB hub to host/Mama Bear (UART GP0/GP1 deprecated)
 *   Core1262-868M: SPI1 (D10/GP10=CLK, D11/GP11=MOSI, A2/GP28=MISO,
 *                  D9/GP9=CS, D6/GP6=BUSY, D8/GP8=RESET, D21/GP21=DIO1)
 *   e-Paper: SPI0 (MO/GP23=DIN, SCK/GP22=CLK, D5/GP5=CS,
 *           D24/GP24=DC, D25/GP25=RST, D7/GP7=BUSY)
 *
 * Core: arduino-pico (earlephilhower)
 *
 * Linear: PRO-48 (key storage on PAW)
 */

#include <Arduino.h>
#include <ShallotLoRaProtocol.h>  // Shared PAW/PLC protocol (types, lengths, timeouts)

// --- Constants ---
#define AES_KEY_SIZE 16
#define KEY_HASH_SIZE 4

// --- Protocol message types (must match UNO Q firmware) ---
#define MSG_HANDSHAKE    0xA1
#define MSG_READY        0xA2
#define MSG_KEY_DATA     0xA3
#define MSG_STORED       0xA4
#define MSG_ERROR        0xA5
#define MSG_COMMIT       0xA6
#define MSG_CANCEL       0xA7

// --- Target IDs ---
#define TARGET_PAW  0x02

// --- Key storage ---
static uint8_t aesKey[AES_KEY_SIZE];
static bool keyStored = false;
static uint32_t activeEpoch = 0;
static uint32_t pendingEpoch = 0;
static uint8_t pendingKey[AES_KEY_SIZE];
static bool pendingValid = false;
static uint32_t pendingDeadlineMs = 0;
static uint8_t pendingSeq = 0;
static inline void secureWipePending() {
  memset(pendingKey, 0, AES_KEY_SIZE);
  pendingValid = false;
  pendingEpoch = 0;
  pendingSeq = 0;
  pendingDeadlineMs = 0;
}

// --- Device ID (unique identifier for this PAW node) ---
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 };  // "PAW\x01"

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
// Minimal SHA-256 (same implementation as UNO Q and PLC firmware)
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
  memcpy(msg, data, len);
  msg[len] = 0x80;
  uint64_t bitLen = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) {
    msg[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;
  }

  for (size_t blk = 0; blk < paddedLen; blk += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)msg[blk + i*4] << 24)
           | ((uint32_t)msg[blk + i*4 + 1] << 16)
           | ((uint32_t)msg[blk + i*4 + 2] << 8)
           | ((uint32_t)msg[blk + i*4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
      w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];
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
    hash[i*4]   = (h[i] >> 24) & 0xFF;
    hash[i*4+1] = (h[i] >> 16) & 0xFF;
    hash[i*4+2] = (h[i] >> 8) & 0xFF;
    hash[i*4+3] = h[i] & 0xFF;
  }

  free(msg);
}

// =============================================================
// CRC32 (must match UNO Q firmware)
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
// Key Reception Protocol (PRO-48)
// =============================================================

bool receiveKey() {
  const uint32_t TIMEOUT_MS = SHALLOT_KEY_DIST_TIMEOUT_MS;
  uint32_t deadline = millis() + TIMEOUT_MS;
  uint32_t resyncSkips = 0;
  uint32_t stagedEpoch = 0;
  uint8_t stagedSeq = 0;

  Serial.println("[PRO-48] Waiting for key distribution from UNO Q (USB epoch-tagged)...");

  // Phase 1: tag-anchored scan for HANDSHAKE (7B). Identity challenges (0xB4)
  // are served inline; stray bytes are dropped with a bounded resync budget.
  bool haveHandshake = false;
  while ((int32_t)(millis() - deadline) < 0 && !haveHandshake) {
    if (!Serial.available()) { delay(1); continue; }
    uint8_t peek = (uint8_t)Serial.peek();
    if (peek == SHALLOT_MSG_ID_CHALLENGE) {
      if (Serial.available() >= SHALLOT_ID_CHALLENGE_FRAME_LEN) {
        handleIdentityChallenge();
        deadline = millis() + TIMEOUT_MS;
      } else {
        delay(1);
      }
      continue;
    }
    if (peek == SHALLOT_MSG_HANDSHAKE) {
      if (Serial.available() < SHALLOT_KD_HANDSHAKE_LEN) { delay(1); continue; }
      uint8_t frame[SHALLOT_KD_HANDSHAKE_LEN];
      for (uint8_t i = 0; i < SHALLOT_KD_HANDSHAKE_LEN; i++) frame[i] = (uint8_t)Serial.read();
      uint8_t target = frame[1];
      uint32_t epoch = shallot_get_be32(&frame[2]);
      uint8_t seq = frame[6];
      if (target != SHALLOT_TARGET_PAW) {
        Serial.println("[PRO-48] Handshake for another target; dropped.");
        continue;
      }
      if (epoch <= activeEpoch) {
        Serial.println("[PRO-48] Epoch not newer - reject");
        continue;
      }
      stagedEpoch = epoch;
      stagedSeq = seq;
      haveHandshake = true;
      Serial.print("[PRO-48] Handshake received epoch "); Serial.print(epoch);
      Serial.print(" seq "); Serial.println(seq);
      break;
    }
    if (resyncSkips++ >= SHALLOT_KD_MAX_RESYNC_SKIPS) {
      Serial.println("[PRO-48] Resync budget exhausted waiting for handshake.");
      return false;
    }
    Serial.read();
  }
  if (!haveHandshake) {
    Serial.println("[PRO-48] Timeout waiting for handshake.");
    return false;
  }

  // Step 2: READY (9B): tag + deviceId[4] + epoch_be4[4]
  Serial.print("[PRO-48] Sending READY epoch "); Serial.println(stagedEpoch);
  Serial.write(SHALLOT_MSG_READY);
  Serial.write(deviceId, sizeof(deviceId));
  {
    uint8_t epochBe[4];
    shallot_put_be32(epochBe, stagedEpoch);
    Serial.write(epochBe, sizeof(epochBe));
  }
  Serial.flush();

  // Phase 2: tag-anchored scan for KEY_DATA (27B), identity challenges inline.
  deadline = millis() + TIMEOUT_MS;
  resyncSkips = 0;
  while ((int32_t)(millis() - deadline) < 0) {
    if (!Serial.available()) { delay(1); continue; }
    uint8_t peek = (uint8_t)Serial.peek();
    if (peek == SHALLOT_MSG_ID_CHALLENGE) {
      if (Serial.available() >= SHALLOT_ID_CHALLENGE_FRAME_LEN) {
        handleIdentityChallenge();
        deadline = millis() + TIMEOUT_MS;
      } else {
        delay(1);
      }
      continue;
    }
    if (peek == SHALLOT_MSG_KEY_DATA) {
      if (Serial.available() < SHALLOT_KD_KEY_DATA_LEN) { delay(1); continue; }
      uint8_t frame[SHALLOT_KD_KEY_DATA_LEN];
      for (uint8_t i = 0; i < SHALLOT_KD_KEY_DATA_LEN; i++) frame[i] = (uint8_t)Serial.read();
      if (frame[1] != SHALLOT_AES_KEY_SIZE) {
        Serial.println("[PRO-48] Bad key-data length; resyncing.");
        continue;
      }
      uint32_t receivedEpoch = shallot_get_be32(&frame[22]);
      uint8_t receivedSeq = frame[26];
      if (receivedEpoch != stagedEpoch || receivedSeq != stagedSeq) {
        Serial.println("[PRO-48] Key-data from another round; dropped.");
        continue;
      }
      uint32_t receivedCrc = shallot_get_be32(&frame[18]);
      if (receivedCrc != crc32(&frame[2], SHALLOT_AES_KEY_SIZE)) {
        Serial.println("[PRO-48] CRC mismatch; waiting for retry.");
        Serial.write(SHALLOT_MSG_ERROR);
        continue;
      }
      if (!shallot_key_looks_valid(&frame[2])) {
        Serial.println("[PRO-48] Refusing degenerate key (fail-closed).");
        Serial.write(SHALLOT_MSG_ERROR);
        continue;
      }
      Serial.println("[PRO-48] CRC verified OK.");

      memcpy(pendingKey, &frame[2], SHALLOT_AES_KEY_SIZE);
      pendingEpoch = stagedEpoch;
      pendingSeq = stagedSeq;
      pendingValid = true;
      pendingDeadlineMs = millis() + 600000;

      uint8_t fullHash[SHALLOT_SHA256_SIZE];
      sha256(pendingKey, SHALLOT_AES_KEY_SIZE, fullHash);
      uint8_t keyHash[SHALLOT_KEY_HASH_SIZE];
      memcpy(keyHash, fullHash, SHALLOT_KEY_HASH_SIZE);
      memset(fullHash, 0, sizeof(fullHash));

      Serial.write(SHALLOT_MSG_STORED);
      Serial.write(keyHash, SHALLOT_KEY_HASH_SIZE);
      {
        uint8_t epochBe[4];
        shallot_put_be32(epochBe, pendingEpoch);
        Serial.write(epochBe, sizeof(epochBe));
      }
      Serial.flush();

      Serial.print("[PRO-48] Pending key stored epoch "); Serial.print(pendingEpoch); Serial.print(" hash ");
      for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
      Serial.println();
      return true;
    }
    if (resyncSkips++ >= SHALLOT_KD_MAX_RESYNC_SKIPS) {
      Serial.println("[PRO-48] Resync budget exhausted waiting for key data.");
      return false;
    }
    Serial.read();
  }
  Serial.println("[PRO-48] Timeout waiting for key data.");
  return false;
}


// API for other components (PRO-50, PRO-57 will use these)
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
    Serial.println("[PRO-48] Commit failed: no pending or epoch mismatch");
    return false;
  }
  if (millis() > pendingDeadlineMs) {
    Serial.println("[PRO-48] Commit failed: deadline expired");
    secureWipePending();
    return false;
  }
  memcpy(aesKey, pendingKey, AES_KEY_SIZE);
  activeEpoch = pendingEpoch;
  keyStored = true;
  Serial.print("[PRO-48] Committed epoch "); Serial.println(activeEpoch);
  return true;
}

static void sendCommitAck() {
  uint8_t fullHash[SHALLOT_SHA256_SIZE];
  sha256(aesKey, SHALLOT_AES_KEY_SIZE, fullHash);
  uint8_t keyHash[SHALLOT_KEY_HASH_SIZE];
  memcpy(keyHash, fullHash, SHALLOT_KEY_HASH_SIZE);
  memset(fullHash, 0, sizeof(fullHash));

  Serial.write(SHALLOT_MSG_STORED);
  Serial.write(keyHash, SHALLOT_KEY_HASH_SIZE);
  uint8_t epochBe[4];
  shallot_put_be32(epochBe, activeEpoch);
  Serial.write(epochBe, sizeof(epochBe));
  Serial.flush();

  Serial.print("[PRO-48] COMMIT acknowledged epoch "); Serial.print(activeEpoch);
  Serial.print(" hash ");
  for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
  Serial.println();
}

void checkPendingExpiry() {
  if (pendingValid && millis() > pendingDeadlineMs) {
    Serial.println("[PRO-48] Pending expired, wiping");
    secureWipePending();
  }
}

// =============================================================
// Setup and Loop
// =============================================================

void setup() {
  Serial.begin(115200); while(!Serial) delay(10);
  // USB distribution (UART GP0/GP1 deprecated 2026-09-04)
  // Serial kept for backwards compat but not used for key

  // Status LED (Feather RP2350 has built-in NeoPixel, but use GP25 if available)
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — PAW Key Receiver (PRO-48)");
  Serial.println("Hardware: Adafruit Feather RP2350");
  Serial.println("============================================");
  Serial.println("Waiting for UNO Q key distribution...");
  Serial.println();

  if (receiveKey()) {
    Serial.println("[PRO-48] Key distribution successful.");
    digitalWrite(LED_BUILTIN, HIGH);
  } else {
    Serial.println("[PRO-48] Key distribution failed. No key stored.");
    for (int i = 0; i < 10; i++) {
      digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
      delay(200);
    }
  }
}

void loop() {
  // Serve identity challenges (0xB4) at any time.
  if (Serial.available() >= SHALLOT_ID_CHALLENGE_FRAME_LEN &&
      (uint8_t)Serial.peek() == SHALLOT_MSG_ID_CHALLENGE) {
    handleIdentityChallenge();
  }

  // COMMIT / CANCEL (6B): tag + target + epoch_be4[4]
  if (Serial.available() >= SHALLOT_KD_COMMIT_LEN) {
    uint8_t peek = (uint8_t)Serial.peek();
    if (peek == SHALLOT_MSG_COMMIT || peek == SHALLOT_MSG_CANCEL) {
      uint8_t frame[SHALLOT_KD_COMMIT_LEN];
      for (uint8_t i = 0; i < SHALLOT_KD_COMMIT_LEN; i++) frame[i] = (uint8_t)Serial.read();
      if (frame[1] == SHALLOT_TARGET_PAW) {
        uint32_t epoch = shallot_get_be32(&frame[2]);
        if (frame[0] == SHALLOT_MSG_COMMIT) {
          if (commitPending(epoch)) sendCommitAck();
        } else {
          secureWipePending();
          Serial.println("[PRO-48] Pending canceled");
        }
      }
    }
  }

  checkPendingExpiry();

  if (keyStored) {
    digitalWrite(LED_BUILTIN, (millis() / 2000) % 2);
  } else if (Serial.available() >= 2) {
    receiveKey();
  }
}
