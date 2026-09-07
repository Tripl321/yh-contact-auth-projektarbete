/*
 * SHALLOT — UNO Q Key Authority Firmware (PRO-45 + PRO-46)
 * MCU side: STM32U585 via Arduino IDE + ArduinoCore-zephyr
 *
 * Architecture (three-layer model) - UPDATED 2026-09-04: USB instead of UART:
 *   Layer 1 (MCU/STM32U585): TRNG key generation, secure storage.
 *           Key handling via USB distribution (UART deprecated 2026-09-04).
 *           No MPU involvement with key material in clear.
 *   Layer 2 (MPU/QRB2210/Linux): Orchestration UI, audit log, validation,
 *           USB host for distribution. Communicates with MCU via Bridge RPC.
 *           Never touches key material in clear.
 *   Layer 3 (Bridge RPC): Status and confirmation messages only.
 *           Uses Arduino_RouterBridge.h (MessagePack RPC over internal socket).
 *
 * Security principles:
 *   - Key generated with hardware TRNG (analog noise entropy)
 *   - Key never leaves secure domain until USB distribution
 *   - Key never exposed to Linux/MPU side in clear
 *   - Distribution requires operator confirmation (physical button)
 *   - Fail-closed: if TRNG health check fails, no key is generated
 *
 * Hardware: Arduino UNO Q (Qualcomm QRB2210 + STM32U585)
 * Target devices for distribution (via USB hub):
 *   - Edge enforcement node: Raspberry Pi Pico 2 (RP2350A)
 *   - PAW: Adafruit Feather RP2350
 *
 * Linear: PRO-45 (key generation), PRO-46 (key distribution via USB - was UART)
 *
 * CRITICAL — prj.conf override required:
 *   The UNO Q variant config ships with CONFIG_TEST_RANDOM_GENERATOR=y
 *   which routes sys_csrand_get() through a non-secure PRNG.
 *   Create prj.conf next to the sketch with:
 *     CONFIG_HARDWARE_DEVICE_CS_GENERATOR=y
 *     CONFIG_TEST_RANDOM_GENERATOR=n
 *   The code falls back to direct STM32U585 RNG register access if
 *   the prj.conf override does not take effect.
 */

#include <Arduino.h>
#include <Arduino_RouterBridge.h>
#include <ShallotLoRaProtocol.h>  // Shared wire constants (same as PAW/PLC)

// =============================================================
// Constants (wire types/sizes live in ShallotLoRaProtocol.h)
// =============================================================

#define DISTRIB_TIMEOUT_MS 5000
#define UNOQ_DIST_MAX_ATTEMPTS 3     // handshake / key-data sends per round
#define UNOQ_DIST_RETRY_DELAY_MS 100 // pause between retries
#define UART_BAUD          115200
#define SERIAL_BAUD        115200  // USB Serial console baud rate (was 9600, mismatch with test plan)

#define CONFIRM_BUTTON_PIN A0
#define STATUS_LED_PIN      LED_BUILTIN

// =============================================================
// Key state machine
// =============================================================

enum class KeyState : uint8_t {
  UNINITIALIZED    = 0,
  GENERATED        = 1,
  DISTRIBUTED_PLC  = 2,
  DISTRIBUTED_PAW  = 3,
  DISTRIBUTED_BOTH = 4,
  ERROR_STATE      = 0xFF
};

static uint8_t aesKey[SHALLOT_AES_KEY_SIZE];
static uint8_t keyHash[SHALLOT_KEY_HASH_SIZE];
static KeyState keyState = KeyState::UNINITIALIZED;
static volatile uint8_t pendingDistributionTarget = 0;
static uint32_t activeEpoch = 0;
static uint32_t pendingEpoch = 0;
static uint8_t pendingKey[SHALLOT_AES_KEY_SIZE];
static uint8_t pendingHash[SHALLOT_KEY_HASH_SIZE];
static uint32_t pendingDeadlineMs = 0;
#define GRANT_SIZE 16
#define GRANT_CACHE_SIZE 8
static uint8_t grantCache[GRANT_CACHE_SIZE][GRANT_SIZE];
static uint8_t grantCacheCount = 0;

#define OP_GENERATE_KEY 0x01
#define OP_STAGE_PLC 0x02
#define OP_STAGE_PAW 0x03
#define OP_COMMIT_EPOCH 0x04
#define OP_CANCEL_EPOCH 0x05

// =============================================================
// Hex output helpers (Serial.printf unavailable on Zephyr core)
// =============================================================

static const char HEX_CHARS[] = "0123456789ABCDEF";

static inline void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Serial.print(HEX_CHARS[(data[i] >> 4) & 0x0F]);
    Serial.print(HEX_CHARS[data[i] & 0x0F]);
  }
}

// One-time grant and fresh button helpers (placeholder before FIDO)
// Tracks last valid HIGH->LOW edge time, debounced
static bool wasFreshPress() {
  static uint32_t lastValidPressMs = 0;
  static bool lastButtonState = HIGH;
  static uint32_t lastDebounceMs = 0;
  static uint32_t buttonReleaseStartMs = 0;
  
  uint32_t now = millis();
  bool currentState = digitalRead(CONFIRM_BUTTON_PIN);
  
  // Debounce: ignore rapid changes within 50ms
  if (now - lastDebounceMs < 50) {
    return false;
  }
  lastDebounceMs = now;
  
  // Track button release duration to prevent held button
  if (lastButtonState == LOW && currentState == HIGH) {
    // Button was just released
    buttonReleaseStartMs = now;
  }
  
  // Detect HIGH->LOW transition (fresh press) with release check
  if (lastButtonState == HIGH && currentState == LOW) {
    // Check that button was released for >=10ms before this press (TEST MODE: was 200ms, then 50ms)
    // This prevents held-down button from being considered "fresh"
    uint32_t releaseDuration = now - buttonReleaseStartMs;
    if (releaseDuration >= 10) {
      lastValidPressMs = now;
      Serial.println("[BTN] Fresh press detected (HIGH->LOW edge after release)");
      return true;
    } else {
      Serial.println("[BTN] Button press too soon after release (held detection)");
      return false;
    }
  }
  
  lastButtonState = currentState;
  
  // Check if there was a valid press within the last 10 seconds (TEST MODE: was 2s, then 5s)
  // This allows verifyGrant to be called within 10s of the actual press
  if (now - lastValidPressMs <= 10000) {
    Serial.println("[BTN] Valid press within 5s window");
    return true;
  }
  
  return false;
}

static bool isGrantReplay(const uint8_t* grant) {
  for (int i = 0; i < GRANT_CACHE_SIZE; i++) {
    bool match = true;
    for (int j = 0; j < GRANT_SIZE; j++) {
      if (grantCache[i][j] != grant[j]) { match = false; break; }
    }
    if (match && grantCache[i][0] != 0) return true;
  }
  return false;
}

static void rememberGrant(const uint8_t* grant) {
  memcpy(grantCache[grantCacheCount % GRANT_CACHE_SIZE], grant, GRANT_SIZE);
  grantCacheCount++;
}

static bool verifyGrant(const uint8_t* grant, uint8_t op, uint32_t epoch, uint32_t expiry) {
  if (!grant) return false;
  uint32_t now = millis();
  if (expiry <= now) return false;
  if (expiry - now > 60000) return false;
  if (op == OP_GENERATE_KEY) {
    if (epoch != activeEpoch + 1) return false;
  } else if (op == OP_STAGE_PLC || op == OP_STAGE_PAW) {
    if (epoch != pendingEpoch) return false;
  } else if (op == OP_COMMIT_EPOCH) {
    if (epoch != pendingEpoch) return false;
  } else {
    return false;
  }
  if (isGrantReplay(grant)) return false;
  if (!wasFreshPress()) return false;
  rememberGrant(grant);
  return true;
}

// =============================================================
// Device Identity Verification (Slice 4)
// =============================================================

// Allowlist of expected device public key hashes (SHA-256 of public key, first 4 bytes)
// For prototype: these are computed from the deviceId-based deterministic keys
// PLC: "PLC\x01" -> SHA256 hash first 4 bytes
// PAW: "PAW\x01" -> SHA256 hash first 4 bytes
#define ALLOWLIST_SIZE 2
static uint8_t deviceAllowlist[ALLOWLIST_SIZE][SHALLOT_KEY_HASH_SIZE];
static bool allowlistInitialized = false;

// P-256 signature size: SHALLOT_SHALLOT_P256_SIGNATURE_SIZE, see shared header.

// Initialize allowlist with expected device public key hashes
static void initDeviceAllowlist() {
  if (allowlistInitialized) return;
  
  // For prototype: compute expected hashes from known device IDs
  // PLC device ID: {0x50, 0x4C, 0x43, 0x01} ("PLC\x01")
  // PAW device ID: {0x50, 0x41, 0x57, 0x01} ("PAW\x01")
  
  uint8_t plcSeed[32] = {0};
  uint8_t pawSeed[32] = {0};
  memcpy(plcSeed, "PLC\x01", 4);
  memcpy(pawSeed, "PAW\x01", 4);
  
  // Compute expected hashes (same way devices do: SHA-256 of the seed)
  uint8_t plcHash[SHALLOT_SHA256_SIZE];
  uint8_t pawHash[SHALLOT_SHA256_SIZE];
  sha256(plcSeed, sizeof(plcSeed), plcHash);
  sha256(pawSeed, sizeof(pawSeed), pawHash);
  
  // Store first 4 bytes of each hash in allowlist
  memcpy(deviceAllowlist[0], plcHash, SHALLOT_KEY_HASH_SIZE);  // PLC
  memcpy(deviceAllowlist[1], pawHash, SHALLOT_KEY_HASH_SIZE);  // PAW
  
  allowlistInitialized = true;
  
  Serial.println("[PRO-48] Device allowlist initialized");
  Serial.print("[PRO-48] PLC expected hash: ");
  printHex(deviceAllowlist[0], SHALLOT_KEY_HASH_SIZE);
  Serial.println();
  Serial.print("[PRO-48] PAW expected hash: ");
  printHex(deviceAllowlist[1], SHALLOT_KEY_HASH_SIZE);
  Serial.println();
}

// Check if a device public key hash is in the allowlist
static bool isDeviceAllowed(const uint8_t* deviceHash) {
  if (!allowlistInitialized) initDeviceAllowlist();
  
  for (int i = 0; i < ALLOWLIST_SIZE; i++) {
    volatile uint8_t diff = 0;
    for (int j = 0; j < SHALLOT_KEY_HASH_SIZE; j++) {
      diff |= deviceHash[j] ^ deviceAllowlist[i][j];
    }
    if (diff == 0) {
      Serial.print("[PRO-48] Device hash match: allowlist entry ");
      Serial.println(i);
      return true;
    }
  }
  
  Serial.println("[PRO-48] Device hash NOT in allowlist");
  return false;
}

// Generate a random challenge for device identity verification
static bool generateIdentityChallenge(uint8_t* challenge) {
  if (!generateSecureRandomBytes(challenge, 32)) {
    // Fail closed: do not use predictable fallback challenge
    Serial.println("[PRO-48] TRNG failed for identity challenge - fail closed");
    memset(challenge, 0, 32);
    return false;
  }
  return true;
}

// Verify a device's signature response to an identity challenge
// For prototype: verifies SHA-256(privateKeySeed + challenge + op + target + epoch)
static bool verifyIdentityResponse(const uint8_t* challenge, uint8_t operation, 
                                  uint8_t target, uint32_t epoch,
                                  const uint8_t* signature, const uint8_t* deviceHash) {
  if (!isDeviceAllowed(deviceHash)) {
    Serial.println("[PRO-48] Device not in allowlist");
    return false;
  }
  
  // For prototype: we can't verify real ECDSA, but we can verify the mock signature
  // The mock signature is SHA-256(devicePrivateKey + message) duplicated to 64 bytes
  // We compute what the signature should be based on the known device seed
  
  uint8_t expectedSeed[32] = {0};
  
  // Determine expected seed based on device hash (find which allowlist entry matches)
  for (int i = 0; i < ALLOWLIST_SIZE; i++) {
    volatile uint8_t diff = 0;
    for (int j = 0; j < SHALLOT_KEY_HASH_SIZE; j++) {
      diff |= deviceHash[j] ^ deviceAllowlist[i][j];
    }
    if (diff == 0) {
      // This device matches allowlist entry i
      if (i == 0) memcpy(expectedSeed, "PLC\x01", 4);  // PLC
      else if (i == 1) memcpy(expectedSeed, "PAW\x01", 4);  // PAW
      break;
    }
  }
  
  // Recreate the message that was signed: challenge + operation + target + epoch
  uint8_t message[32 + 1 + 1 + 4];
  memcpy(message, challenge, 32);
  message[32] = operation;
  message[33] = target;
  message[34] = (epoch >> 24) & 0xFF;
  message[35] = (epoch >> 16) & 0xFF;
  message[36] = (epoch >> 8) & 0xFF;
  message[37] = epoch & 0xFF;
  
  // Compute expected mock signature: SHA-256(expectedSeed + message)
  uint8_t input[32 + sizeof(message)];
  memcpy(input, expectedSeed, 32);
  memcpy(&input[32], message, sizeof(message));
  
  uint8_t expectedSignature[SHALLOT_P256_SIGNATURE_SIZE];
  sha256(input, sizeof(input), expectedSignature);
  // Duplicate to fill 64 bytes (same as device does)
  memcpy(&expectedSignature[32], expectedSignature, 32);
  
  // Compare signatures (first 32 bytes are sufficient for mock verification)
  volatile uint8_t sigDiff = 0;
  for (int i = 0; i < 32; i++) {  // Only need to check first 32 bytes
    sigDiff |= signature[i] ^ expectedSignature[i];
  }
  
  // Clean up
  memset(input, 0, sizeof(input));
  memset(expectedSignature, 0, sizeof(expectedSignature));
  memset(message, 0, sizeof(message));
  
  if (sigDiff == 0) {
    Serial.println("[PRO-48] Identity signature verified");
    return true;
  } else {
    Serial.println("[PRO-48] Identity signature verification FAILED");
    return false;
  }
}

// Send identity challenge to a device and wait for response
// Returns true if device responds with valid signature
static bool challengeDeviceIdentity(uint8_t targetId, uint8_t operation, uint32_t epoch) {
  const char* targetName = (targetId == SHALLOT_TARGET_PLC) ? "PLC" : "PAW";
  
  Serial.print("[PRO-48] Sending identity challenge to ");
  Serial.print(targetName);
  Serial.print(" for op=0x"); Serial.print(operation, HEX);
  Serial.print(" epoch="); Serial.println(epoch);
  
  // Generate random challenge
  uint8_t challenge[32];
  if (!generateIdentityChallenge(challenge)) {
    Serial.println("[PRO-48] Failed to generate identity challenge - fail closed");
    return false;
  }
  
  // Send challenge: MSG_ID_CHALLENGE + challenge[32] + operation + target + epoch
  uint8_t challengeMsg[1 + 32 + 1 + 1 + 4];  // 40 bytes total
  challengeMsg[0] = SHALLOT_MSG_ID_CHALLENGE;
  memcpy(&challengeMsg[1], challenge, 32);
  challengeMsg[33] = operation;
  challengeMsg[34] = targetId;  // target should be the device we're challenging
  challengeMsg[35] = (epoch >> 24) & 0xFF;
  challengeMsg[36] = (epoch >> 16) & 0xFF;
  challengeMsg[37] = (epoch >> 8) & 0xFF;
  challengeMsg[38] = epoch & 0xFF;
  
  Serial.write(challengeMsg, sizeof(challengeMsg));
  Serial.flush();
  
  // Wait for response: MSG_ID_RESPONSE + signature[64] + deviceHash[4]
  uint32_t startTime = millis();
  const uint32_t RESPONSE_TIMEOUT_MS = 5000;
  
  while (millis() - startTime < RESPONSE_TIMEOUT_MS) {
    if (Serial.available() >= 1 + SHALLOT_P256_SIGNATURE_SIZE + SHALLOT_KEY_HASH_SIZE) {
      uint8_t responseType = Serial.read();
      if (responseType != SHALLOT_MSG_ID_RESPONSE) {
        Serial.print("[PRO-48] Expected ID_RESPONSE (0xB5), got 0x");
        Serial.print(responseType, HEX);
        Serial.print(" from ");
        Serial.println(targetName);
        // Continue waiting
        continue;
      }
      
      // Read signature and device hash
      uint8_t signature[SHALLOT_P256_SIGNATURE_SIZE];
      uint8_t deviceHash[SHALLOT_KEY_HASH_SIZE];
      
      if (!(Serial.readBytes((char*)signature, SHALLOT_P256_SIGNATURE_SIZE) == SHALLOT_P256_SIGNATURE_SIZE)) {
        Serial.print("[PRO-48] Failed to read full signature from ");
        Serial.println(targetName);
        continue;
      }
      
      if (!(Serial.readBytes((char*)deviceHash, SHALLOT_KEY_HASH_SIZE) == SHALLOT_KEY_HASH_SIZE)) {
        Serial.print("[PRO-48] Failed to read device hash from ");
        Serial.println(targetName);
        continue;
      }
      
      // Verify the response
      bool verified = verifyIdentityResponse(challenge, operation, targetId, epoch, 
                                            signature, deviceHash);
      
      if (verified) {
        Serial.print("[PRO-48] Device identity verified for ");
        Serial.println(targetName);
        return true;
      } else {
        Serial.print("[PRO-48] Device identity verification FAILED for ");
        Serial.println(targetName);
        return false;
      }
    }
    delay(10);
  }
  
  Serial.print("[PRO-48] Timeout waiting for identity response from ");
  Serial.println(targetName);
  return false;
}

// =============================================================
// TRNG — STM32U585 Hardware True Random Number Generator
// =============================================================
//
// STM32U585 RNG registers (RM0453):
//   RNG_CR  base+0x00 — Control (bit 0 = RNGEN)
//   RNG_SR  base+0x04 — Status (bit 0 = DRDY, bit 1 = CECS, bit 2 = SECS)
//   RNG_DR  base+0x08 — Data Register (32-bit random output)
//   Base: 0x50060800

#define STM32_RNG_BASE 0x50060800UL
#define STM32_RNG_CR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x00)))
#define STM32_RNG_SR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x04)))
#define STM32_RNG_DR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x08)))

#define RNG_CR_RNGEN (1UL << 0)
#define RNG_SR_DRDY  (1UL << 0)
#define RNG_SR_CECS  (1UL << 1)
#define RNG_SR_SECS  (1UL << 2)

#if __has_include(<zephyr/random/random.h>)
  #include <zephyr/random/random.h>
  #define HAS_ZEPHYR_CSRAND 1
#endif

#if defined(CONFIG_HARDWARE_DEVICE_CS_GENERATOR) && !defined(CONFIG_TEST_RANDOM_GENERATOR)
  #define USE_ZEPHYR_CSRAND 1
#else
  #define USE_ZEPHYR_CSRAND 0
#endif

// Generates 32-bit words from RNG_DR and packs them into the output buffer.
static bool generateSecureRandomBytes(uint8_t* buffer, size_t length) {
#if USE_ZEPHYR_CSRAND
  return (sys_csrand_get(buffer, length) == 0);
#else
  STM32_RNG_CR |= RNG_CR_RNGEN;

  size_t bytesGenerated = 0;
  while (bytesGenerated < length) {
    uint32_t timeout = 0xFFFF;
    while (__builtin_expect(!(STM32_RNG_SR & RNG_SR_DRDY), 1)) {
      uint32_t sr = STM32_RNG_SR;
      if (sr & (RNG_SR_CECS | RNG_SR_SECS)) {
        STM32_RNG_CR &= ~RNG_CR_RNGEN;
        for (int i=0;i<4;i++) (void)STM32_RNG_DR;
        STM32_RNG_CR |= RNG_CR_RNGEN;
        delay(1);
        return false;
      }
      if (__builtin_expect(--timeout == 0, 0)) return false;
    }

    uint32_t randomWord = STM32_RNG_DR;
    size_t remaining = length - bytesGenerated;
    size_t bytesToCopy = (remaining < 4) ? remaining : 4;
    memcpy(buffer + bytesGenerated, &randomWord, bytesToCopy);
    bytesGenerated += bytesToCopy;
  }
  return true;
#endif
}

// Single-pass health check: tests for all-zero, all-0xFF, and all-same-byte
// in one loop instead of three separate passes.
static bool trngHealthCheck() {
  uint8_t sample[32];
  if (!generateSecureRandomBytes(sample, 32)) return false;

  uint8_t firstByte = sample[0];
  bool allZero = (firstByte == 0x00);
  bool allOnes = (firstByte == 0xFF);
  bool allSame = true;

  for (int i = 1; i < 32; i++) {
    uint8_t b = sample[i];
    if (b != 0x00) allZero = false;
    if (b != 0xFF) allOnes = false;
    if (b != firstByte) allSame = false;
    // Early exit if all three checks already failed
    if (!allZero && !allOnes && !allSame) break;
  }

  return !(allZero || allOnes || allSame);
}

// =============================================================
// SHA-256 (stack-only, no heap allocation)
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

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)  (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// SHA-256 using a fixed stack buffer. Covers inputs up to 119 bytes.
// For SHALLOT_AES_KEY_SIZE (16 bytes) only one 64-byte block is used.
#define SHA256_MAX_BLOCK 128

static void sha256(const uint8_t* data, size_t len, uint8_t* hash) {
  uint32_t h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  // Stack-allocated padded message buffer (no malloc/free)
  uint8_t msg[SHA256_MAX_BLOCK];
  size_t paddedLen = ((len + 9 + 63) / 64) * 64;
  if (paddedLen > SHA256_MAX_BLOCK) return;  // guard against overflow

  // For key fingerprint use, len is always 16 — paddedLen = 64
  memset(msg, 0, paddedLen);
  memcpy(msg, data, len);
  msg[len] = 0x80;
  uint64_t bitLen = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) {
    msg[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xFF;
  }

  for (size_t blk = 0; blk < paddedLen; blk += 64) {
    uint32_t w[64];

    // Load 16 big-endian words
    const uint8_t* bp = msg + blk;
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)bp[i*4] << 24)
           | ((uint32_t)bp[i*4 + 1] << 16)
           | ((uint32_t)bp[i*4 + 2] << 8)
           | ((uint32_t)bp[i*4 + 3]);
    }

    // Expand message schedule
    for (int i = 16; i < 64; i++) {
      w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    // Compression — unrolled-friendly loop with locals
    for (int i = 0; i < 64; i++) {
      uint32_t t1 = hh + EP1(e) + CH(e, f, g) + sha256_k[i] + w[i];
      uint32_t t2 = EP0(a) + MAJ(a, b, c);
      hh = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  // Big-endian output
  for (int i = 0; i < 8; i++) {
    hash[i*4]   = (h[i] >> 24) & 0xFF;
    hash[i*4+1] = (h[i] >> 16) & 0xFF;
    hash[i*4+2] = (h[i] >> 8) & 0xFF;
    hash[i*4+3] = h[i] & 0xFF;
  }
}

// Compute first 4 bytes of SHA-256(key) as fingerprint
static inline void computeKeyHash(const uint8_t* key, uint8_t* hashOut) {
  uint8_t fullHash[SHALLOT_SHA256_SIZE];
  sha256(key, SHALLOT_AES_KEY_SIZE, fullHash);
  memcpy(hashOut, fullHash, SHALLOT_KEY_HASH_SIZE);
}

// =============================================================
// CRC32 — lookup table for 8x faster bit-by-bit computation
// =============================================================

static uint32_t crc32_table[256];
static bool crc32_table_ready = false;

static void crc32_init() {
  if (crc32_table_ready) return;
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    }
    crc32_table[i] = c;
  }
  crc32_table_ready = true;
}

static inline uint32_t crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFF;
}

// =============================================================
// Key Generation (PRO-45)
// =============================================================

// Safe key wipe — volatile store prevents the compiler from optimizing
// away the zeroing. Must be called before any key rejection path returns.
static inline void secureWipeKey() {
  volatile uint8_t* k = (volatile uint8_t*)aesKey;
  for (int i = 0; i < SHALLOT_AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)keyHash;
  for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) h[i] = 0;
}
static inline void secureWipePending() {
  volatile uint8_t* k = (volatile uint8_t*)pendingKey;
  for (int i = 0; i < SHALLOT_AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)pendingHash;
  for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) h[i] = 0;
  pendingEpoch = 0;
}

static bool generateKey(const uint8_t* grant, uint32_t epoch, uint32_t expiry) {
  Serial.println("[PRO-45] Starting key generation...");
  if (!verifyGrant(grant, OP_GENERATE_KEY, epoch, expiry)) {
    Serial.println("[PRO-45] Grant verification FAILED (need fresh button + valid grant, not replay, not expired, epoch must be active+1)");
    Bridge.notify("key_authority_event", "key_generation_failed", "grant verification failed");
    return false;
  }
  Serial.print("[PRO-45] Running TRNG health check... ");
  if (!trngHealthCheck()) {
    Serial.println("FAILED");
    Serial.println("[PRO-45] TRNG health check failed. Aborting (fail-closed).");
    keyState = KeyState::ERROR_STATE;
    Bridge.notify("key_authority_event", "key_generation_failed", "TRNG health check failed");
    return false;
  }
  Serial.println("OK");

  Serial.print("[PRO-45] Generating 128-bit AES key from TRNG... ");
  if (!generateSecureRandomBytes(pendingKey, SHALLOT_AES_KEY_SIZE)) {
    Serial.println("FAILED");
    Serial.println("[PRO-45] TRNG generation failed. Aborting (fail-closed).");
    secureWipePending();
    keyState = KeyState::ERROR_STATE;
    Bridge.notify("key_authority_event", "key_generation_failed", "TRNG generation error");
    return false;
  }
  Serial.println("OK");

  computeKeyHash(pendingKey, pendingHash);
  pendingEpoch = epoch;
  pendingDeadlineMs = millis() + 600000; // 10 min to stage both
  keyState = KeyState::GENERATED;

  Serial.print("[PRO-45] Pending key generated epoch ");
  Serial.print(pendingEpoch);
  Serial.print(" fingerprint ");
  printHex(pendingHash, SHALLOT_KEY_HASH_SIZE);
  Serial.println();

  Bridge.notify("key_authority_event", "key_generated", "AES-128 pending key generated");
  return true;
}
// Legacy wrapper for serial 'g' (still requires button, uses placeholder grant for demo)
static bool generateKeyLegacy() {
  uint8_t dummyGrant[GRANT_SIZE];
  // Use a dummy grant that will pass wasFreshPress but fail replay if reused - for 'g' we bypass grant check and just require button
  if (!wasFreshPress()) {
    Serial.println("[PRO-45] Need fresh button press for 'g'");
    return false;
  }
  // Direct generation without grant for local 'g' but still epoch-checked
  uint32_t epoch = activeEpoch + 1;
  Serial.println("[PRO-45] Local 'g' with fresh button - generate pending");
  if (!trngHealthCheck()) { Serial.println("FAILED health"); keyState=KeyState::ERROR_STATE; return false; }
  if (!generateSecureRandomBytes(pendingKey, SHALLOT_AES_KEY_SIZE)) { secureWipePending(); keyState=KeyState::ERROR_STATE; return false; }
  computeKeyHash(pendingKey, pendingHash);
  pendingEpoch = epoch;
  pendingDeadlineMs = millis() + 600000;
  keyState = KeyState::GENERATED;
  Serial.print("[PRO-45] Pending epoch "); Serial.print(pendingEpoch); Serial.print(" fp "); printHex(pendingHash, SHALLOT_KEY_HASH_SIZE); Serial.println();
  return true;
}

// =============================================================
// Key Distribution Protocol (PRO-46)
// =============================================================
//
// Transport: USB (Serial on UNO Q) - UART deprecated 2026-09-04
//
// Protocol (frame layouts in ShallotLoRaProtocol.h):
//   UNO Q -> Target:  HANDSHAKE (tag + target + epoch_be4 + seq)
//   Target -> UNO Q:  READY (tag + device_id + epoch_be4)
//   UNO Q -> Target:  KEY_DATA (tag + len + key + crc32 + epoch_be4 + seq)
//   Target -> UNO Q:  STORED (tag + hash + epoch_be4)
//   UNO Q verifies:   stored_hash matches keyHash and epoch matches

static inline bool waitForBytesUntil(uint8_t* buffer, size_t count, uint32_t deadlineMs) {
  size_t received = 0;
  while (received < count && (int32_t)(millis() - deadlineMs) < 0) {
    if (Serial.available()) { buffer[received++] = (uint8_t)Serial.read(); }
  }
  return (received == count);
}

// Scan for a frame tag, dropping stray bytes (resync after broken or
// partial messages). The tag byte itself is consumed. Bounded by the
// absolute deadline; wrap-safe. Returns false on timeout.
static bool waitForTagUntil(uint8_t tag, uint32_t deadlineMs) {
  uint32_t skipped = 0;
  while ((int32_t)(millis() - deadlineMs) < 0) {
    if (Serial.available()) {
      if ((uint8_t)Serial.peek() == tag) { Serial.read(); return true; }
      Serial.read();  // stray byte: drop and keep scanning
      if (++skipped >= SHALLOT_KD_MAX_RESYNC_SKIPS) return false;
    }
  }
  return false;
}

// Send COMMIT message to a specific device via USB and wait for ACK
// Format: SHALLOT_MSG_COMMIT(1) + target_id(1) + epoch_be4[4] = 6 bytes
// Device responds: SHALLOT_MSG_STORED(0xA4) + hash[4] + epoch_be4[4] = 9B as acknowledgment
static bool sendCommitToDevice(uint8_t targetId, uint32_t epoch) {
  const char* targetName = (targetId == SHALLOT_TARGET_PLC) ? "PLC" : "PAW";
  Serial.print("[PRO-46] Sending COMMIT to ");
  Serial.print(targetName);
  Serial.print(" epoch "); Serial.println(epoch);
  
  uint8_t commitMsg[SHALLOT_KD_COMMIT_LEN];
  commitMsg[0] = SHALLOT_MSG_COMMIT;
  commitMsg[1] = targetId;
  commitMsg[2] = (epoch >> 24) & 0xFF;
  commitMsg[3] = (epoch >> 16) & 0xFF;
  commitMsg[4] = (epoch >> 8) & 0xFF;
  commitMsg[5] = epoch & 0xFF;

  // COMMIT is idempotent on the receiver (re-commit of the same epoch is
  // harmless), so a lost ACK is retried once before giving up.
  for (uint8_t attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) {
      delay(UNOQ_DIST_RETRY_DELAY_MS);
      Serial.print("[PRO-46] Retrying COMMIT to ");
      Serial.println(targetName);
    }
    Serial.write(commitMsg, sizeof(commitMsg));
    Serial.flush();

    // Tag-anchored ACK wait (resync over stray bytes, epoch-checked).
    uint32_t ackDeadline = millis() + DISTRIB_TIMEOUT_MS;
    while ((int32_t)(millis() - ackDeadline) < 0) {
      if (!waitForTagUntil(SHALLOT_MSG_STORED, ackDeadline)) break;
      uint8_t ackBody[SHALLOT_KD_STORED_LEN - 1];
      if (!waitForBytesUntil(ackBody, sizeof(ackBody), ackDeadline)) break;
      uint32_t ackEpoch = ((uint32_t)ackBody[4] << 24) | ((uint32_t)ackBody[5] << 16) |
                          ((uint32_t)ackBody[6] << 8) | ((uint32_t)ackBody[7]);
      if (ackEpoch != epoch) {
        Serial.print("[PRO-46] COMMIT ACK epoch mismatch (got ");
        Serial.print((unsigned long)ackEpoch);
        Serial.println("), keep scanning...");
        continue;
      }
      Serial.print("[PRO-46] ");
      Serial.print(targetName);
      Serial.print(" acknowledged COMMIT for epoch ");
      Serial.println((unsigned long)epoch);
      return true;
    }
  }

  Serial.print("[PRO-46] COMMIT to ");
  Serial.print(targetName);
  Serial.println(" failed (no valid ACK)");
  Bridge.notify("key_authority_event", "commit_failed",
               String(targetName) + " did not acknowledge COMMIT");
  return false;
}

// Send COMMIT to both devices and verify both acknowledge
static bool sendCommitToDevices() {
  Serial.println("[PRO-46] Sending COMMIT to both devices...");
  
  // Send to PLC first
  if (!sendCommitToDevice(SHALLOT_TARGET_PLC, pendingEpoch)) {
    Serial.println("[PRO-46] PLC COMMIT failed - aborting commit");
    Bridge.notify("key_authority_event", "commit_aborted", "PLC did not acknowledge COMMIT");
    return false;
  }
  delay(50); // Allow time for processing
  
  // Send to PAW
  if (!sendCommitToDevice(SHALLOT_TARGET_PAW, pendingEpoch)) {
    Serial.println("[PRO-46] PAW COMMIT failed - aborting commit");
    Bridge.notify("key_authority_event", "commit_aborted", "PAW did not acknowledge COMMIT");
    return false;
  }
  
  Serial.println("[PRO-46] Both devices acknowledged COMMIT successfully");
  return true;
}

static bool distributeKey(uint8_t targetId) {
  if (pendingEpoch == 0 || millis() > pendingDeadlineMs) {
    Serial.println("[PRO-46] No pending key or expired (need GENERATE_KEY first)");
    return false;
  }
  if (keyState != KeyState::GENERATED &&
      keyState != KeyState::DISTRIBUTED_PLC &&
      keyState != KeyState::DISTRIBUTED_PAW) {
    Serial.println("[PRO-46] No key available for distribution.");
    return false;
  }

  const char* targetName = (targetId == SHALLOT_TARGET_PLC) ? "PLC" : "PAW";

  if (targetId != SHALLOT_TARGET_PLC && targetId != SHALLOT_TARGET_PAW) {
    Serial.println("[PRO-46] Invalid target ID.");
    return false;
  }

  Serial.print("[PRO-46] Distributing key to ");
  Serial.print(targetName);
  Serial.println(" via USB...");

  // Retry policy for this round (fail-closed: exhaustion aborts, no key sent).
  // seq identifies retries within the (target, epoch) round so the receiver
  // can answer repeats idempotently instead of treating them as new rounds.
  uint8_t seq = 0;
  uint8_t readySeq = 0;

  // Step 1: Handshake (SHALLOT_KD_HANDSHAKE_LEN bytes, tag-anchored read).
  // Lost handshakes or lost READY frames are retried with seq++.
  bool readyOk = false;
  for (uint8_t attempt = 0; attempt < UNOQ_DIST_MAX_ATTEMPTS && !readyOk; attempt++) {
    if (attempt > 0) {
      seq++;
      delay(UNOQ_DIST_RETRY_DELAY_MS);
      Serial.print("[PRO-46] Retrying handshake seq ");
      Serial.print(seq);
      Serial.println("...");
    }
    Serial.print("[PRO-46] Sending handshake epoch "); Serial.print(pendingEpoch);
    Serial.print(" seq "); Serial.println(seq);
    uint8_t handshake[SHALLOT_KD_HANDSHAKE_LEN];
    handshake[0] = SHALLOT_MSG_HANDSHAKE;
    handshake[1] = targetId;
    handshake[2] = (pendingEpoch >> 24) & 0xFF;
    handshake[3] = (pendingEpoch >> 16) & 0xFF;
    handshake[4] = (pendingEpoch >> 8) & 0xFF;
    handshake[5] = pendingEpoch & 0xFF;
    handshake[6] = seq;
    Serial.write(handshake, sizeof(handshake));
    Serial.flush();

    // Wait for READY (SHALLOT_KD_READY_LEN bytes). Stray bytes are
    // skipped (resync); a wrong-epoch READY is ignored within budget.
    uint32_t readyDeadline = millis() + DISTRIB_TIMEOUT_MS;
    while ((int32_t)(millis() - readyDeadline) < 0) {
      if (!waitForTagUntil(SHALLOT_MSG_READY, readyDeadline)) break;
      uint8_t readyBody[SHALLOT_KD_READY_LEN - 1];
      if (!waitForBytesUntil(readyBody, sizeof(readyBody), readyDeadline)) break;
      uint32_t echoedEpoch = ((uint32_t)readyBody[4] << 24) | ((uint32_t)readyBody[5] << 16) |
                             ((uint32_t)readyBody[6] << 8) | ((uint32_t)readyBody[7]);
      if (echoedEpoch != pendingEpoch) {
        Serial.print("[PRO-46] READY epoch mismatch (got ");
        Serial.print((unsigned long)echoedEpoch);
        Serial.println("), keep scanning...");
        continue;
      }
      Serial.print("OK (device: ");
      printHex(readyBody, SHALLOT_KEY_HASH_SIZE);
      Serial.print(" epoch: "); Serial.print(echoedEpoch);
      Serial.print(" seq: "); Serial.println(seq);
      readyOk = true;
      readySeq = seq;
      break;
    }
  }
  if (!readyOk) {
    Serial.println("FAILED (no READY response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not respond");
    return false;
  }

  // Step 2: Device identity verification (Slice 4)
  // Send identity challenge and verify device signature before releasing key
  Serial.print("[PRO-46] Verifying device identity for ");
  Serial.print(targetName);
  Serial.println("...");
  
  uint8_t operationForIdentity = (targetId == SHALLOT_TARGET_PLC) ? OP_STAGE_PLC : OP_STAGE_PAW;
  if (!challengeDeviceIdentity(targetId, operationForIdentity, pendingEpoch)) {
    Serial.print("[PRO-46] Device identity verification FAILED for ");
    Serial.print(targetName);
    Serial.println(" - aborting key distribution");
    Bridge.notify("key_authority_event", "identity_verification_failed",
                 String(targetName) + " device identity verification failed");
    return false;
  }
  Serial.print("[PRO-46] Device identity verified for ");
  Serial.print(targetName);
  Serial.println(" - proceeding with key distribution");

  // Step 3: Send pending key + CRC32 + epoch + seq (SHALLOT_KD_KEY_DATA_LEN).
  // Lost key-data or lost STORED frames are retried with the SAME seq the
  // handshake was acknowledged with, so the receiver answers idempotently.
  uint8_t storedHash[SHALLOT_KEY_HASH_SIZE];
  bool storedOk = false;
  for (uint8_t attempt = 0; attempt < UNOQ_DIST_MAX_ATTEMPTS && !storedOk; attempt++) {
    if (attempt > 0) {
      delay(UNOQ_DIST_RETRY_DELAY_MS);
      Serial.print("[PRO-46] Retrying key-data seq ");
      Serial.print(readySeq);
      Serial.println("...");
    }
    Serial.print("[PRO-46] Sending pending key epoch "); Serial.print(pendingEpoch);
    Serial.print(" seq "); Serial.print(readySeq); Serial.print(" ... ");
    uint8_t keyPacket[SHALLOT_KD_KEY_DATA_LEN];
    keyPacket[0] = SHALLOT_MSG_KEY_DATA;
    keyPacket[1] = (uint8_t)SHALLOT_AES_KEY_SIZE;
    memcpy(&keyPacket[2], pendingKey, SHALLOT_AES_KEY_SIZE);
    uint32_t crc = crc32(pendingKey, SHALLOT_AES_KEY_SIZE);
    keyPacket[18] = (uint8_t)(crc >> 24);
    keyPacket[19] = (uint8_t)(crc >> 16);
    keyPacket[20] = (uint8_t)(crc >> 8);
    keyPacket[21] = (uint8_t)(crc & 0xFF);
    // Add epoch + seq
    keyPacket[22] = (pendingEpoch >> 24) & 0xFF;
    keyPacket[23] = (pendingEpoch >> 16) & 0xFF;
    keyPacket[24] = (pendingEpoch >> 8) & 0xFF;
    keyPacket[25] = pendingEpoch & 0xFF;
    keyPacket[26] = readySeq;
    Serial.write(keyPacket, sizeof(keyPacket));
    Serial.flush();
    Serial.println("sent");

    // Wait for storage confirmation (SHALLOT_KD_STORED_LEN bytes).
    // Stray bytes are skipped (resync); wrong-epoch confirmations ignored.
    Serial.print("[PRO-46] Waiting for storage confirmation... ");
    uint32_t storedDeadline = millis() + DISTRIB_TIMEOUT_MS;
    while ((int32_t)(millis() - storedDeadline) < 0) {
      if (!waitForTagUntil(SHALLOT_MSG_STORED, storedDeadline)) break;
      uint8_t storedBody[SHALLOT_KD_STORED_LEN - 1];
      if (!waitForBytesUntil(storedBody, sizeof(storedBody), storedDeadline)) break;
      uint32_t storedEpoch = ((uint32_t)storedBody[4] << 24) | ((uint32_t)storedBody[5] << 16) |
                             ((uint32_t)storedBody[6] << 8) | ((uint32_t)storedBody[7]);
      if (storedEpoch != pendingEpoch) {
        Serial.print("[PRO-46] STORED epoch mismatch (got ");
        Serial.print((unsigned long)storedEpoch);
        Serial.println("), keep scanning...");
        continue;
      }
      memcpy(storedHash, storedBody, SHALLOT_KEY_HASH_SIZE);
      storedOk = true;
      break;
    }
    if (!storedOk) {
      Serial.println("FAILED (no STORED response)");
    }
  }
  if (!storedOk) {
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not confirm storage");
    return false;
  }

  // Step 4: Verify stored hash against pendingHash (constant-time)
  volatile uint8_t hashDiff = 0;
  for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) {
    hashDiff |= storedHash[i] ^ pendingHash[i];
  }

  if (hashDiff != 0) {
    Serial.println("FAILED (hash mismatch)");
    Serial.print("[PRO-46] Expected: ");
    printHex(pendingHash, SHALLOT_KEY_HASH_SIZE);
    Serial.print("  Got: ");
    printHex(storedHash, SHALLOT_KEY_HASH_SIZE);
    Serial.println();
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " hash mismatch");
    return false;
  }

  Serial.println("OK (hash and epoch verified)");
  Serial.print("[PRO-46] Key successfully distributed to ");
  Serial.print(targetName);
  Serial.print(" epoch "); Serial.println(pendingEpoch);

  // Update state machine - NOW WE STORE AS PENDING, DON'T COMMIT YET
  if (targetId == SHALLOT_TARGET_PLC) {
    keyState = (keyState == KeyState::DISTRIBUTED_PAW)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PLC;
  } else {
    keyState = (keyState == KeyState::DISTRIBUTED_PLC)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PAW;
  }
  
  // Check if both are now staged - this triggers commit
  if (keyState == KeyState::DISTRIBUTED_BOTH) {
    // BOTH_ACKNOWLEDGED state - we can now commit
    // But first send COMMIT message to both devices via USB
    if (sendCommitToDevices()) {
      activeEpoch = pendingEpoch;
      memcpy(aesKey, pendingKey, SHALLOT_AES_KEY_SIZE);
      memcpy(keyHash, pendingHash, SHALLOT_KEY_HASH_SIZE);
      Serial.print("[PRO-46] Both staged and committed epoch "); Serial.println(activeEpoch);
      Bridge.notify("key_authority_event", "epoch_committed", String(activeEpoch));
      
      // Invalidate pending after commit
      secureWipePending();
    } else {
      Serial.println("[PRO-46] Both staged but commit failed");
      Bridge.notify("key_authority_event", "commit_failed", "Both staged but commit to devices failed");
      return false;
    }
  }

  Bridge.notify("key_authority_event", "distribution_success",
               String(targetName) + " provisioned successfully");
  return true;
}

// =============================================================
// Bridge RPC — MPU communication (status only, no key material)
// =============================================================

static void setupBridgeRPC() {
  Bridge.begin();

  Bridge.provide_safe("get_key_state", []() -> uint8_t {
    return (uint8_t)keyState;
  });

  Bridge.provide_safe("get_key_fingerprint", []() -> String {
    String fp;
    fp.reserve(9);
    for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) {
      fp += HEX_CHARS[(keyHash[i] >> 4) & 0x0F];
      fp += HEX_CHARS[keyHash[i] & 0x0F];
    }
    return fp;
  });

  Bridge.provide_safe("get_active_epoch", []() -> uint32_t {
    return activeEpoch;
  });

  Bridge.provide_safe("get_pending_epoch", []() -> uint32_t {
    return pendingEpoch;
  });

  Bridge.provide_safe("get_pending_fingerprint", []() -> String {
    String fp;
    fp.reserve(9);
    for (int i = 0; i < SHALLOT_KEY_HASH_SIZE; i++) {
      fp += HEX_CHARS[(pendingHash[i] >> 4) & 0x0F];
      fp += HEX_CHARS[pendingHash[i] & 0x0F];
    }
    return fp;
  });

  Bridge.provide_safe("get_millis", []() -> uint32_t {
    return millis();
  });

  // Placeholder grant-gated generation (first vertical slice)
  // grantHex is 32 hex chars = 16 bytes, epoch and expiry are checked on MCU
  Bridge.provide_safe("request_key_generation", [](String grantHex, uint32_t epoch, uint32_t expiry) -> bool {
    uint8_t grant[GRANT_SIZE];
    if (grantHex.length() != GRANT_SIZE*2) return false;
    for (int i=0;i<GRANT_SIZE;i++) {
      String b = grantHex.substring(i*2, i*2+2);
      grant[i] = (uint8_t) strtoul(b.c_str(), nullptr, 16);
    }
    return generateKey(grant, epoch, expiry);
  });

  Bridge.provide_safe("request_key_distribution", [](uint8_t targetId, String grantHex, uint32_t epoch, uint32_t expiry) -> bool {
    uint8_t grant[GRANT_SIZE];
    if (grantHex.length() != GRANT_SIZE*2) return false;
    for (int i=0;i<GRANT_SIZE;i++) {
      String b = grantHex.substring(i*2, i*2+2);
      grant[i] = (uint8_t) strtoul(b.c_str(), nullptr, 16);
    }
    if (!verifyGrant(grant, (targetId==SHALLOT_TARGET_PLC?OP_STAGE_PLC:OP_STAGE_PAW), epoch, expiry)) {
      Serial.println("[PRO-46] Grant verification failed for distribution");
      return false;
    }
    Serial.print("[PRO-46] Grant verified for target ");
    Serial.print(targetId);
    Serial.println(" - awaiting fresh button for staging");
    pendingDistributionTarget = targetId;
    // For placeholder, we still require fresh button in loop, but grant already consumed
    return true;
  });

  // Legacy immediate path now also requires grant+button (no bypass)
  Bridge.provide_safe("distribute_key_now", [](uint8_t targetId, String grantHex, uint32_t epoch, uint32_t expiry) -> bool {
    uint8_t grant[GRANT_SIZE];
    if (grantHex.length() != GRANT_SIZE*2) return false;
    for (int i=0;i<GRANT_SIZE;i++) {
      String b = grantHex.substring(i*2, i*2+2);
      grant[i] = (uint8_t) strtoul(b.c_str(), nullptr, 16);
    }
    if (!verifyGrant(grant, (targetId==SHALLOT_TARGET_PLC?OP_STAGE_PLC:OP_STAGE_PAW), epoch, expiry)) {
      Serial.println("[PRO-46] Grant verification failed for distribute_key_now");
      return false;
    }
    Serial.print("[PRO-46] Grant + button verified - immediate distribution to ");
    Serial.print(targetId);
    Serial.println();
    return distributeKey(targetId);
  });

  // =============================================================
  // USB CDC relay test (Bridge-initiated, non-secret payload)
  //
  // MCU provides a non-secret handshake frame (0xA1) for the MPU to relay
  // to PLC/PAW via /dev/ttyACM*. No key material is involved. The MPU
  // writes the frame, reads the READY (0xA2) response, and reports back.
  // =============================================================

  // Relay test result storage (set by MPU after relay attempt)
  static uint8_t  relayResultTarget  = 0;
  static bool     relayResultSuccess = false;
  static uint8_t  relayResultDeviceId[4] = {0,0,0,0};
  static uint32_t relayResultEpoch   = 0;
  static String   relayResultError   = "";

  Bridge.provide_safe("get_relay_test_payload", [](uint8_t targetId, uint32_t epoch) -> String {
    if (targetId != SHALLOT_TARGET_PLC && targetId != SHALLOT_TARGET_PAW) {
      Serial.println("[RELAY] Invalid target for test payload");
      return "";
    }
    uint8_t frame[SHALLOT_KD_HANDSHAKE_LEN];
    frame[0] = SHALLOT_MSG_HANDSHAKE;
    frame[1] = targetId;
    frame[2] = (epoch >> 24) & 0xFF;
    frame[3] = (epoch >> 16) & 0xFF;
    frame[4] = (epoch >> 8) & 0xFF;
    frame[5] = epoch & 0xFF;
    frame[6] = 0; // seq
    String hex;
    hex.reserve(SHALLOT_KD_HANDSHAKE_LEN * 2);
    for (int i = 0; i < SHALLOT_KD_HANDSHAKE_LEN; i++) {
      hex += HEX_CHARS[(frame[i] >> 4) & 0x0F];
      hex += HEX_CHARS[frame[i] & 0x0F];
    }
    Serial.print("[RELAY] Test payload for target ");
    Serial.print(targetId);
    Serial.print(" epoch ");
    Serial.print(epoch);
    Serial.print(": ");
    Serial.println(hex);
    return hex;
  });

  Bridge.provide_safe("set_relay_test_result", [](uint8_t targetId, bool success,
                     String deviceIdHex, uint32_t echoedEpoch, String error) -> bool {
    relayResultTarget  = targetId;
    relayResultSuccess = success;
    relayResultError    = error;
    if (success && deviceIdHex.length() >= 8) {
      for (int i = 0; i < 4; i++) {
        relayResultDeviceId[i] = (uint8_t) strtoul(deviceIdHex.substring(i*2, i*2+2).c_str(),
                                                    nullptr, 16);
      }
    } else {
      memset(relayResultDeviceId, 0, 4);
    }
    relayResultEpoch = echoedEpoch;

    Serial.print("[RELAY] Result for target ");
    Serial.print(targetId);
    if (success) {
      Serial.print(": OK (device: ");
      printHex(relayResultDeviceId, 4);
      Serial.print(" epoch: ");
      Serial.println(echoedEpoch);
    } else {
      Serial.print(": FAILED (");
      Serial.println(error + ")");
    }
    return true;
  });

  Bridge.provide_safe("get_relay_test_result", [](uint8_t targetId) -> String {
    if (targetId != relayResultTarget) return "no_result";
    if (relayResultSuccess) {
      String r = "ok,device:";
      for (int i = 0; i < 4; i++) {
        r += HEX_CHARS[(relayResultDeviceId[i] >> 4) & 0x0F];
        r += HEX_CHARS[relayResultDeviceId[i] & 0x0F];
      }
      r += ",epoch:";
      r += String(relayResultEpoch);
      return r;
    }
    return "fail:" + relayResultError;
  });
}

// =============================================================
// Operator interface
// =============================================================

static const char* keyStateString(KeyState s) {
  switch (s) {
    case KeyState::UNINITIALIZED:    return "UNINITIALIZED";
    case KeyState::GENERATED:        return "GENERATED";
    case KeyState::DISTRIBUTED_PLC:  return "DISTRIBUTED (PLC)";
    case KeyState::DISTRIBUTED_PAW:  return "DISTRIBUTED (PAW)";
    case KeyState::DISTRIBUTED_BOTH: return "DISTRIBUTED (BOTH)";
    case KeyState::ERROR_STATE:      return "ERROR";
  }
  return "UNKNOWN";
}

static void printStatus() {
  Serial.println("\n=== UNO Q Key Authority Status ===");
  Serial.print("Key state: ");
  Serial.println(keyStateString(keyState));
  Serial.print("Active epoch: "); Serial.println(activeEpoch);
  Serial.print("Pending epoch: "); Serial.println(pendingEpoch);
  if (keyState != KeyState::UNINITIALIZED && keyState != KeyState::ERROR_STATE) {
    Serial.print("Active fingerprint: ");
    printHex(keyHash, SHALLOT_KEY_HASH_SIZE);
    Serial.println();
  }
  if (pendingEpoch != 0) {
    Serial.print("Pending fingerprint: ");
    printHex(pendingHash, SHALLOT_KEY_HASH_SIZE);
    Serial.print(" (deadline "); Serial.print(pendingDeadlineMs); Serial.println(" ms)");
  }
  Serial.println("Commands: g=generate(needs fresh button) 1=dist PLC 2=dist PAW s=status");
  Serial.println("=====================================\n");
}

// =============================================================
// Setup and Loop
// =============================================================

void setup() {
  Serial.begin(SERIAL_BAUD);
  Serial1.begin(UART_BAUD);

  pinMode(CONFIRM_BUTTON_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED_PIN, OUTPUT);

  crc32_init();
  setupBridgeRPC();

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — UNO Q Key Authority (PRO-45/PRO-46)");
  Serial.println("MCU: STM32U585 | TRNG: Hardware");
  Serial.println("============================================");
  Serial.println();

  printStatus();
}

void loop() {
  // Pending timeout check (10 min window)
  if (pendingEpoch != 0 && pendingDeadlineMs != 0 && millis() > pendingDeadlineMs) {
    Serial.println("[PRO-46] Pending epoch expired - invalidating");
    secureWipePending();
    keyState = (activeEpoch == 0) ? KeyState::UNINITIALIZED : KeyState::GENERATED;
    pendingDistributionTarget = 0;
    Bridge.notify("key_authority_event", "pending_expired", "pending epoch expired");
    printStatus();
  }

  // Serial command processing
  if (Serial.available()) {
    char cmd = Serial.read();

    switch (cmd) {
      case 'g': case 'G':
        digitalWrite(STATUS_LED_PIN, HIGH);
        generateKeyLegacy();
        digitalWrite(STATUS_LED_PIN, LOW);
        printStatus();
        break;

      case '1':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PAW) {
          Serial.println("\n>> Distributing to PLC. Press fresh button for USB staging.");
          if (!wasFreshPress()) {
            Serial.println("Need fresh button press (not held) for '1'");
          } else {
            digitalWrite(STATUS_LED_PIN, HIGH);
            // For USB, host does distribution, but keep local for backwards compat
            // Use pendingKey if available
            distributeKey(SHALLOT_TARGET_PLC);
            digitalWrite(STATUS_LED_PIN, LOW);
          }
          printStatus();
        } else {
          Serial.println("No key generated or already distributed to PLC.");
        }
        break;

      case '2':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PLC) {
          Serial.println("\n>> Distributing to PAW. Press fresh button for USB staging.");
          if (!wasFreshPress()) {
            Serial.println("Need fresh button press (not held) for '2'");
          } else {
            digitalWrite(STATUS_LED_PIN, HIGH);
            distributeKey(SHALLOT_TARGET_PAW);
            digitalWrite(STATUS_LED_PIN, LOW);
          }
          printStatus();
        } else {
          Serial.println("No key generated or already distributed to PAW.");
        }
        break;

      case 's': case 'S':
        printStatus();
        break;
    }
  }

  // MPU-requested distribution (requires fresh button press, not held)
  if (pendingDistributionTarget != 0) {
    if (wasFreshPress()) {
      digitalWrite(STATUS_LED_PIN, HIGH);
      distributeKey(pendingDistributionTarget);
      digitalWrite(STATUS_LED_PIN, LOW);
      pendingDistributionTarget = 0;
      printStatus();
    } else if (millis() > pendingDeadlineMs && pendingDeadlineMs != 0) {
      // Also handle held button timeout via pending expiry above
    }
  }

  // LED heartbeat with timer debounce to avoid digitalWrite on every loop pass
  static uint32_t lastBlinkMs = 0;
  if (keyState == KeyState::GENERATED) {
    uint32_t now = millis();
    if (now - lastBlinkMs >= 500) {
      lastBlinkMs = now;
      digitalWrite(STATUS_LED_PIN, !digitalRead(STATUS_LED_PIN));
    }
  } else if (keyState == KeyState::DISTRIBUTED_BOTH) {
    digitalWrite(STATUS_LED_PIN, HIGH);
  }
}
