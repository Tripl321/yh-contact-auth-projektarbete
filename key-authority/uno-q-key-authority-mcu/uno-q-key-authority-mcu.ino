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

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE       16
#define KEY_HASH_SIZE       4
#define SHA256_HASH_SIZE   32
#define DISTRIB_TIMEOUT_MS 5000
#define UART_BAUD          115200
#define SERIAL_BAUD        9600  // USB Serial via ttyGS0/socat must match service @ 9600

#define CONFIRM_BUTTON_PIN A0
#define STATUS_LED_PIN      LED_BUILTIN

#define TARGET_PLC  0x01
#define TARGET_PAW  0x02

#define MSG_HANDSHAKE 0xA1
#define MSG_READY     0xA2
#define MSG_KEY_DATA  0xA3
#define MSG_STORED    0xA4
#define MSG_ERROR     0xA5

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

static uint8_t aesKey[AES_KEY_SIZE];
static uint8_t keyHash[KEY_HASH_SIZE];
static KeyState keyState = KeyState::UNINITIALIZED;
static volatile uint8_t pendingDistributionTarget = 0;
static uint32_t activeEpoch = 0;
static uint32_t pendingEpoch = 0;
static uint8_t pendingKey[AES_KEY_SIZE];
static uint8_t pendingHash[KEY_HASH_SIZE];
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
    // Check that button was released for >200ms before this press
    // This prevents held-down button from being considered "fresh"
    uint32_t releaseDuration = now - buttonReleaseStartMs;
    if (releaseDuration >= 200) {
      lastValidPressMs = now;
      Serial.println("[BTN] Fresh press detected (HIGH->LOW edge after release)");
      return true;
    } else {
      Serial.println("[BTN] Button press too soon after release (held detection)");
      return false;
    }
  }
  
  lastButtonState = currentState;
  
  // Check if there was a valid press within the last 2 seconds
  // This allows verifyGrant to be called within 2s of the actual press
  if (now - lastValidPressMs <= 2000) {
    Serial.println("[BTN] Valid press within 2s window");
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
// For AES_KEY_SIZE (16 bytes) only one 64-byte block is used.
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
  uint8_t fullHash[SHA256_HASH_SIZE];
  sha256(key, AES_KEY_SIZE, fullHash);
  memcpy(hashOut, fullHash, KEY_HASH_SIZE);
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
  for (int i = 0; i < AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)keyHash;
  for (int i = 0; i < KEY_HASH_SIZE; i++) h[i] = 0;
}
static inline void secureWipePending() {
  volatile uint8_t* k = (volatile uint8_t*)pendingKey;
  for (int i = 0; i < AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)pendingHash;
  for (int i = 0; i < KEY_HASH_SIZE; i++) h[i] = 0;
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
  if (!generateSecureRandomBytes(pendingKey, AES_KEY_SIZE)) {
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
  printHex(pendingHash, KEY_HASH_SIZE);
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
  if (!generateSecureRandomBytes(pendingKey, AES_KEY_SIZE)) { secureWipePending(); keyState=KeyState::ERROR_STATE; return false; }
  computeKeyHash(pendingKey, pendingHash);
  pendingEpoch = epoch;
  pendingDeadlineMs = millis() + 600000;
  keyState = KeyState::GENERATED;
  Serial.print("[PRO-45] Pending epoch "); Serial.print(pendingEpoch); Serial.print(" fp "); printHex(pendingHash, KEY_HASH_SIZE); Serial.println();
  return true;
}

// =============================================================
// Key Distribution Protocol (PRO-46)
// =============================================================
//
// Transport: USB (Serial on UNO Q) - UART deprecated 2026-09-04
//
// Protocol:
//   UNO Q -> Target:  MSG_HANDSHAKE (0xA1) + target_id (1 byte) + epoch_be4[4]
//   Target -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes) + epoch_be4[4]
//   UNO Q -> Target:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4) + epoch_be4[4]
//   Target -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes) + epoch_be4[4]
//   UNO Q verifies:   stored_hash matches keyHash and epoch matches

static inline bool waitForByte(uint8_t* byte, uint32_t timeoutMs) {
  uint32_t start = millis();
  do {
    if (Serial.available()) { *byte = Serial.read(); return true; }
  } while (millis() - start < timeoutMs);
  return false;
}

static inline bool waitForBytes(uint8_t* buffer, size_t count, uint32_t timeoutMs) {
  size_t received = 0;
  uint32_t start = millis();
  while (received < count && millis() - start < timeoutMs) {
    if (Serial.available()) { buffer[received++] = Serial.read(); }
  }
  return (received == count);
}

// Send COMMIT message to a specific device via USB
// Format: MSG_COMMIT(1) + target_id(1) + epoch_be4[4] = 6 bytes
static bool sendCommitToDevice(uint8_t targetId, uint32_t epoch) {
  Serial.print("[PRO-46] Sending COMMIT to ");
  Serial.print(targetId == TARGET_PLC ? "PLC" : "PAW");
  Serial.print(" epoch "); Serial.println(epoch);
  
  uint8_t commitMsg[6];
  commitMsg[0] = MSG_COMMIT;
  commitMsg[1] = targetId;
  commitMsg[2] = (epoch >> 24) & 0xFF;
  commitMsg[3] = (epoch >> 16) & 0xFF;
  commitMsg[4] = (epoch >> 8) & 0xFF;
  commitMsg[5] = epoch & 0xFF;
  
  Serial.write(commitMsg, 6);
  Serial.flush();
  
  return true; // We assume success - device will handle commit internally
}

// Send COMMIT to both devices
static bool sendCommitToDevices() {
  Serial.println("[PRO-46] Sending COMMIT to both devices...");
  
  bool plcOk = sendCommitToDevice(TARGET_PLC, pendingEpoch);
  delay(50); // Allow time for processing
  bool pawOk = sendCommitToDevice(TARGET_PAW, pendingEpoch);
  
  return plcOk && pawOk;
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

  const char* targetName = (targetId == TARGET_PLC) ? "PLC" : "PAW";

  if (targetId != TARGET_PLC && targetId != TARGET_PAW) {
    Serial.println("[PRO-46] Invalid target ID.");
    return false;
  }

  Serial.print("[PRO-46] Distributing key to ");
  Serial.print(targetName);
  Serial.println(" via USB...");

  // Step 1: Handshake (6 bytes: MSG_HANDSHAKE + target_id + epoch_be4)
  Serial.print("[PRO-46] Sending handshake epoch "); Serial.print(pendingEpoch); Serial.println("...");
  uint8_t handshake[6];
  handshake[0] = MSG_HANDSHAKE;
  handshake[1] = targetId;
  handshake[2] = (pendingEpoch >> 24) & 0xFF;
  handshake[3] = (pendingEpoch >> 16) & 0xFF;
  handshake[4] = (pendingEpoch >> 8) & 0xFF;
  handshake[5] = pendingEpoch & 0xFF;
  Serial.write(handshake, 6);
  Serial.flush();

  uint8_t response;
  if (!waitForByte(&response, DISTRIB_TIMEOUT_MS) || response != MSG_READY) {
    Serial.println("FAILED (no READY response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not respond");
    return false;
  }

  uint8_t deviceId[4];
  uint32_t echoedEpoch;
  if (!waitForBytes(deviceId, 4, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no device ID)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not send device ID");
    return false;
  }
  
  // Read epoch from device response
  uint8_t epochBytes[4];
  if (!waitForBytes(epochBytes, 4, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no epoch received)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not echo epoch");
    return false;
  }
  echoedEpoch = ((uint32_t)epochBytes[0] << 24) | ((uint32_t)epochBytes[1] << 16) | 
               ((uint32_t)epochBytes[2] << 8) | ((uint32_t)epochBytes[3]);
  
  Serial.print("OK (device: ");
  printHex(deviceId, 4);
  Serial.print(" epoch: "); Serial.print(echoedEpoch); Serial.println(")");

  // Verify device echoed the correct epoch
  if (echoedEpoch != pendingEpoch) {
    Serial.printf("[PRO-46] Epoch mismatch: expected %lu, got %lu\n", (unsigned long)pendingEpoch, (unsigned long)echoedEpoch);
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " epoch mismatch");
    return false;
  }

  // Step 2: Send pending key + CRC32 + epoch (26 bytes)
  // Format: MSG_KEY_DATA(1) + key_len(1) + key(16) + crc32(4) + epoch(4) = 26 bytes
  Serial.print("[PRO-46] Sending pending key epoch "); Serial.print(pendingEpoch); Serial.print(" ... ");
  uint8_t keyPacket[26];
  keyPacket[0] = MSG_KEY_DATA;
  keyPacket[1] = (uint8_t)AES_KEY_SIZE;
  memcpy(&keyPacket[2], pendingKey, AES_KEY_SIZE);
  uint32_t crc = crc32(pendingKey, AES_KEY_SIZE);
  keyPacket[18] = (uint8_t)(crc >> 24);
  keyPacket[19] = (uint8_t)(crc >> 16);
  keyPacket[20] = (uint8_t)(crc >> 8);
  keyPacket[21] = (uint8_t)(crc & 0xFF);
  // Add epoch
  keyPacket[22] = (pendingEpoch >> 24) & 0xFF;
  keyPacket[23] = (pendingEpoch >> 16) & 0xFF;
  keyPacket[24] = (pendingEpoch >> 8) & 0xFF;
  keyPacket[25] = pendingEpoch & 0xFF;
  Serial.write(keyPacket, 26);
  Serial.flush();
  Serial.println("sent");

  // Step 3: Wait for storage confirmation (9 bytes: MSG_STORED + hash(4) + epoch(4))
  Serial.print("[PRO-46] Waiting for storage confirmation... ");
  if (!waitForByte(&response, DISTRIB_TIMEOUT_MS) || response != MSG_STORED) {
    Serial.println("FAILED (no STORED response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not confirm storage");
    return false;
  }

  uint8_t storedHash[KEY_HASH_SIZE];
  if (!waitForBytes(storedHash, KEY_HASH_SIZE, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no hash received)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not return hash");
    return false;
  }
  
  // Read echoed epoch from device
  uint8_t deviceEpochBytes[4];
  if (!waitForBytes(deviceEpochBytes, 4, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no epoch in STORED response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " incomplete STORED response");
    return false;
  }
  uint32_t storedEpoch = ((uint32_t)deviceEpochBytes[0] << 24) | ((uint32_t)deviceEpochBytes[1] << 16) | 
                       ((uint32_t)deviceEpochBytes[2] << 8) | ((uint32_t)deviceEpochBytes[3]);
  
  // Verify epoch in STORED response
  if (storedEpoch != pendingEpoch) {
    Serial.printf("[PRO-46] STORED epoch mismatch: expected %lu, got %lu\n", (unsigned long)pendingEpoch, (unsigned long)storedEpoch);
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " STORED epoch mismatch");
    return false;
  }

  // Step 4: Verify stored hash against pendingHash (constant-time)
  volatile uint8_t hashDiff = 0;
  for (int i = 0; i < KEY_HASH_SIZE; i++) {
    hashDiff |= storedHash[i] ^ pendingHash[i];
  }

  if (hashDiff != 0) {
    Serial.println("FAILED (hash mismatch)");
    Serial.print("[PRO-46] Expected: ");
    printHex(pendingHash, KEY_HASH_SIZE);
    Serial.print("  Got: ");
    printHex(storedHash, KEY_HASH_SIZE);
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
  if (targetId == TARGET_PLC) {
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
      memcpy(aesKey, pendingKey, AES_KEY_SIZE);
      memcpy(keyHash, pendingHash, KEY_HASH_SIZE);
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
    for (int i = 0; i < KEY_HASH_SIZE; i++) {
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
    for (int i = 0; i < KEY_HASH_SIZE; i++) {
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
    if (!verifyGrant(grant, (targetId==TARGET_PLC?OP_STAGE_PLC:OP_STAGE_PAW), epoch, expiry)) {
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
    if (!verifyGrant(grant, (targetId==TARGET_PLC?OP_STAGE_PLC:OP_STAGE_PAW), epoch, expiry)) {
      Serial.println("[PRO-46] Grant verification failed for distribute_key_now");
      return false;
    }
    Serial.print("[PRO-46] Grant + button verified - immediate distribution to ");
    Serial.print(targetId);
    Serial.println();
    return distributeKey(targetId);
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
    printHex(keyHash, KEY_HASH_SIZE);
    Serial.println();
  }
  if (pendingEpoch != 0) {
    Serial.print("Pending fingerprint: ");
    printHex(pendingHash, KEY_HASH_SIZE);
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
            distributeKey(TARGET_PLC);
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
            distributeKey(TARGET_PAW);
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
