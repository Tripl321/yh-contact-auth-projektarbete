/*
 * SHALLOT — UNO Q Key Authority Firmware (PRO-45 + PRO-46)
 * MCU side: STM32U585 via Arduino IDE + ArduinoCore-zephyr
 *
 * Architecture (three-layer model):
 *   Layer 1 (MCU/STM32U585): TRNG key generation, secure storage,
 *           UART key distribution. No MPU involvement with key material.
 *   Layer 2 (MPU/QRB2210/Linux): Orchestration UI, audit log, validation.
 *           Communicates with MCU via Bridge RPC. Never touches key material.
 *   Layer 3 (Bridge RPC): Status and confirmation messages only.
 *           Uses Arduino_RouterBridge.h (MessagePack RPC over internal socket).
 *
 * Security principles:
 *   - Key generated with hardware TRNG (analog noise entropy)
 *   - Key never leaves MCU domain until UART distribution
 *   - Key never exposed to Linux/MPU side
 *   - Distribution requires operator confirmation (physical button)
 *   - Fail-closed: if TRNG health check fails, no key is generated
 *
 * Hardware: Arduino UNO Q (Qualcomm QRB2210 + STM32U585)
 * Target devices for distribution:
 *   - Edge enforcement node: Raspberry Pi Pico 2 (RP2350A)
 *   - PAW: Adafruit Feather RP2350
 *
 * Linear: PRO-45 (key generation), PRO-46 (key distribution via UART)
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
// Phase 2 envelope (docs/12-envelope-protocol.md, spec v0.2)
// =============================================================
// Compile-time feature flag, default OFF. Enabling is allowed in the
// secured fixture only, with TEST-ONLY keys (see §9/§11: the fixture flow
// is test-only, never a production fallback).
// When enabled, the raw-key UART sender below is compiled OUT (fail-closed
// against accidental raw distribution from envelope builds).
#define ENVELOPE_PHASE2 0
#if ENVELOPE_PHASE2
#include "envelope.h"
#endif

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE       16
#define KEY_HASH_SIZE       4
#define SHA256_HASH_SIZE   32
#define DISTRIB_TIMEOUT_MS 5000
#define UART_BAUD          115200

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
#if __has_include(<zephyr/drivers/entropy.h>)
  #include <zephyr/drivers/entropy.h>
  #define HAS_ZEPHYR_ENTROPY_DRV 1
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
#elif defined(HAS_ZEPHYR_ENTROPY_DRV)
  // Preferred on-device path: the Zephyr STM32 RNG entropy driver
  // (present and initialized in this build). Raw register access is NOT
  // used: on STM32U585 hardware it faults the MCU (bench-proven 2026-09-10
  // via disassembly + deterministic wedge on first RNG touch; the KAT
  // probe never touched TRNG, which is why vetting passed).
  const struct device *dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
  if (!device_is_ready(dev)) return false;
  return entropy_get_entropy(dev, buffer, (uint16_t)length) == 0;
#else
  STM32_RNG_CR |= RNG_CR_RNGEN;

  size_t bytesGenerated = 0;
  while (bytesGenerated < length) {
    uint32_t timeout = 0xFFFF;
    while (__builtin_expect(!(STM32_RNG_SR & RNG_SR_DRDY), 1)) {
      uint32_t sr = STM32_RNG_SR;
      if (sr & (RNG_SR_CECS | RNG_SR_SECS)) {
        // BUG: toggling RNG_CR here resets the error flags but does NOT
        // clear the FIFO. Residual corrupted data may be read on the next
        // call. A full RNG disable/enable with DRDY polling is safer.
        STM32_RNG_CR &= ~RNG_CR_RNGEN;
        STM32_RNG_CR |= RNG_CR_RNGEN;
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

static bool generateKey() {
  Serial.println("[PRO-45] Starting key generation...");

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
  if (!generateSecureRandomBytes(aesKey, AES_KEY_SIZE)) {
    Serial.println("FAILED");
    Serial.println("[PRO-45] TRNG generation failed. Aborting (fail-closed).");
    secureWipeKey();
    keyState = KeyState::ERROR_STATE;
    Bridge.notify("key_authority_event", "key_generation_failed", "TRNG generation error");
    return false;
  }
  Serial.println("OK");

  computeKeyHash(aesKey, keyHash);
  keyState = KeyState::GENERATED;

  Serial.println("[PRO-45] Key generated successfully.");
  Serial.print("[PRO-45] Key fingerprint (SHA-256[:4]): ");
  printHex(keyHash, KEY_HASH_SIZE);
  Serial.println();

  Bridge.notify("key_authority_event", "key_generated", "AES-128 key generated successfully");
  return true;
}

// =============================================================
// Key Distribution Protocol (PRO-46)
// =============================================================
//
// Transport: UART (Serial1 on UNO Q D0/D1)
//
// Protocol:
//   UNO Q -> Target:  MSG_HANDSHAKE (0xA1) + target_id (1 byte)
//   Target -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes)
//   UNO Q -> Target:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4)
//   Target -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes)
//   UNO Q verifies:   stored_hash matches keyHash

static inline bool waitForByte(uint8_t* byte, uint32_t timeoutMs) {
  uint32_t start = millis();
  do {
    if (Serial1.available()) { *byte = Serial1.read(); return true; }
  } while (millis() - start < timeoutMs);
  return false;
}

static inline bool waitForBytes(uint8_t* buffer, size_t count, uint32_t timeoutMs) {
  size_t received = 0;
  uint32_t start = millis();
  while (received < count && millis() - start < timeoutMs) {
    if (Serial1.available()) { buffer[received++] = Serial1.read(); }
  }
  return (received == count);
}

static bool distributeKey(uint8_t targetId) {
#if ENVELOPE_PHASE2
  // Raw-key sender is compiled out of envelope builds: fixture builds can
  // only move keys inside sealed envelopes (spec §11, Phase 4 gate).
  (void)targetId;
  Serial.println("[PRO-46] Raw distribution disabled in envelope builds.");
  return false;
#else
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
  Serial.println(" via UART...");

  // Step 1: Handshake (2 bytes, single write)
  Serial.print("[PRO-46] Sending handshake... ");
  uint8_t handshake[2] = { MSG_HANDSHAKE, targetId };
  Serial1.write(handshake, 2);
  Serial1.flush();

  uint8_t response;
  if (!waitForByte(&response, DISTRIB_TIMEOUT_MS) || response != MSG_READY) {
    Serial.println("FAILED (no READY response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not respond");
    return false;
  }

  uint8_t deviceId[4];
  if (!waitForBytes(deviceId, 4, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no device ID)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not send device ID");
    return false;
  }
  Serial.print("OK (device: ");
  printHex(deviceId, 4);
  Serial.println(")");

  // Step 2: Send key + CRC32 in a single batched write (22 bytes)
  // Format: MSG_KEY_DATA(1) + key_len(1) + key(16) + crc32(4) = 22 bytes
  Serial.print("[PRO-46] Sending key data... ");
  uint8_t keyPacket[22];
  keyPacket[0] = MSG_KEY_DATA;
  keyPacket[1] = (uint8_t)AES_KEY_SIZE;
  memcpy(&keyPacket[2], aesKey, AES_KEY_SIZE);
  uint32_t crc = crc32(aesKey, AES_KEY_SIZE);
  keyPacket[18] = (uint8_t)(crc >> 24);
  keyPacket[19] = (uint8_t)(crc >> 16);
  keyPacket[20] = (uint8_t)(crc >> 8);
  keyPacket[21] = (uint8_t)(crc & 0xFF);
  Serial1.write(keyPacket, 22);
  Serial1.flush();
  Serial.println("sent");

  // Step 3: Wait for storage confirmation
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

  // Step 4: Verify stored hash (constant-time comparison)
  volatile uint8_t hashDiff = 0;
  for (int i = 0; i < KEY_HASH_SIZE; i++) {
    hashDiff |= storedHash[i] ^ keyHash[i];
  }

  if (hashDiff != 0) {
    Serial.println("FAILED (hash mismatch)");
    Serial.print("[PRO-46] Expected: ");
    printHex(keyHash, KEY_HASH_SIZE);
    Serial.print("  Got: ");
    printHex(storedHash, KEY_HASH_SIZE);
    Serial.println();
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " hash mismatch");
    return false;
  }

  Serial.println("OK (hash verified)");
  Serial.print("[PRO-46] Key successfully distributed to ");
  Serial.print(targetName);
  Serial.println(".");

  // Update state machine
  if (targetId == TARGET_PLC) {
    keyState = (keyState == KeyState::DISTRIBUTED_PAW)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PLC;
  } else {
    keyState = (keyState == KeyState::DISTRIBUTED_PLC)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PAW;
  }

  Bridge.notify("key_authority_event", "distribution_success",
               String(targetName) + " provisioned successfully");
  return true;
#endif  // !ENVELOPE_PHASE2
}

// =============================================================
// Phase 2 envelope wrap (spec v0.2 §4-§7). Fixture-only, TEST-ONLY keys.
// The MPU/Bridge sees E1/E2 hex (public fields) and VERIFY only — never
// the operational key, KEK, shared secret, or ephemeral secrets.
// =============================================================
#if ENVELOPE_PHASE2

// Fixture interlock: latched when the confirm button is held at boot
// (if present) OR when the MPU operator explicitly arms via env_fixture_arm
// (the UNO Q bench unit has no button; the RPC arm is the operable path).
// SRAM-only, reboot clears, monotonic (no disarm except reboot). Every arm
// is audit-logged via Bridge.notify. Fixture builds wrap TEST-ONLY keys,
// so a spurious arm cannot leak production material (none exists here).
static bool envFixtureMode = false;
// SRAM epoch counter, first wrap uses epoch 1 (spec §7).
static uint32_t envEpoch = 0;
// Fingerprint of the last wrapped key, for E3 confirmation (public, 4 B).
static uint8_t envLastFingerprint[KEY_HASH_SIZE];
static bool envHasWrapped = false;

// Async wrap staging (transport constraint: crypto runs on the loop
// thread, never in an RPC handler). Single session at a time; the worker
// thread only flips envReqPending, loop() owns the rest. Volatile flags
// follow the existing pendingDistributionTarget precedent.
static volatile bool envReqPending = false;
static volatile bool envResReady = false;
static bool envResConsumed = true;
// E1 assembly: 3 x 15 bytes (30 hex chars each, transport constraint 2).
static uint8_t envReqE1[ENV_E1_LEN];
static uint8_t envReqHave = 0;  // bitmask: bit i == part i received
static uint8_t envReqTarget = 0;
static uint8_t envResE2[ENV_E2_LEN];
static char envResVerify[ENV_VERIFY_LEN + 1];
static bool envResOk = false;

static inline void envLatchFixtureMode() {
  envFixtureMode = (digitalRead(CONFIRM_BUTTON_PIN) == LOW);
  if (envFixtureMode) {
    Serial.println("[ENV] TEST-ONLY fixture mode latched (button held at boot).");
  }
}

static inline int envHexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Strict hex decode: exactly outLen bytes from 2*outLen hex chars.
static bool envHexDecode(const String &hex, uint8_t *out, size_t outLen) {
  if (hex.length() != (int)(2 * outLen)) return false;
  for (size_t i = 0; i < outLen; i++) {
    int hi = envHexVal(hex.charAt(2 * i));
    int lo = envHexVal(hex.charAt(2 * i + 1));
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static String envHexEncode(const uint8_t *data, size_t len) {
  String s;
  s.reserve(2 * len + 1);
  for (size_t i = 0; i < len; i++) {
    s += HEX_CHARS[(data[i] >> 4) & 0x0F];
    s += HEX_CHARS[data[i] & 0x0F];
  }
  return s;
}

static inline void envWipe(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}

// Wrap one envelope. e1[45] in, e2[81] + verify17 out. Returns true on
// success. Operational key is fresh TRNG per wrap (TEST-ONLY fixture key).
// The device_id is PAW-asserted via E1 and bound into the AAD; the PAW
// re-checks with its true id at open, so a swapped E1 fails closed.
static bool envelopeWrap(const uint8_t e1[ENV_E1_LEN], uint8_t targetId,
                         uint8_t e2[ENV_E2_LEN], char verify17[ENV_VERIFY_LEN + 1]) {
  if (!envFixtureMode) {
    Serial.println("[ENV] Refused: not in fixture mode.");
    return false;
  }
  if (targetId != TARGET_PLC && targetId != TARGET_PAW) return false;

  uint8_t devId[4], pubP[ENV_PUB_LEN], nonceP[ENV_NONCE_P];
  if (!env_parse_e1(e1, ENV_E1_LEN, devId, pubP, nonceP)) {
    Serial.println("[ENV] Refused: malformed E1.");
    return false;
  }

  uint8_t secM[ENV_SEC_LEN], nonceM[ENV_NONCE_M];
  uint8_t opKey[AES_KEY_SIZE];
  if (!generateSecureRandomBytes(secM, sizeof(secM)) ||
      !generateSecureRandomBytes(nonceM, sizeof(nonceM)) ||
      !generateSecureRandomBytes(opKey, sizeof(opKey))) {
    Serial.println("[ENV] TRNG failed, aborting (fail-closed).");
    envWipe(secM, sizeof(secM));
    envWipe(nonceM, sizeof(nonceM));
    envWipe(opKey, sizeof(opKey));
    return false;
  }

  uint8_t shared[ENV_SEC_LEN], pubM[ENV_PUB_LEN];
  bool ok = false;
  do {
    if (!env_x25519_dh(secM, pubP, shared)) break;
    if (env_is_all_zero(shared, sizeof(shared))) {
      Serial.println("[ENV] Degenerate shared secret, aborting.");
      break;
    }
    if (!env_x25519_pub(secM, pubM)) break;
    uint32_t epoch = ++envEpoch;  // first wrap: epoch 1
    uint8_t aad[ENV_AAD_LEN], salt[ENV_SALT_LEN], kek[AES_KEY_SIZE];
    env_build_aad(targetId, devId, epoch, pubP, pubM, nonceP, nonceM, aad);
    env_kek_salt(aad, salt);
    env_derive_kek(shared, salt, kek);
    uint8_t ct[AES_KEY_SIZE], tag[ENV_TAG_LEN];
    env_seal(kek, nonceM, aad, sizeof(aad), opKey, ct, tag);
    env_encode_e2(epoch, pubM, nonceM, ct, tag, e2);
    env_verify_hex(pubP, pubM, verify17);
    computeKeyHash(opKey, envLastFingerprint);
    envHasWrapped = true;
    envWipe(ct, sizeof(ct));
    envWipe(tag, sizeof(tag));
    envWipe(kek, sizeof(kek));
    envWipe(aad, sizeof(aad));
    envWipe(salt, sizeof(salt));
    ok = true;
    Serial.print("[ENV] Wrapped TEST-ONLY key, epoch ");
    Serial.print(epoch);
    Serial.print(", VERIFY ");
    Serial.println(verify17);
    // NOTE: no Bridge.notify here. A notify interleaved with the in-flight
    // RPC response corrupts the daemon's MessagePack stream (bench-proven
    // wedge: "invalid packet, expected array", all later RPCs hang). The
    // MPU audit-logs the wrap outcome itself from the poll result.
  } while (0);

  envWipe(secM, sizeof(secM));
  envWipe(nonceM, sizeof(nonceM));
  envWipe(opKey, sizeof(opKey));
  envWipe(shared, sizeof(shared));
  envWipe(pubP, sizeof(pubP));
  return ok;
}

#endif  // ENVELOPE_PHASE2

// =============================================================
// Bridge RPC — MPU communication (status only, no key material)
// =============================================================

static void setupBridgeRPC() {
  Bridge.begin();

  Bridge.provide_safe("get_key_state", []() -> uint8_t {
    return (uint8_t)keyState;
  });

  Bridge.provide_safe("get_key_fingerprint", []() -> String {
    // Pre-allocate exact size (8 hex chars + null terminator)
    String fp;
    fp.reserve(9);
    for (int i = 0; i < KEY_HASH_SIZE; i++) {
      fp += HEX_CHARS[(keyHash[i] >> 4) & 0x0F];
      fp += HEX_CHARS[keyHash[i] & 0x0F];
    }
    return fp;
  });

  Bridge.provide_safe("request_key_generation", []() -> bool {
    return generateKey();
  });

  Bridge.provide_safe("request_key_distribution", [](uint8_t targetId) -> bool {
    Serial.print("[PRO-46] MPU requested distribution to target ");
    Serial.print(targetId);
    Serial.println(". Awaiting button press.");
    pendingDistributionTarget = targetId;
    return true;
  });

#if ENVELOPE_PHASE2
// Envelope RPCs: hex-encoded public fields only (E1 in, E2 out).
//
// TRANSPORT CONSTRAINTS (bench-proven 2026-09-10, three wedge incidents):
// 1. Worker handlers stay tiny. Every RPC that reached crypto/TRNG stack
//    depth wedged deterministically while small handlers answer instantly;
//    the identical code runs fine on the main thread (Phase 0 KAT probe
//    computed everything in setup()). So e1a/e1b/e1c/go stage only,
//    loop() runs envelopeWrap on the main thread (same pattern as
//    pendingDistributionTarget), env_wrap_poll collects. No key material
//    crosses the Bridge.
// 2. No Bridge.notify from any worker handler: a notify interleaved with
//    the in-flight RPC response corrupts the daemon's MessagePack stream
//    ("invalid packet, expected array", all later RPCs hang). The MPU
//    audit-logs outcomes from poll results instead.
// 3. String ARGS stay <=30 chars: 93-char args wedged three times while
//    <=82 always answered instantly, so the 90-hex E1 travels as three
//    30-hex parts (uint8 go assembles). Responses to ~300 chars are proven
//    fine (Phase 0 kat_run), so the 183-char poll response stays whole.
//
// e1a/e1b/e1c take 30 hex chars ("ok"/""/"busy"). env_wrap_go takes a
// uint8 target ("queued"/"busy"/""). env_wrap_poll returns "pending",
// "fail", or "ok:<e2hex>.<verify16>".
  Bridge.provide_safe("env_fixture_armed", []() -> bool {
    return envFixtureMode;
  });

  // Operator arm (audited by the MPU caller; no notify from the worker
  // thread — worker handlers stay tiny and side-effect-free apart from
  // staging). The only operable path on buttonless units.
  Bridge.provide_safe("env_fixture_arm", []() -> bool {
    envFixtureMode = true;
    Serial.println("[ENV] Fixture mode ARMED by operator RPC (TEST-ONLY).");
    return true;
  });

// Async wrap staging (constraints documented at the section header above).
// Rejects overlap with "busy" (fail-closed; one session at a time).
  // One E1 third: exactly 30 hex chars into bytes [15*i, 15*i+15).
  // Idempotent (re-sending a part overwrites it); refused while a wrap
  // is in flight or its result uncollected.
  Bridge.provide_safe("env_wrap_e1a", [](String hex) -> String {
    if (!envFixtureMode) return String("");
    if (envReqPending || !envResConsumed) return String("busy");
    if (hex.length() != 30) return String("");
    for (size_t i = 0; i < 15; i++) {
      int hi = envHexVal(hex.charAt(2 * i));
      int lo = envHexVal(hex.charAt(2 * i + 1));
      if (hi < 0 || lo < 0) return String("");
      envReqE1[i] = (uint8_t)((hi << 4) | lo);
    }
    envReqHave |= 0x01;
    return String("ok");
  });

  Bridge.provide_safe("env_wrap_e1b", [](String hex) -> String {
    if (!envFixtureMode) return String("");
    if (envReqPending || !envResConsumed) return String("busy");
    if (hex.length() != 30) return String("");
    for (size_t i = 0; i < 15; i++) {
      int hi = envHexVal(hex.charAt(2 * i));
      int lo = envHexVal(hex.charAt(2 * i + 1));
      if (hi < 0 || lo < 0) return String("");
      envReqE1[15 + i] = (uint8_t)((hi << 4) | lo);
    }
    envReqHave |= 0x02;
    return String("ok");
  });

  Bridge.provide_safe("env_wrap_e1c", [](String hex) -> String {
    if (!envFixtureMode) return String("");
    if (envReqPending || !envResConsumed) return String("busy");
    if (hex.length() != 30) return String("");
    for (size_t i = 0; i < 15; i++) {
      int hi = envHexVal(hex.charAt(2 * i));
      int lo = envHexVal(hex.charAt(2 * i + 1));
      if (hi < 0 || lo < 0) return String("");
      envReqE1[30 + i] = (uint8_t)((hi << 4) | lo);
    }
    envReqHave |= 0x04;
    return String("ok");
  });

  // Assemble + queue. Requires all three parts (bitmask 0x07); clears the
  // mask so the next session starts clean. Refuses a malformed E1 or a
  // busy pipeline. Structural check only (tiny frame); the crypto runs
  // on the loop thread.
  Bridge.provide_safe("env_wrap_go", [](uint8_t targetId) -> String {
    if (!envFixtureMode) return String("");
    if (envReqPending || !envResConsumed) return String("busy");
    if (envReqHave != 0x07) return String("");
    envReqHave = 0;
    if (targetId != TARGET_PLC && targetId != TARGET_PAW) return String("");
    uint8_t dev[4], pub[ENV_PUB_LEN], nonce[ENV_NONCE_P];
    if (!env_parse_e1(envReqE1, sizeof(envReqE1), dev, pub, nonce)) {
      Serial.println("[ENV] Refused: malformed E1.");
      return String("");
    }
    envReqTarget = targetId;
    envResConsumed = false;
    envReqPending = true;
    return String("queued");
  });

  Bridge.provide_safe("env_wrap_poll", []() -> String {
    if (!envResReady) return String("pending");
    envResReady = false;
    envResConsumed = true;
    if (!envResOk) return String("fail");
    String out("ok:");
    out += envHexEncode(envResE2, sizeof(envResE2));
    out += '.';
    out += envResVerify;
    return out;
  });

  // env_confirm compares the PAW-returned E3 hash against the last wrapped
  // key fingerprint (constant-time). Both are public fingerprints. No
  // notify from the worker thread (transport constraint above).
  Bridge.provide_safe("env_confirm", [](String hashHex) -> bool {
    if (!envHasWrapped) return false;
    uint8_t claimed[KEY_HASH_SIZE];
    if (!envHexDecode(hashHex, claimed, sizeof(claimed))) return false;
    volatile uint8_t diff = 0;
    for (int i = 0; i < KEY_HASH_SIZE; i++) diff |= claimed[i] ^ envLastFingerprint[i];
    envWipe(claimed, sizeof(claimed));
    return diff == 0;
  });
#endif  // ENVELOPE_PHASE2
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
  if (keyState != KeyState::UNINITIALIZED && keyState != KeyState::ERROR_STATE) {
    Serial.print("Key fingerprint: ");
    printHex(keyHash, KEY_HASH_SIZE);
    Serial.println();
  }
  Serial.println("Commands: g=generate  1=dist PLC  2=dist PAW  s=status");
  Serial.println("=====================================\n");
}

// =============================================================
// Setup and Loop
// =============================================================

void setup() {
  Serial.begin(UART_BAUD);
  Serial1.begin(UART_BAUD);

  pinMode(CONFIRM_BUTTON_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED_PIN, OUTPUT);

  crc32_init();
#if ENVELOPE_PHASE2
  envLatchFixtureMode();
#endif
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
  // Serial command processing
  if (Serial.available()) {
    char cmd = Serial.read();

    switch (cmd) {
      case 'g': case 'G':
        digitalWrite(STATUS_LED_PIN, HIGH);
        generateKey();
        digitalWrite(STATUS_LED_PIN, LOW);
        printStatus();
        break;

      case '1':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PAW) {
          Serial.println("\n>> Distributing to PLC. Connect UART and press button.");
          while (digitalRead(CONFIRM_BUTTON_PIN) == HIGH) delay(10);
          digitalWrite(STATUS_LED_PIN, HIGH);
          distributeKey(TARGET_PLC);
          digitalWrite(STATUS_LED_PIN, LOW);
          printStatus();
        } else {
          Serial.println("No key generated or already distributed to PLC.");
        }
        break;

      case '2':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PLC) {
          Serial.println("\n>> Distributing to PAW. Connect UART and press button.");
          while (digitalRead(CONFIRM_BUTTON_PIN) == HIGH) delay(10);
          digitalWrite(STATUS_LED_PIN, HIGH);
          distributeKey(TARGET_PAW);
          digitalWrite(STATUS_LED_PIN, LOW);
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

  // MPU-requested distribution (requires physical button press)
  if (pendingDistributionTarget != 0) {
    if (digitalRead(CONFIRM_BUTTON_PIN) == LOW) {
      digitalWrite(STATUS_LED_PIN, HIGH);
      distributeKey(pendingDistributionTarget);
      digitalWrite(STATUS_LED_PIN, LOW);
      pendingDistributionTarget = 0;
      printStatus();
    }
  }

#if ENVELOPE_PHASE2
  // Async envelope wrap on the main thread (transport constraint: the RPC
  // worker stack cannot hold crypto/TRNG depth). Handoff is interrupt-
  // guarded so the worker thread can never leave a torn request.
  if (envReqPending) {
    uint8_t e1[ENV_E1_LEN];
    uint8_t targetId;
    noInterrupts();
    memcpy(e1, envReqE1, sizeof(e1));
    targetId = envReqTarget;
    envReqPending = false;
    interrupts();
    digitalWrite(STATUS_LED_PIN, HIGH);
    char verify17[ENV_VERIFY_LEN + 1];
    envResOk = envelopeWrap(e1, targetId, envResE2, verify17);
    if (envResOk) memcpy(envResVerify, verify17, sizeof(envResVerify));
    envWipe(e1, sizeof(e1));
    envWipe(verify17, sizeof(verify17));
    digitalWrite(STATUS_LED_PIN, LOW);
    envResReady = true;
  }
#endif

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
