/*
 * SHALLOT — UNO Q Key Authority Firmware (PRO-45 + PRO-46)
 * Modified for App Lab testing: Bridge RPC enabled for key generation and distribution
 * 
 * This version allows the MPU (Linux side) to trigger key generation and distribution
 * via Bridge RPC without requiring physical button presses, for testing purposes.
 * 
 * Security Note: This modifies the fail-safe button requirement for testing.
 * Production firmware should retain the physical button requirement.
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
// Hex output helpers
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

#define STM32_RNG_BASE 0x50060800UL
#define STM32_RNG_CR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x00)))
#define STM32_RNG_SR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x04)))
#define STM32_RNG_DR   (*((volatile uint32_t*)(STM32_RNG_BASE + 0x08)))

#define RNG_CR_RNGEN (1UL << 0)
#define RNG_SR_DRDY  (1UL << 0)
#define RNG_SR_CECS  (1UL << 1)
#define RNG_SR_SECS  (1UL << 2)

// For App Lab testing, we use Zephyr's secure random if available
#if __has_include(<zephyr/random/random.h>)
  #include <zephyr/random/random.h>
  #define HAS_ZEPHYR_CSRAND 1
#endif

// Check if hardware TRNG is configured
#if defined(CONFIG_HARDWARE_DEVICE_CS_GENERATOR) && !defined(CONFIG_TEST_RANDOM_GENERATOR)
  #define USE_ZEPHYR_CSRAND 1
#else
  #define USE_ZEPHYR_CSRAND 0
#endif

static bool generateSecureRandomBytes(uint8_t* buffer, size_t length) {
#if USE_ZEPHYR_CSRAND
  return (sys_csrand_get(buffer, length) == 0);
#else
  // Fallback: Direct register access for STM32U585 RNG
  STM32_RNG_CR |= RNG_CR_RNGEN;

  size_t bytesGenerated = 0;
  while (bytesGenerated < length) {
    uint32_t timeout = 0xFFFF;
    while (__builtin_expect(!(STM32_RNG_SR & RNG_SR_DRDY), 1)) {
      uint32_t sr = STM32_RNG_SR;
      if (sr & (RNG_SR_CECS | RNG_SR_SECS)) {
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
    if (!allZero && !allOnes && !allSame) break;
  }

  return !(allZero || allOnes || allSame);
}

// =============================================================
// SHA-256 (stack-only implementation from original)
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

static void sha256(const uint8_t* data, size_t len, uint8_t* hash) {
  uint32_t h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  #define SHA256_MAX_BLOCK 128
  uint8_t msg[SHA256_MAX_BLOCK];
  size_t paddedLen = ((len + 9 + 63) / 64) * 64;
  if (paddedLen > SHA256_MAX_BLOCK) return;

  memset(msg, 0, paddedLen);
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
      w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
      uint32_t t1 = hh + EP1(e) + CH(e, f, g) + sha256_k[i] + w[i];
      uint32_t t2 = EP0(a) + MAJ(a, b, c);
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
}

static inline void computeKeyHash(const uint8_t* key, uint8_t* hashOut) {
  uint8_t fullHash[SHA256_HASH_SIZE];
  sha256(key, AES_KEY_SIZE, fullHash);
  memcpy(hashOut, fullHash, KEY_HASH_SIZE);
}

// =============================================================
// CRC32
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
  if (keyState != KeyState::GENERATED &&
      keyState != KeyState::DISTRIBUTED_PLC &&
      keyState != KeyState::DISTRIBUTED_PAW) {
    Serial.println("[PRO-46] No key available for distribution.");
    Bridge.notify("key_authority_event", "distribution_failed", "No key available");
    return false;
  }

  const char* targetName = (targetId == TARGET_PLC) ? "PLC" : "PAW";

  if (targetId != TARGET_PLC && targetId != TARGET_PAW) {
    Serial.println("[PRO-46] Invalid target ID.");
    Bridge.notify("key_authority_event", "distribution_failed", "Invalid target ID");
    return false;
  }

  Serial.print("[PRO-46] Distributing key to ");
  Serial.print(targetName);
  Serial.println(" via UART...");

  // Step 1: Handshake
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
  Serial.println(");");

  // Step 2: Send key + CRC32
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

  // Step 4: Verify stored hash
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
}

// =============================================================
// Bridge RPC — MPU communication
// =============================================================

static void setupBridgeRPC() {
  Bridge.begin();

  // Original RPC methods
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

  Bridge.provide_safe("request_key_generation", []() -> bool {
    return generateKey();
  });

  // NEW: Direct distribution methods for App Lab (bypass button requirement)
  Bridge.provide_safe("distribute_key_to_plc", []() -> bool {
    Serial.println("[APP LAB] MPU requested direct PLC distribution");
    return distributeKey(TARGET_PLC);
  });

  Bridge.provide_safe("distribute_key_to_paw", []() -> bool {
    Serial.println("[APP LAB] MPU requested direct PAW distribution");
    return distributeKey(TARGET_PAW);
  });

  // NEW: Combined method to generate and distribute to both
  Bridge.provide_safe("generate_and_distribute_all", []() -> String {
    if (!generateKey()) {
      return "{" + String("status") + ":\"failed\",\"error\":\"Key generation failed\"}";
    }
    
    bool plcSuccess = distributeKey(TARGET_PLC);
    bool pawSuccess = distributeKey(TARGET_PAW);
    
    String result = "{";
    result += "\"status\":\"partial\"";
    result += ",\"generated\":true";
    result += ",\"plc_success\":" + String(plcSuccess ? "true" : "false");
    result += ",\"paw_success\":" + String(pawSuccess ? "true" : "false");
    result += ",\"fingerprint\":\"" + Bridge.call_safe("get_key_fingerprint") + "\"";
    result += "}";
    
    return result;
  });

  // Existing pending distribution (still requires button press)
  Bridge.provide_safe("request_key_distribution", [](uint8_t targetId) -> bool {
    Serial.print("[PRO-46] MPU requested distribution to target ");
    Serial.print(targetId);
    Serial.println(". Awaiting button press.");
    pendingDistributionTarget = targetId;
    return true;
  });
}

// =============================================================
// Status Helpers
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
  Serial.println("Bridge RPC: get_key_state, get_key_fingerprint, request_key_generation");
  Serial.println("            distribute_key_to_plc, distribute_key_to_paw, generate_and_distribute_all");
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
  setupBridgeRPC();

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — UNO Q Key Authority (PRO-45/PRO-46)");
  Serial.println("MCU: STM32U585 | TRNG: Hardware");
  Serial.println("App Lab Enabled: Bridge RPC with direct distribution");
  Serial.println("============================================");
  Serial.println();

  printStatus();
}

void loop() {
  // Serial command processing for debugging
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

  // MPU-requested distribution (requires physical button press - original behavior)
  if (pendingDistributionTarget != 0) {
    if (digitalRead(CONFIRM_BUTTON_PIN) == LOW) {
      digitalWrite(STATUS_LED_PIN, HIGH);
      distributeKey(pendingDistributionTarget);
      digitalWrite(STATUS_LED_PIN, LOW);
      pendingDistributionTarget = 0;
      printStatus();
    }
  }

  // LED heartbeat with timer debounce
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

  delay(10);
}