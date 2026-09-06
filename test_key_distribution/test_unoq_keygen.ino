/*
 * Test sketch for UNO Q Key Generation and Distribution
 * Modified to use USB Serial for testing instead of Serial1 UART
 * This allows testing the key generation and distribution protocol
 * without physical UART connections between devices
 */

#include <Arduino.h>

// Constants from original firmware
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

// Key state machine
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

// Hex output helpers
static const char HEX_CHARS[] = "0123456789ABCDEF";

static inline void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Serial.print(HEX_CHARS[(data[i] >> 4) & 0x0F]);
    Serial.print(HEX_CHARS[data[i] & 0x0F]);
  }
}

// Simplified TRNG for testing (uses Arduino random)
static bool generateTestRandomBytes(uint8_t* buffer, size_t length) {
  for (size_t i = 0; i < length; i++) {
    buffer[i] = random(256);
  }
  return true;
}

// SHA-256 implementation (same as original)
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

  size_t paddedLen = ((len + 9 + 63) / 64) * 64;
  uint8_t* msg = (uint8_t*)malloc(paddedLen);
  if (!msg) return;
  
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
  free(msg);
}

static inline void computeKeyHash(const uint8_t* key, uint8_t* hashOut) {
  uint8_t fullHash[SHA256_HASH_SIZE];
  sha256(key, AES_KEY_SIZE, fullHash);
  memcpy(hashOut, fullHash, KEY_HASH_SIZE);
}

// CRC32
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

// Key Generation
static inline void secureWipeKey() {
  volatile uint8_t* k = (volatile uint8_t*)aesKey;
  for (int i = 0; i < AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)keyHash;
  for (int i = 0; i < KEY_HASH_SIZE; i++) h[i] = 0;
}

static bool generateKey() {
  Serial.println("[TEST] Starting key generation...");

  Serial.print("[TEST] Generating 128-bit AES key... ");
  if (!generateTestRandomBytes(aesKey, AES_KEY_SIZE)) {
    Serial.println("FAILED");
    secureWipeKey();
    keyState = KeyState::ERROR_STATE;
    return false;
  }
  Serial.println("OK");

  computeKeyHash(aesKey, keyHash);
  keyState = KeyState::GENERATED;

  Serial.println("[TEST] Key generated successfully.");
  Serial.print("[TEST] Key fingerprint (SHA-256[:4]): ");
  printHex(keyHash, KEY_HASH_SIZE);
  Serial.println();
  Serial.print("[TEST] Full key (for testing): ");
  printHex(aesKey, AES_KEY_SIZE);
  Serial.println();

  return true;
}

// Modified distribution to use USB Serial instead of Serial1
static bool distributeKey(uint8_t targetId) {
  if (keyState != KeyState::GENERATED) {
    Serial.println("[TEST] No key available for distribution.");
    return false;
  }

  const char* targetName = (targetId == TARGET_PLC) ? "PLC" : "PAW";

  Serial.print("[TEST] Distributing key to ");
  Serial.print(targetName);
  Serial.println(" via USB Serial...");

  // Step 1: Handshake
  Serial.print("[TEST] Sending handshake... ");
  uint8_t handshake[2] = { MSG_HANDSHAKE, targetId };
  Serial.write(handshake, 2);
  Serial.flush();
  Serial.println("sent");

  // Step 2: Send key + CRC32
  Serial.print("[TEST] Sending key data... ");
  uint8_t keyPacket[22];
  keyPacket[0] = MSG_KEY_DATA;
  keyPacket[1] = (uint8_t)AES_KEY_SIZE;
  memcpy(&keyPacket[2], aesKey, AES_KEY_SIZE);
  uint32_t crc = crc32(aesKey, AES_KEY_SIZE);
  keyPacket[18] = (uint8_t)(crc >> 24);
  keyPacket[19] = (uint8_t)(crc >> 16);
  keyPacket[20] = (uint8_t)(crc >> 8);
  keyPacket[21] = (uint8_t)(crc & 0xFF);
  Serial.write(keyPacket, 22);
  Serial.flush();
  Serial.println("sent");

  Serial.print("[TEST] Key distribution packet: ");
  for (int i = 0; i < 22; i++) {
    Serial.print(HEX_CHARS[(keyPacket[i] >> 4) & 0x0F]);
    Serial.print(HEX_CHARS[keyPacket[i] & 0x0F]);
    Serial.print(" ");
  }
  Serial.println();

  // Update state machine
  if (targetId == TARGET_PLC) {
    keyState = KeyState::DISTRIBUTED_PLC;
  } else {
    keyState = KeyState::DISTRIBUTED_PAW;
  }

  Serial.print("[TEST] Key distributed to ");
  Serial.print(targetName);
  Serial.println(". Awaiting confirmation.");

  return true;
}

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
  Serial.println("\n=== UNO Q Key Authority Test Status ===");
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

void setup() {
  Serial.begin(UART_BAUD);
  
  pinMode(CONFIRM_BUTTON_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED_PIN, OUTPUT);

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — UNO Q Key Authority Test");
  Serial.println("UART Test Mode - Using USB Serial");
  Serial.println("============================================");
  Serial.println();

  printStatus();
}

void loop() {
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
          Serial.println("\n>> Distributing to PLC via USB Serial.");
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
          Serial.println("\n>> Distributing to PAW via USB Serial.");
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

  // LED heartbeat
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