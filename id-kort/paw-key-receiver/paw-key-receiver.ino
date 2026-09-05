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
static inline void secureWipePending() {
  memset(pendingKey, 0, AES_KEY_SIZE);
  pendingValid = false;
  pendingEpoch = 0;
  pendingDeadlineMs = 0;
}

// --- Device ID (unique identifier for this PAW node) ---
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 };  // "PAW\x01"

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
  uint32_t timeoutStart = millis();
  const uint32_t TIMEOUT_MS = 10000;

  Serial.println("[PRO-48] Waiting for key distribution from UNO Q (USB epoch-tagged)...");

  // Step 1: Wait for handshake 0xA1 target[1] epoch[4] (6B)
  uint32_t stagedEpoch = 0;
  while (millis() - timeoutStart < TIMEOUT_MS) {
    if (Serial.available() >= 6) {
      uint8_t msgType = Serial.read();
      uint8_t targetId = Serial.read();
      uint32_t epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
      if (msgType == MSG_HANDSHAKE && targetId == TARGET_PAW) {
        Serial.print("[PRO-48] Handshake received epoch "); Serial.println(epoch);
        if (epoch <= activeEpoch) {
          Serial.println("[PRO-48] Epoch not newer - reject");
          return false;
        }
        stagedEpoch = epoch;
        break;
      } else {
        Serial.printf("[PRO-48] Unexpected message: 0x%02X target: 0x%02X epoch %lu\n", msgType, targetId, (unsigned long)epoch);
        return false;
      }
    }
  }
  if (stagedEpoch == 0) {
    Serial.println("[PRO-48] Timeout waiting for handshake.");
    return false;
  }

  // Step 2: Send READY + device ID + epoch (9B)
  Serial.print("[PRO-48] Sending READY epoch "); Serial.println(stagedEpoch);
  Serial.write(MSG_READY);
  Serial.write(deviceId, 4);
  Serial.write((stagedEpoch >> 24) & 0xFF);
  Serial.write((stagedEpoch >> 16) & 0xFF);
  Serial.write((stagedEpoch >> 8) & 0xFF);
  Serial.write(stagedEpoch & 0xFF);
  Serial.flush();

  // Step 3: Wait for key data 0xA3 len key16 crc4 epoch4 = 26B
  timeoutStart = millis();
  while (Serial.available() < 26 && millis() - timeoutStart < TIMEOUT_MS) {
    delay(1);
  }
  if (Serial.available() < 26) {
    Serial.println("[PRO-48] Timeout waiting for key data.");
    return false;
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

  // Read key
  uint8_t receivedKey[AES_KEY_SIZE];
  Serial.readBytes(receivedKey, AES_KEY_SIZE);

  // Read CRC32 and epoch (big-endian)
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

  // Verify CRC32
  uint32_t computedCrc = crc32(receivedKey, AES_KEY_SIZE);
  if (computedCrc != receivedCrc) {
    Serial.printf("[PRO-48] CRC mismatch! Expected: %08X Got: %08X\n",
                   computedCrc, receivedCrc);
    Serial.write(MSG_ERROR);
    return false;
  }
  Serial.println("[PRO-48] CRC verified OK.");

  // Step 4: Store as pending (not active) for second slice
  memcpy(pendingKey, receivedKey, AES_KEY_SIZE);
  pendingEpoch = stagedEpoch;
  pendingValid = true;
  pendingDeadlineMs = millis() + 600000;

  // Clear receivedKey buffer
  memset(receivedKey, 0, AES_KEY_SIZE);

  // Step 5: Compute hash of pending key and send confirmation with epoch
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
  // Key reception handled in setup(). Main loop reserved for
  // PRO-50 (HMAC-SHA256 on PAW), PRO-57 (e-Paper driver),
  // PRO-58-60 (status display).

  if (pendingValid && Serial.available() >= 5) {
    int peek = Serial.peek();
    if (peek == MSG_COMMIT || peek == MSG_CANCEL) {
      uint8_t msg = Serial.read();
      uint32_t epoch = ((uint32_t)Serial.read() << 24) | ((uint32_t)Serial.read() << 16) | ((uint32_t)Serial.read() << 8) | ((uint32_t)Serial.read());
      if (msg == MSG_COMMIT) {
        if (commitPending(epoch)) Serial.println("[PRO-48] Committed via USB");
      } else {
        secureWipePending();
        Serial.println("[PRO-48] Pending canceled");
      }
    }
  }
  checkPendingExpiry();
  if (keyStored) {
    digitalWrite(LED_BUILTIN, (millis() / 2000) % 2);
  } else {
    if (Serial.available() >= 2) {
      receiveKey();
    }
  }
  if (pendingValid && !keyStored) {
    // Also allow key reception when pending but not yet committed
    if (Serial.available() >= 2) {
      receiveKey();
    }
  }
}
