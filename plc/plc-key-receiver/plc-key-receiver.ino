/*
 * SHALLOT — PLC Complete Firmware (PRO-47 + PRO-49 + PRO-51 + PRO-52)
 * Edge enforcement node: Raspberry Pi Pico 2 (RP2350A) + Core1262-868M
 *
 * Complete implementation:
 *   - PRO-47: Key reception from UNO Q via UART
 *   - PRO-51: Nonce generation (16-byte random)
 *   - PRO-52: Challenge-response protocol over LoRa P2P
 *   - PRO-49: HMAC-SHA256 verification of PAW responses
 *
 * Distribution protocol (matches UNO Q MCU firmware):
 *   UNO Q -> PLC:  MSG_HANDSHAKE (0xA1) + target_id (1 byte)
 *   PLC -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes)
 *   UNO Q -> PLC:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4)
 *   PLC -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes)
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
 *   UART: Serial1 (GP0=TX, GP1=RX) — connected to UNO Q Serial1
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
static const uint8_t deviceId[4] = { 0x50, 0x4C, 0x43, 0x01 };  // "PLC\x01"

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

  Serial.println("[PRO-47] Waiting for key distribution from UNO Q...");

  // Step 1: Wait for handshake
  while (millis() - timeoutStart < TIMEOUT_MS) {
    if (Serial1.available() >= 2) {
      uint8_t msgType = Serial1.read();
      uint8_t targetId = Serial1.read();

      if (msgType == MSG_HANDSHAKE && targetId == TARGET_PLC) {
        Serial.println("[PRO-47] Handshake received.");
        break;
      } else {
        Serial.printf("[PRO-47] Unexpected message: 0x%02X target: 0x%02X\n", msgType, targetId);
        return false;
      }
    }
  }
  if (millis() - timeoutStart >= TIMEOUT_MS) {
    Serial.println("[PRO-47] Timeout waiting for handshake.");
    return false;
  }

  // Step 2: Send READY + device ID
  Serial.print("[PRO-47] Sending READY with device ID: ");
  for (int i = 0; i < 4; i++) Serial.printf("%02X", deviceId[i]);
  Serial.println();

  Serial1.write(MSG_READY);
  Serial1.write(deviceId, 4);
  Serial1.flush();

  // Step 3: Wait for key data
  timeoutStart = millis();
  while (Serial1.available() < 22 && millis() - timeoutStart < TIMEOUT_MS) {
    delay(1);
  }
  if (Serial1.available() < 22) {
    Serial.println("[PRO-47] Timeout waiting for key data.");
    return false;
  }

  uint8_t msgType = Serial1.read();
  if (msgType != MSG_KEY_DATA) {
    Serial.printf("[PRO-47] Expected KEY_DATA, got 0x%02X\n", msgType);
    return false;
  }

  uint8_t receivedKeyLen = Serial1.read();
  if (receivedKeyLen != AES_KEY_SIZE) {
    Serial.printf("[PRO-47] Unexpected key length: %d\n", receivedKeyLen);
    return false;
  }

  uint8_t receivedKey[AES_KEY_SIZE];
  Serial1.readBytes(receivedKey, AES_KEY_SIZE);

  uint32_t receivedCrc = ((uint32_t)Serial1.read() << 24)
                       | ((uint32_t)Serial1.read() << 16)
                       | ((uint32_t)Serial1.read() << 8)
                       | ((uint32_t)Serial1.read());

  uint32_t computedCrc = crc32(receivedKey, AES_KEY_SIZE);
  if (computedCrc != receivedCrc) {
    Serial.printf("[PRO-47] CRC mismatch! Expected: %08X Got: %08X\n",
                   computedCrc, receivedCrc);
    Serial1.write(MSG_ERROR);
    return false;
  }
  Serial.println("[PRO-47] CRC verified OK.");

  memcpy(aesKey, receivedKey, AES_KEY_SIZE);
  keyStored = true;
  memset(receivedKey, 0, AES_KEY_SIZE);

  uint8_t fullHash[32];
  sha256(aesKey, AES_KEY_SIZE, fullHash);
  uint8_t keyHash[KEY_HASH_SIZE];
  memcpy(keyHash, fullHash, KEY_HASH_SIZE);

  Serial1.write(MSG_STORED);
  Serial1.write(keyHash, KEY_HASH_SIZE);
  Serial1.flush();

  Serial.print("[PRO-47] Key stored. Hash sent: ");
  for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
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

// =============================================================
// Challenge-Response Protocol (PRO-52)
// =============================================================

static bool loraInitialized = false;
static uint8_t currentNonce[CHALLENGE_SIZE];
static uint32_t lastChallengeTime = 0;

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
  Serial.println();

  uint8_t txPacket[1 + CHALLENGE_SIZE];
  txPacket[0] = MSG_CHALLENGE;
  memcpy(txPacket + 1, currentNonce, CHALLENGE_SIZE);

  int txState = radio.transmit(txPacket, sizeof(txPacket));
  if (txState == RADIOLIB_ERR_NONE) {
    Serial.println("[PRO-52] Challenge sent over LoRa to PAW.");
    lastChallengeTime = millis();
    return true;
  } else {
    Serial.printf("[PRO-52] LoRa transmit error: %d\n", txState);
    return false;
  }
}

bool verifyResponse(const uint8_t* response, size_t responseLen) {
  if (!keyStored) {
    Serial.println("[PRO-49] Cannot verify: no key stored.");
    return false;
  }
  if (responseLen != HMAC_SIZE) {
    Serial.printf("[PRO-49] Invalid response length: %u (expected %u)\n",
                  responseLen, HMAC_SIZE);
    return false;
  }

  uint8_t expectedHmac[HMAC_SIZE];
  hmac_sha256(aesKey, AES_KEY_SIZE, currentNonce, CHALLENGE_SIZE, expectedHmac);

  volatile uint8_t diff = 0;
  for (size_t i = 0; i < HMAC_SIZE; i++) {
    diff |= response[i] ^ expectedHmac[i];
  }

  memset(expectedHmac, 0, HMAC_SIZE);

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

void setup() {
  Serial.begin(115200);

  loraSPI.setSCK(SPI1_SCK_PIN);
  loraSPI.setTX(SPI1_MOSI_PIN);
  loraSPI.setRX(SPI1_MISO_PIN);
  loraSPI.begin();
  Serial.println("[PRO-27] SPI1 initialized for Core1262.");

  Serial1.begin(UART_BAUD);

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

      if (msgType == MSG_RESPONSE && rxLen >= (1 + HMAC_SIZE)) {
        Serial.println("[PRO-52] Response received from PAW over LoRa");

        bool verified = verifyResponse(rxBuffer + 1, rxLen - 1);

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
    if (millis() - lastChallengeTime >= CHALLENGE_INTERVAL) {
      sendChallenge();
    }
  }

  if (!keyStored) {
    if (Serial1.available() >= 2) {
      receiveKey();
    }
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
