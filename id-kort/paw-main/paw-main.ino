/*
 * SHALLOT PAW Main Firmware
 * Target: Adafruit Feather RP2350 + Core1262-868M + 1.54" 3-color e-Paper
 * 
 * Full PAW firmware combining:
 *   - PRO-48: Key reception from UNO Q (paw-key-receiver.ino)
 *   - PRO-50: HMAC-SHA256 challenge-response
 *   - PRO-57: e-Paper status display (via GxEPD2 3-color driver)
 *   - PRO-58: LoRa P2P communication with PLC (RadioLib SX1262)
 *
 * Hardware pin mapping (Feather RP2350 silkscreen labels):
 *   UART (UNO Q):  TX->1, RX->0 (Serial1)
 *   LoRa (SPI1):   SCK=D10, MOSI=D11, MISO=D24, CS=D9, BUSY=pin7, RESET=pin4, DIO1=A2
 *   e-Paper (SPI0):CS=5, DC=A0(GPIO26), RST=A1(GPIO27), BUSY=D25(GPIO25)
 *                   SPI0 MO(GP23) -> DIN, SPI0 SCK(GP22) -> CLK
 *
 * e-Paper panel: Waveshare 1.54" 3-färg B/W/R (GDEH0154Z90, SSD1682).
 * Korrekt drivare är GxEPD2_3C/GxEPD2_154_Z90c; B/W-drivaren (D67) lämnar
 * röda planet oskrivet -> röd bakgrund. Full refresh ~14 s.
 *
 * Architecture:
 *   1. Wait for key from UNO Q at startup via Serial1
 *   2. Initialize LoRa (SX1262 on SPI1) and e-Paper (SPI0)
 *   3. Listen for challenge (nonce) from PLC over LoRa
 *   4. Compute HMAC-SHA256(key, nonce) and transmit response
 *   5. Update e-Paper with privacy-compliant authentication status icons
 *
 * Privacy: e-Paper shows ONLY status icons (no text, no PII)
 *   States: AUTHENTICATING, AUTHENTICATED, FAILED
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <GxEPD2_3C.h>

enum EpdStatus {
    EPD_STATUS_AUTHENTICATING = 0,
    EPD_STATUS_AUTHENTICATED  = 1,
    EPD_STATUS_FAILED         = 2,
    EPD_STATUS_BLANK          = 3
};

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
#define CHALLENGE_TIMEOUT        30000  // ms

// =============================================================
// Pin Definitions
// =============================================================

// --- LoRa Core1262 (SPI1) ---
#define LORA_SCK_PIN     10
#define LORA_MOSI_PIN    11
#define LORA_MISO_PIN    24
#define LORA_CS_PIN      9
#define LORA_BUSY_PIN    7
#define LORA_RESET_PIN   4
#define LORA_DIO1_PIN    A2

// --- e-Paper (SPI0) via GxEPD2 ---
// CS=5, DC=A0(26), RST=A1(27), BUSY=D25(25)

// --- UART to UNO Q ---
// Hardware Serial1: TX->1, RX->0

#undef LED_BUILTIN
#define LED_BUILTIN 6

// =============================================================
// SPI1 Instance for Core1262
// =============================================================
SPIClassRP2040 loraSPI(spi1, LORA_MISO_PIN, LORA_CS_PIN, LORA_SCK_PIN, LORA_MOSI_PIN);

// =============================================================
// RadioLib SX1262 Module
// =============================================================
SX1262 radio = new Module(LORA_CS_PIN, LORA_DIO1_PIN, LORA_RESET_PIN, LORA_BUSY_PIN, loraSPI);

static volatile bool loraPacketReceived = false;

#if defined(ESP8266) || defined(ESP32)
  ICACHE_RAM_ATTR
#endif
static void setLoRaFlag(void) {
    loraPacketReceived = true;
}

// =============================================================
// Protocol Message Types
// =============================================================

#define MSG_HANDSHAKE    0xA1
#define MSG_READY        0xA2
#define MSG_KEY_DATA     0xA3
#define MSG_STORED       0xA4
#define MSG_ERROR        0xA5

#define MSG_CHALLENGE    0xB1
#define MSG_RESPONSE     0xB2
#define MSG_RESULT       0xB3

#define TARGET_PAW       0x02
#define TARGET_PLC       0x01

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE     16
#define KEY_HASH_SIZE     4
#define CHALLENGE_SIZE    16
#define HMAC_SIZE         32

// =============================================================
// e-Paper via GxEPD2
// =============================================================

// Waveshare 1.54" 3-color B/W/R panel (GDEH0154Z90, SSD1682), 200x200.
// Uses GxEPD2_3C tricolor driver so the red plane is always written white.
// Full refresh takes ~14s; GxEPD2 uses timed waits (BUSY may not be wired).
GxEPD2_3C<GxEPD2_154_Z90c, GxEPD2_154_Z90c::HEIGHT> display(
  GxEPD2_154_Z90c(5, 26, 27, 25)  // CS, DC, RST, BUSY
);

void epdInit() {
    display.init(0, true, 2, false);  // serial_diag, initial, reset_duration, pulldown_rst
    display.setRotation(0);
}

static EpdStatus lastShownStatus = EPD_STATUS_BLANK;
static bool hasShownResult = false;

void epdShowStatus(EpdStatus status) {
    // Avoid redundant full refreshes (the 3-color panel flickers and blocks
    // ~14s per refresh). Only redraw when the displayed status actually changes.
    if (status == lastShownStatus) {
        return;
    }
    // Once a definitive result (AUTHENTICATED/FAILED) has been shown, don't
    // bounce back to the AUTHENTICATING splash on background timeouts or
    // repeat challenges.
    if (status == EPD_STATUS_AUTHENTICATING && hasShownResult) {
        return;
    }
    if (status == EPD_STATUS_AUTHENTICATED || status == EPD_STATUS_FAILED) {
        hasShownResult = true;
    }
    lastShownStatus = status;

    // Restore the screen buffer to full window (necessary after powerOff)
    display.setFullWindow();
    display.firstPage();
    do {
        display.fillScreen(GxEPD_WHITE);

        int cx = 100, cy = 100, r = 50;

        display.drawRect(4, 4, 192, 192, GxEPD_BLACK);

        switch (status) {
            case EPD_STATUS_AUTHENTICATING:
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                display.fillCircle(cx, cy - r / 2, r / 5, GxEPD_BLACK);
                display.fillCircle(cx - r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
                display.fillCircle(cx + r / 2, cy + r / 2, r / 5, GxEPD_BLACK);
                break;

            case EPD_STATUS_AUTHENTICATED: {
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                int s = r * 2 / 3;
                display.drawLine(cx - s, cy, cx - s / 4, cy + s / 2, GxEPD_BLACK);
                display.drawLine(cx - s / 4, cy + s / 2, cx + s, cy - s / 2, GxEPD_BLACK);
                break;
            }

            case EPD_STATUS_FAILED: {
                display.drawCircle(cx, cy, r, GxEPD_BLACK);
                int s = r * 2 / 3;
                display.drawLine(cx - s, cy - s, cx + s, cy + s, GxEPD_BLACK);
                display.drawLine(cx - s, cy + s, cx + s, cy - s, GxEPD_BLACK);
                break;
            }

            default:
                break;
        }
    } while (display.nextPage());
}

// =============================================================
// Key Storage
// =============================================================

static uint8_t aesKey[AES_KEY_SIZE];
static bool keyStored = false;
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 }; // "PAW\x01"

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
// HMAC-SHA256 Implementation (PRO-50)
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
// USB Key Injection (host pushes key over USB Serial @ 115200)
// =============================================================
// Host sends one ASCII line:
//   K <32 hex chars>          (16-byte AES key)
// Parses hex, stores key, prints fingerprint. USB-C is the
// distribution port (no UART needed).
// =============================================================

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool receiveKeyOverUSB() {
    if (keyStored) return false;

    char line[64];
    size_t n = 0;
    while (Serial.available() && n < sizeof(line) - 1) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') break;
        line[n++] = c;
    }
    line[n] = '\0';

    const char* p = line;
    while (*p == ' ') p++;

    size_t hexLen = strlen(p);
    if (hexLen != AES_KEY_SIZE * 2) {
        Serial.printf("[USB-KEY] Bad key length: %u hex chars (expected %u)\n",
                      (unsigned)hexLen, AES_KEY_SIZE * 2);
        return false;
    }

    uint8_t key[AES_KEY_SIZE];
    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        int h = hexval(p[i * 2]);
        int l = hexval(p[i * 2 + 1]);
        if (h < 0 || l < 0) {
            Serial.println("[USB-KEY] Invalid hex digit.");
            return false;
        }
        key[i] = (uint8_t)((h << 4) | l);
    }

    memset(aesKey, 0, AES_KEY_SIZE);
    memcpy(aesKey, key, AES_KEY_SIZE);
    memset(key, 0, AES_KEY_SIZE);
    keyStored = true;

    uint8_t fullHash[32];
    sha256(aesKey, AES_KEY_SIZE, fullHash);
    uint8_t keyHash[KEY_HASH_SIZE];
    memcpy(keyHash, fullHash, KEY_HASH_SIZE);

    Serial.print("[USB-KEY] Key stored. Fingerprint: ");
    for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
    Serial.println();

    memset(fullHash, 0, 32);
    memset(keyHash, 0, KEY_HASH_SIZE);
    return true;
}

// =============================================================
// Key Reception from UNO Q (PRO-48)
// =============================================================

bool receiveKeyFromUNOQ() {
    uint32_t timeoutStart = millis();

    Serial.println("[PRO-48] Waiting for key distribution from UNO Q...");

    while (millis() - timeoutStart < KEY_DISTRIBUTION_TIMEOUT) {
        if (Serial1.available() >= 2) {
            uint8_t msgType = Serial1.read();
            uint8_t targetId = Serial1.read();

            if (msgType == MSG_HANDSHAKE && targetId == TARGET_PAW) {
                Serial.println("[PRO-48] Handshake received.");
                break;
            }
        }
    }
    if (millis() - timeoutStart >= KEY_DISTRIBUTION_TIMEOUT) {
        Serial.println("[PRO-48] Timeout waiting for handshake.");
        return false;
    }

    Serial.print("[PRO-48] Sending READY with device ID: ");
    for (int i = 0; i < 4; i++) Serial.printf("%02X", deviceId[i]);
    Serial.println();

    Serial1.write(MSG_READY);
    Serial1.write(deviceId, 4);
    Serial1.flush();

    timeoutStart = millis();
    while (Serial1.available() < 22 && millis() - timeoutStart < KEY_DISTRIBUTION_TIMEOUT) {
        delay(1);
    }
    if (Serial1.available() < 22) {
        Serial.println("[PRO-48] Timeout waiting for key data.");
        return false;
    }

    uint8_t msgType = Serial1.read();
    if (msgType != MSG_KEY_DATA) {
        Serial.printf("[PRO-48] Expected KEY_DATA, got 0x%02X\n", msgType);
        return false;
    }

    uint8_t receivedKeyLen = Serial1.read();
    if (receivedKeyLen != AES_KEY_SIZE) {
        Serial.printf("[PRO-48] Unexpected key length: %d\n", receivedKeyLen);
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
        Serial.printf("[PRO-48] CRC mismatch! Expected: %08X Got: %08X\n", computedCrc, receivedCrc);
        Serial1.write(MSG_ERROR);
        memset(receivedKey, 0, AES_KEY_SIZE);
        return false;
    }
    Serial.println("[PRO-48] CRC verified OK.");

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

    Serial.print("[PRO-48] Key stored. Hash sent: ");
    for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
    Serial.println();

    memset(fullHash, 0, 32);
    return true;
}

// =============================================================
// Authentication State Machine
// =============================================================

enum AuthState {
    STATE_WAITING_FOR_KEY,
    STATE_WAITING_FOR_CHALLENGE,
    STATE_COMPUTING_RESPONSE,
    STATE_WAITING_FOR_RESULT
};

static AuthState currentState = STATE_WAITING_FOR_KEY;
static bool loraInitialized = false;

// =============================================================
// Setup
// =============================================================

void setup() {
    Serial.begin(115200);
    Serial1.begin(115200);

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    delay(2000);

    Serial.println("============================================");
    Serial.println("SHALLOT PAW Main Firmware");
    Serial.println("Hardware: Adafruit Feather RP2350");
    Serial.println("Components: Core1262 LoRa + e-Paper");
    Serial.println("============================================");

    Serial.println("[PRO-57] Initializing e-Paper (GxEPD2)...");
    epdInit();
    Serial.println("[PRO-57] e-Paper initialized.");
    epdShowStatus(EPD_STATUS_AUTHENTICATING);

    loraSPI.begin();
    Serial.println("[PRO-28] SPI1 initialized for Core1262.");

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

    Serial.println("[PRO-48] Starting key reception...");

    // USB injection first: wait for "K <32 hex>" over USB Serial (~10s).
    {
        uint32_t t0 = millis();
        bool usbKeyReceived = false;
        Serial.println("[USB-KEY] Waiting for key over USB...");
        while (millis() - t0 < KEY_DISTRIBUTION_TIMEOUT) {
            if (Serial.available()) {
                if (Serial.peek() == 'K') {
                    Serial.read();
                    while (Serial.available() && Serial.peek() == ' ') Serial.read();
                    if (receiveKeyOverUSB()) {
                        usbKeyReceived = true;
                        break;
                    }
                } else {
                    Serial.read();  // drain non-K input
                }
            }
            delay(10);
        }
        if (usbKeyReceived) {
            currentState = STATE_WAITING_FOR_CHALLENGE;
            Serial.println("[USB-KEY] Key received successfully over USB.");
            digitalWrite(LED_BUILTIN, HIGH);
            epdShowStatus(EPD_STATUS_AUTHENTICATING);
        } else if (receiveKeyFromUNOQ()) {
            currentState = STATE_WAITING_FOR_CHALLENGE;
            Serial.println("[PRO-48] Key received successfully.");
            digitalWrite(LED_BUILTIN, HIGH);
            epdShowStatus(EPD_STATUS_AUTHENTICATING);
        } else {
            Serial.println("[PRO-48] Key reception FAILED / Waiting...");
            currentState = STATE_WAITING_FOR_KEY;
            epdShowStatus(EPD_STATUS_FAILED);
        }
    }
}

// =============================================================
// Loop
// =============================================================

void loop() {
    static uint32_t lastChallengeTime = 0;
    static uint8_t challenge[CHALLENGE_SIZE];
    static uint8_t response[HMAC_SIZE];
    static uint8_t rxBuffer[64];

    // USB key injection: accept "K <32 hex>" over USB Serial at any time the
    // node does not yet hold a key (mirrors the PLC, robust to boot timing).
    if (!keyStored && Serial.available()) {
        if (Serial.peek() == 'K') {
            Serial.read();
            while (Serial.available() && Serial.peek() == ' ') Serial.read();
            if (receiveKeyOverUSB()) {
                currentState = STATE_WAITING_FOR_CHALLENGE;
                digitalWrite(LED_BUILTIN, HIGH);
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
        } else {
            Serial.read();
        }
    }

    if (loraInitialized && loraPacketReceived) {
        loraPacketReceived = false;

        size_t rxLen = radio.getPacketLength();
        if (rxLen > sizeof(rxBuffer)) rxLen = sizeof(rxBuffer);

        int state = radio.readData(rxBuffer, rxLen);
        if (state == RADIOLIB_ERR_NONE && rxLen > 0) {
            uint8_t msgType = rxBuffer[0];
            Serial.printf("[LoRa RX] Type: 0x%02X, Length: %u bytes, RSSI: %.1f dBm, SNR: %.1f dB\n",
                          msgType, (unsigned)rxLen, radio.getRSSI(), radio.getSNR());

            if (msgType == MSG_CHALLENGE && rxLen >= (1 + CHALLENGE_SIZE)) {
                Serial.println("[PRO-50] Challenge received from PLC over LoRa");
                memcpy(challenge, rxBuffer + 1, CHALLENGE_SIZE);
                lastChallengeTime = millis();
                currentState = STATE_COMPUTING_RESPONSE;
                epdShowStatus(EPD_STATUS_AUTHENTICATING);

                Serial.print("[PRO-50] Challenge nonce: ");
                for (int i = 0; i < CHALLENGE_SIZE; i++) Serial.printf("%02X", challenge[i]);
                Serial.println();
            }
            else if (msgType == MSG_RESULT && rxLen >= 2) {
                uint8_t result = rxBuffer[1];
                if (result == 0x01) {
                    Serial.println("[PRO-50] Authentication SUCCESS (LoRa)");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epdShowStatus(EPD_STATUS_AUTHENTICATED);
                    for (int i = 0; i < 5; i++) {
                        digitalWrite(LED_BUILTIN, HIGH); delay(100);
                        digitalWrite(LED_BUILTIN, LOW); delay(100);
                    }
                } else {
                    Serial.println("[PRO-50] Authentication FAILED (LoRa)");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epdShowStatus(EPD_STATUS_FAILED);
                    for (int i = 0; i < 10; i++) {
                        digitalWrite(LED_BUILTIN, HIGH); delay(50);
                        digitalWrite(LED_BUILTIN, LOW); delay(50);
                    }
                }
            }
        }
        radio.startReceive();
    }

    switch (currentState) {
        case STATE_WAITING_FOR_KEY:
            if (receiveKeyFromUNOQ()) {
                currentState = STATE_WAITING_FOR_CHALLENGE;
                digitalWrite(LED_BUILTIN, HIGH);
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_WAITING_FOR_CHALLENGE:
            if (lastChallengeTime > 0 && (millis() - lastChallengeTime > CHALLENGE_TIMEOUT)) {
                lastChallengeTime = 0;
                Serial.println("[PRO-50] Challenge timeout.");
                epdShowStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_COMPUTING_RESPONSE:
            if (keyStored) {
                hmac_sha256(aesKey, AES_KEY_SIZE, challenge, CHALLENGE_SIZE, response);

                Serial.print("[PRO-50] HMAC Response computed: ");
                for (int i = 0; i < HMAC_SIZE; i++) Serial.printf("%02X", response[i]);
                Serial.println();

                uint8_t txPacket[1 + CHALLENGE_SIZE + HMAC_SIZE];
                txPacket[0] = MSG_RESPONSE;
                memcpy(txPacket + 1, challenge, CHALLENGE_SIZE);
                memcpy(txPacket + 1 + CHALLENGE_SIZE, response, HMAC_SIZE);

                if (loraInitialized) {
                    int txState = radio.transmit(txPacket, sizeof(txPacket));
                    if (txState == RADIOLIB_ERR_NONE) {
                        Serial.println("[PRO-50] Response sent over LoRa to PLC.");
                    } else {
                        Serial.printf("[PRO-50] LoRa transmit error: %d\n", txState);
                    }
                    radio.startReceive();
                }

                Serial.write(txPacket, sizeof(txPacket));
                Serial.flush();

                currentState = STATE_WAITING_FOR_RESULT;
                memset(challenge, 0, CHALLENGE_SIZE);
            } else {
                Serial.println("[PRO-50] ERROR: No key stored!");
                currentState = STATE_WAITING_FOR_KEY;
                epdShowStatus(EPD_STATUS_FAILED);
            }
            break;

        case STATE_WAITING_FOR_RESULT:
            break;
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
