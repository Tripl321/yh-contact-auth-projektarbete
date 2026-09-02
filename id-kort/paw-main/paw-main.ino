/*
 * SHALLOT PAW Main Firmware
 * Target: Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper
 * 
 * Full PAW firmware combining:
 *   - PRO-48: Key reception from UNO Q (paw-key-receiver.ino)
 *   - PRO-50: HMAC-SHA256 challenge-response (to be integrated)
 *   - PRO-57: e-Paper status display (epaper-status-display.ino)
 *   - PRO-58: LoRa P2P communication with PLC
 *
 * Hardware pin mapping (using exact Feather RP2350 silkscreen labels):
 *   UART (UNO Q):  TX->1, RX->0 (Serial1)
 *   LoRa (SPI1):   SCK=10, MOSI=11, MISO=6, CS=9, BUSY=7, RESET=8, DIO1=A2
 *   e-Paper (SPI0):DIN=MO, CLK=SCK, CS=5, DC=A0, RST=A1, BUSY=A3
 *
 * Architecture:
 *   1. Wait for key from UNO Q at startup
 *   2. Initialize LoRa and e-Paper
 *   3. Listen for challenge (nonce) from PLC
 *   4. Compute HMAC-SHA256(key, nonce) and respond
 *   5. Update e-Paper with authentication status
 *
 * Privacy: e-Paper shows ONLY status icons (no text, no PII)
 *   States: AUTHENTICATING, AUTHENTICATED, FAILED
 */

#include <Arduino.h>
#include <SPI.h>

// =============================================================
// Configuration
// =============================================================

// LoRa settings
#define LORA_FREQUENCY   868.0
#define LORA_BANDWIDTH   125.0
#define LORA_SPREADING_FACTOR 9
#define LORA_CODING_RATE  5
#define LORA_PREAMBLE_LENGTH 8
#define LORA_SYNC_WORD    0x12

// Timeouts
#define KEY_DISTRIBUTION_TIMEOUT 10000  // ms
#define CHALLENGE_TIMEOUT        30000  // ms

// =============================================================
// Pin Definitions
// =============================================================

// --- LoRa Core1262 (SPI1) ---
#define LORA_SCK_PIN     10  // SCK pin on Feather silkscreen
#define LORA_MOSI_PIN    11  // MOSI pin on Feather silkscreen
#define LORA_MISO_PIN    12  // D12 on Feather silkscreen (GPIO12 = SPI1 MISO)   // MISO pin on Feather silkscreen
#define LORA_CS_PIN      9   // Pin 9 on Feather silkscreen
#define LORA_BUSY_PIN    7   // Pin 7 on Feather silkscreen
#d
efine LORA_RESET_PIN   8   // Pin 8 on Feather silkscreen
#define LORA_DIO1_PIN    A2  // A2 on Feather silkscreen

// --- e-Paper (SPI0) ---
#define EPD_DIN_PIN      MO  // MO pin on Feather silkscreen (SPI0 MOSI)
#define EPD_CLK_PIN      SCK // SCK pin on Feather silkscreen (SPI0 SCK)
#define EPD_CS_PIN       5   // Pin 5 on Feather silkscreen
#define EPD_DC_PIN       A0  // A0 on Feather silkscreen
#define EPD_RST_PIN      A1  // A1 on Feather silkscreen
#define EPD_BUSY_PIN     A3  // A3 on Feather silkscreen

// --- UART to UNO Q ---
// Hardware Serial1: TX->1, RX->0 on Feather silkscreen
// No pin defines needed - using Serial1 directly

// =============================================================
// Protocol Message Types
// =============================================================

// Key distribution (from paw-key-receiver.ino)
#define MSG_HANDSHAKE    0xA1
#define MSG_READY        0xA2
#define MSG_KEY_DATA     0xA3
#define MSG_STORED       0xA4
#define MSG_ERROR        0xA5

// Authentication protocol
#define MSG_CHALLENGE    0xB1
#define MSG_RESPONSE     0xB2
#define MSG_RESULT       0xB3

// Target IDs
#define TARGET_PAW       0x02
#define TARGET_PLC       0x01

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE     16
#define KEY_HASH_SIZE     4
#define CHALLENGE_SIZE    16  // Nonce size
#define HMAC_SIZE         32  // HMAC-SHA256 output

// =============================================================
// e-Paper Display Constants
// =============================================================

#define EPD_WIDTH        200
#define EPD_HEIGHT       200
#define EPD_BUFFER_SIZE  ((EPD_WIDTH / 8) * EPD_HEIGHT)

// =============================================================
// Key Storage
// =============================================================

static uint8_t aesKey[AES_KEY_SIZE];
static bool keyStored = false;
static const 
uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 }; // "PAW\x01"

// =============================================================
// Waveform LUT for e-Paper (from epaper-status-display.ino)
// =============================================================

static const unsigned char WF_FULL_1IN54[159] = {
    0x80, 0x48, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x40, 0x48, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x80, 0x48, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x40, 0x48, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0xA, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x8, 0x1, 0x0, 0x8, 0x1, 0x0, 0x2,
    0xA, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x0, 0x0, 0x0,
    0x22, 0x17, 0x41, 0x0, 0x32, 0x20
};

// =============================================================
// Privacy-Masked Status Enumeration
// =============================================================

enum EpdStatus {
    EPD_STATUS_AUTHENTICATING = 0,
    EPD_STATUS_AUTHENTICATED  = 1,
    EPD_STATUS_FAILED         = 2,
    EPD_STATUS_BLANK          = 3
};

// =============================================================
// e-Paper Driver Class (from epaper-status-display.ino)
// =============================================================

class ShallotEPD {
public:
    ShallotEPD();
    bool begin();
    void sleep();
    void clear();
    void displayFrame(const uint8_t* frameBuffer);
    void showStatus(EpdStatus status);

private:
    void sendCommand(uint8_t cmd);
    void sendData(uint8_t data);
    void waitUntilIdle();
    void reset();
    void setLut(const unsigned char* lut);
    void clearBuffer();
    void drawPixel(i
nt x, int y, bool white);
    void drawLine(int x0, int y0, int x1, int y1, bool white);
    void drawRect(int x, int y, int w, int h, bool white);
    void drawCircle(int cx, int cy, int r, bool white);
    void drawCircleFilled(int cx, int cy, int r, bool white);
    void drawIcon(int cx, int cy, int size, EpdStatus status);

    uint8_t _buffer[EPD_BUFFER_SIZE];
};

ShallotEPD::ShallotEPD() {
    memset(_buffer, 0xFF, EPD_BUFFER_SIZE);
}

void ShallotEPD::sendCommand(uint8_t cmd) {
    digitalWrite(EPD_DC_PIN, LOW);
    digitalWrite(EPD_CS_PIN, LOW);
    SPI.transfer(cmd);
    digitalWrite(EPD_CS_PIN, HIGH);
}

void ShallotEPD::sendData(uint8_t data) {
    digitalWrite(EPD_DC_PIN, HIGH);
    digitalWrite(EPD_CS_PIN, LOW);
    SPI.transfer(data);
    digitalWrite(EPD_CS_PIN, HIGH);
}

void ShallotEPD::waitUntilIdle() {
    while (digitalRead(EPD_BUSY_PIN) == HIGH) {
        delay(100);
    }
    delay(200);
}

void ShallotEPD::reset() {
    digitalWrite(EPD_RST_PIN, HIGH);
    delay(20);
    digitalWrite(EPD_RST_PIN, LOW);
    delay(5);
    digitalWrite(EPD_RST_PIN, HIGH);
    delay(20);
}

void ShallotEPD::setLut(const unsigned char* lut) {
    sendCommand(0x32);
    for (uint8_t i = 0; i < 153; i++) {
        sendData(lut[i]);
    }
    waitUntilIdle();
    sendCommand(0x3F);
    sendData(lut[153]);
    sendCommand(0x03);
    sendData(lut[154]);
    sendCommand(0x04);
    sendData(lut[155]);
    sendData(lut[156]);
    sendData(lut[157]);
    sendCommand(0x2C);
    sendData(lut[158]);
}

bool ShallotEPD::begin() {
    pinMode(EPD_CS_PIN, OUTPUT);
    pinMode(EPD_DC_PIN, OUTPUT);
    pinMode(EPD_RST_PIN, OUTPUT);
    pinMode(EPD_BUSY_PIN, INPUT);

    // SPI0 is hardware-wired on Feather RP2350: SCK (GP22), MO (GP23), MI (GP20)
    // Do NOT use SPI.setTX() or SPI.setSCK() for SPI0 - it's already configured!
    SPI.begin();
    SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));

    reset();
    waitUntilIdle();

    sendCommand(0x12);  // SWRESET

    waitUntilIdle();

    sendCommand(0x01);  // Driver output control
    sendData(0xC7);
    sendData(0x00);
    sendData(0x01);

    sendCommand(0x11);  // Data entry mode
    sendData(0x01);

    sendCommand(0x44);  // Set RAM-X start/end
    sendData(0x00);
    sendData(0x18);

    sendCommand(0x45);  // Set RAM-Y start/end
    sendData(0xC7);
    sendData(0x00);
    sendData(0x00);
    sendData(0x00);

    sendCommand(0x3C);  // Border waveform
    sendData(0x01);

    sendCommand(0x18);  // Read built-in temperature sensor
    sendData(0x80);

    sendCommand(0x22);  // Load temperature and waveform setting
    sendData(0xB1);
    sendCommand(0x20);

    sendCommand(0x4E);  // Set RAM-X address counter
    sendData(0x00);
    sendCommand(0x4F);  // Set RAM-Y address counter
    sendData(0xC7);
    sendData(0x00);
    waitUntilIdle();

    setLut(WF_FULL_1IN54);
    return true;
}

void ShallotEPD::clear() {
    int w = (EPD_WIDTH % 8 == 0) ? (EPD_WIDTH / 8) : (EPD_WIDTH / 8 + 1);
    int h = EPD_HEIGHT;

    sendCommand(0x24);
    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            sendData(0xFF);
        }
    }
    sendCommand(0x26);
    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            sendData(0xFF);
        }
    }
    sendCommand(0x22);
    sendData(0xC7);
    sendCommand(0x20);
    waitUntilIdle();
}

void ShallotEPD::displayFrame(const uint8_t* frameBuffer) {
    int w = (EPD_WIDTH % 8 == 0) ? (EPD_WIDTH / 8) : (EPD_WIDTH / 8 + 1);
    int h = EPD_HEIGHT;

    if (frameBuffer != nullptr) {
        sendCommand(0x24);
        for (int j = 0; j < h; j++) {
            for (int i = 0; i < w; i++) {
                sendData(frameBuffer[i + j * w]);
            }
        }
    }
    sendCommand(0x22);
    sendData(0xC7);
    sendCommand(0x20);
    waitUntilIdle();
}

void ShallotEPD::sleep() {
    sendCommand(0x10);  // Enter deep sleep
    sendData(0x01);
    delay(200);
    digitalWrite(EPD_RST_PIN
, LOW);
}

void ShallotEPD::clearBuffer() {
    memset(_buffer, 0xFF, EPD_BUFFER_SIZE);
}

void ShallotEPD::drawPixel(int x, int y, bool white) {
    if (x < 0 || x >= EPD_WIDTH || y < 0 || y >= EPD_HEIGHT) return;
    int byteIdx = x / 8 + y * (EPD_WIDTH / 8);
    uint8_t bit = 0x80 >> (x % 8);
    if (white) {
        _buffer[byteIdx] |= bit;
    } else {
        _buffer[byteIdx] &= ~bit;
    }
}

void ShallotEPD::drawLine(int x0, int y0, int x1, int y1, bool white) {
    int dx = abs(x1 - x0);
    int dy = abs(y1 - y0);
    int sx = (x0 < x1) ? 1 : -1;
    int sy = (y0 < y1) ? 1 : -1;
    int err = dx - dy;

    while (true) {
        drawPixel(x0, y0, white);
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 > -dy) { err -= dy; x0 += sx; }
        if (e2 < dx)  { err += dx; y0 += sy; }
    }
}

void ShallotEPD::drawRect(int x, int y, int w, int h, bool white) {
    drawLine(x, y, x + w - 1, y, white);
    drawLine(x, y + h - 1, x + w - 1, y + h - 1, white);
    drawLine(x, y, x, y + h - 1, white);
    drawLine(x + w - 1, y, x + w - 1, y + h - 1, white);
}

void ShallotEPD::drawCircle(int cx, int cy, int r, bool white) {
    int x = r, y = 0;
    int err = 1 - r;

    while (x >= y) {
        drawPixel(cx + x, cy + y, white);
        drawPixel(cx - x, cy + y, white);
        drawPixel(cx + x, cy - y, white);
        drawPixel(cx - x, cy - y, white);
        drawPixel(cx + y, cy + x, white);
        drawPixel(cx - y, cy + x, white);
        drawPixel(cx + y, cy - x, white);
        drawPixel(cx - y, cy - x, white);

        y++;
        if (err < 0) {
            err += 2 * y + 1;
        } else {
            x--;
            err += 2 * (y - x) + 1;
        }
    }
}

void ShallotEPD::drawCircleFilled(int cx, int cy, int r, bool white) {
    for (int y = -r; y <= r; y++) {
        for (int x = -r; x <= r; x++) {
            if (x * x + y * y <= r * r) {
                drawPixel(cx + x, cy + y, white);
            }
        }
    }

}

void ShallotEPD::drawIcon(int cx, int cy, int size, EpdStatus status) {
    int r = size;

    switch (status) {
        case EPD_STATUS_AUTHENTICATING: {
            // Three dots in triangle pattern
            drawCircleFilled(cx, cy - r / 2, r / 5, false);
            drawCircleFilled(cx - r / 2, cy + r / 2, r / 5, false);
            drawCircleFilled(cx + r / 2, cy + r / 2, r / 5, false);
            drawCircle(cx, cy, r + 10, false);
            break;
        }

        case EPD_STATUS_AUTHENTICATED: {
            // Checkmark inside circle
            drawCircle(cx, cy, r, false);
            int cm_size = r * 2 / 3;
            drawLine(cx - cm_size, cy, cx - cm_size / 4, cy + cm_size / 2, false);
            drawLine(cx - cm_size / 4, cy + cm_size / 2, cx + cm_size, cy - cm_size / 2, false);
            break;
        }

        case EPD_STATUS_FAILED: {
            // X mark inside circle
            drawCircle(cx, cy, r, false);
            int x_size = r * 2 / 3;
            drawLine(cx - x_size, cy - x_size, cx + x_size, cy + x_size, false);
            drawLine(cx - x_size, cy + x_size, cx + x_size, cy - x_size, false);
            break;
        }

        case EPD_STATUS_BLANK:
        default:
            break;
    }
}

void ShallotEPD::showStatus(EpdStatus status) {
    if (status == EPD_STATUS_BLANK) {
        clearBuffer();
        displayFrame(_buffer);
        sleep();
        return;
    }

    clearBuffer();
    drawRect(4, 4, EPD_WIDTH - 8, EPD_HEIGHT - 8, false);

    int centerX = EPD_WIDTH / 2;
    int centerY = EPD_HEIGHT / 2;
    int iconRadius = 50;

    drawIcon(centerX, centerY, iconRadius, status);
    displayFrame(_buffer);
    sleep();
}

// =============================================================
// SHA-256 Implementation (from paw-key-receiver.ino)
// =============================================================

static const uint32_t sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59
f111f1, 0x923f82a4, 0xab1c5ed5,
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
           | ((uint32_t)msg[
blk + i*4 + 3]);
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

  // Prepare inner and outer padding
  memset(k_ipad, 0x36, HMAC_BLOCK_SIZE);
  memset(k_opad, 0x5C, HMAC_BLOCK_SIZE);

  // XOR key with ipad and opad
  for (size_t i = 0; i < keyLen; i++) {
    if (i < HMAC_BLOCK_SIZE) {
      k_ipad[i] ^= key[i];
      k_opad[i] ^= key[i];
    }
  }

  // Inner hash: SHA256(k_ipad || msg)
 
  uint8_t* innerMsg = (uint8_t*)calloc(HMAC_BLOCK_SIZE + msgLen, 1);
  if (!innerMsg) { memset(mac,0,32); return; }
  memcpy(innerMsg, k_ipad, HMAC_BLOCK_SIZE);
  memcpy(innerMsg + HMAC_BLOCK_SIZE, msg, msgLen);
  sha256(innerMsg, HMAC_BLOCK_SIZE + msgLen, innerHash);

  // Outer hash: SHA256(k_opad || innerHash)
  uint8_t outerMsg[HMAC_BLOCK_SIZE + 32];
  memcpy(outerMsg, k_opad, HMAC_BLOCK_SIZE);
  memcpy(outerMsg + HMAC_BLOCK_SIZE, innerHash, 32);
  sha256(outerMsg, sizeof(outerMsg), outerHash);

  memcpy(mac, outerHash, 32);

  // Clear sensitive data
  memset(k_ipad, 0, HMAC_BLOCK_SIZE);
  memset(k_opad, 0, HMAC_BLOCK_SIZE);
  memset(innerHash, 0, 32);
  memset(outerHash, 0, 32);
  memset(innerMsg, 0, HMAC_BLOCK_SIZE + msgLen);
  free(innerMsg);
  memset(outerMsg, 0, sizeof(outerMsg));
}

// =============================================================
// Key Reception from UNO Q (PRO-48)
// =============================================================

bool receiveKeyFromUNOQ() {
  uint32_t timeoutStart = millis();

  Serial.println("[PRO-48] Waiting for key distribution from UNO Q...");

  // Step 1: Wait for handshake
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

  // Step 2: Send READY + device ID
  Serial.print("[PRO-48] Sending READY with device ID: ");
  for (int i = 0; i < 4; i++) Serial.printf("%02X", deviceId[i]);
  Serial.println();

  Serial1.write(MSG_READY);
  Serial1.write(deviceId, 4);
  Serial1.flush();

  // Step 3: Wait for key data (22 bytes)
  timeoutStart = millis();
  while (Serial1.available() < 22 && millis() - timeoutStart < KEY_DISTRIBUTION_TIMEOUT) {
    delay(1);
  }
  if (Serial1.available() < 22) {
    Seri
al.println("[PRO-48] Timeout waiting for key data.");
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

  // Read CRC32
  uint32_t receivedCrc = ((uint32_t)Serial1.read() << 24)
                       | ((uint32_t)Serial1.read() << 16)
                       | ((uint32_t)Serial1.read() << 8)
                       | ((uint32_t)Serial1.read());

  // Verify CRC32
  uint32_t computedCrc = crc32(receivedKey, AES_KEY_SIZE);
  if (computedCrc != receivedCrc) {
    Serial.printf("[PRO-48] CRC mismatch! Expected: %08X Got: %08X\n",
                   computedCrc, receivedCrc);
    Serial1.write(MSG_ERROR);
    memset(receivedKey, 0, AES_KEY_SIZE);
    return false;
  }
  Serial.println("[PRO-48] CRC verified OK.");

  // Store key
  memcpy(aesKey, receivedKey, AES_KEY_SIZE);
  keyStored = true;
  memset(receivedKey, 0, AES_KEY_SIZE);

  // Send confirmation with hash
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
// LoRa Simulated Functions (Placeholder for RadioLib)
// =============================================================
// Note: For actual use, include RadioLib and implement proper SX1262 driver
// This is a placeholder that s
imulates LoRa communication via Serial for testing

class MockLoRa {
public:
    bool begin() {
        Serial.println("[LoRa] Mock LoRa initialized (simulated)");
        return true;
    }

    bool available() {
        // Check if there's data on Serial (simulating LoRa)
        return Serial.available() > 0;
    }

    int read(uint8_t* buf, int len) {
        // Read from Serial
        int available = Serial.available();
        int toRead = min(len, available);
        for (int i = 0; i < toRead; i++) {
            buf[i] = Serial.read();
        }
        return toRead;
    }

    uint8_t read() {
        return Serial.read();
    }

    void write(const uint8_t* buf, int len) {
        Serial.write(buf, len);
    }

    void write(uint8_t byte) {
        Serial.write(byte);
    }

    void flush() {
        Serial.flush();
    }

    // For actual RadioLib implementation, uncomment and configure:
    /*
    #include <RadioLib.h>
    SX1262 radio = new Module(LORA_CS_PIN, LORA_DIO1_PIN, LORA_RESET_PIN, LORA_BUSY_PIN);
    
    bool begin() {
        int state = radio.begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SPREADING_FACTOR, 
                                LORA_CODING_RATE, LORA_SYNC_WORD, LORA_PREAMBLE_LENGTH);
        if (state == RADIOLIB_ERR_NONE) {
            Serial.println("[LoRa] SX1262 initialized");
            radio.setDio1Action(setFlag);
            return true;
        }
        Serial.printf("[LoRa] SX1262 init failed: %d\n", state);
        return false;
    }
    
    static volatile bool receivedFlag = false;
    static void setFlag() { receivedFlag = true; }
    
    bool available() { return receivedFlag; }
    
    int read(uint8_t* buf, int len) {
        int state = radio.readData(buf, len);
        if (state == RADIOLIB_ERR_NONE) {
            receivedFlag = false;
            return len;
        }
        return 0;
    }
    
    void write(const uint8_t* buf, int len) {
        radio.transmit(buf, len);
    }
    */
};

MockLoRa
 lora;

// =============================================================
// Authentication State Machine
// =============================================================

enum AuthState {
    STATE_WAITING_FOR_KEY,
    STATE_WAITING_FOR_CHALLENGE,
    STATE_COMPUTING_RESPONSE,
    STATE_WAITING_FOR_RESULT
};

AuthState currentState = STATE_WAITING_FOR_KEY;

// =============================================================
// Global e-Paper Instance
// =============================================================

ShallotEPD epd;

// =============================================================
// Setup
// =============================================================

void setup() {
    Serial.begin(115200);
    Serial1.begin(115200);  // UART to UNO Q

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    delay(2000);

    Serial.println("============================================");
    Serial.println("SHALLOT PAW Main Firmware");
    Serial.println("Hardware: Adafruit Feather RP2350");
    Serial.println("Components: Core1262 LoRa + e-Paper");
    Serial.println("============================================");

    // Initialize e-Paper
    Serial.println("[PRO-57] Initializing e-Paper...");
    if (!epd.begin()) {
        Serial.println("[PRO-57] e-Paper initialization FAILED!");
    } else {
        Serial.println("[PRO-57] e-Paper initialized.");
        epd.clear();
        epd.showStatus(EPD_STATUS_AUTHENTICATING);
    }

    // Initialize SPI1 for Core1262 (PRO-28)
    SPI1.setSCK(LORA_SCK_PIN);
    SPI1.setTX(LORA_MOSI_PIN);
    SPI1.setRX(LORA_MISO_PIN);
    SPI1.begin();
    Serial.println("[PRO-28] SPI1 initialized for Core1262.");

    // Initialize LoRa (mock for now)
    Serial.println("[PRO-58] Initializing LoRa...");
    if (!lora.begin()) {
        Serial.println("[PRO-58] LoRa initialization FAILED!");
    } else {
        Serial.println("[PRO-58] LoRa initialized.");
    }

    // Step 1: Receive key from UNO Q
    Serial.println("[PRO-48] Starting key reception...");
    if (receiveKeyFromUNOQ()) {
        currentState = STATE_WAITING_FOR_CHALLENGE;
        Serial.println("[PRO-48] Key received successfully.");
        digitalWrite(LED_BUI
LTIN, HIGH);
        
        // Update e-Paper to show waiting for challenge
        epd.begin();
        epd.showStatus(EPD_STATUS_AUTHENTICATING);
    } else {
        Serial.println("[PRO-48] Key reception FAILED!");
        currentState = STATE_WAITING_FOR_KEY;
        // Show error on e-Paper
        epd.begin();
        epd.showStatus(EPD_STATUS_FAILED);
    }
}

// =============================================================
// Loop
// =============================================================

void loop() {
    static uint32_t lastChallengeTime = 0;
    static uint8_t challenge[CHALLENGE_SIZE];
    static uint8_t response[HMAC_SIZE];

    switch (currentState) {
        case STATE_WAITING_FOR_KEY:
            // Try to receive key again
            if (receiveKeyFromUNOQ()) {
                currentState = STATE_WAITING_FOR_CHALLENGE;
                digitalWrite(LED_BUILTIN, HIGH);
                epd.begin();
                epd.showStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_WAITING_FOR_CHALLENGE:
            // Listen for challenge from PLC
            if (Serial.available() > 0) {
                uint8_t msgType = Serial.read();
                
                if (msgType == MSG_CHALLENGE) {
                    Serial.println("[PRO-50] Challenge received from PLC");
                    
                    // Read challenge (16 bytes)
                    if (Serial.available() >= CHALLENGE_SIZE) {
                        Serial.readBytes(challenge, CHALLENGE_SIZE);
                        lastChallengeTime = millis();
                        currentState = STATE_COMPUTING_RESPONSE;
                        
                        // Show computing state on e-Paper
                        epd.begin();
                        epd.showStatus(EPD_STATUS_AUTHENTICATING);
                        
                        Serial.print("[PRO-50] Challenge: ");
                        for (int i = 0; i < CHALLENGE
_SIZE; i++) {
                            Serial.printf("%02X", challenge[i]);
                        }
                        Serial.println();
                    }
                }
            }
            
            // Timeout check
            if (millis() - lastChallengeTime > CHALLENGE_TIMEOUT && lastChallengeTime > 0) {
                currentState = STATE_WAITING_FOR_CHALLENGE;
                lastChallengeTime = 0;
                Serial.println("[PRO-50] Challenge timeout.");
                epd.begin();
                epd.showStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_COMPUTING_RESPONSE:
            // Compute HMAC-SHA256 response
            if (keyStored && aesKey != nullptr) {
                hmac_sha256(aesKey, AES_KEY_SIZE, challenge, CHALLENGE_SIZE, response);
                
                Serial.print("[PRO-50] Response computed: ");
                for (int i = 0; i < HMAC_SIZE; i++) {
                    Serial.printf("%02X", response[i]);
                }
                Serial.println();
                
                // Send response to PLC
                Serial.write(MSG_RESPONSE);
                Serial.write(response, HMAC_SIZE);
                Serial.flush();
                
                Serial.println("[PRO-50] Response sent to PLC");
                currentState = STATE_WAITING_FOR_RESULT;
                
                // Clear sensitive data
                memset(challenge, 0, CHALLENGE_SIZE);
            } else {
                Serial.println("[PRO-50] ERROR: No key stored!");
                currentState = STATE_WAITING_FOR_KEY;
                epd.begin();
                epd.showStatus(EPD_STATUS_FAILED);
            }
            break;

        case STATE_WAITING_FOR_RESULT:
            // Wait for authentication result from PLC
            if (Serial.available() > 0) {
                uint8_t result = Serial.read();
                
                if (result == 0x01) {  // Success
                    Serial.println("[PRO-50] Authentication SUCCESS");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    
            
        // Show success on e-Paper
                    epd.begin();
                    epd.showStatus(EPD_STATUS_AUTHENTICATED);
                    
                    // Blink LED to indicate success
                    for (int i = 0; i < 5; i++) {
                        digitalWrite(LED_BUILTIN, HIGH);
                        delay(100);
                        digitalWrite(LED_BUILTIN, LOW);
                        delay(100);
                    }
                } else if (result == 0x00) {  // Failure
                    Serial.println("[PRO-50] Authentication FAILED");
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    
                    // Show failure on e-Paper
                    epd.begin();
                    epd.showStatus(EPD_STATUS_FAILED);
                    
                    // Blink LED rapidly to indicate failure
                    for (int i = 0; i < 10; i++) {
                        digitalWrite(LED_BUILTIN, HIGH);
                        delay(50);
                        digitalWrite(LED_BUILTIN, LOW);
                        delay(50);
                    }
                }
            }
            break;
    }

    // Heartbeat
    static uint32_t lastHeartbeat = 0;
    if (millis() - lastHeartbeat > 1000) {
        lastHeartbeat = millis();
        
        if (keyStored) {
            digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
        } else {
            // No key: blink rapidly
            digitalWrite(LED_BUILTIN, (millis() / 200) % 2);
        }
    }

    // Small delay to prevent CPU overload
    delay(10);
}
