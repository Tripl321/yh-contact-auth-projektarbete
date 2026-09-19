/*
 * SHALLOT PAW Main Firmware
 * Target: Adafruit Feather RP2350 + Core1262-868M + 1.54" Waveshare e-Paper
 * 
 * Full PAW firmware combining:
 *   - PRO-47: secure key storage in SRAM (clear on timeout/disconnect/reset)
 *   - PRO-48: Key reception from UNO Q (paw-key-receiver.ino)
 *   - PRO-50: HMAC-SHA256 challenge-response
 *   - PRO-57: e-Paper status display (epaper-status-display.ino)
 *   - PRO-58: e-paper status during challenge-response + LoRa P2P (RadioLib SX1262)
 *   - PRO-59: approved authentication text on e-paper
 *
 * Hardware pin mapping (Feather RP2350 silkscreen labels):
 *   USB Serial (Mama Bear): key provisioning over USB-C (no GPIO)
 *   UART Serial1 (DEN dock): TX=GPIO0, RX=GPIO1 (UART0 defaults, dock only)
 *   LoRa (SPI1):   SCK=D10, MOSI=D11, MISO=D24, CS=D9, BUSY=pin7, RESET=pin4, DIO1=A2
 *   e-Paper (SPI0):DIN=MO, CLK=SCK, CS=5, DC=A0, RST=A1, BUSY=A3
 *
 * Architecture:
 *   1. Wait for key from Mama Bear at startup over USB Serial
 *   2. Initialize LoRa (SX1262 on SPI1) and e-Paper (SPI0)
 *   3. Listen for challenge (8-byte nonce) from PLC over LoRa
 *   4. Compute HMAC-SHA256(key, nonce) and transmit response
 *   5. Update e-Paper with privacy-compliant authentication status icons
 *
 * Privacy: e-Paper shows ONLY status icons (no text, no PII)
 *   States: AUTHENTICATING, AUTHENTICATED, FAILED
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <DenUartProtocol.h>  // PRO-84/87: dock framing from shared module
#include <ShallotCrypto.h>  // PRO-49: SHA/HMAC/KDF/wipe from shared module

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
#define LORA_SCK_PIN     10  // SCK pin on Feather silkscreen (GPIO10)
#define LORA_MOSI_PIN    11  // MOSI pin on Feather silkscreen (GPIO11)
#define LORA_MISO_PIN    24  // D24 on Feather silkscreen (GPIO24, hardware SPI1 MISO)
#define LORA_CS_PIN      9   // Pin 9 on Feather silkscreen (GPIO9)
#define LORA_BUSY_PIN    7   // Pin 7 on Feather silkscreen (GPIO7)
#define LORA_RESET_PIN   4   // Pin 4 on Feather silkscreen (GPIO4, digital output for RESET)
#define LORA_DIO1_PIN    A2  // A2 on Feather silkscreen (GPIO28)

// --- e-Paper (SPI0) ---
#define EPD_DIN_PIN      MO  // MO pin on Feather silkscreen (SPI0 MOSI - GPIO23)
#define EPD_CLK_PIN      SCK // SCK pin on Feather silkscreen (SPI0 SCK - GPIO22)
#define EPD_CS_PIN       5   // Pin 5 on Feather silkscreen (GPIO5)
#define EPD_DC_PIN       A0  // A0 on Feather silkscreen (GPIO26)
#define EPD_RST_PIN      A1  // A1 on Feather silkscreen (GPIO27)
#define EPD_BUSY_PIN     A3  // A3 on Feather silkscreen (GPIO29)

// --- Transports (split, never shared) ---
// USB Serial: Mama Bear key provisioning (PRO-48) + logs.
// Serial1: DEN dock ONLY, TX=GPIO0, RX=GPIO1 (UART0 defaults).

// =============================================================
// SPI1 Instance for Core1262
// =============================================================
// SPIClassRP2040 constructor: (spi_inst_t *spi, rx_pin, cs_pin, sck_pin, tx_pin)
SPIClassRP2040 loraSPI(spi1, LORA_MISO_PIN, LORA_CS_PIN, LORA_SCK_PIN, LORA_MOSI_PIN);

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
#define TARGET_PAW       0x02
#define TARGET_PLC       0x01

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE     16
#define KEY_HASH_SIZE     4
#define CHALLENGE_SIZE    8  // Nonce size (PRO-51: 64-bit RNG)
#define HMAC_SIZE         32  // HMAC-SHA256 output

// PRO-93: Debug configuration — must be explicitly defined to enable
// sensitive diagnostic output. Off by default (define SECURE_DEBUG=1 to enable).
#ifdef SECURE_DEBUG
#define SECURE_DEBUG 1
#endif

// =============================================================
// e-Paper Display Constants
// =============================================================

#define EPD_WIDTH        200
#define EPD_HEIGHT       200
#define EPD_BUFFER_SIZE  ((EPD_WIDTH / 8) * EPD_HEIGHT)

// BUSY bounds (PRO-11). Bench-measured full refresh on the 1.54" B V2 is
// ~18 s: completion may take up to 90 s, init-phase steps only 2 s each.
// A stuck BUSY (wedged/disconnected panel) must degrade, never hang.
#define EPD_REFRESH_TIMEOUT_MS 90000
#define EPD_INIT_TIMEOUT_MS    2000

// =============================================================
// Key Storage (PRO-47 + PRO-49)
// =============================================================
//
// Key hierarchy (SRAM-only, never flash/serial):
//   aesKey   : master key (128-bit, received from UNO Q via USB provisioning)
//   kMac     : HMAC-SHA256 key (derived: SHA-256(master || "MAC")[:16])
//   kEnc     : encryption key (derived: SHA-256(master || "ENC")[:16], reserved)
//
// All three roles are kept in separate SRAM buffers. Boundaries are
// enforced by naming convention: never mix key material across roles
// without explicit derivation. Key material is NEVER written to flash,
// logs, or serial output. Only the 4-byte SHA-256 fingerprint is transmitted.
//
// PRO-49: K_mac is derived on key receipt via hardware-accelerated SHA-256
// where available (RP2350 SHA accelerator), falling back to software.
// HMAC always uses K_mac, never the master key directly.
// =============================================================

static uint8_t aesKey[AES_KEY_SIZE];
static uint8_t kMac[AES_KEY_SIZE];   // derived HMAC key (PRO-49)
static uint8_t kEnc[AES_KEY_SIZE];   // derived encryption key (reserved)
static bool keyStored = false;

static void secure_clear_key() {
    volatile uint8_t* k = (volatile uint8_t*)aesKey;
    for (int i = 0; i < AES_KEY_SIZE; i++) k[i] = 0;
    volatile uint8_t* m = (volatile uint8_t*)kMac;
    for (int i = 0; i < AES_KEY_SIZE; i++) m[i] = 0;
    volatile uint8_t* e = (volatile uint8_t*)kEnc;
    for (int i = 0; i < AES_KEY_SIZE; i++) e[i] = 0;
    keyStored = false;
}

// Validated retrieval: a stored key is usable only when the flag is set
// AND the master buffer is non-zero. An all-zero master is
// indistinguishable from unprovisioned/wiped SRAM, so it must never
// authenticate (fail closed on corrupt key).
static bool key_is_valid() {
    if (!keyStored) return false;
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        if (aesKey[i] != 0) return true;
    }
    return false;
}

// PRO-49: K_mac derivation lives in <ShallotCrypto.h>
// (shalot_derive_k_mac) — single shared implementation.
static const uint8_t deviceId[4] = { 0x50, 0x41, 0x57, 0x01 }; // "PAW\x01"

// =============================================================
// Waveform LUT for e-Paper
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
// e-Paper Driver Class
// =============================================================

class ShallotEPD {
public:
    ShallotEPD();
    bool begin();
    void sleep();
    void clear();
    void displayFrame(const uint8_t* frameBuffer);
    // showStatus draws the icon and STARTS the refresh, then returns
    // immediately (never waits). Call poll() every loop pass to complete
    // the refresh, run the post-BLANK sleep, or degrade on BUSY timeout.
    void showStatus(EpdStatus status);
    void poll();

private:
    void sendCommand(uint8_t cmd);
    void sendData(uint8_t data);
    // Bounded BUSY wait: true when idle, false on timeout (never hangs).
    bool waitUntilIdle(uint32_t timeoutMs);
    void reset();
    void setLut(const unsigned char* lut);

    void clearBuffer();
    void drawPixel(int x, int y, bool white);
    void drawLine(int x0, int y0, int x1, int y1, bool white);
    void drawRect(int x, int y, int w, int h, bool white);
    void drawCircle(int cx, int cy, int r, bool white);
    void drawCircleFilled(int cx, int cy, int r, bool white);
    void drawIcon(int cx, int cy, int size, EpdStatus status);
    void drawChar(char c, int x, int y);
    void drawText(const char* text, int x, int y);

    uint8_t _buffer[EPD_BUFFER_SIZE];
    // Async refresh state (PRO-11): transmit starts in showStatus/clear,
    // completion (or BUSY-timeout degrade) happens in poll(). Never blocks.
    bool _degraded = false;      // latched on BUSY timeout: skip all future work
    bool _updateBusy = false;    // refresh in flight
    uint32_t _updateStart = 0;   // millis at trigger
    bool _pendingSleep = false;  // BLANK path sleeps after completion
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

bool ShallotEPD::waitUntilIdle(uint32_t timeoutMs) {
    uint32_t t0 = millis();
    while (digitalRead(EPD_BUSY_PIN) == HIGH) {
        if (millis() - t0 > timeoutMs) return false;
        delay(10);
    }
    delay(200);
    return true;
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
    // Best-effort wait: begin() re-checks idleness with its own bound.
    waitUntilIdle(EPD_INIT_TIMEOUT_MS);
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
    SPI.begin();
    SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));

    reset();
    if (!waitUntilIdle(EPD_INIT_TIMEOUT_MS)) return false;

    sendCommand(0x12);  // SWRESET
    if (!waitUntilIdle(EPD_INIT_TIMEOUT_MS)) return false;

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
    if (!waitUntilIdle(EPD_INIT_TIMEOUT_MS)) return false;

    setLut(WF_FULL_1IN54);
    if (!waitUntilIdle(EPD_INIT_TIMEOUT_MS)) return false;
    return true;
}

// Transmit-only frame update: sends the buffer and arms completion for
// poll(). Never waits — call poll() every loop pass.
void ShallotEPD::clear() {
    clearBuffer();
    sendCommand(0x26);  // red plane white (preserves original clear behavior)
    for (int i = 0; i < EPD_BUFFER_SIZE; i++) sendData(0xFF);
    displayFrame(_buffer);
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
    // No wait here: poll() completes the refresh (or degrades on timeout).
    _updateBusy = true;
    _updateStart = millis();
}

void ShallotEPD::sleep() {
    sendCommand(0x10);  // Enter deep sleep
    sendData(0x01);
    delay(200);
    digitalWrite(EPD_RST_PIN, LOW);
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

// =============================================================
// 5x7 Bitmap Font (uppercase A-Z, space)
// =============================================================
// Each glyph is 7 bytes (7 rows, 5 columns). Bits 4..0 map to
// columns left..right. Bit set = black pixel.
static const uint8_t FONT_5X7[][7] = {
    {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},  // A
    {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},  // B
    {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},  // C
    {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E},  // D
    {0x1F, 0x10, 0x10, 0x1C, 0x10, 0x10, 0x1F},  // E
    {0x1F, 0x10, 0x10, 0x1C, 0x10, 0x10, 0x10},  // F
    {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0E},  // G
    {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},  // H
    {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},  // I
    {0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C},  // J
    {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},  // K
    {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},  // L
    {0x11, 0x1B, 0x15, 0x11, 0x11, 0x11, 0x11},  // M
    {0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11},  // N
    {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},  // O
    {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},  // P
    {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},  // Q
    {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},  // R
    {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},  // S
    {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},  // T
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},  // U
    {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},  // V
    {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A},  // W
    {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},  // X
    {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},  // Y
    {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},  // Z
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}   // space
};

void ShallotEPD::drawChar(char c, int x, int y) {
    if (c >= 'A' && c <= 'Z') {
        const uint8_t* glyph = FONT_5X7[c - 'A'];
        for (int row = 0; row < 7; row++) {
            uint8_t bits = glyph[row];
            for (int col = 0; col < 5; col++) {
                if (bits & (0x10 >> col)) {
                    drawPixel(x + col, y + row, false);
                }
            }
        }
    } else if (c == ' ') {
        // space: advance cursor only
    }
}

void ShallotEPD::drawText(const char* text, int x, int y) {
    while (*text) {
        drawChar(*text++, x, y);
        x += 6;
    }
}

void ShallotEPD::showStatus(EpdStatus status) {
    if (_degraded) return;  // fail silent: display stays as-is, loop stays fast
    if (status == EPD_STATUS_BLANK) {
        clearBuffer();
        displayFrame(_buffer);
        _pendingSleep = true;
        return;
    }

    clearBuffer();
    drawRect(4, 4, EPD_WIDTH - 8, EPD_HEIGHT - 8, false);

    int centerX = EPD_WIDTH / 2;
    int centerY = EPD_HEIGHT / 2;
    int iconRadius = 50;

    drawIcon(centerX, centerY, iconRadius, status);
    if (status == EPD_STATUS_AUTHENTICATED) {
        drawText("AUTHENTICATED", 61, 160);
    }
    displayFrame(_buffer);
    _pendingSleep = false;
}

// Background completion for an armed refresh. Cheap when idle: one GPIO
// read per pass. On BUSY timeout latches degraded mode (log once) so all
// future display work is skipped and auth/LoRa timing is unaffected.
void ShallotEPD::poll() {
    if (_degraded || !_updateBusy) return;
    if (digitalRead(EPD_BUSY_PIN) == LOW) {
        _updateBusy = false;
        if (_pendingSleep) {
            _pendingSleep = false;
            sleep();
        }
        return;
    }
    if (millis() - _updateStart > EPD_REFRESH_TIMEOUT_MS) {
        _degraded = true;
        _updateBusy = false;
        _pendingSleep = false;
        Serial.println("[EPD] BUSY timeout - degraded display mode, dock auth continues");
    }
}

// SHA-256, HMAC-SHA256 and KDF live in <ShallotCrypto.h> (single shared
// implementation, KAT-verified). Local copies removed (ticket 02).

// =============================================================
// CRC32 Implementation (framing-adjacent; not part of ShallotCrypto)
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

// HMAC-SHA256 lives in <ShallotCrypto.h> (shalot_hmac_sha256).
// Local copy removed (ticket 02).

// =============================================================
// Key Reception from Mama Bear over USB Serial (PRO-48, PRO-11 poll)
// =============================================================
//
// Non-blocking poll: each call consumes only already-available USB
// bytes and returns immediately, so the Serial1 dock parser is never
// delayed. Partial state lives in static storage and is wiped on every
// failure/timeout (fail-closed: nothing staged, nothing stored).
// Wire behavior identical to the old blocking version: handshake pair
// scan -> READY -> exactly 22 key-data bytes -> strict tag/len/CRC
// checks -> store + fingerprint + STORED.

 // Poll result codes (uint8_t to keep the Arduino preprocessor happy).
#define PROV_PENDING 0  // no complete attempt yet this pass; call again
#define PROV_DONE    1  // key validated, stored, STORED sent
#define PROV_FAILED  2  // attempt concluded negatively; state reset, retry next pass

#define PROV_PH_HANDSHAKE 0
#define PROV_PH_KEYDATA   1
#define PROV_KEYDATA_LEN  22  // type(1) + len(1) + key(16) + crc(4)

static uint8_t provPhase = PROV_PH_HANDSHAKE;
static uint32_t provT0 = 0;
static uint8_t provBuf[PROV_KEYDATA_LEN];
static uint8_t provGot = 0;

static uint8_t pollProvisioning() {
    if (provPhase == PROV_PH_HANDSHAKE) {
        // Scan pairs exactly like the original step 1 (non-matching pairs
        // are skipped, same as before).
        while (Serial.available() >= 2) {
            uint8_t msgType = Serial.read();
            uint8_t targetId = Serial.read();
            if (msgType == MSG_HANDSHAKE && targetId == TARGET_PAW) {
#if SECURE_DEBUG
                Serial.println("[PRO-48] Handshake received.");
                Serial.print("[PRO-48] Sending READY with device ID: ");
                for (int i = 0; i < 4; i++) Serial.printf("%02X", deviceId[i]);
                Serial.println();
#endif
                Serial.write(MSG_READY);
                Serial.write(deviceId, 4);
                Serial.flush();
                provPhase = PROV_PH_KEYDATA;
                provT0 = millis();
                provGot = 0;
                memset(provBuf, 0, sizeof(provBuf));
                // PRO-47: new provisioning session starts - clear any
                // previously stored key (SRAM hygiene, fail-closed).
                secure_clear_key();
                return PROV_PENDING;
            }
        }
        return PROV_PENDING;
    }

    // PROV_PH_KEYDATA: accumulate exactly 22 bytes, bounded by the same
    // 10 s window the old blocking wait used.
    while (provGot < PROV_KEYDATA_LEN && Serial.available()) {
        provBuf[provGot++] = (uint8_t)Serial.read();
    }
    if (provGot < PROV_KEYDATA_LEN) {
        if (millis() - provT0 > KEY_DISTRIBUTION_TIMEOUT) {
#if SECURE_DEBUG
            Serial.println("[PRO-48] Timeout waiting for key data.");
#endif
            provPhase = PROV_PH_HANDSHAKE;
            provGot = 0;
            memset(provBuf, 0, sizeof(provBuf));
            // PRO-47: timeout -> clear stored key (fail-closed).
            secure_clear_key();
            return PROV_FAILED;
        }
        return PROV_PENDING;
    }

    uint8_t outcome = PROV_FAILED;
    do {
        if (provBuf[0] != MSG_KEY_DATA) {
#if SECURE_DEBUG
            Serial.printf("[PRO-48] Expected KEY_DATA, got 0x%02X\n", provBuf[0]);
#endif
            break;
        }
        if (provBuf[1] != AES_KEY_SIZE) {
#if SECURE_DEBUG
            Serial.printf("[PRO-48] Unexpected key length: %d\n", provBuf[1]);
#endif
            break;
        }
        uint32_t receivedCrc = ((uint32_t)provBuf[18] << 24)
                             | ((uint32_t)provBuf[19] << 16)
                             | ((uint32_t)provBuf[20] << 8)
                             | ((uint32_t)provBuf[21]);
        uint32_t computedCrc = crc32(provBuf + 2, AES_KEY_SIZE);
        if (computedCrc != receivedCrc) {
#if SECURE_DEBUG
            Serial.printf("[PRO-48] CRC mismatch! Expected: %08X Got: %08X\n",
                          computedCrc, receivedCrc);
#endif
            Serial.write(MSG_ERROR);
            break;
        }
#if SECURE_DEBUG
        Serial.println("[PRO-48] CRC verified OK.");
#endif

        // Fail-closed: an all-zero master is indistinguishable from
        // unprovisioned/wiped SRAM — reject it as corrupt (never store).
        {
            bool allZero = true;
            for (int i = 0; i < AES_KEY_SIZE; i++) {
                if (provBuf[2 + i] != 0) { allZero = false; break; }
            }
            if (allZero) {
#if SECURE_DEBUG
                Serial.println("[PRO-48] Zero key rejected.");
#endif
                Serial.write(MSG_ERROR);
                break;
            }
        }

        // Store key securely
        memcpy(aesKey, provBuf + 2, AES_KEY_SIZE);
        keyStored = true;

        // PRO-49: Derive K_mac from master key (SRAM-only, never exposed)
        shalot_derive_k_mac(aesKey, kMac);

        // Send confirmation with hash (fingerprint only, never key bytes)
        uint8_t fullHash[32];
        shalot_sha256(aesKey, AES_KEY_SIZE, fullHash);
        uint8_t keyHash[KEY_HASH_SIZE];
        memcpy(keyHash, fullHash, KEY_HASH_SIZE);
        memset(fullHash, 0, 32);

        Serial.write(MSG_STORED);
        Serial.write(keyHash, KEY_HASH_SIZE);
        Serial.flush();
#if SECURE_DEBUG
        Serial.print("[PRO-48] Key stored. Hash sent: ");
        for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
        Serial.println();
#endif
        outcome = PROV_DONE;
    } while (0);

    memset(provBuf, 0, sizeof(provBuf));
    provGot = 0;
    provPhase = PROV_PH_HANDSHAKE;
    // PRO-47: on any failure, ensure no stale key remains in SRAM.
    if (outcome != PROV_DONE) {
        secure_clear_key();
    }
    return outcome;
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

// PRO-95: bounded grant indication. The AUTHENTICATED e-paper image is a
// stale-access risk if shown indefinitely (e-paper is bistable and keeps
// the image without power). A grant is therefore only *displayed* for
// AUTH_GRANTED_DISPLAY_MS; afterwards the display reverts to the locked
// AUTHENTICATING indication. Protocol state already returns to
// STATE_WAITING_FOR_CHALLENGE at grant time, so this only bounds the
// human-readable indication — DEN re-locks after DEN_SESSION_GAP_MS.
#define AUTH_GRANTED_DISPLAY_MS 30000  // ms, same scale as CHALLENGE_TIMEOUT
static uint32_t authGrantedAt = 0;
static bool authDisplayed = false;

// =============================================================
// Docked UART responder (PRO-84, DEN link over Serial1)
// =============================================================
//
// Responder-only: PAW never initiates UART traffic. Valid CHALLENGE
// frames (exactly 8-byte nonce) are answered with a framed RESPONSE
// carrying HMAC-SHA256(devkey, nonce) via the existing PRO-50
// hmac_sha256 (reused, not duplicated). Everything else — malformed,
// CRC-invalid, oversized, timed-out, unexpected type — is logged and
// ignored with zero state change (fail-closed). LoRa flow untouched.
//
// =============================================================
// Docked UART auth (PRO-84 bridge to DEN)
// =============================================================
//
// PAW responds to DEN CHALLENGE with HMAC-SHA256(K_mac, nonce)
// over the dock connector (Serial1). K_mac is derived from the
// provisioned AES-128 master key (see aesKey above).
//
// PRO-93: No hardcoded development key. Authentication is
// fail-closed: if no key is provisioned (keyStored == false),
// all dock auth attempts are rejected.
// =============================================================

static den_scanner_t denScanner;

// e-Paper instance lives below (Global e-Paper Instance); declared here
// so the responder can show AUTHENTICATING on dock activity.
extern ShallotEPD epd;

// PAW-side ACK watchdog (PRO-60). Not a state machine: a single flag + timer
// that only drives the e-paper. It never affects DEN deadlines or auth.
static uint32_t paw_last_resp_sent_at = 0;
static bool paw_ack_pending = false;

static void handleDockAuth() {
    uint32_t now = millis();

    // PAW-side ACK watchdog: if we sent a RESPONSE and got no ACK
    // within 2.5 s, show FAILED. This is display-only; DEN is
    // authoritative for auth and its 2 s deadline is unaffected.
    if (paw_ack_pending && now - paw_last_resp_sent_at > 2500) {
        epd.showStatus(EPD_STATUS_FAILED);
        paw_ack_pending = false;
        Serial.println("[PRO-60] PAW ACK timeout -> FAILED on e-paper");
    }

    while (Serial1.available()) {
        den_frame_t f;
        den_status_t st = den_scanner_push(&denScanner, (uint8_t)Serial1.read(), now, &f);
        if (st == DEN_INCOMPLETE) continue;
        if (st != DEN_OK) {
#if SECURE_DEBUG
            Serial.print("[PRO-84] Dock frame rejected, code ");
            Serial.println((int)st);
#endif
            continue;  // fail-closed: keep seeking SYNC, change nothing
        }
        if (f.type == DEN_TYPE_CHALLENGE) {
                 // PRO-94: fail-closed without a valid provisioned key. Never
                 // answer (and never touch display state) when missing or
                 // corrupt (all-zero): an HMAC under a wiped/zero key is not
                 // a credential.
                 if (!key_is_valid()) {
#if SECURE_DEBUG
                     Serial.println("[PRO-84] CHALLENGE ignored, no key stored");
#endif
                     continue;
                 }
                 epd.showStatus(EPD_STATUS_AUTHENTICATING);
                 // den_decode guarantees payloadLen == DEN_NONCE_LEN (8) here.
                 uint8_t mac[DEN_HMAC_LEN];
                 shalot_hmac_sha256(kMac, AES_KEY_SIZE, f.payload, f.payloadLen, mac);
             uint8_t resp[DEN_MAX_FRAME];
             size_t n = den_encode(DEN_TYPE_RESPONSE, mac, DEN_HMAC_LEN, resp, sizeof(resp));
             memset(mac, 0, sizeof(mac));
             if (!n) {
#if SECURE_DEBUG
                 Serial.println("[PRO-84] Response encode failed");
#endif
                 continue;
             }
            Serial1.write(resp, n);
             Serial1.flush();
             paw_last_resp_sent_at = now;
             paw_ack_pending = true;
             memset(resp, 0, sizeof(resp));
#if SECURE_DEBUG
            Serial.println("[PRO-84] CHALLENGE answered over dock UART");
#endif
        } else if (f.type == DEN_TYPE_ACK) {
            if (!paw_ack_pending) {
                // Late ACK after PAW timeout: ignore to avoid
                // overwriting FAILED for a session that already
                // timed out from PAW's perspective.
#if SECURE_DEBUG
                Serial.println("[PRO-84] ACK ignored (no pending response)");
#endif
                continue;
            }
            paw_ack_pending = false;
            if (f.payloadLen == 1 && f.payload[0] == 0x01) {
                 epd.showStatus(EPD_STATUS_AUTHENTICATED);
                 authGrantedAt = millis();  // PRO-95: arm the display window
                 authDisplayed = true;
#if SECURE_DEBUG
                 Serial.println("[PRO-84] DEN acknowledged success");
#endif
             } else {
                 epd.showStatus(EPD_STATUS_FAILED);
#if SECURE_DEBUG
                 Serial.println("[PRO-84] DEN denied (ACK 0x00)");
#endif
             }
         } else {
#if SECURE_DEBUG
             Serial.print("[PRO-84] Dock frame ignored, type 0x");
             Serial.println(f.type, HEX);
#endif
        }
    }
}

// =============================================================
// Global e-Paper Instance
// =============================================================

ShallotEPD epd;

// =============================================================
// Setup
// =============================================================

void setup() {
    Serial.begin(115200);
    Serial1.begin(115200);  // DEN dock only (TX=GPIO0, RX=GPIO1)
    den_scanner_init(&denScanner);

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    delay(2000);

    Serial.println("============================================");
    Serial.println("SHALLOT PAW Main Firmware");
    Serial.println("Hardware: Adafruit Feather RP2350");
    Serial.println("Components: Core1262 LoRa + e-Paper");
    Serial.println("============================================");

    // PRO-47: secure boot - clear any residual key material from SRAM
    secure_clear_key();

    // Initialize e-Paper (bounded init; a dead panel degrades instead of
    // hanging boot — dock auth starts on the first loop passes regardless).
    Serial.println("[PRO-57] Initializing e-Paper...");
    if (!epd.begin()) {
        Serial.println("[PRO-57] e-Paper initialization FAILED (degraded mode).");
    } else {
        Serial.println("[PRO-57] e-Paper initialized.");
    }
    epd.showStatus(EPD_STATUS_AUTHENTICATING);  // request only, returns fast

    // Initialize SPI1 for Core1262
    loraSPI.begin();
    Serial.println("[PRO-28] SPI1 initialized for Core1262.");

    // Initialize LoRa SX1262 via RadioLib
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

    // Key reception runs via pollProvisioning() in loop() (non-blocking);
    // boot never waits for a key, so dock auth starts immediately.
    Serial.println("[PRO-48] Key reception via loop poll (non-blocking)...");
    currentState = STATE_WAITING_FOR_KEY;
    epd.showStatus(EPD_STATUS_AUTHENTICATING);
}

// =============================================================
// Loop
// =============================================================

void loop() {
    static uint32_t lastChallengeTime = 0;
    static uint8_t challenge[CHALLENGE_SIZE];
    static uint8_t response[HMAC_SIZE];
    static uint8_t rxBuffer[64];

    // 1. Docked UART (DEN) responder poll FIRST: keeps challenge->answer
    // latency minimal so a slow LoRa pass cannot push it past the 2 s
    // session deadline. Passive, never initiates.
    handleDockAuth();

    // 2. e-Paper background completion (microseconds when idle; never waits).
    epd.poll();

    // 3. Check for incoming LoRa packet via interrupt flag
    if (loraInitialized && loraPacketReceived) {
        loraPacketReceived = false;

        size_t rxLen = radio.getPacketLength();
        if (rxLen > sizeof(rxBuffer)) rxLen = sizeof(rxBuffer);

        int state = radio.readData(rxBuffer, rxLen);
        if (state == RADIOLIB_ERR_NONE && rxLen > 0) {
            uint8_t msgType = rxBuffer[0];
#if SECURE_DEBUG
            Serial.printf("[LoRa RX] Type: 0x%02X, Length: %u bytes, RSSI: %.1f dBm, SNR: %.1f dB\n",
                          msgType, (unsigned)rxLen, radio.getRSSI(), radio.getSNR());
#endif

            // Handle MSG_CHALLENGE (0xB1)
            if (msgType == MSG_CHALLENGE && rxLen >= (1 + CHALLENGE_SIZE)) {
#if SECURE_DEBUG
                Serial.println("[PRO-50] Challenge received from PLC over LoRa");
#endif
                memcpy(challenge, rxBuffer + 1, CHALLENGE_SIZE);
                lastChallengeTime = millis();
                currentState = STATE_COMPUTING_RESPONSE;

                epd.showStatus(EPD_STATUS_AUTHENTICATING);
#if SECURE_DEBUG
                Serial.print("[PRO-50] Challenge nonce: ");
                for (int i = 0; i < CHALLENGE_SIZE; i++) Serial.printf("%02X", challenge[i]);
                Serial.println();
#endif
            }
            // Handle MSG_RESULT (0xB3)
            // Grant-gated like the dock ACK path (paw_ack_pending): an
            // unsolicited RESULT must never drive the display. Only a
            // RESULT for a response we actually sent (WAITING_FOR_RESULT)
            // may show AUTHENTICATED; anything else leaves the display
            // untouched (ongoing/denied never shows authenticated).
            else if (msgType == MSG_RESULT && rxLen >= 2) {
                if (currentState != STATE_WAITING_FOR_RESULT) {
#if SECURE_DEBUG
                    Serial.println("[PRO-50] RESULT ignored (no pending response)");
#endif
                } else {
                uint8_t result = rxBuffer[1];
                if (result == 0x01) {
#if SECURE_DEBUG
                    Serial.println("[PRO-50] Authentication SUCCESS (LoRa)");
#endif
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epd.showStatus(EPD_STATUS_AUTHENTICATED);
                    authGrantedAt = millis();  // PRO-95: arm the display window
                    authDisplayed = true;

                    for (int i = 0; i < 5; i++) {
                        digitalWrite(LED_BUILTIN, HIGH);
                        delay(100);
                        digitalWrite(LED_BUILTIN, LOW);
                        delay(100);
                    }
                } else {
#if SECURE_DEBUG
                    Serial.println("[PRO-50] Authentication FAILED (LoRa)");
#endif
                    currentState = STATE_WAITING_FOR_CHALLENGE;
                    epd.showStatus(EPD_STATUS_FAILED);

                    for (int i = 0; i < 10; i++) {
                        digitalWrite(LED_BUILTIN, HIGH);
                        delay(50);
                        digitalWrite(LED_BUILTIN, LOW);
                        delay(50);
                    }
                }
                }
            }
        }
        // Resume listening on LoRa
        radio.startReceive();
    }

    // 4. Docked UART poll already ran first (see section 1).

    // 5. Main State Machine Execution
    switch (currentState) {
        case STATE_WAITING_FOR_KEY: {
            uint8_t pr = pollProvisioning();
            if (pr == PROV_DONE) {
                currentState = STATE_WAITING_FOR_CHALLENGE;
                digitalWrite(LED_BUILTIN, HIGH);
                epd.showStatus(EPD_STATUS_AUTHENTICATING);
            }
            // PROV_PENDING/PROV_FAILED: keep waiting, retry next pass.
            break;
        }

        case STATE_WAITING_FOR_CHALLENGE:
            if (lastChallengeTime > 0 && (millis() - lastChallengeTime > CHALLENGE_TIMEOUT)) {
                lastChallengeTime = 0;
#if SECURE_DEBUG
                Serial.println("[PRO-50] Challenge timeout.");
#endif
                epd.showStatus(EPD_STATUS_AUTHENTICATING);
            }
            break;

        case STATE_COMPUTING_RESPONSE:
            if (key_is_valid()) {
                shalot_hmac_sha256(kMac, AES_KEY_SIZE, challenge, CHALLENGE_SIZE, response);
#if SECURE_DEBUG
                Serial.print("[PRO-50] HMAC Response computed: ");
                for (int i = 0; i < HMAC_SIZE; i++) Serial.printf("%02X", response[i]);
                Serial.println();
#endif

                // Transmit LoRa packet: [MSG_RESPONSE, response(32)]
                uint8_t txPacket[1 + HMAC_SIZE];
                txPacket[0] = MSG_RESPONSE;
                memcpy(txPacket + 1, response, HMAC_SIZE);

                if (loraInitialized) {
                    int txState = radio.transmit(txPacket, sizeof(txPacket));
                    if (txState == RADIOLIB_ERR_NONE) {
#if SECURE_DEBUG
                        Serial.println("[PRO-50] Response sent over LoRa to PLC.");
#endif
                    } else {
#if SECURE_DEBUG
                        Serial.printf("[PRO-50] LoRa transmit error: %d\n", txState);
#endif
                    }
                    radio.startReceive();
                }

                // PRO-93: HMAC response must not be sent over USB Serial
                // in production. Guarded for debugging only.
#if SECURE_DEBUG
                // Also output over Serial for debugging/telemetry
                Serial.write(MSG_RESPONSE);
                Serial.write(response, HMAC_SIZE);
                Serial.flush();
#endif

                currentState = STATE_WAITING_FOR_RESULT;
                memset(challenge, 0, CHALLENGE_SIZE);
            } else {
#if SECURE_DEBUG
                Serial.println("[PRO-50] ERROR: No key stored!");
#endif
                currentState = STATE_WAITING_FOR_KEY;
                epd.showStatus(EPD_STATUS_FAILED);
            }
            break;

        case STATE_WAITING_FOR_RESULT:
            break;
    }

    // PRO-95: grant indication expires regardless of protocol state — revert
    // a stale AUTHENTICATED image to the locked indication. Placed outside
    // the switch on purpose: WAITING_FOR_RESULT has no timeout (it waits
    // for LoRa RESULT), so a grant shown mid-session would otherwise never
    // expire. Fires at most once per grant (flag cleared on fire).
    if (authDisplayed && (millis() - authGrantedAt > AUTH_GRANTED_DISPLAY_MS)) {
        authDisplayed = false;
        epd.showStatus(EPD_STATUS_AUTHENTICATING);
    }

    // 4. Heartbeat LED Indicator
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
