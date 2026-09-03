/*
 * SHALLOT E-Paper Status Display Driver
 * Task: PRO-57 — E-Paper driver with privacy masking on PAW
 * Target: Adafruit Feather RP2350 + Waveshare 1.54inch e-Paper Module V2
 *
 * Display: 200x200 pixels, black/white, SPI Mode 0 (CPOL=0, CPHA=0)
 * Interface: SPI0 on Feather RP2350
 *
 * Privacy masking requirement:
 *   The display shows ONLY authentication status — never role, name, or any
 *   personally identifiable information. Three states are permitted:
 *     1. AUTHENTICATING  — hourglass / "..." indicator
 *     2. AUTHENTICATED   — checkmark / lock-closed indicator
 *     3. FAILED          — X mark / lock-open indicator (fail-closed)
 *
 * Hardware pin mapping (from id-kort/README.md):
 *   SPI0 on Feather RP2350:
 *     MO  (GPIO23) -> DIN  (MOSI)
 *     SCK (GPIO22) -> CLK  (SCLK)
 *     D5  (GPIO5)  -> CS   (Chip Select, active low)
 *     D24 (GPIO24) -> DC   (Data/Command)
 *     D25 (GPIO25) -> RST  (Reset)
 *     D7  (GPIO7)  -> BUSY (Busy signal)
 *     3.3V         -> VCC
 *     GND         -> GND
 *
 * Safety notes (from Waveshare manual):
 *   - Screen cannot be powered on indefinitely; enter sleep mode after each
 *     refresh to prevent high-voltage damage.
 *   - Refresh interval should be at least 180 seconds.
 *   - Full refresh at least once every 24 hours.
 *   - Full refresh produces flickering; this is normal.
 *   - After deep sleep, the display must be re-initialized before refreshing.
 *
 * Based on Waveshare epd1in54_V2 driver (MIT licensed).
 * Adapted for RP2350 + arduino-pico core by SHALLOT project.
 */

#include <Arduino.h>
#include <SPI.h>

/* ===== Pin Definitions (Feather RP2350) ===== */

#define EPD_DIN_PIN   23   // GPIO23 — SPI0 MOSI
#define EPD_CLK_PIN   22   // GPIO22 — SPI0 SCK
#define EPD_CS_PIN     5   // GPIO5  — D5  — Chip Select
#define EPD_DC_PIN    A0   // GPIO26 — A0  — Data/Command (moved from D24)
#define EPD_RST_PIN   A1   // GPIO27 — A1  — Reset (moved from D25)
#define EPD_BUSY_PIN  25   // GPIO25 — D25 — Busy (moved from D7/A3, D7 is LoRa BUSY, A3 not free)

/* ===== Display Constants ===== */

#define EPD_WIDTH   200
#define EPD_HEIGHT  200

// Buffer size: 200x200 pixels, 1 bit per pixel = 200/8 * 200 = 5000 bytes
#define EPD_BUFFER_SIZE  ((EPD_WIDTH / 8) * EPD_HEIGHT)

/* ===== Waveform LUTs (from Waveshare epd1in54_V2) ===== */

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
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x0, 0x0, 0x0,
    0x22, 0x17, 0x41, 0x0, 0x32, 0x20
};

/* ===== Privacy-Masked Status Enumeration ===== */

enum EpdStatus {
    EPD_STATUS_AUTHENTICATING = 0,
    EPD_STATUS_AUTHENTICATED  = 1,
    EPD_STATUS_FAILED         = 2,
    EPD_STATUS_BLANK          = 3  // Clear / sleep state
};

/* ===== EPD Driver Class ===== */

class ShallotEPD {
public:
    ShallotEPD();

    // Lifecycle
    bool  begin();
    void  sleep();

    // Display operations
    void  clear();
    void  displayFrame(const uint8_t* frameBuffer);
    void  setMemoryArea(int xStart, int yStart, int xEnd, int yEnd);
    void  setFrameMemory(const uint8_t* imageBuffer, int x, int y, int w, int h);

    // Low-level
    void  sendCommand(uint8_t cmd);
    void  sendData(uint8_t data);
    void  waitUntilIdle();
    void  reset();

    // Status display (privacy-masked)
    void  showStatus(EpdStatus status);

private:
    void  setLut(const unsigned char* lut);

    // Framebuffer for status rendering
    uint8_t _buffer[EPD_BUFFER_SIZE];

    void  clearBuffer();
    void  drawPixel(int x, int y, bool white);   // white=true (bit=1), black=false (bit=0)
    void  drawIcon(int cx, int cy, int size, EpdStatus status);
    void  drawRect(int x, int y, int w, int h, bool white);
    void  drawLine(int x0, int y0, int x1, int y1, bool white);
    void  drawCircle(int cx, int cy, int r, bool white);
    void  drawCircleFilled(int cx, int cy, int r, bool white);
};

/* ===== Implementation ===== */

ShallotEPD::ShallotEPD() {
    memset(_buffer, 0xFF, EPD_BUFFER_SIZE); // Initialize all white
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
    // BUSY pin: HIGH = busy, LOW = idle (per epd1in54_V2 driver)
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

    SPI.setTX(EPD_DIN_PIN);
    SPI.setSCK(EPD_CLK_PIN);
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
    sendData(0x18);    // (24+1)*8 = 200

    sendCommand(0x45);  // Set RAM-Y start/end
    sendData(0xC7);    // (199+1) = 200
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
    // Display refresh
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
    // Display refresh
    sendCommand(0x22);
    sendData(0xC7);
    sendCommand(0x20);
    waitUntilIdle();
}

void ShallotEPD::setMemoryArea(int xStart, int yStart, int xEnd, int yEnd) {
    sendCommand(0x44);
    sendData((xStart >> 3) & 0xFF);
    sendData((xEnd >> 3) & 0xFF);
    sendCommand(0x45);
    sendData(yStart & 0xFF);
    sendData((yStart >> 8) & 0xFF);
    sendData(yEnd & 0xFF);
    sendData((yEnd >> 8) & 0xFF);
}

void ShallotEPD::setFrameMemory(const uint8_t* imageBuffer, int x, int y,
                                int imageWidth, int imageHeight) {
    int xEnd, yEnd;

    digitalWrite(EPD_RST_PIN, LOW);
    delay(2);
    digitalWrite(EPD_RST_PIN, HIGH);
    delay(2);
    sendCommand(0x3C);
    sendData(0x80);

    if (imageBuffer == nullptr || x < 0 || imageWidth < 0 ||
        y < 0 || imageHeight < 0) {
        return;
    }

    x &= 0xF8;
    imageWidth &= 0xF8;

    if (x + imageWidth >= EPD_WIDTH) {
        xEnd = EPD_WIDTH - 1;
    } else {
        xEnd = x + imageWidth - 1;
    }
    if (y + imageHeight >= EPD_HEIGHT) {
        yEnd = EPD_HEIGHT - 1;
    } else {
        yEnd = y + imageHeight - 1;
    }

    setMemoryArea(x, y, xEnd, yEnd);

    // Set memory pointer
    sendCommand(0x4E);
    sendData((x >> 3) & 0xFF);
    sendCommand(0x4F);
    sendData(y & 0xFF);
    sendData((y >> 8) & 0xFF);
    waitUntilIdle();

    sendCommand(0x24);
    for (int j = 0; j < yEnd - y + 1; j++) {
        for (int i = 0; i < (xEnd - x + 1) / 8; i++) {
            sendData(imageBuffer[i + j * (imageWidth / 8)]);
        }
    }
}

void ShallotEPD::sleep() {
    sendCommand(0x10);  // Enter deep sleep
    sendData(0x01);
    delay(200);
    digitalWrite(EPD_RST_PIN, LOW);
}

/* ===== Framebuffer Drawing Primitives ===== */

void ShallotEPD::clearBuffer() {
    memset(_buffer, 0xFF, EPD_BUFFER_SIZE);
}

void ShallotEPD::drawPixel(int x, int y, bool white) {
    if (x < 0 || x >= EPD_WIDTH || y < 0 || y >= EPD_HEIGHT) return;
    int byteIdx = x / 8 + y * (EPD_WIDTH / 8);
    uint8_t bit = 0x80 >> (x % 8);
    if (white) {
        _buffer[byteIdx] |= bit;   // 1 = white
    } else {
        _buffer[byteIdx] &= ~bit;  // 0 = black
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
    drawLine(x, y, x + w - 1, y, white);             // top
    drawLine(x, y + h - 1, x + w - 1, y + h - 1, white); // bottom
    drawLine(x, y, x, y + h - 1, white);             // left
    drawLine(x + w - 1, y, x + w - 1, y + h - 1, white); // right
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

/*
 * drawIcon — renders privacy-masked status icons.
 * All icons are abstract symbols with no text, no name, no role.
 * cx/cy = center, size = radius/thickness scale.
 *
 * AUTHENTICATING: Rotating dots pattern (three dots in a triangle)
 *   Drawn as three filled circles — abstract "waiting" indicator.
 *
 * AUTHENTICATED: Checkmark inside a circle
 *   Drawn as a filled circle outline with a checkmark.
 *
 * FAILED: X mark inside a circle
 *   Drawn as a circle outline with an X.
 *
 * BLANK: All white (clear screen).
 */
void ShallotEPD::drawIcon(int cx, int cy, int size, EpdStatus status) {
    int r = size;

    switch (status) {
        case EPD_STATUS_AUTHENTICATING: {
            // Three dots arranged in a triangle — abstract waiting indicator
            // Top dot
            drawCircleFilled(cx, cy - r / 2, r / 5, false);
            // Bottom-left dot
            drawCircleFilled(cx - r / 2, cy + r / 2, r / 5, false);
            // Bottom-right dot
            drawCircleFilled(cx + r / 2, cy + r / 2, r / 5, false);

            // Outer circle ring (thin)
            drawCircle(cx, cy, r + 10, false);
            break;
        }

        case EPD_STATUS_AUTHENTICATED: {
            // Circle outline
            drawCircle(cx, cy, r, false);
            // Checkmark inside circle
            // Start lower-left, up to middle, then up-right to upper-right
            int cm_size = r * 2 / 3;
            drawLine(cx - cm_size, cy, cx - cm_size / 4, cy + cm_size / 2, false);
            drawLine(cx - cm_size / 4, cy + cm_size / 2, cx + cm_size, cy - cm_size / 2, false);
            break;
        }

        case EPD_STATUS_FAILED: {
            // Circle outline
            drawCircle(cx, cy, r, false);
            // X mark inside circle
            int x_size = r * 2 / 3;
            drawLine(cx - x_size, cy - x_size, cx + x_size, cy + x_size, false);
            drawLine(cx - x_size, cy + x_size, cx + x_size, cy - x_size, false);
            break;
        }

        case EPD_STATUS_BLANK:
        default:
            // No icon — blank display
            break;
    }
}

/*
 * showStatus — main privacy-masked display function.
 * Renders only an abstract status icon centered on the 200x200 display.
 * Never displays text, name, role, or any identifying information.
 *
 * After rendering, the display enters deep sleep to protect the e-Paper
 * from high-voltage damage (per Waveshare manual requirement).
 */
void ShallotEPD::showStatus(EpdStatus status) {
    if (status == EPD_STATUS_BLANK) {
        clearBuffer();
        displayFrame(_buffer);
        sleep();
        return;
    }

    clearBuffer();

    // Draw border frame
    drawRect(4, 4, EPD_WIDTH - 8, EPD_HEIGHT - 8, false);

    // Draw centered status icon (no text)
    int centerX = EPD_WIDTH / 2;
    int centerY = EPD_HEIGHT / 2;
    int iconRadius = 50;

    drawIcon(centerX, centerY, iconRadius, status);

    // Push buffer to display (full refresh)
    displayFrame(_buffer);

    // Enter sleep to protect screen (per Waveshare safety requirement)
    sleep();
}

/* ===== Global Instance ===== */

ShallotEPD epd;

/* ===== Arduino Setup/Loop ===== */

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println("SHALLOT E-Paper Status Display (PRO-57)");
    Serial.println("Initializing e-Paper...");

    if (!epd.begin()) {
        Serial.println("EPD initialization FAILED");
        while (true) { delay(1000); }
    }

    Serial.println("EPD initialized. Clearing screen...");
    epd.clear();

    // Demo: cycle through all status states
    Serial.println("Showing AUTHENTICATING...");
    epd.showStatus(EPD_STATUS_AUTHENTICATING);
    delay(3000);

    // Must re-init after sleep
    epd.begin();
    Serial.println("Showing AUTHENTICATED...");
    epd.showStatus(EPD_STATUS_AUTHENTICATED);
    delay(3000);

    epd.begin();
    Serial.println("Showing FAILED...");
    epd.showStatus(EPD_STATUS_FAILED);
    delay(3000);

    epd.begin();
    Serial.println("Showing BLANK (clear)...");
    epd.showStatus(EPD_STATUS_BLANK);

    Serial.println("Demo complete. Display is now in sleep mode.");
}

void loop() {
    // The e-Paper is a static display — no continuous loop needed.
    // Status updates are event-driven from the authentication state machine.
    //
    // Usage from the PAW authentication module:
    //   epd.begin();
    //   epd.showStatus(EPD_STATUS_AUTHENTICATING);
    //   // ... wait for challenge-response ...
    //   epd.begin();
    //   epd.showStatus(EPD_STATUS_AUTHENTICATED);  // or EPD_STATUS_FAILED
    //
    // Note: epd.begin() must be called after sleep() before each refresh.
    // Note: Minimum 180s between refreshes recommended by Waveshare.
    // Note: Full refresh at least once every 24 hours.

    delay(10000);
}
