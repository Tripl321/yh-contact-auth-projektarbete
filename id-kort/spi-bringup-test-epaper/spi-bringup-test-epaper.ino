/*
 * SHALLOT — SPI Bring-up Test for PAW e-Paper (PRO-29, B V2 driver)
 * Hardware: Adafruit Feather RP2350 + Waveshare 1.54" e-Paper Module (B) V2
 *           black/white/red tri-color, 200x200, SSD1681, on SPI0
 *
 * Implements the OFFICIAL Waveshare 1.54inch e-Paper Module (B) V2 driver
 * protocol (waveshareteam/e-Paper, Arduino epd1in54b_V2 demo):
 *   - Init: Reset, SWRESET, driver-output 0xC7/0x00/0x01, entry 0x01,
 *     X-window 0x00/0x18, Y-window 0xC7/0x00/0x00/0x00, border 0x05,
 *     internal temp sensor 0x80, counters X=0x00 Y=0xC7/0x00.
 *     (No custom LUT upload exists in the official Arduino driver; the
 *     0xF7 full update uses the built-in waveform.)
 *   - Two RAM planes: 0x24 black/white (0-bit = black) and 0x26 red/white
 *     (1-bit = red), each 5000 bytes. Update: 0x22 + 0xF7, 0x20.
 *   - BUSY is HIGH while busy; wait for LOW. Reset: HIGH 200 ms,
 *     LOW 10 ms, HIGH 200 ms (official timing).
 *
 * First test: full white clear, then black checkerboard with red border
 * and red "EPD OK / B V2" text (3x5 microfont, 4x scale).
 *
 * Diagnostics kept: BUSY sampled around reset/update with timestamps,
 * HIGH-pulse catch (proves panel executes), GPIO readback.
 *
 * Pin mapping UNCHANGED (confirmed PAW mapping):
 *   SPI0 SCK  -> SCK (GPIO22)    SPI0 MOSI -> MO (GPIO23)
 *   SPI0 CS   -> D5  (GPIO5)     DC -> A0 (GPIO26)
 *   RST       -> A1  (GPIO27)    BUSY -> A3 (GPIO29)
 * SPI @400kHz bring-up speed. No MISO. No UART GPIO0/1. No LoRa/radio code.
 */

#include <Arduino.h>
#include <SPI.h>

// --- e-Paper Pin Definitions (SPI0) - DO NOT CHANGE ---
#define EPD_CS_PIN       5
#define EPD_DC_PIN       A0
#define EPD_RST_PIN      A1
#define EPD_BUSY_PIN     A3

// --- Panel Constants (1.54" B V2, 200x200) ---
#define EPD_WIDTH        200
#define EPD_HEIGHT       200
#define EPD_BYTES        ((EPD_WIDTH / 8) * EPD_HEIGHT)  // 5000
#define EPD_SPI_HZ       400000
#define EPD_BUSY_TIMEOUT 12000

static uint32_t busyHighSeen = 0;

static void logBusy(const char *label) {
  int b = digitalRead(EPD_BUSY_PIN);
  Serial.printf("BUSY %s: %s (t=%lums)\n", label,
                b ? "HIGH" : "LOW", (unsigned long)millis());
  if (b) busyHighSeen++;
}

// Wait for BUSY LOW; catches the HIGH pulse that proves execution.
static bool waitBusy(const char *label, uint32_t timeoutMs) {
  uint32_t t0 = millis();
  bool sawHigh = false;
  if (digitalRead(EPD_BUSY_PIN)) {
    sawHigh = true;
    busyHighSeen++;
    Serial.printf("BUSY %s: HIGH right after trigger (panel executes)\n", label);
  } else {
    Serial.printf("BUSY %s: LOW right after trigger\n", label);
  }
  while (digitalRead(EPD_BUSY_PIN) == HIGH) {
    sawHigh = true;
    busyHighSeen++;
    if (millis() - t0 > timeoutMs) {
      Serial.printf("BUSY %s: STUCK HIGH after %lums\n", label, (unsigned long)timeoutMs);
      return false;
    }
    delay(10);
  }
  Serial.printf("BUSY %s: idle after %lums (sawHigh=%d)\n", label,
                (unsigned long)(millis() - t0), (int)sawHigh);
  return true;
}

static void epdCmd(uint8_t cmd) {
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(cmd);
  digitalWrite(EPD_CS_PIN, HIGH);
}

static void epdData(const uint8_t *buf, size_t len) {
  digitalWrite(EPD_DC_PIN, HIGH);
  digitalWrite(EPD_CS_PIN, LOW);
  for (size_t i = 0; i < len; i++) SPI.transfer(buf[i]);
  digitalWrite(EPD_CS_PIN, HIGH);
}

static void epdDataFill(uint8_t value, size_t len) {
  digitalWrite(EPD_DC_PIN, HIGH);
  digitalWrite(EPD_CS_PIN, LOW);
  for (size_t i = 0; i < len; i++) SPI.transfer(value);
  digitalWrite(EPD_CS_PIN, HIGH);
}

// Official reset timing: HIGH 200 ms, LOW 10 ms, HIGH 200 ms.
static void epdReset() {
  Serial.println("--- Reset (official timing) ---");
  logBusy("before reset");
  digitalWrite(EPD_RST_PIN, HIGH);
  delay(200);
  digitalWrite(EPD_RST_PIN, LOW);
  delay(10);
  digitalWrite(EPD_RST_PIN, HIGH);
  delay(200);
  logBusy("after reset");
}

// Official B V2 init sequence (transcribed from Waveshare demo).
static void epdInit() {
  Serial.println("--- B V2 init (official) ---");
  epdCmd(0x12);  // SWRESET
  waitBusy("swreset", 4000);

  epdCmd(0x01);  // Driver output control
  { uint8_t d[3] = {0xC7, 0x00, 0x01}; epdData(d, 3); }

  epdCmd(0x11);  // Data entry mode
  { uint8_t d[1] = {0x01}; epdData(d, 1); }

  epdCmd(0x44);  // RAM X window: 0..24 (24+1)*8=200
  { uint8_t d[2] = {0x00, 0x18}; epdData(d, 2); }

  epdCmd(0x45);  // RAM Y window
  { uint8_t d[4] = {0xC7, 0x00, 0x00, 0x00}; epdData(d, 4); }

  epdCmd(0x3C);  // Border waveform
  { uint8_t d[1] = {0x05}; epdData(d, 1); }

  epdCmd(0x18);  // Built-in temperature sensor
  { uint8_t d[1] = {0x80}; epdData(d, 1); }

  epdCmd(0x4E);  // RAM X counter: 0
  { uint8_t d[1] = {0x00}; epdData(d, 1); }

  epdCmd(0x4F);  // RAM Y counter: 0x199
  { uint8_t d[2] = {0xC7, 0x00}; epdData(d, 2); }

  waitBusy("init", 4000);
  Serial.println("Init done.");
}

// Full update with the two framebuffers already staged.
// BLOCKS until the panel is truly idle: firing the next frame while BUSY
// is still HIGH silently drops it (observed: clear's refresh outlasted
// the old 12 s timeout, so the demo that followed never took effect).
static void epdUpdate(const char *label) {
  epdCmd(0x22);
  { uint8_t d[1] = {0xF7}; epdData(d, 1); }
  epdCmd(0x20);
  uint32_t t0 = millis();
  while (!waitBusy(label, 15000)) {
    if (millis() - t0 > 90000) {
      Serial.printf("BUSY %s: still busy after 90s, continuing anyway\n", label);
      break;
    }
  }
}

// RAM counters MUST be rewound before every framebuffer staging: after a
// 5000-byte write they sit at the window end, and further bytes would land
// outside RAM (previous run: clear displayed, demo frame silently lost).
static void epdHome() {
  epdCmd(0x4E);  // RAM X counter: 0
  { uint8_t d[1] = {0x00}; epdData(d, 1); }
  epdCmd(0x4F);  // RAM Y counter: 0x199 (official value)
  { uint8_t d[2] = {0xC7, 0x00}; epdData(d, 2); }
}

// Diagnostic clear: FULL BLACK (not white). If the glass turns black the
// update engine works and prior all-white was unwritten POR RAM; if it
// stays white, no update ever drives pixels (mode/power/panel issue).
static void epdClear() {
  Serial.println("--- Clear: full BLACK (diagnostic) ---");
  epdHome();
  epdCmd(0x24);
  epdDataFill(0x00, EPD_BYTES);
  epdCmd(0x26);
  epdDataFill(0x00, EPD_BYTES);
  epdUpdate("clear-black");
}

// --- Framebuffers (panel-native polarity) ---
static uint8_t fbBW[EPD_BYTES];   // 0-bit = black
static uint8_t fbRed[EPD_BYTES];  // 1-bit = red

static inline void pxBW(int x, int y, int black) {
  if (x < 0 || x >= EPD_WIDTH || y < 0 || y >= EPD_HEIGHT) return;
  uint8_t mask = (uint8_t)(0x80 >> (x & 7));
  if (black) fbBW[y * 25 + (x >> 3)] &= (uint8_t)~mask;
  else fbBW[y * 25 + (x >> 3)] |= mask;
}

static inline void pxRed(int x, int y) {
  if (x < 0 || x >= EPD_WIDTH || y < 0 || y >= EPD_HEIGHT) return;
  fbRed[y * 25 + (x >> 3)] |= (uint8_t)(0x80 >> (x & 7));
}

// 3x5 microfont, rows top->bottom, low 3 bits per row. Chars: E P D O K B V 2 - space
static uint8_t glyph(char c, uint8_t row) {
  switch (c) {
    case 'E': { static const uint8_t g[5] = {0x7,0x4,0x7,0x4,0x7}; return g[row]; }
    case 'P': { static const uint8_t g[5] = {0x7,0x5,0x7,0x4,0x4}; return g[row]; }
    case 'D': { static const uint8_t g[5] = {0x6,0x5,0x5,0x5,0x6}; return g[row]; }
    case 'O': { static const uint8_t g[5] = {0x2,0x5,0x5,0x5,0x2}; return g[row]; }
    case 'K': { static const uint8_t g[5] = {0x5,0x5,0x6,0x5,0x5}; return g[row]; }
    case 'B': { static const uint8_t g[5] = {0x6,0x5,0x6,0x5,0x6}; return g[row]; }
    case 'V': { static const uint8_t g[5] = {0x5,0x5,0x5,0x5,0x2}; return g[row]; }
    case '2': { static const uint8_t g[5] = {0x7,0x1,0x7,0x4,0x7}; return g[row]; }
    case '-': { static const uint8_t g[5] = {0x0,0x0,0x7,0x0,0x0}; return g[row]; }
    default:  return 0x0;  // space / unknown
  }
}

static void drawText(const char *s, int x0, int y0, int scale) {
  for (int ci = 0; s[ci]; ci++) {
    for (uint8_t r = 0; r < 5; r++) {
      uint8_t bits = glyph(s[ci], r);
      for (uint8_t c = 0; c < 3; c++) {
        if (bits & (0x4 >> c)) {
          for (int dy = 0; dy < scale; dy++)
            for (int dx = 0; dx < scale; dx++)
              pxRed(x0 + ci * (3 * scale + scale) + c * scale + dx, y0 + r * scale + dy);
        }
      }
    }
  }
}

static void drawRedBorder(int w) {
  for (int x = 0; x < EPD_WIDTH; x++)
    for (int k = 0; k < w; k++) {
      pxRed(x, k);
      pxRed(x, EPD_HEIGHT - 1 - k);
    }
  for (int y = 0; y < EPD_HEIGHT; y++)
    for (int k = 0; k < w; k++) {
      pxRed(k, y);
      pxRed(EPD_WIDTH - 1 - k, y);
    }
}

static void stageCheckerRedDemo() {
  // BW plane: 16px checkerboard (0 = black squares).
  for (int y = 0; y < EPD_HEIGHT; y++)
    for (int bx = 0; bx < 25; bx++) {
      uint8_t v = (((bx >> 1) + (y >> 4)) & 1) ? 0x00 : 0xFF;
      fbBW[y * 25 + bx] = v;
    }
  // RED plane: clear, then border + text.
  memset(fbRed, 0x00, sizeof(fbRed));
  drawRedBorder(8);
  drawText("EPD OK", 24, 24, 4);
  drawText("B-V2", 24, 56, 4);
}

static void sendFramebuffers() {
  epdHome();
  epdCmd(0x24);
  epdData(fbBW, sizeof(fbBW));
  epdCmd(0x26);
  epdData(fbRed, sizeof(fbRed));
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT - e-Paper B V2 bring-up (PRO-29)");
  Serial.println("Feather RP2350 + 1.54in B V2, official driver");
  Serial.println("============================================");

  pinMode(EPD_CS_PIN, OUTPUT);
  pinMode(EPD_DC_PIN, OUTPUT);
  pinMode(EPD_RST_PIN, OUTPUT);
  pinMode(EPD_BUSY_PIN, INPUT);

  digitalWrite(EPD_CS_PIN, HIGH);
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_RST_PIN, HIGH);

  SPI.begin();
  SPI.beginTransaction(SPISettings(EPD_SPI_HZ, MSBFIRST, SPI_MODE0));
  SPI.endTransaction();
  Serial.println("SPI0 @400kHz, pins SCK=22 MOSI=23 CS=5 DC=26 RST=27 BUSY=29");

  epdReset();
  epdInit();
  epdClear();

  Serial.println("--- Demo frame: checker + red border/text ---");
  stageCheckerRedDemo();
  sendFramebuffers();
  epdUpdate("demo");

  Serial.println();
  Serial.printf("BUSY ever HIGH during run: %s\n", busyHighSeen ? "YES (panel executes)" : "NO (panel silent)");
  Serial.println("=== LOOK AT PANEL: white flash, then checker + red border/text ===");
  Serial.println("=== END (LED blinks in loop) ===");
}

void loop() {
  digitalWrite(LED_BUILTIN, (millis() / 1000) % 2);
  delay(100);
}
