/*
 * SHALLOT — SPI Bring-up Test for PAW e-Paper (PRO-29)
 * Hardware: Adafruit Feather RP2350 + Waveshare 1.54" e-Paper V2 on SPI0
 *
 * This sketch verifies SPI0 wiring to the e-Paper display by:
 *   1. Sending a software reset command
 *   2. Reading the busy pin state
 *   3. Displaying a test pattern (checkerboard)
 *
 * Pin mapping (verified against Adafruit Feather RP2350 pinout):
 *   SPI0 SCK  -> SCK (GPIO22)
 *   SPI0 MOSI -> MO  (GPIO23)
 *   SPI0 CS   -> D5  (GPIO5)
 *   DC        -> A0  (GPIO26)
 *   RST       -> A1  (GPIO27)
 *   BUSY      -> D25 (GPIO25) — moved from A3 (A3 not free per 2026-09-03)
 *
 * Core: arduino-pico (earlephilhower)
 */

#include <Arduino.h>
#include <SPI.h>

// --- e-Paper Pin Definitions (SPI0) ---
#define EPD_CS_PIN       5
#define EPD_DC_PIN       A0
#define EPD_RST_PIN      A1
#define EPD_BUSY_PIN     25  // D25 GPIO25 — moved from A3

// --- e-Paper Constants ---
#define EPD_WIDTH        200
#define EPD_HEIGHT       200

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — SPI Bring-up Test (PRO-29)");
  Serial.println("Hardware: Feather RP2350 + 1.54in e-Paper on SPI0");
  Serial.println("============================================");

  // Configure pins
  pinMode(EPD_CS_PIN, OUTPUT);
  pinMode(EPD_DC_PIN, OUTPUT);
  pinMode(EPD_RST_PIN, OUTPUT);
  pinMode(EPD_BUSY_PIN, INPUT);

  digitalWrite(EPD_CS_PIN, HIGH);
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_RST_PIN, HIGH);

  // Initialize SPI0 (default pins on Feather RP2350: SCK=GP22, MO=GP23)
  SPI.begin();
  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
  SPI.endTransaction();

  Serial.println();
  Serial.println("SPI0 initialized (default Feather pins):");
  Serial.println("  SCK  = SCK (GPIO22)");
  Serial.println("  MOSI = MO  (GPIO23)");
  Serial.printf("  CS   = D5  (GPIO%d)\n", EPD_CS_PIN);
  Serial.printf("  DC   = A0  (GPIO26)\n");
  Serial.printf("  RST  = A1  (GPIO27)\n");
  Serial.printf("  BUSY = D25 (GPIO25)\n");
  Serial.println();

  // Reset the e-Paper
  Serial.println("Resetting e-Paper...");
  digitalWrite(EPD_RST_PIN, HIGH);
  delay(20);
  digitalWrite(EPD_RST_PIN, LOW);
  delay(5);
  digitalWrite(EPD_RST_PIN, HIGH);
  delay(20);

  // Check BUSY pin
  Serial.println();
  Serial.println("--- Pin State Check ---");
  int busyState = digitalRead(EPD_BUSY_PIN);
  Serial.printf("BUSY pin (D25/GPIO25): %s\n", busyState ? "HIGH (busy)" : "LOW (ready)");

  if (busyState == HIGH) {
    Serial.println("Waiting for e-Paper to become ready...");
    uint32_t timeout = millis();
    while (digitalRead(EPD_BUSY_PIN) == HIGH) {
      if (millis() - timeout > 3000) {
        Serial.println("WARNING: BUSY still HIGH after 3s (may be normal during init)");
        break;
      }
      delay(100);
    }
  }

  // Send software reset command
  Serial.println();
  Serial.println("Sending software reset (0x12)...");
  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
  digitalWrite(EPD_CS_PIN, LOW);
  digitalWrite(EPD_DC_PIN, LOW);
  SPI.transfer(0x12);  // SWRESET
  digitalWrite(EPD_CS_PIN, HIGH);
  SPI.endTransaction();
  delay(20);

  // Read BUSY after reset
  busyState = digitalRead(EPD_BUSY_PIN);
  Serial.printf("BUSY after reset: %s\n", busyState ? "HIGH (busy)" : "LOW (ready)");

  if (busyState == HIGH) {
    Serial.println("Waiting for post-reset busy to clear...");
    uint32_t timeout = millis();
    while (digitalRead(EPD_BUSY_PIN) == HIGH) {
      if (millis() - timeout > 3000) {
        Serial.println("ERROR: BUSY stuck HIGH after reset!");
        Serial.println("Possible causes:");
        Serial.println("  1. RST pin not connected");
        Serial.println("  2. BUSY pin not connected to D25");
        Serial.println("  3. e-Paper not powered (3.3V)");
        Serial.println();
        Serial.println("=== SPI TEST: FAILED ===");
        return;
      }
      delay(100);
    }
  }

  Serial.println();
  Serial.println("Sending display data (checkerboard pattern)...");

  // Send a simple checkerboard pattern to verify data path
  SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));

  // Write to RAM
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(0x24);  // Write RAM for black/white
  digitalWrite(EPD_CS_PIN, HIGH);

  digitalWrite(EPD_DC_PIN, HIGH);
  digitalWrite(EPD_CS_PIN, LOW);
  for (int i = 0; i < (EPD_WIDTH / 8) * EPD_HEIGHT; i++) {
    SPI.transfer(0xAA);  // Alternating pattern
  }
  digitalWrite(EPD_CS_PIN, HIGH);

  // Also write to red RAM (clear it)
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(0x26);  // Write RAM for red
  digitalWrite(EPD_CS_PIN, HIGH);

  digitalWrite(EPD_DC_PIN, HIGH);
  digitalWrite(EPD_CS_PIN, LOW);
  for (int i = 0; i < (EPD_WIDTH / 8) * EPD_HEIGHT; i++) {
    SPI.transfer(0xFF);  // All white (no red)
  }
  digitalWrite(EPD_CS_PIN, HIGH);

  // Trigger display update
  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(0x22);  // Display update command
  digitalWrite(EPD_CS_PIN, HIGH);

  digitalWrite(EPD_DC_PIN, HIGH);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(0xC7);  // Full update
  digitalWrite(EPD_CS_PIN, HIGH);

  digitalWrite(EPD_DC_PIN, LOW);
  digitalWrite(EPD_CS_PIN, LOW);
  SPI.transfer(0x20);  // Master activate
  digitalWrite(EPD_CS_PIN, HIGH);

  SPI.endTransaction();

  Serial.println("Display update triggered. Wait ~2s for e-Paper refresh.");
  delay(3000);

  busyState = digitalRead(EPD_BUSY_PIN);
  Serial.printf("BUSY after update: %s\n", busyState ? "HIGH (still refreshing)" : "LOW (done)");

  Serial.println();
  if (busyState == LOW) {
    Serial.println("=== SPI TEST: PASSED ===");
    Serial.println("e-Paper SPI0 communication verified.");
    Serial.println("You should see a checkerboard pattern on the display.");
  } else {
    Serial.println("=== SPI TEST: PARTIAL ===");
    Serial.println("Commands sent but BUSY still HIGH.");
    Serial.println("Check DC, RST, and BUSY pin connections.");
  }
}

void loop() {
  digitalWrite(LED_BUILTIN, (millis() / 1000) % 2);
  delay(100);
}
