/*
 * SHALLOT — SPI Bring-up Test for PAW Core1262 (PRO-28)
 * Hardware: Adafruit Feather RP2350 + Core1262-868M on SPI1
 *
 * This sketch verifies SPI1 wiring by reading the Core1262/SX1262
 * chip version register.
 *
 * CRITICAL: MISO must be on D24 (GPIO24), NOT on "MI" (GPIO20).
 *   "MI" on Feather silkscreen = GPIO20 = SPI0 MISO (used by e-Paper)
 *   D24 on Feather silkscreen = GPIO24, hardware SPI1 MISO
 *   GPIO4 (silkscreen "4") is SPI0 MISO, NOT SPI1 MISO — using it for SPI1 will cause a runtime panic.
 *   RESET is on pin "4" (GPIO4), which is fine as a digital output.
 *
 * Pin mapping (verified against Adafruit Feather RP2350 pinout):
 *   SPI1 SCK  -> D10  (GPIO10)
 *   SPI1 MOSI -> D11  (GPIO11)
 *   SPI1 MISO -> D24  (GPIO24)  <-- hardware SPI1 MISO, NOT "MI" silkscreen!
 *   CS        -> D9   (GPIO9)
 *   BUSY      -> D7   (GPIO7)
 *   RESET     -> pin4 (GPIO4)  <-- digital output, NOT SPI
 *   DIO1      -> A2   (GPIO28)
 *
 * Core: arduino-pico (earlephilhower)
 */

#include <Arduino.h>
#include <SPI.h>

// --- SPI1 Pin Definitions for Core1262 ---
#define SPI1_SCK_PIN   10  // D10 on Feather silkscreen
#define SPI1_MOSI_PIN  11  // D11 on Feather silkscreen
#define SPI1_MISO_PIN  24  // D24 on Feather silkscreen (GPIO24, hardware SPI1 MISO)
#define CS_PIN          9  // D9 on Feather silkscreen
#define BUSY_PIN        7  // D7 on Feather silkscreen
#define RESET_PIN       4  // Pin "4" on Feather silkscreen (GPIO4, digital output)
#define DIO1_PIN        A2 // A2 on Feather silkscreen (GPIO28)

// --- SX1262 Register ---
#define SX1262_REG_VERSION  0x14
#define SX1262_CMD_READ_REGISTER  0x1D

SPIClassRP2040 spi1(spi1);

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — SPI Bring-up Test (PRO-28)");
  Serial.println("Hardware: Feather RP2350 + Core1262 on SPI1");
  Serial.println("============================================");

  // Configure pins
  pinMode(CS_PIN, OUTPUT);
  pinMode(BUSY_PIN, INPUT);
  pinMode(RESET_PIN, OUTPUT);
  pinMode(DIO1_PIN, INPUT);

  digitalWrite(CS_PIN, HIGH);

  // Reset the SX1262
  digitalWrite(RESET_PIN, LOW);
  delay(10);
  digitalWrite(RESET_PIN, HIGH);
  delay(10);


  // Ini
tialize SPI1 with custom pins
  spi1.setSCK(SPI1_SCK_PIN);
  spi1.setTX(SPI1_MOSI_PIN);
  spi1.setRX(SPI1_MISO_PIN);
  spi1.begin();

  Serial.println();
  Serial.println("SPI1 initialized:");
  Serial.printf("  SCK  = D10 (GPIO%d)\n", SPI1_SCK_PIN);
  Serial.printf("  MOSI = D11 (GPIO%d)\n", SPI1_MOSI_PIN);
  Serial.printf("  MISO = D24 (GPIO%d)\n", SPI1_MISO_PIN);
  Serial.printf("  CS   = D9  (GPIO%d)\n", CS_PIN);
  Serial.println();
  Serial.println("NOTE: MISO is on D24 (GPIO24, hardware SPI1 MISO)");
  Serial.println("      NOT on 'MI' silkscreen (GPIO20 = SPI0 MISO)");
  Serial.println("      NOT on pin '4' (GPIO4 = SPI0 MISO, used for RESET)");
  Serial.println();

  // Read SX1262 version register
  Serial.println("Reading SX1262 version register...");

  uint32_t timeout = millis();
  while (digitalRead(BUSY_PIN) == HIGH) {
    if (millis() - timeout > 1000) {
      Serial.println("ERROR: BUSY pin stuck HIGH!");
      Serial.println("Possible causes:");
      Serial.println("  1. SX1262 not powered");
      Serial.println("  2. RESET pin not connected");
      Serial.println("  3. BUSY pin not connected to D7");
      Serial.println();
      Serial.println("=== SPI TEST: FAILED ===");
      return;
    }
  }

  spi1.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
  digitalWrite(CS_PIN, LOW);

  spi1.transfer(SX1262_CMD_READ_REGISTER);
  spi1.transfer(0x00);
  spi1.transfer(SX1262_REG_VERSION);

  uint8_t version = spi1.transfer(0x00);

  digitalWrite(CS_PIN, HIGH);
  spi1.endTransaction();

  Serial.printf("SX1262 version register: 0x%02X\n", version);

  if (version == 0x00 || version == 0xFF) {
    Serial.println();
    Serial.println("ERROR: Invalid version read!");
    Serial.println("Possible causes:");
    Serial.println("  1. MISO on wrong pin (check: should be D24, not 'MI' or pin '4')");
    Serial.println("  2. CS not connected");
    Serial.println("  3. SCK not connected");
    Serial.println("  4. SX1262 not powered properly");
    Serial.println("  5. MISO and MOSI swapped");
    Serial.println();
    Seria
l.println("=== SPI
 TEST: FAILED ===");
  } else {
    Serial.println();
    Serial.println("SPI1 communication verified!");
    Serial.println("Wiring is correct for Core1262 on SPI1.");
    Serial.println();
    Serial.println("=== SPI TEST: PASSED ===");
  }

  Serial.println();
  Serial.println("--- Pin State Check ---");
  Serial.printf("BUSY pin (D7/GPIO%d): %s\n", BUSY_PIN, digitalRead(BUSY_PIN) ? "HIGH" : "LOW");
  Serial.printf("DIO1 pin (A2/GPIO%d): %s\n", DIO1_PIN, digitalRead(DIO1_PIN) ? "HIGH" : "LOW");
  Serial.printf("RESET pin (pin4/GPIO%d): %s\n", RESET_PIN, digitalRead(RESET_PIN) ? "HIGH" : "LOW");
}

void loop() {
  digitalWrite(LED_BUILTIN, (millis() / 1000) % 2);
  delay(100);
}
