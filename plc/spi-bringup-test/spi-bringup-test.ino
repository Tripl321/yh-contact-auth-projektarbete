/*
 * SHALLOT — SPI Bring-up Test for Edge Enforcement Node (PRO-27)
 * Hardware: Raspberry Pi Pico 2 W (RP2350)
 * Core1262-868M LoRa module on SPI1
 *
 * This sketch verifies SPI1 wiring by reading the Core1262/SX1262
 * chip version register. If SPI is correctly wired, it will print:
 *   SX1262 version: 0x?? (typically 0x03 or 0x43)
 *
 * Pin mapping (verified against Pico 2 W pinout):
 *   SPI1 SCK  -> GP10 (physical pin 14)
 *   SPI1 MOSI -> GP11 (physical pin 15)
 *   SPI1 MISO -> GP12 (physical pin 16)
 *   CS        -> GP9  (physical pin 12, software CS)
 *   BUSY      -> GP6  (physical pin 9)
 *   RESET     -> GP8  (physical pin 11)
 *   DIO1      -> GP21 (physical pin 27)
 *
 * Core: arduino-pico (earlephilhower)
 */

#include <Arduino.h>
#include <SPI.h>

// --- SPI1 Pin Definitions ---
#define SPI1_SCK_PIN   10
#define SPI1_MOSI_PIN  11
#define SPI1_MISO_PIN  12
#define CS_PIN          9
#define BUSY_PIN        6
#define RESET_PIN       8
#define DIO1_PIN        21

// --- SX1262 Register ---
#define SX1262_REG_VERSION  0x14
#define SX1262_CMD_READ_REGISTER  0x1D

SPIClassRP2040 loraSPI(spi1_hw);

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — SPI Bring-up Test (PRO-27)");
  Serial.println("Hardware: Pico 2 W + Core1262 on SPI1");
  Serial.println("============================================");

  // Configure pins
  pinMode(CS_PIN, OUTPUT);
  pinMode(BUSY_PIN, INPUT);
  pinMode(RESET_PIN, OUTPUT);
  pinMode(DIO1_PIN, INPUT);

  digitalWrite(CS_PIN, HIGH);  // CS idle high

  // Reset the SX1262
  digitalWrite(RESET_PIN, LOW);
  delay(10);
  digitalWrite(RESET_PIN, HIGH);
  delay(10);

  // Initialize SPI1 with custom pins
  loraSPI.setSCK(SPI1_SCK_PIN);
  loraSPI.setTX(SPI1_MOSI_PIN);
  loraSPI.setRX(SPI1_MISO_PIN);
  loraSPI.begin();

  Serial.println();
  Serial.println("SPI1 initialized:");
  Serial.printf("  SCK  = GP%d\n", SPI1_SCK_PIN);
  Serial.printf("  MOSI = GP%d\n", SPI1_MOSI_PIN);
  Serial.printf("  MISO = GP%d\n", SPI1_MISO_PIN);
  Serial.printf("  CS   = GP%d\n", CS_PIN);
  Serial.println();

  // Read SX1262 version register
  Serial.println("Reading SX1262 version register...");

  // Wait for BUSY to go low
  uint32_t timeout = millis();
  while (digitalRead(BUSY_PIN) == HIGH) {
    if (millis() - timeout > 1000) {
      Serial.println("ERROR: BUSY pin stuck HIGH!");
      Serial.println("Possible causes:");
      Serial.println("  1. SX1262 not powered");
      Serial.println("  2. RESET pin not connected");
      Serial.println("  3. BUSY pin not connected to GP6");
      Serial.println();
      Serial.println("=== SPI TEST: FAILED ===");
      return;
    }
  }

  loraSPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
  digitalWrite(CS_PIN, LOW);

  // Send read register command + address
  loraSPI.transfer(SX1262_CMD_READ_REGISTER);
  loraSPI.transfer(0x00);  // status byte (dummy)
  loraSPI.transfer(SX1262_REG_VERSION);

  // Read the version byte
  uint8_t version = loraSPI.transfer(0x00);

  digitalWrite(CS_PIN, HIGH);
  loraSPI.endTransaction();

  Serial.printf("SX1262 version register: 0x%02X\n", version);

  if (version == 0x00 || version == 0xFF) {
    Serial.println();
    Serial.println("ERROR: Invalid version read!");
    Serial.println("Possible causes:");
    Serial.println("  1. MISO not connected or on wrong pin");
    Serial.println("  2. CS not connected");
    Serial.println("  3. SCK not connected");
    Serial.println("  4. SX1262 not powered properly");
    Serial.println();
    Serial.println("=== SPI TEST: FAILED ===");
  } else {
    Serial.println();
    Serial.println("SPI1 communication verified!");
    Serial.println("Wiring is correct for Core1262 on SPI1.");
    Serial.println();
    Serial.println("=== SPI TEST: PASSED ===");
  }

  Serial.println();
  Serial.println("--- Pin State Check ---");
  Serial.printf("BUSY pin (GP%d): %s\n", BUSY_PIN, digitalRead(BUSY_PIN) ? "HIGH" : "LOW");
  Serial.printf("DIO1 pin (GP%d): %s\n", DIO1_PIN, digitalRead(DIO1_PIN) ? "HIGH" : "LOW");
  Serial.printf("RESET pin (GP%d): %s\n", RESET_PIN, digitalRead(RESET_PIN) ? "HIGH" : "LOW");
}

void loop() {
  // Pulse LED to show we're alive
  digitalWrite(LED_BUILTIN, (millis() / 1000) % 2);
  delay(100);
}
