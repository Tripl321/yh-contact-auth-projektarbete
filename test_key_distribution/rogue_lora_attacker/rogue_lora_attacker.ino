/*
 * SHALLOT — Rogue LoRa Transmitter (TEST TOOL ONLY, see docs/14)
 *
 * Sends forged/malformed PAW->PLC responses so the physical test plan can
 * verify that PLC denies them: bad HMAC, wrong nonce, wrong epoch, short
 * packet and replayed (duplicate) responses.
 *
 * SAFETY:
 *   - Test tool only. Never operate near production systems.
 *   - Learns no keys: forged HMAC bytes are random, never computed.
 *   - Transmits ONLY on operator single-letter commands below.
 *   - Keep PAW powered OFF for the b/n/e/s cases (deterministic).
 *
 * Hardware: spare Raspberry Pi Pico 2 + Core1262-868M wired EXACTLY like
 * PLC (docs/04 section 2.1): SPI1 SCK=GP10 MOSI=GP11 MISO=GP12 CS=GP9,
 * BUSY=GP6 RESET=GP8 DIO1=GP21. USB to host for commands (115200 baud).
 *
 * Build (from repo root):
 *   arduino-cli compile --fqbn rp2040:rp2040:rpipico2 \
 *     --library libraries/ShallotLoRa \
 *     --output-dir /tmp/rogue \
 *     test_key_distribution/rogue_lora_attacker/rogue_lora_attacker.ino
 *
 * Commands (serial monitor, 115200):
 *   b — send response with BAD (random) HMAC for the sniffed live challenge
 *   n — send response with WRONG (random) nonce
 *   e — send response with WRONG epoch (live nonce, epoch + 1)
 *   s — send SHORT packet (tag + 3 bytes)
 *   d — replay the last sniffed PAW response verbatim (duplicate)
 *   ? — print this help
 */

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <ShallotLoRaProtocol.h>

// RF params identical to PAW/PLC (see plc-key-receiver.ino LORA_*).
#define ROGUE_LORA_FREQUENCY        868.0
#define ROGUE_LORA_BANDWIDTH        125.0
#define ROGUE_LORA_SPREADING_FACTOR 9
#define ROGUE_LORA_CODING_RATE      5
#define ROGUE_LORA_PREAMBLE_LENGTH  8
#define ROGUE_LORA_SYNC_WORD        0x12
#define ROGUE_LORA_OUTPUT_POWER     14

// Pins identical to PLC wiring (docs/04 section 2.1).
#define ROGUE_SCK_PIN   10
#define ROGUE_MOSI_PIN  11
#define ROGUE_MISO_PIN  12
#define ROGUE_CS_PIN     9
#define ROGUE_BUSY_PIN   6
#define ROGUE_RESET_PIN  8
#define ROGUE_DIO1_PIN  21

SPIClassRP2040 rogueSPI(spi1, ROGUE_MISO_PIN, ROGUE_CS_PIN, ROGUE_SCK_PIN, ROGUE_MOSI_PIN);
SX1262 radio = new Module(ROGUE_CS_PIN, ROGUE_DIO1_PIN, ROGUE_RESET_PIN, ROGUE_BUSY_PIN, rogueSPI);

static volatile bool roguePacketReceived = false;

static void setRogueFlag(void) {
  roguePacketReceived = true;
}

static uint8_t lastChallenge[SHALLOT_LORA_CHALLENGE_LEN];
static bool haveChallenge = false;
static uint8_t lastPawResponse[SHALLOT_LORA_RESPONSE_LEN];
static bool havePawResponse = false;

static void randomBytes(uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i++) out[i] = (uint8_t)random(256);
}

static void txBytes(const uint8_t* pkt, size_t n, const char* what) {
  int st = radio.transmit(const_cast<uint8_t*>(pkt), n);
  Serial.print("[ROGUE] TX ");
  Serial.print(what);
  Serial.print(" (");
  Serial.print((unsigned)n);
  Serial.print("B): ");
  Serial.println(st == RADIOLIB_ERR_NONE ? "sent" : "TX ERROR");
  radio.startReceive();
}

static void sniffOnce() {
  if (!roguePacketReceived) return;
  roguePacketReceived = false;
  size_t len = radio.getPacketLength();
  if (len > 64) len = 64;
  uint8_t buf[64];
  if (radio.readData(buf, len) != RADIOLIB_ERR_NONE || len == 0) {
    radio.startReceive();
    return;
  }
  if (buf[0] == SHALLOT_MSG_CHALLENGE && len >= SHALLOT_LORA_CHALLENGE_LEN) {
    memcpy(lastChallenge, buf, SHALLOT_LORA_CHALLENGE_LEN);
    haveChallenge = true;
    Serial.println("[ROGUE] sniffed PLC CHALLENGE (live nonce stored)");
  } else if (buf[0] == SHALLOT_MSG_RESPONSE && len >= SHALLOT_LORA_RESPONSE_LEN) {
    memcpy(lastPawResponse, buf, SHALLOT_LORA_RESPONSE_LEN);
    havePawResponse = true;
    Serial.println("[ROGUE] sniffed PAW RESPONSE (stored for replay)");
  }
  radio.startReceive();
}

static void cmdBadHmac() {
  if (!haveChallenge) { Serial.println("[ROGUE] no live challenge sniffed yet"); return; }
  uint8_t pkt[SHALLOT_LORA_RESPONSE_LEN];
  pkt[0] = SHALLOT_MSG_RESPONSE;
  memcpy(&pkt[1], &lastChallenge[1], SHALLOT_CHALLENGE_SIZE);  // live nonce
  memcpy(&pkt[1 + SHALLOT_CHALLENGE_SIZE], &lastChallenge[1 + SHALLOT_CHALLENGE_SIZE], 4);  // epoch
  randomBytes(&pkt[1 + SHALLOT_CHALLENGE_SIZE + 4], SHALLOT_HMAC_SIZE);  // forged MAC
  txBytes(pkt, sizeof(pkt), "bad-HMAC response");
}

static void cmdWrongNonce() {
  if (!haveChallenge) { Serial.println("[ROGUE] no live challenge sniffed yet"); return; }
  uint8_t pkt[SHALLOT_LORA_RESPONSE_LEN];
  pkt[0] = SHALLOT_MSG_RESPONSE;
  randomBytes(&pkt[1], SHALLOT_CHALLENGE_SIZE);  // attacker nonce, never live
  memcpy(&pkt[1 + SHALLOT_CHALLENGE_SIZE], &lastChallenge[1 + SHALLOT_CHALLENGE_SIZE], 4);
  memset(&pkt[1 + SHALLOT_CHALLENGE_SIZE + 4], 0, SHALLOT_HMAC_SIZE);
  txBytes(pkt, sizeof(pkt), "wrong-nonce response");
}

static void cmdWrongEpoch() {
  if (!haveChallenge) { Serial.println("[ROGUE] no live challenge sniffed yet"); return; }
  uint8_t pkt[SHALLOT_LORA_RESPONSE_LEN];
  pkt[0] = SHALLOT_MSG_RESPONSE;
  memcpy(&pkt[1], &lastChallenge[1], SHALLOT_CHALLENGE_SIZE);  // live nonce
  uint32_t epoch = ((uint32_t)lastChallenge[1 + SHALLOT_CHALLENGE_SIZE] << 24) |
                   ((uint32_t)lastChallenge[1 + SHALLOT_CHALLENGE_SIZE + 1] << 16) |
                   ((uint32_t)lastChallenge[1 + SHALLOT_CHALLENGE_SIZE + 2] << 8) |
                   ((uint32_t)lastChallenge[1 + SHALLOT_CHALLENGE_SIZE + 3]);
  epoch += 1;  // forged epoch: PLC must reject before any HMAC check
  pkt[1 + SHALLOT_CHALLENGE_SIZE] = (epoch >> 24) & 0xFF;
  pkt[1 + SHALLOT_CHALLENGE_SIZE + 1] = (epoch >> 16) & 0xFF;
  pkt[1 + SHALLOT_CHALLENGE_SIZE + 2] = (epoch >> 8) & 0xFF;
  pkt[1 + SHALLOT_CHALLENGE_SIZE + 3] = epoch & 0xFF;
  randomBytes(&pkt[1 + SHALLOT_CHALLENGE_SIZE + 4], SHALLOT_HMAC_SIZE);
  txBytes(pkt, sizeof(pkt), "wrong-epoch response");
}

static void cmdShort() {
  const uint8_t pkt[] = { SHALLOT_MSG_RESPONSE, 0xDE, 0xAD, 0xBE };
  txBytes(pkt, sizeof(pkt), "SHORT packet");
}

static void cmdDuplicate() {
  if (!havePawResponse) { Serial.println("[ROGUE] no PAW response sniffed yet"); return; }
  txBytes(lastPawResponse, SHALLOT_LORA_RESPONSE_LEN, "DUPLICATE of sniffed PAW response");
}

static void printHelp() {
  Serial.println("SHALLOT ROGUE tester (doc 14). Commands: b=bad-HMAC n=wrong-nonce");
  Serial.println("  e=wrong-epoch s=short-packet d=duplicate-replay ?=help");
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  randomSeed((unsigned long)analogRead(A0) ^ micros());

  rogueSPI.setSCK(ROGUE_SCK_PIN);
  rogueSPI.setTX(ROGUE_MOSI_PIN);
  rogueSPI.setRX(ROGUE_MISO_PIN);
  rogueSPI.begin();

  Serial.println("============================================");
  Serial.println("SHALLOT ROGUE LoRa tester (doc 14) - TEST TOOL ONLY");
  Serial.println("Listens passively; transmits ONLY on command.");
  Serial.println("============================================");

  int st = radio.begin(ROGUE_LORA_FREQUENCY, ROGUE_LORA_BANDWIDTH,
                       ROGUE_LORA_SPREADING_FACTOR, ROGUE_LORA_CODING_RATE,
                       ROGUE_LORA_SYNC_WORD, ROGUE_LORA_OUTPUT_POWER,
                       ROGUE_LORA_PREAMBLE_LENGTH);
  if (st != RADIOLIB_ERR_NONE) {
    Serial.print("[ROGUE] radio begin FAILED: ");
    Serial.println(st);
    return;
  }
  radio.setDio1Action(setRogueFlag);
  radio.startReceive();
  printHelp();
}

void loop() {
  sniffOnce();
  if (Serial.available()) {
    char c = (char)Serial.read();
    switch (c) {
      case 'b': cmdBadHmac(); break;
      case 'n': cmdWrongNonce(); break;
      case 'e': cmdWrongEpoch(); break;
      case 's': cmdShort(); break;
      case 'd': cmdDuplicate(); break;
      case '?': printHelp(); break;
      default: break;
    }
  }
  delay(10);
}
