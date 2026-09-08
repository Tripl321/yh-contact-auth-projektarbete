
/*
 * SHALLOT PAW (Personal Authentication Wearable) — Challenge-Response (PRO-52)
 *
 * Hardware: Adafruit Feather RP2350
 *           Core1262 LoRa transceiver on SPI1
 *           1.54" e-Paper display on SPI0
 *
 * Pin mapping (SPI1 / Core1262):
 *   CS    = GPIO9   RST   = GPIO4   BUSY  = GPIO7
 *   DIO1  = GPIO28  SCK   = GPIO10  MOSI   = GPIO11  MISO = GPIO24
 *
 * CRITICAL: GPIO4 is SPI0 MISO on RP2350. We use it as RST for Core1262.
 *           Do NOT call SPI1.setRX(4). The SPI1 MISO is on GPIO24 (D24).
 *           RST is output-only so it does not conflict with SPI0 MISO
 *           functionally, but ensure the e-Paper library does not
 *           reconfigure GPIO4 as SPI0 MISO after Core1262 RST is set.
 *
 * LoRa config (PRO-78): 868.1 MHz, SF7, BW125, CR4/5, sync 0x12, 20 dBm
 * Protocol (PRO-81): challenge-response with HMAC-SHA256 truncated to 8 bytes
 */

#include <SPI.h>
#include <RadioLib.h>
#include "hardware/sha256.h"
#include "pico/rand.h"
#include "shallot_protocol.h"

#define LORA_CS    9
#define LORA_RST   4
#define LORA_BUSY  7
#define LORA_DIO1  28
#define LORA_SCK   10
#define LORA_MOSI  11
#define LORA_MISO  24

#define LORA_FREQ       868.1
#define LORA_BW         125.0
#define LORA_SF         7
#define LORA_CR         5
#define LORA_SYNC_WORD  0x12
#define LORA_TX_POWER   20
#define LORA_TIMEOUT_MS 5000

static const uint8_t MASTER_KEY[SHALLOT_MASTER_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t PAW_SENDER_ID[SHALLOT_SENDERID_LEN] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static SPIClass spi1(spi1);
static SX1262 radio = RadioLibModule(&spi1, LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY);
static ShallotKeys keys;
static uint32_t pawSeqNum = 0;
static SeqWhitelist seqWhitelist;

#define LED_PIN 25

static uint8_t txBuf[SHALLOT_MAX_PACKET];
static uint8_t rxBuf[SHALLOT_MAX_PACKET];

static void display_status(const char *status) {
    Serial.print("[E-PAPER] ");
    Serial.println(status);
}

void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }
    Serial.println("[SHALLOT] PAW starting...");

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);

    spi1.setSCK(LORA_SCK);
    spi1.setTX(LORA_MOSI);
    spi1.setRX(LORA_MISO);
    spi1.setCS(LORA_CS);
    spi1.begin();

    int state = radio.begin(LORA_FREQ, LORA_SF, LORA_BW, LORA_CR,
                            LORA_SYNC_WORD, LORA_TX_POWER);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("[SHALLOT] Radio init failed: ");
        Serial.println(state);
        display_status("ERROR: Radio init failed");
        while (true) {
            digitalWrite(LED_PIN, HIGH); delay(200);
            digitalWrite(LED_PIN, LOW);  delay(200);
        }
    }
    Serial.println("[SHALLOT] Radio initialized (868.1 MHz, SF7, BW125, CR4/5, 20dBm)");

    derive_keys(MASTER_KEY, keys);
    Serial.println("[SHALLOT] Keys derived from master key.");

    display_status("PAW Ready");
    Serial.println("[SHALLOT] PAW ready. Listening for challenges...");
}

static bool send_packet(const ShallotPacket &pkt) {
    size_t pktLen = build_packet(pkt, txBuf, sizeof(txBuf));
    if (pktLen == 0) {
        Serial.println("[SHALLOT] ERROR: build_packet returned 0");
        return false;
    }

    int state = radio.transmit(txBuf, pktLen);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("[SHALLOT] TX failed: ");
        Serial.println(state);
        return false;
    }
    return true;
}

static bool receive_packet(size_t &rxLen, ShallotPacket &pkt, uint32_t timeoutMs) {
    int state = radio.receive(rxBuf, SHALLOT_MAX_PACKET, timeoutMs);
    if (state != RADIOLIB_ERR_NONE) {
        if (state != RADIOLIB_ERR_RX_TIMEOUT) {
            Serial.print("[SHALLOT] RX error: ");
            Serial.println(state);
        }
        return false;
    }

    rxLen = radio.getPacketLength();
    if (!parse_packet(rxBuf, rxLen, pkt)) {
        Serial.println("[SHALLOT] ERROR: parse_packet failed (malformed)");
        return false;
    }
    return true;
}

static void handle_challenge(size_t challengeWireLen, const ShallotPacket &challenge) {
    Serial.println("[SHALLOT] === Handling CHALLENGE ===");

    uint8_t computedHmac[SHALLOT_HMAC_LEN];
    compute_packet_hmac(keys, rxBuf, challengeWireLen, computedHmac);

    if (constant_time_compare(computedHmac, challenge.hmac, SHALLOT_HMAC_LEN) != 0) {
        Serial.println("[SHALLOT] CHALLENGE HMAC verification FAILED — ignoring");
        display_status("WARNING: Invalid challenge");
        return;
    }
    Serial.println("[SHALLOT] CHALLENGE HMAC verified OK");

    if (!seqWhitelist.check_and_add(challenge.seqNum)) {
        Serial.println("[SHALLOT] CHALLENGE replay detected — ignoring");
        display_status("WARNING: Replay attempt");
        return;
    }

    ShallotPacket response;
    response.version = SHALLOT_VERSION;
    response.msgType = MSG_RESPONSE;
    memcpy(response.senderID, PAW_SENDER_ID, SHALLOT_SENDERID_LEN);
    response.seqNum = pawSeqNum++;
    generate_nonce(response.nonce);

    memcpy(response.payload, challenge.nonce, SHALLOT_NONCE_LEN);
    response.payloadLen = SHALLOT_NONCE_LEN;

    aes_ctr_crypt(keys.k_enc, response.seqNum, response.nonce,
                  response.payload, response.payloadLen);

    compute_packet_hmac(keys, response, response.hmac);

    Serial.println("[SHALLOT] Sending RESPONSE...");
    send_packet(response);

    size_t verdictLen = 0;
    ShallotPacket verdict;

    if (!receive_packet(verdictLen, verdict, LORA_TIMEOUT_MS)) {
        Serial.println("[SHALLOT] No verdict received from edge");
        display_status("Timeout: No verdict");
        return;
    }

    uint8_t verdictHmac[SHALLOT_HMAC_LEN];
    compute_packet_hmac(keys, rxBuf, verdictLen, verdictHmac);

    if (constant_time_compare(verdictHmac, verdict.hmac, SHALLOT_HMAC_LEN) != 0) {
        Serial.println("[SHALLOT] VERDICT HMAC verification FAILED");
        display_status("WARNING: Invalid verdict");
        return;
    }

    if (verdict.msgType == MSG_SUCCESS) {
        Serial.println("[SHALLOT] AUTHENTICATION SUCCESSFUL");
        digitalWrite(LED_PIN, HIGH);
        display_status("Access Granted");
        delay(3000);
        digitalWrite(LED_PIN, LOW);
    } else if (verdict.msgType == MSG_FAILURE) {
        Serial.println("[SHALLOT] AUTHENTICATION DENIED");
        digitalWrite(LED_PIN, LOW);
        display_status("Access Denied");
    } else {
        Serial.print("[SHALLOT] Unexpected verdict type: 0x");
        Serial.println(verdict.msgType, HEX);
        display_status("Unknown verdict");
    }
}

void loop() {
    size_t rxLen = 0;
    ShallotPacket incoming;

    if (receive_packet(rxLen, incoming, 10000)) {
        if (incoming.msgType == MSG_CHALLENGE) {
            handle_challenge(rxLen, incoming);
        } else {
            Serial.print("[SHALLOT] Ignoring non-CHALLENGE message: 0x");
            Serial.println(incoming.msgType, HEX);
        }
    }
}
