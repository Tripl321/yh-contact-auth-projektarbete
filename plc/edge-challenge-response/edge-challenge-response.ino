
/*
 * SHALLOT Edge Enforcement — Challenge-Response (PRO-52)
 *
 * Hardware: Raspberry Pi Pico 2 (RP2350)
 *           Core1262 LoRa transceiver on SPI1
 *
 * Pin mapping (SPI1 / Core1262) — Pico 2 bench wiring per
 * docs/04-kopplingsdokumentation and plc-key-receiver.ino:
 *   CS    = GPIO9   RST   = GPIO8   BUSY  = GPIO6
 *   DIO1  = GPIO21  SCK   = GPIO10  MOSI   = GPIO11  MISO = GPIO12
 *
 * NOTE: Pico 2 onboard LED is a WS2812 RGB on GPIO25 — plain
 * digitalWrite(LED_PIN) toggles the pin but does not visibly light it
 * (needs a NeoPixel/PIO driver). Status is on Serial; LED kept for
 * convention with plc-key-receiver.ino.
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
#define LORA_RST   8   // bench wiring (PLC Pico 2)
#define LORA_BUSY  6   // bench wiring (PLC Pico 2)
#define LORA_DIO1  21  // bench wiring (PLC Pico 2)
#define LORA_SCK   10
#define LORA_MOSI  11
#define LORA_MISO  12

#define LORA_FREQ       868.1
#define LORA_BW         125.0
#define LORA_SF         7
#define LORA_CR         5
#define LORA_SYNC_WORD  0x12
#define LORA_TX_POWER   20
#define LORA_TIMEOUT_MS 5000
#define LORA_RETRIES    3

static const uint8_t MASTER_KEY[SHALLOT_MASTER_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t EDGE_SENDER_ID[SHALLOT_SENDERID_LEN] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static SPIClassRP2040 loraSPI(spi1, LORA_MISO, LORA_CS, LORA_SCK, LORA_MOSI);
static SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY, loraSPI);
static ShallotKeys keys;
static uint32_t edgeSeqNum = 0;
static SeqWhitelist seqWhitelist;

#define LED_PIN 25

// Reusable TX/RX buffers — allocated once at file scope, not per-call.
static uint8_t txBuf[SHALLOT_MAX_PACKET];
static uint8_t rxBuf[SHALLOT_MAX_PACKET];

void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }
    Serial.println("[SHALLOT] Edge Enforcement starting...");

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);

    loraSPI.setSCK(LORA_SCK);
    loraSPI.setTX(LORA_MOSI);
    loraSPI.setRX(LORA_MISO);
    loraSPI.setCS(LORA_CS);
    loraSPI.begin();

    // RadioLib order: freq, bandwidth, spreading factor, coding rate.
    int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                            LORA_SYNC_WORD, LORA_TX_POWER);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("[SHALLOT] Radio init failed: ");
        Serial.println(state);
        while (true) {
            digitalWrite(LED_PIN, HIGH); delay(200);
            digitalWrite(LED_PIN, LOW);  delay(200);
        }
    }
    Serial.println("[SHALLOT] Radio initialized (868.1 MHz, SF7, BW125, CR4/5, 20dBm)");

    derive_keys(MASTER_KEY, keys);
    Serial.println("[SHALLOT] Keys derived from master key.");
    Serial.println("[SHALLOT] Edge Enforcement ready.");
    delay(2000);
}

// Serialize and transmit a ShallotPacket using the shared txBuf.
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

// Receive into shared rxBuf, parse into pkt, output raw length via rxLen.
static bool receive_packet(size_t &rxLen, ShallotPacket &pkt, uint32_t timeoutMs) {
    int state = radio.receive(rxBuf, SHALLOT_MAX_PACKET, timeoutMs);
    if (state != RADIOLIB_ERR_NONE) {
        if (state == RADIOLIB_ERR_RX_TIMEOUT) {
            Serial.println("[SHALLOT] RX timeout.");
        } else {
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

// Fill a ShallotPacket with header fields and compute its HMAC.
// Uses memcpy_fast for fixed-size fields and avoids redundant work.
static void build_simple_packet(ShallotPacket &pkt, uint8_t msgType,
                                const uint8_t *challengeNonce) {
    pkt.version = SHALLOT_VERSION;
    pkt.msgType = msgType;
    memcpy(pkt.senderID, EDGE_SENDER_ID, SHALLOT_SENDERID_LEN);
    pkt.seqNum = edgeSeqNum++;
    if (challengeNonce)
        memcpy(pkt.nonce, challengeNonce, SHALLOT_NONCE_LEN);
    else
        generate_nonce(pkt.nonce);
    pkt.payloadLen = 0;
    compute_packet_hmac(keys, pkt, pkt.hmac);
}

static bool run_challenge_response() {
    Serial.println("\n[SHALLOT] === Challenge-Response Cycle ===");

    for (int attempt = 0; attempt < LORA_RETRIES; attempt++) {
        ShallotPacket challenge;
        build_simple_packet(challenge, MSG_CHALLENGE, nullptr);

        Serial.print("[SHALLOT] Sending CHALLENGE (attempt ");
        Serial.print(attempt + 1);
        Serial.print("/");
        Serial.print(LORA_RETRIES);
        Serial.println(")...");

        if (!send_packet(challenge)) {
            delay(1000);
            continue;
        }

        Serial.println("[SHALLOT] Waiting for RESPONSE...");
        size_t rxLen = 0;
        ShallotPacket response;

        if (!receive_packet(rxLen, response, LORA_TIMEOUT_MS)) {
            Serial.println("[SHALLOT] No response received, retrying...");
            delay(500);
            continue;
        }

        if (response.msgType != MSG_RESPONSE) {
            Serial.print("[SHALLOT] Unexpected message type: 0x");
            Serial.println(response.msgType, HEX);
            continue;
        }

        // HMAC verification before seq check — only consume sequence numbers for authenticated packets.
        uint8_t computedHmac[SHALLOT_HMAC_LEN];
        compute_packet_hmac(keys, rxBuf, rxLen, computedHmac);

        if (constant_time_compare(computedHmac, response.hmac, SHALLOT_HMAC_LEN) != 0) {
            Serial.println("[SHALLOT] HMAC VERIFICATION FAILED");
            ShallotPacket failure;
            build_simple_packet(failure, MSG_FAILURE, challenge.nonce);
            send_packet(failure);
            digitalWrite(LED_PIN, LOW);
            return false;
        }

        if (!seqWhitelist.check_and_add(response.seqNum)) {
            Serial.println("[SHALLOT] REPLAY DETECTED: sequence number rejected");
            continue;
        }

        Serial.println("[SHALLOT] HMAC VERIFICATION PASSED");

        ShallotPacket success;
        build_simple_packet(success, MSG_SUCCESS, challenge.nonce);
        send_packet(success);

        digitalWrite(LED_PIN, HIGH);
        Serial.println("[SHALLOT] Challenge-Response SUCCESS");
        return true;
    }

    Serial.println("[SHALLOT] Challenge-Response FAILED after all retries");
    digitalWrite(LED_PIN, LOW);
    return false;
}

void loop() {
    run_challenge_response();
    Serial.println("[SHALLOT] Next cycle in 10 seconds...");
    delay(10000);
}
