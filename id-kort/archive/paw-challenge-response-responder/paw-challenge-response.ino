
/*
 * SHALLOT PAW (Personal Authentication Wearable) — Challenge-Response (PRO-52)
 *
 * Hardware: Adafruit Feather RP2350
 *           Core1262 LoRa transceiver on SPI1
 *           1.54" e-Paper display on SPI0
 *
 * Pin mapping (SPI1 / Core1262):
 *   CS    = GPIO9   RST   = GPIO4   BUSY  = GPIO7
 *   DIO1  = GPIO28  SCK   = GPIO10  MOSI   = GPIO11  MISO = GPIO24 (Feather D24)
 *
 * CRITICAL: GPIO4 is SPI0 MISO on RP2350. We use it as RST for Core1262.
 *           Do NOT call SPI1.setRX(4). The SPI1 MISO is on GPIO24 (D24)
 *           per docs/04-kopplingsdokumentation (NOT GPIO12 — that is the
 *           PLC Pico 2 wiring).
 *           RST is output-only so it does not conflict with SPI0 MISO
 *           functionally, but ensure the e-Paper library does not
 *           reconfigure GPIO4 as SPI0 MISO after Core1262 RST is set.
 *
 * LoRa config (PRO-78): 868.1 MHz, SF7, BW125, CR4/5, sync 0x12, 20 dBm
 * Protocol (PRO-81): challenge-response with HMAC-SHA256 truncated to 8 bytes
 *
 * ARKIVERAD (se ../README.md) — RadioLib/LoRa är ur scope.
 *
 * TEST-ONLY DEVELOPMENT KEY (bench fixture, NEVER production):
 * MASTER_KEY = 00..0F är en publik testvektor, inte ett hemlighet.
 * Den får aldrig byggas till en firmware-artefakt utan explicit
 * opt-in, precis som plc/edge-challenge-response/edge-challenge-response.ino:
 * -DPAW_ARCHIVE_ALLOW_DEV_KEY=1. Utan flaggan vägrar bygget med #error.
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
#define LORA_MISO  24  // Feather D24 per docs/04 (PLC uses GPIO12)

#define LORA_FREQ       868.1
#define LORA_BW         125.0
#define LORA_SF         7
#define LORA_CR         5
#define LORA_SYNC_WORD  0x12
#define LORA_TX_POWER   20
#define LORA_TIMEOUT_MS 5000

// Fail-closed dev-key guard: MASTER_KEY nedan är en publik bänkvektor
// (00..0F). Ingen artefakt får byggas från den utan att byggaren
// uttryckligen opt-in:ar, och ingen CI-jobb gör det (jobbet
// build-paw-pro52 är borttaget). Mönster: edge-challenge-response.ino.
#ifndef PAW_ARCHIVE_ALLOW_DEV_KEY
#error "arkiverad paw-challenge-response bäddar in en TEST-ONLY dev-nyckel; bygg aldrig den här filen (opt-in: -DPAW_ARCHIVE_ALLOW_DEV_KEY=1)"
#endif

static const uint8_t MASTER_KEY[SHALLOT_MASTER_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t PAW_SENDER_ID[SHALLOT_SENDERID_LEN] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static SPIClassRP2040 loraSPI(spi1, LORA_MISO, LORA_CS, LORA_SCK, LORA_MOSI);
static SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY, loraSPI);
static ShallotKeys keys;
static uint32_t pawSeqNum = 0;
static SeqWhitelist seqWhitelist;

// Outstanding cycle for verdict binding (PRO-52 review): the challenge
// nonce we last responded to and still await a verdict for. A verdict is
// acted on only if its payload decrypts to this exact nonce.
static bool awaitingVerdict = false;
static uint8_t outstandingNonce[SHALLOT_NONCE_LEN];

#define LED_PIN 6  // NOT 7 (Core1262 BUSY) and NOT 25 (e-Paper BUSY on this
                   // Feather wiring) — matches paw-main.ino LED relocation

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
        // HMAC-valid challenge outside our window: the edge rebooted and
        // restarted its seq counter. Re-anchor — safe: answering a
        // replayed old challenge only yields a response echoing a STALE
        // nonce, which the edge rejects against its live challenge, so
        // this oracle is unusable (fail-closed at the edge).
        Serial.println("[SHALLOT] Resync: re-anchoring replay window after edge reboot");
        seqWhitelist.resync(challenge.seqNum);
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

    // The verdict must echo THIS challenge: remember its nonce while we
    // await the verdict (a newer challenge overwrites it; a stale verdict
    // then mismatches and is ignored).
    memcpy(outstandingNonce, challenge.nonce, SHALLOT_NONCE_LEN);
    awaitingVerdict = true;

    Serial.println("[SHALLOT] Sending RESPONSE...");
    send_packet(response);

    size_t verdictLen = 0;
    ShallotPacket verdict;

    if (!receive_packet(verdictLen, verdict, LORA_TIMEOUT_MS)) {
        Serial.println("[SHALLOT] No verdict received from edge");
        display_status("Timeout: No verdict");
        awaitingVerdict = false;
        return;
    }

    // A fresh CHALLENGE (or any non-verdict type) is NEVER a verdict:
    // ignore it without state change, HMAC work, or display update.
    // The 5 s verdict window bounds the wait; the next edge retry then
    // succeeds normally.
    if (verdict.msgType != MSG_SUCCESS && verdict.msgType != MSG_FAILURE) {
        Serial.println("[SHALLOT] Non-verdict packet during verdict wait — ignoring");
        return;
    }

    uint8_t verdictHmac[SHALLOT_HMAC_LEN];
    compute_packet_hmac(keys, rxBuf, verdictLen, verdictHmac);

    if (constant_time_compare(verdictHmac, verdict.hmac, SHALLOT_HMAC_LEN) != 0) {
        Serial.println("[SHALLOT] VERDICT HMAC verification FAILED");
        display_status("WARNING: Invalid verdict");
        return;
    }

    // Bind the verdict to the outstanding cycle: its payload must decrypt
    // (K_enc) to the echo of the challenge nonce we responded to.
    // Unknown or mismatched verdicts are ignored (fail-closed: no display
    // change, outstanding cycle kept for the real verdict).
    if (!awaitingVerdict || verdict.payloadLen != SHALLOT_NONCE_LEN ||
        !verify_echo_binding(keys, verdict.payload, verdict.seqNum,
                             verdict.nonce, outstandingNonce,
                             SHALLOT_NONCE_LEN)) {
        Serial.println("[SHALLOT] VERDICT not bound to outstanding challenge — ignoring");
        return;
    }
    awaitingVerdict = false;
    memset(outstandingNonce, 0, sizeof(outstandingNonce));

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
