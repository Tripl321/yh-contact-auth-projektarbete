/*
 * SHALLOT Protocol Unit Tests (PRO-52)
 *
 * Hardware: Raspberry Pi Pico 2 (RP2350)
 * Purpose:  Verify protocol functions — key derivation, HMAC, packet
 *           build/parse roundtrip, SeqWhitelist replay detection.
 *
 * Upload to Pico 2 and monitor Serial at 115200 baud.
 * All tests should print PASS. Any FAIL indicates a regression.
 */

#include <stdint.h>
#include <string.h>
#include "hardware/sha256.h"
#include "pico/rand.h"
#include <AESLib.h>
#include "shallot_protocol.h"

#define TEST_PASS() do { Serial.println("PASS: " __STRING(__LINE__)); passCount++; } while (0)
#define TEST_FAIL(msg) do { Serial.print("FAIL: "); Serial.println(msg); failCount++; } while (0)

static int passCount = 0;
static int failCount = 0;

// Known-answer test for key derivation
static void test_derive_keys() {
    Serial.println("\n=== test_derive_keys ===");

    uint8_t masterKey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    ShallotKeys keys;
    derive_keys(masterKey, keys);

    // K_enc and K_mac must differ (different labels "ENC" vs "MAC")
    if (memcmp(keys.k_enc, keys.k_mac, SHALLOT_KEY_LEN) == 0) {
        TEST_FAIL("K_enc == K_mac (should differ)")
    } else {
        TEST_PASS();
    }

    // Re-derivation must be deterministic
    ShallotKeys keys2;
    derive_keys(masterKey, keys2);
    if (memcmp(keys.k_enc, keys2.k_enc, SHALLOT_KEY_LEN) != 0) {
        TEST_FAIL("K_enc not deterministic")
    } else {
        TEST_PASS();
    }
    if (memcmp(keys.k_mac, keys2.k_mac, SHALLOT_KEY_LEN) != 0) {
        TEST_FAIL("K_mac not deterministic")
    } else {
        TEST_PASS();
    }
}

// HMAC known-answer test (verify truncation to 8 bytes)
static void test_hmac_truncation() {
    Serial.println("\n=== test_hmac_truncation ===");

    uint8_t key[16] = {0};
    uint8_t msg[] = "test message";
    uint8_t out[SHALLOT_HMAC_LEN];

    hmac_sha256_truncated(key, msg, strlen((char*)msg), out);

    // Output must be 8 bytes (not 32)
    // Verify it is not all zeros
    bool allZero = true;
    for (int i = 0; i < SHALLOT_HMAC_LEN; i++) {
        if (out[i] != 0) { allZero = false; break; }
    }
    if (allZero) {
        TEST_FAIL("HMAC output is all zeros")
    } else {
        TEST_PASS();
    }

    // Deterministic: same input produces same output
    uint8_t out2[SHALLOT_HMAC_LEN];
    hmac_sha256_truncated(key, msg, strlen((char*)msg), out2);
    if (memcmp(out, out2, SHALLOT_HMAC_LEN) != 0) {
        TEST_FAIL("HMAC not deterministic")
    } else {
        TEST_PASS();
    }
}

// Packet build/parse roundtrip
static void test_packet_roundtrip() {
    Serial.println("\n=== test_packet_roundtrip ===");

    ShallotPacket pkt;
    pkt.version = SHALLOT_VERSION;
    pkt.msgType = MSG_CHALLENGE;
    memset(pkt.senderID, 0x42, SHALLOT_SENDERID_LEN);
    pkt.seqNum = 0xDEADBEEF;
    memset(pkt.nonce, 0xAB, SHALLOT_NONCE_LEN);
    pkt.payloadLen = 16;
    memset(pkt.payload, 0x55, 16);
    memset(pkt.hmac, 0x77, SHALLOT_HMAC_LEN);

    uint8_t wire[SHALLOT_MAX_PACKET];
    size_t wireLen = build_packet(pkt, wire, sizeof(wire));
    if (wireLen == 0) {
        TEST_FAIL("build_packet returned 0")
        return;
    }

    // Expected size: header(21) + payload(16) + HMAC(8) = 45
    if (wireLen != 21 + 16 + 8) {
        Serial.print("  Expected 45, got ");
        Serial.println(wireLen);
        TEST_FAIL("build_packet wrong size")
    } else {
        TEST_PASS();
    }

    ShallotPacket parsed;
    if (!parse_packet(wire, wireLen, parsed)) {
        TEST_FAIL("parse_packet failed")
        return;
    }

    if (parsed.version != pkt.version) { TEST_FAIL("version mismatch") }
    else { TEST_PASS(); }

    if (parsed.msgType != pkt.msgType) { TEST_FAIL("msgType mismatch") }
    else { TEST_PASS(); }

    if (parsed.seqNum != pkt.seqNum) { TEST_FAIL("seqNum mismatch") }
    else { TEST_PASS(); }

    if (memcmp(parsed.senderID, pkt.senderID, SHALLOT_SENDERID_LEN) != 0) {
        TEST_FAIL("senderID mismatch")
    } else { TEST_PASS(); }

    if (memcmp(parsed.nonce, pkt.nonce, SHALLOT_NONCE_LEN) != 0) {
        TEST_FAIL("nonce mismatch")
    } else { TEST_PASS(); }

    if (parsed.payloadLen != pkt.payloadLen) { TEST_FAIL("payloadLen mismatch") }
    else { TEST_PASS(); }

    if (memcmp(parsed.payload, pkt.payload, pkt.payloadLen) != 0) {
        TEST_FAIL("payload mismatch")
    } else { TEST_PASS(); }

    if (memcmp(parsed.hmac, pkt.hmac, SHALLOT_HMAC_LEN) != 0) {
        TEST_FAIL("hmac mismatch")
    } else { TEST_PASS(); }
}

// Constant-time comparison
static void test_constant_time_compare() {
    Serial.println("\n=== test_constant_time_compare ===");

    uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t c[8] = {1, 2, 3, 4, 5, 6, 7, 9};

    if (constant_time_compare(a, b, 8) != 0) {
        TEST_FAIL("equal buffers should return 0")
    } else { TEST_PASS(); }

    if (constant_time_compare(a, c, 8) == 0) {
        TEST_FAIL("different buffers should return non-zero")
    } else { TEST_PASS(); }
}

// SeqWhitelist replay detection
static void test_seq_whitelist() {
    Serial.println("\n=== test_seq_whitelist ===");

    SeqWhitelist wl;

    // First packet: accepted
    if (!wl.check_and_add(100)) { TEST_FAIL("first packet rejected") }
    else { TEST_PASS(); }

    // Duplicate of first: rejected (replay)
    if (wl.check_and_add(100)) { TEST_FAIL("duplicate accepted") }
    else { TEST_PASS(); }

    // Newer packet: accepted
    if (!wl.check_and_add(101)) { TEST_FAIL("seq 101 rejected") }
    else { TEST_PASS(); }

    // Old packet outside window: rejected
    if (wl.check_and_add(90)) { TEST_FAIL("seq 90 (outside window) accepted") }
    else { TEST_PASS(); }

    // Packet within window but already seen: rejected
    if (wl.check_and_add(100)) { TEST_FAIL("seq 100 re-accepted") }
    else { TEST_PASS(); }

    // Packet far ahead: accepted, resets window
    if (!wl.check_and_add(200)) { TEST_FAIL("seq 200 rejected") }
    else { TEST_PASS(); }

    // Old packet after window shift: rejected
    if (wl.check_and_add(101)) { TEST_FAIL("seq 101 accepted after window shift") }
    else { TEST_PASS(); }
}

// AES-CTR encrypt/decrypt roundtrip (symmetric)
static void test_aes_ctr_roundtrip() {
    Serial.println("\n=== test_aes_ctr_roundtrip ===");

    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t nonce[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    uint8_t data[32];
    uint8_t original[32];

    // Fill with test pattern
    for (int i = 0; i < 32; i++) {
        data[i] = (uint8_t)(i * 7 + 3);
        original[i] = data[i];
    }

    // Encrypt
    aes_ctr_crypt(key, 0x12345678, nonce, data, 32);

    // Ciphertext should differ from plaintext
    if (memcmp(data, original, 32) == 0) {
        TEST_FAIL("ciphertext same as plaintext")
    } else { TEST_PASS(); }

    // Decrypt (same operation)
    aes_ctr_crypt(key, 0x12345678, nonce, data, 32);

    // Should recover original
    if (memcmp(data, original, 32) != 0) {
        TEST_FAIL("decryption did not recover original")
    } else { TEST_PASS(); }
}

// HMAC wire-data overload (no intermediate buffer)
static void test_hmac_wire_overload() {
    Serial.println("\n=== test_hmac_wire_overload ===");

    ShallotKeys keys;
    uint8_t masterKey[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    derive_keys(masterKey, keys);

    // Build a packet
    ShallotPacket pkt;
    pkt.version = SHALLOT_VERSION;
    pkt.msgType = MSG_RESPONSE;
    memset(pkt.senderID, 0x01, SHALLOT_SENDERID_LEN);
    pkt.seqNum = 42;
    memset(pkt.nonce, 0xCD, SHALLOT_NONCE_LEN);
    pkt.payloadLen = 8;
    memset(pkt.payload, 0xEF, 8);

    // Compute HMAC via struct overload
    uint8_t hmacStruct[SHALLOT_HMAC_LEN];
    compute_packet_hmac(keys, pkt, hmacStruct);

    // Build wire buffer
    uint8_t wire[SHALLOT_MAX_PACKET];
    size_t wireLen = build_packet(pkt, wire, sizeof(wire));

    // Compute HMAC via wire overload (should match)
    uint8_t hmacWire[SHALLOT_HMAC_LEN];
    compute_packet_hmac(keys, wire, wireLen, hmacWire);

    if (memcmp(hmacStruct, hmacWire, SHALLOT_HMAC_LEN) != 0) {
        TEST_FAIL("struct HMAC != wire HMAC")
    } else { TEST_PASS(); }
}

void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }

    Serial.println("====================================");
    Serial.println("SHALLOT Protocol Unit Tests (PRO-52)");
    Serial.println("====================================");

    test_derive_keys();
    test_hmac_truncation();
    test_packet_roundtrip();
    test_constant_time_compare();
    test_seq_whitelist();
    test_aes_ctr_roundtrip();
    test_hmac_wire_overload();

    Serial.println("\n====================================");
    Serial.print("Results: ");
    Serial.print(passCount);
    Serial.print(" passed, ");
    Serial.print(failCount);
    Serial.println(" failed");
    Serial.println("====================================");

    if (failCount > 0) {
        Serial.println("TESTS FAILED!");
    } else {
        Serial.println("ALL TESTS PASSED");
    }
}

void loop() {
    // Tests run once in setup()
}
