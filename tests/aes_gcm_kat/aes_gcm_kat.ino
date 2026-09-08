/*
 * SHALLOT — AES-128-GCM Known-Answer Tests (PLC/PAW)
 *
 * Standalone sketch that verifies BearSSL's AES-128-GCM implementation
 * against NIST SP 800-38D test vectors.
 *
 * Upload to PLC (Pico 2W) or PAW (Feather RP2350) and open Serial Monitor.
 * All tests must print PASS before any envelope implementation begins.
 *
 * Test vectors: NIST GCM test vectors from BearSSL test_crypto.c
 * Format per vector: key, plaintext, AAD, IV, ciphertext, tag
 *
 * No real keys. No provisioning. No USB relay. Test only.
 */

#include <Arduino.h>
#include <bearssl/bearssl_aead.h>
#include <bearssl/bearssl_block.h>

// =============================================================
// NIST AES-128-GCM Test Vectors (from NIST SP 800-38D, also in BearSSL test_crypto.c)
// Format: key, plaintext, AAD, IV, expected_ciphertext, expected_tag
// =============================================================

struct GCMTest {
    const char* name;
    const uint8_t* key;     size_t keyLen;
    const uint8_t* pt;      size_t ptLen;
    const uint8_t* aad;     size_t aadLen;
    const uint8_t* iv;      size_t ivLen;
    const uint8_t* ct;      size_t ctLen;
    const uint8_t* tag;     size_t tagLen;
};

// Test 1: Empty plaintext, empty AAD
static const uint8_t k1_key[]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t k1_iv[]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t k1_tag[] = {0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};

// Test 2: Single block plaintext, empty AAD
static const uint8_t k2_key[]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t k2_pt[]   = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t k2_iv[]   = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t k2_ct[]   = {0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
static const uint8_t k2_tag[] = {0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};

// Test 3: Full plaintext, empty AAD, non-zero key
static const uint8_t k3_key[]  = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
static const uint8_t k3_pt[]   = {0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
                                  0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
                                  0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
                                  0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55};
static const uint8_t k3_iv[]   = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
static const uint8_t k3_ct[]   = {0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
                                  0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
                                  0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
                                  0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85};
static const uint8_t k3_tag[] = {0x4d,0x5c,0x2a,0xf3,0x27,0xcd,0x64,0xa6,0x2c,0xf3,0x5a,0xbd,0x2b,0xa6,0xfa,0xb4};

// Test 4: Full plaintext with AAD, non-zero key
static const uint8_t k4_aad[]  = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
                                  0xab,0xad,0xda,0xd2};
static const uint8_t k4_ct[]   = {0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
                                  0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
                                  0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
                                  0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91};
static const uint8_t k4_tag[] = {0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47};

// Test 5: SHALLOT-specific — verify AAD binding fails with wrong AAD
// Same as Test 3 but with wrong AAD — tag check must FAIL
static const uint8_t k5_aad[]  = {0x02,0x00,0x00,0x00,0x01,0x00}; // target=PAW, epoch=1, seq=0

static const GCMTest tests[] = {
    {"Test 1: empty pt, empty aad",
     k1_key, 16,
     nullptr, 0,
     nullptr, 0,
     k1_iv, 12,
     nullptr, 0,
     k1_tag, 16},
    {"Test 2: one block pt, empty aad",
     k2_key, 16,
     k2_pt, 16,
     nullptr, 0,
     k2_iv, 12,
     k2_ct, 16,
     k2_tag, 16},
    {"Test 3: full pt, empty aad",
     k3_key, 16,
     k3_pt, sizeof(k3_pt),
     nullptr, 0,
     k3_iv, 12,
     k3_ct, sizeof(k3_ct),
     k3_tag, 16},
    {"Test 4: full pt with aad",
     k4_aad ? k3_key : k3_key, 16,
     k3_pt, 60,  // truncated to match ct
     k4_aad, sizeof(k4_aad),
     k3_iv, 12,
     k4_ct, sizeof(k4_ct),
     k4_tag, 16},
};

static const int numTests = 4;

// =============================================================
// Test runner
// =============================================================

static bool run_gcm_test(const GCMTest* t, bool expectTagMatch) {
    br_aes_big_ctr_keys bc;
    br_gcm_context gcm;
    uint8_t ct[128];
    uint8_t tag[16];

    // Initialize
    br_aes_big_ctr_init(&bc, t->key, t->keyLen);
    br_gcm_init(&gcm, (const br_block_ctr_class **)&br_aes_big_ctr_vtable, br_ghash_ctmul32);

    // Reset with IV
    br_gcm_reset(&gcm, t->iv, t->ivLen);

    // Inject AAD
    if (t->aadLen > 0) {
        br_gcm_aad_inject(&gcm, t->aad, t->aadLen);
    }

    // Flip to cipher mode
    br_gcm_flip(&gcm);

    // Encrypt plaintext
    if (t->ptLen > 0) {
        memcpy(ct, t->pt, t->ptLen);
        br_gcm_run(&gcm, 1, ct, t->ptLen);
    } else {
        // No plaintext — but we still need to check the tag
    }

    // Get tag
    br_gcm_get_tag(&gcm, tag);

    // Compare ciphertext
    bool ctOK = true;
    if (t->ctLen > 0) {
        if (memcmp(ct, t->ct, t->ctLen) != 0) {
            ctOK = false;
            Serial.print("  Ciphertext mismatch: got ");
            for (size_t i = 0; i < t->ctLen; i++) {
                if (ct[i] < 0x10) Serial.print('0');
                Serial.print(ct[i], HEX);
            }
            Serial.println();
        }
    }

    // Compare tag
    uint32_t tagCheck = br_gcm_check_tag(&gcm, t->tag);
    bool tagOK = (tagCheck == 1);

    if (!tagOK) {
        Serial.print("  Tag mismatch: got ");
        for (int i = 0; i < 16; i++) {
            if (tag[i] < 0x10) Serial.print('0');
            Serial.print(tag[i], HEX);
        }
        Serial.print(" expected ");
        for (size_t i = 0; i < t->tagLen; i++) {
            if (t->tag[i] < 0x10) Serial.print('0');
            Serial.print(t->tag[i], HEX);
        }
        Serial.println();
    }

    // Zeroize
    memset(&bc, 0, sizeof(bc));
    memset(&gcm, 0, sizeof(gcm));
    memset(ct, 0, sizeof(ct));
    memset(tag, 0, sizeof(tag));

    if (expectTagMatch) {
        return ctOK && tagOK;
    } else {
        return !tagOK; // Expect failure
    }
}

void setup() {
    Serial.begin(115200);
    delay(3000);

    Serial.println();
    Serial.println("============================================");
    Serial.println("SHALLOT — AES-128-GCM Known-Answer Tests");
    Serial.println("Library: BearSSL (br_gcm_*)");
    Serial.println("Vectors: NIST SP 800-38D");
    Serial.println("============================================");
    Serial.println();

    int passed = 0;
    int failed = 0;

    // Run NIST tests
    for (int i = 0; i < numTests; i++) {
        Serial.print(tests[i].name);
        Serial.print("... ");
        bool ok = run_gcm_test(&tests[i], true);
        if (ok) {
            Serial.println("PASS");
            passed++;
        } else {
            Serial.println("FAIL");
            failed++;
        }
    }

    // Test 5: Wrong AAD must fail tag check
    Serial.print("Test 5: wrong AAD tag must fail... ");
    GCMTest t5 = tests[2]; // Reuse test 3 key/plaintext/iv
    t5.name = "Test 5: wrong AAD (SHALLOT binding)";
    t5.aad = k5_aad;
    t5.aadLen = sizeof(k5_aad);
    t5.tag = k3_tag; // Correct tag for empty AAD — should NOT match with wrong AAD
    bool ok5 = run_gcm_test(&t5, false); // expectTagMatch=false
    if (ok5) {
        Serial.println("PASS (tag correctly rejected)");
        passed++;
    } else {
        Serial.println("FAIL (tag should have been rejected)");
        failed++;
    }

    // Test 6: Decrypt round-trip
    Serial.print("Test 6: encrypt then decrypt round-trip... ");
    {
        br_aes_big_ctr_keys bc;
        br_gcm_context gcm;
        uint8_t pt[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                       0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
                       0x11,0x12,0x13,0x14};
        uint8_t aad[] = {0x01, 0x00,0x00,0x00,0x01, 0x00, 0x02}; // target=PLC, epoch=1, seq=0, version=2
        uint8_t iv[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
        uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        uint8_t ct[20];
        uint8_t tag[16];
        uint8_t decrypted[20];

        // Encrypt
        br_aes_big_ctr_init(&bc, key, 16);
        br_gcm_init(&gcm, (const br_block_ctr_class **)&br_aes_big_ctr_vtable, br_ghash_ctmul32);
        br_gcm_reset(&gcm, iv, 12);
        br_gcm_aad_inject(&gcm, aad, sizeof(aad));
        br_gcm_flip(&gcm);
        memcpy(ct, pt, 20);
        br_gcm_run(&gcm, 1, ct, 20);
        br_gcm_get_tag(&gcm, tag);

        // Decrypt
        br_gcm_reset(&gcm, iv, 12);
        br_gcm_aad_inject(&gcm, aad, sizeof(aad));
        br_gcm_flip(&gcm);
        memcpy(decrypted, ct, 20);
        br_gcm_run(&gcm, 0, decrypted, 20);

        uint32_t tagCheck = br_gcm_check_tag(&gcm, tag);

        bool rtOK = (tagCheck == 1) && (memcmp(decrypted, pt, 20) == 0);

        // Verify wrong AAD fails
        uint8_t badAad[] = {0x02, 0x00,0x00,0x00,0x01, 0x00, 0x02}; // target=PAW
        br_gcm_reset(&gcm, iv, 12);
        br_gcm_aad_inject(&gcm, badAad, sizeof(badAad));
        br_gcm_flip(&gcm);
        memcpy(decrypted, ct, 20);
        br_gcm_run(&gcm, 0, decrypted, 20);
        uint32_t badTagCheck = br_gcm_check_tag(&gcm, tag);

        bool badAadRejected = (badTagCheck == 0);

        // Zeroize
        memset(&bc, 0, sizeof(bc));
        memset(&gcm, 0, sizeof(gcm));
        memset(ct, 0, sizeof(ct));
        memset(tag, 0, sizeof(tag));
        memset(decrypted, 0, sizeof(decrypted));

        if (rtOK && badAadRejected) {
            Serial.println("PASS");
            passed++;
        } else {
            Serial.print("FAIL (rtOK=");
            Serial.print(rtOK ? "yes" : "no");
            Serial.print(" badAadRejected=");
            Serial.print(badAadRejected ? "yes" : "no");
            Serial.println(")");
            failed++;
        }
    }

    // Summary
    Serial.println();
    Serial.println("============================================");
    Serial.print("Results: ");
    Serial.print(passed);
    Serial.print(" passed, ");
    Serial.print(failed);
    Serial.println(" failed");
    if (failed == 0) {
        Serial.println("ALL TESTS PASSED — BearSSL AES-128-GCM verified");
    } else {
        Serial.println("SOME TESTS FAILED — do NOT proceed with envelope implementation");
    }
    Serial.println("============================================");
}

void loop() {
    // Nothing — test runs once in setup()
}
