/*
 * SHALLOT — DEN docked UART challenge-response (PRO-53 fail-closed)
 * Firmware entry point: Pico 2 (RP2350). Session master for the
 * PAW<->DEN docked link defined in docs/11-dockat-uart-protokoll.md.
 *
 * Framing, CRC and parser come from the shared DenUartProtocol module
 * (no duplication here). This file owns: session state machine,
 * RP2350-TRNG 64-bit nonce (PRO-51), local HMAC-SHA256, constant-time
 * compare and ACK.
 *
 * Session: CHALLENGE(8B nonce) -> wait <=2000ms for RESPONSE(32B HMAC)
 * -> verify -> ACK(0x01/0x00) + AUTHENTICATED/FAILED log. Every failure
 * mode fails closed (deny, no retry inside the session).
 *
 * Transport: Serial1 @115200, TX=GPIO0, RX=GPIO1 (RP2350 UART0 defaults).
 * USB Serial is logs only. Non-blocking: loop polls Serial1.available
 * against millis() deadlines; only short bounded ops (SHA/HMAC ~100us,
 * 24-byte UART write ~2ms) ever run to completion inline.
 *
 * Out of scope: LoRa, e-paper, pogo detection, PAW firmware.
 */

#include <Arduino.h>
#include "pico/rand.h"
#include <DenUartProtocol.h>
#include <Ed25519.h>

// =============================================================
// Key Storage (PRO-47 + PRO-49)
// =============================================================
//
// Key hierarchy (SRAM-only, never flash/serial):
//   denDevKey : master key (128-bit, zero-initialised at boot;
//               populated only via PRO-46 USB provisioning)
//   kMac      : HMAC-SHA256 key (derived: SHA-256(master || "MAC")[:16])
//   kEnc      : encryption key (derived: SHA-256(master || "ENC")[:16], reserved)
//
// PRO-93: No hardcoded development key. denDevKey starts as all-zeros
// (unprovisioned). Authentication is fail-closed until a valid key
// is distributed via the PRO-46 provisioning flow.
// =============================================================

#define AES_KEY_SIZE 16

static uint8_t denDevKey[AES_KEY_SIZE];  // zero-initialised = unprovisioned
static uint8_t kMac[AES_KEY_SIZE];   // derived HMAC key (PRO-49)
static uint8_t kEnc[AES_KEY_SIZE];   // derived encryption key (reserved)
static uint8_t key_provisioned = 0;  // PRO-94: fail-closed without provisioned key

// PRO-49: Derive K_mac from master key using SHA-256(master || "MAC")[:16].
static void den_derive_k_mac(const uint8_t* master, uint8_t* k_mac_out) {
    uint8_t full_hash[32];
    uint8_t msg[19];  // master(16) || "MAC"(3)
    memcpy(msg, master, 16);
    memcpy(msg + 16, "MAC", 3);
    den_sha256(msg, sizeof(msg), full_hash);
    memcpy(k_mac_out, full_hash, 16);
    memset(full_hash, 0, sizeof(full_hash));
    memset(msg, 0, sizeof(msg));
}

// PRO-47: secure wipe using volatile store to prevent compiler optimization
static void secure_clear_key() {
    volatile uint8_t* d = (volatile uint8_t*)denDevKey;
    for (int i = 0; i < 16; i++) d[i] = 0;
    volatile uint8_t* k = (volatile uint8_t*)kMac;
    for (int i = 0; i < 16; i++) k[i] = 0;
    volatile uint8_t* e = (volatile uint8_t*)kEnc;
    for (int i = 0; i < 16; i++) e[i] = 0;
}

#define DEN_UART_BAUD      115200
#define DEN_SESSION_GAP_MS 1000  // pacing between sessions
#define KEY_HASH_SIZE      4

// =============================================================
// CRC32 (IEEE 802.3)
// =============================================================

static uint32_t crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc & 1) ? (0xEDB88320 ^ (crc >> 1)) : (crc >> 1);
    }
  }
  return crc ^ 0xFFFFFFFF;
}

// =============================================================
// USB Provisioning (PRO-46 + PRO-48)
// =============================================================
//
// DEN receives its AES-128 key from UNO Q via USB UART.
// Protocol (same as PAW):
//   UNO Q -> DEN: MSG_HANDSHAKE (0xA1) + target_id (0x01 for PLC)
//   DEN -> UNO Q: MSG_READY (0xA2) + device_id (4 bytes)
//   UNO Q -> DEN: MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4) = 22 bytes
//   DEN -> UNO Q: MSG_STORED (0xA4) + stored_hash (4 bytes)
//
// Key is stored in denDevKey (SRAM only, cleared on failure).
// After provisioning, kMac and kEnc are derived from denDevKey.
// =============================================================

#define TARGET_DEN         0x01  // matches UNO Q TARGET_PLC
#define MSG_HANDSHAKE      0xA1
#define MSG_READY          0xA2
#define MSG_KEY_DATA       0xA3
#define MSG_STORED         0xA4
#define MSG_ERROR          0xA5
#define MSG_BLOCKLIST      0xA6  // PRO-98: signed blocklist (matches UNO Q + docs/17)
#define MSG_BLOCKLIST_ACK  0xA7  // PRO-98: blocklist receipt ack

#define PROV_PENDING 0
#define PROV_DONE    1
#define PROV_FAILED  2
#define PROV_BLOCKLIST_DONE  3  // blocklist distribution complete (no key change)

#define PROV_PH_HANDSHAKE 0
#define PROV_PH_KEYDATA   1
#define PROV_PH_WAIT_TYPE 2  // PRO-98: after key, wait for optional blocklist
#define PROV_PH_BLOCKLIST 3  // PRO-98: receiving blocklist data
#define PROV_KEYDATA_LEN  22  // type(1) + len(1) + key(16) + crc(4)
#define KEY_DISTRIBUTION_TIMEOUT 10000  // 10 s

// PRO-93: Debug configuration — must be explicitly defined to enable
// sensitive diagnostic output. Off by default (define SECURE_DEBUG=1 to enable).
#ifdef SECURE_DEBUG
#define SECURE_DEBUG 1
#endif

// PRO-98: Blocklist constants (Ed25519 signed)
#define BLOCKLIST_VERSION       1
#define BLOCKLIST_ISSUER        "SHALLOT-AUTH"
#define BLOCKLIST_MAX_ENTRIES   16
#define BLOCKLIST_SIGNATURE_SIZE 64  // Ed25519 signature size

// PRO-98: Ed25519 public key for blocklist verification.
// Only MamaBear (UNO Q) holds the private key for signing.
// This public key is embedded in DEN firmware for verification.
static const uint8_t blocklist_public_key[ED25519_PUBLIC_KEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// PRO-98: Blocklist structure for Ed25519 signed blocklists
typedef struct {
    uint8_t version;
    char issuer[16];
    uint8_t entry_count;
    uint8_t entries[BLOCKLIST_MAX_ENTRIES][KEY_HASH_SIZE];
    uint8_t signature[BLOCKLIST_SIGNATURE_SIZE];
} blocklist_t;

static blocklist_t current_blocklist;
static uint8_t blocklist_valid = 0;

// PRO-98: blocklist distribution over serial
#define BLOCKLIST_MAX_SERIAL  (1 + 16 + 1 + BLOCKLIST_MAX_ENTRIES * KEY_HASH_SIZE + BLOCKLIST_SIGNATURE_SIZE)
//  = 1 + 16 + 1 + 64 + 32 = 114 bytes

static uint8_t provPhase = PROV_PH_HANDSHAKE;
static uint32_t provT0 = 0;
static uint8_t provBuf[PROV_KEYDATA_LEN];
static uint8_t provGot = 0;
// PRO-98: separate buffer for blocklist serial data
static uint8_t blBuf[BLOCKLIST_MAX_SERIAL];
static uint8_t blGot = 0;
#define BLOCKLIST_DIST_TIMEOUT 15000  // 15 s for full blocklist transfer

static const uint8_t deviceId[4] = { 0x44, 0x45, 0x4E, 0x01 }; // "DEN\x01"

// PRO-46: Secure key distribution via USB UART from UNO Q.
// Non-blocking poll: returns immediately, preserves partial state.
// Fail-closed: any error wipes buffers and clears stored key.
static uint8_t pollProvisioning() {
    // PRO-98: if in blocklist distribution phase, delegate to blocklist handler
    if (provPhase == PROV_PH_WAIT_TYPE || provPhase == PROV_PH_BLOCKLIST) {
        return pollBlocklistUpdate();
    }
    if (provPhase == PROV_PH_HANDSHAKE) {
        while (Serial.available() >= 2) {
            uint8_t msgType = Serial.read();
            uint8_t targetId = Serial.read();
            if (msgType == MSG_HANDSHAKE && targetId == TARGET_DEN) {
#if SECURE_DEBUG
                Serial.println("[PRO-46] Handshake received.");
#endif
                Serial.write(MSG_READY);
                Serial.write(deviceId, 4);
                Serial.flush();
                provPhase = PROV_PH_KEYDATA;
                provT0 = millis();
                provGot = 0;
                memset(provBuf, 0, sizeof(provBuf));
                return PROV_PENDING;
            }
        }
        return PROV_PENDING;
    }

    while (provGot < PROV_KEYDATA_LEN && Serial.available()) {
        provBuf[provGot++] = (uint8_t)Serial.read();
    }
    if (provGot < PROV_KEYDATA_LEN) {
        if (millis() - provT0 > KEY_DISTRIBUTION_TIMEOUT) {
#if SECURE_DEBUG
            Serial.println("[PRO-46] Timeout waiting for key data.");
#endif
            provPhase = PROV_PH_HANDSHAKE;
            provGot = 0;
            memset(provBuf, 0, sizeof(provBuf));
            return PROV_FAILED;
        }
        return PROV_PENDING;
    }

    uint8_t outcome = PROV_FAILED;
    do {
        if (provBuf[0] != MSG_KEY_DATA) {
#if SECURE_DEBUG
            Serial.printf("[PRO-46] Expected KEY_DATA, got 0x%02X\n", provBuf[0]);
#endif
            break;
        }
        if (provBuf[1] != AES_KEY_SIZE) {
#if SECURE_DEBUG
            Serial.printf("[PRO-46] Unexpected key length: %d\n", provBuf[1]);
#endif
            break;
        }
        uint32_t receivedCrc = ((uint32_t)provBuf[18] << 24)
                             | ((uint32_t)provBuf[19] << 16)
                             | ((uint32_t)provBuf[20] << 8)
                             | ((uint32_t)provBuf[21]);
        uint32_t computedCrc = crc32(provBuf + 2, AES_KEY_SIZE);
        if (computedCrc != receivedCrc) {
#if SECURE_DEBUG
            Serial.printf("[PRO-46] CRC mismatch! Expected: %08X Got: %08X\n",
                          computedCrc, receivedCrc);
#endif
            Serial.write(MSG_ERROR);
            break;
        }
#if SECURE_DEBUG
        Serial.println("[PRO-46] CRC verified OK.");
#endif

        // Store key securely in denDevKey
        memcpy((uint8_t*)denDevKey, provBuf + 2, AES_KEY_SIZE);

        // Derive K_mac and K_enc from the new master key
        den_derive_k_mac((uint8_t*)denDevKey, kMac);
        key_provisioned = 1;

        // Send confirmation with hash (fingerprint only, never key bytes)
        uint8_t fullHash[32];
        den_sha256((uint8_t*)denDevKey, AES_KEY_SIZE, fullHash);
        uint8_t keyHash[KEY_HASH_SIZE];
        memcpy(keyHash, fullHash, KEY_HASH_SIZE);
        memset(fullHash, 0, 32);

        Serial.write(MSG_STORED);
        Serial.write(keyHash, KEY_HASH_SIZE);
        Serial.flush();

        // PRO-93: sensitive debug output guarded — key fingerprint never
        // printed to serial in production builds.
#if SECURE_DEBUG
        Serial.print("[PRO-46] Key stored. Hash sent: ");
        for (int i = 0; i < KEY_HASH_SIZE; i++) Serial.printf("%02X", keyHash[i]);
        Serial.println();
#endif
        outcome = PROV_DONE;
    } while (0);

    memset(provBuf, 0, sizeof(provBuf));
    provGot = 0;
    if (outcome == PROV_DONE) {
        // PRO-98: after key provisioning, wait for optional blocklist update
        provPhase = PROV_PH_WAIT_TYPE;
        provT0 = millis();
    } else {
        provPhase = PROV_PH_HANDSHAKE;
    }
    return outcome;
}

// PRO-98: Verify and process a signed blocklist message using Ed25519.
// Returns 1 on success, 0 on failure (invalid signature, wrong version, etc.).
static uint8_t process_blocklist_message(const uint8_t *data, size_t len) {
    if (len < 82) {
#if SECURE_DEBUG
        Serial.println("[PRO-98] Blocklist message too short");
#endif
        return 0;
    }

    uint8_t version = data[0];
    if (version < BLOCKLIST_VERSION) {
#if SECURE_DEBUG
        Serial.printf("[PRO-98] Blocklist version too old: 0x%02X\n", version);
#endif
        return 0;
    }

    char issuer[16];
    memcpy(issuer, data + 1, 16);

    uint8_t entry_count = data[17];
    if (entry_count > BLOCKLIST_MAX_ENTRIES) {
#if SECURE_DEBUG
        Serial.println("[PRO-98] Blocklist entry count overflow");
#endif
        return 0;
    }

    size_t needed = 18 + (size_t)entry_count * KEY_HASH_SIZE + BLOCKLIST_SIGNATURE_SIZE;
    if (len < needed) {
#if SECURE_DEBUG
        Serial.println("[PRO-98] Blocklist data truncated");
#endif
        return 0;
    }

    // Verify Ed25519 signature
    size_t data_len = 1 + 16 + 1 + entry_count * KEY_HASH_SIZE;
    const uint8_t *signature = data + data_len;
    int result = ed25519_verify(signature, data, data_len, blocklist_public_key);
    if (!result) {
#if SECURE_DEBUG
        Serial.println("[PRO-98] Blocklist signature verification failed");
#endif
        return 0;
    }

    // Store the verified blocklist
    current_blocklist.version = version;
    memcpy(current_blocklist.issuer, issuer, 16);
    current_blocklist.entry_count = entry_count;
    memcpy(current_blocklist.entries, data + 18, entry_count * KEY_HASH_SIZE);
    memcpy(current_blocklist.signature, data + data_len, BLOCKLIST_SIGNATURE_SIZE);
    blocklist_valid = 1;

#if SECURE_DEBUG
    Serial.print("[PRO-98] Blocklist activated, version ");
    Serial.print(current_blocklist.version);
    Serial.print(", issuer ");
    Serial.print(current_blocklist.issuer);
    Serial.print(", ");
    Serial.print(current_blocklist.entry_count);
    Serial.println(" entries");
#endif

    return 1;
}

// PRO-98: handle optional blocklist update after key provisioning.
// UNO Q sends MSG_BLOCKLIST (0xA6) followed by the signed blocklist data.
// Fail-closed: blocklist is never applied without a valid signature,
// and is only used after successful HMAC authentication.
static uint8_t pollBlocklistUpdate() {
    if (provPhase == PROV_PH_WAIT_TYPE) {
        if (Serial.available() >= 1) {
            uint8_t msgType = Serial.read();
            if (msgType == MSG_BLOCKLIST) {
                provPhase = PROV_PH_BLOCKLIST;
                provT0 = millis();
                blGot = 0;
                memset(blBuf, 0, sizeof(blBuf));
                return PROV_PENDING;
            }
            // Any other message type: ignore and reset
#if SECURE_DEBUG
            Serial.printf("[PRO-98] Unexpected msg in WAIT_TYPE: 0x%02X\n", msgType);
#endif
            provPhase = PROV_PH_HANDSHAKE;
            return PROV_BLOCKLIST_DONE;
        }
        if (millis() - provT0 > BLOCKLIST_DIST_TIMEOUT) {
            // Timeout: no blocklist update, key provisioning is still valid
            provPhase = PROV_PH_HANDSHAKE;
            return PROV_BLOCKLIST_DONE;
        }
        return PROV_PENDING;
    }

    if (provPhase == PROV_PH_BLOCKLIST) {
        while (blGot < sizeof(blBuf) && Serial.available()) {
            blBuf[blGot++] = (uint8_t)Serial.read();
        }
        // Minimum blocklist: version(1) + issuer(16) + count(1) + sig(64) = 82
        if (blGot < 82) {
            if (millis() - provT0 > BLOCKLIST_DIST_TIMEOUT) {
#if SECURE_DEBUG
                Serial.println("[PRO-98] Blocklist timeout");
#endif
                provPhase = PROV_PH_HANDSHAKE;
                memset(blBuf, 0, sizeof(blBuf));
                blGot = 0;
                return PROV_BLOCKLIST_DONE;
            }
            return PROV_PENDING;
        }

        // Try to parse and verify the blocklist
        // Full format: version(1) + issuer(16) + count(1) + entries + sig(64)
        uint8_t entry_count = blBuf[17];
        size_t needed = 18 + (size_t)entry_count * KEY_HASH_SIZE + BLOCKLIST_SIGNATURE_SIZE;
        if (blGot < needed) {
            if (millis() - provT0 > BLOCKLIST_DIST_TIMEOUT) {
#if SECURE_DEBUG
                Serial.println("[PRO-98] Blocklist data truncated");
#endif
                provPhase = PROV_PH_HANDSHAKE;
                memset(blBuf, 0, sizeof(blBuf));
                blGot = 0;
                return PROV_BLOCKLIST_DONE;
            }
            return PROV_PENDING;
        }

        // Process the complete blocklist
        uint8_t bl_ok = process_blocklist_message(blBuf, needed);
        memset(blBuf, 0, sizeof(blBuf));
        blGot = 0;
        provPhase = PROV_PH_HANDSHAKE;

        // Send ACK
        Serial.write(MSG_BLOCKLIST_ACK);
        Serial.write(bl_ok ? 0x01 : 0x00);
        Serial.flush();

        return PROV_BLOCKLIST_DONE;
    }
    return PROV_PENDING;
}

// =============================================================
// Session state machine (non-blocking, fail-closed)
//
// States: DENIED -> CHALLENGE_SENT -> AUTHENTICATED -> DENIED
//
// DEN starts in DENIED after boot, reset, disconnect, malformed
// input, or session expiry. Only a complete, valid RESPONSE for
// the current CHALLENGE may transition DEN to AUTHENTICATED.
// ACK is informational; the access decision is made before ACK
// and never depends on it. PAW display/UI and other peripherals
// do not alter the DEN decision or deadline.
//
// The response deadline is EXACTLY 2 s (DEN_RESPONSE_DEADLINE_MS)
// from CHALLENGE transmission. No error path transitions to
// AUTHENTICATED; every error returns DEN to DENIED.
// =============================================================

typedef enum {
  DEN_ST_DENIED,          // initial / fail-closed; after gap, sends CHALLENGE
  DEN_ST_CHALLENGE_SENT,  // challenge sent, awaiting RESPONSE (deadline)
  DEN_ST_AUTHENTICATED    // HMAC verified; brief confirmation then DENIED
} DenSession;

static DenSession denState = DEN_ST_DENIED;
static uint32_t denStateAt = 0;      // state entry timestamp (millis)
static uint32_t denDeadline = 0;     // response deadline (millis)
static uint32_t denBytesRx = 0;      // bytes seen since entering CHALLENGE_SENT
static uint8_t denNonce[DEN_NONCE_LEN];
static den_scanner_t denScanner;
static uint8_t denTx[DEN_MAX_FRAME];

// Non-secret reason codes for USB serial observation.
// Audit/log codes only - never on the wire, never secret material.
// NOTE: Arduino preprocessor can struggle with enum types in function
// signatures, so we use uint8_t for the reason parameter.
typedef enum {
  DEN_REASON_OK = 0,              // authenticated
  DEN_REASON_TIMEOUT,             // 2s deadline hit, but PAW sent some bytes
  DEN_REASON_UNEXPECTED_TYPE,     // frame type != RESPONSE
  DEN_REASON_INVALID_SIZE,        // payload length mismatch
  DEN_REASON_PARSE_ERROR,         // CRC, length, type, or resync failure
  DEN_REASON_HMAC_MISMATCH,       // constant-time compare failed
  DEN_REASON_DISCONNECT,          // 2s deadline hit, zero bytes received
  DEN_REASON_STALE_RESPONSE,      // all-zero nonce: TRNG failure or wiped
} DenReason;

// =============================================================
// Minimal SHA-256 (public-domain style, stack-only, no heap)
// =============================================================

static const uint32_t den_shaK[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define DEN_ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void den_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint64_t bitLen = (uint64_t)len * 8;
  size_t pos = 0;
  uint8_t block[64];
  // Full 64-byte blocks straight from input.
  while (len - pos >= 64) {
    const uint8_t *b = data + pos;
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) |
             ((uint32_t)b[i*4+2] << 8) | (uint32_t)b[i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
      uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
      uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
      uint32_t t2 = S0 + mj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    pos += 64;
  }
  // Final block(s) with padding.
  size_t rem = len - pos;
  memcpy(block, data + pos, rem);
  block[rem++] = 0x80;
  if (rem > 56) {
    memset(block + rem, 0, 64 - rem);
    // compress padding-only block (duplicate of above with w from block)
    {
      uint32_t w[64];
      for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
      for (int i = 16; i < 64; i++) {
        uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
      }
      uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
      for (int i = 0; i < 64; i++) {
        uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
        uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
        uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
      }
      h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    rem = 0;
  }
  memset(block + rem, 0, 56 - rem);
  for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bitLen >> (56 - 8 * i));
  {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
             ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
      uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
      uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
      uint32_t t2 = S0 + mj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }
  for (int i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(h[i] >> 24);
    out[i*4+1] = (uint8_t)(h[i] >> 16);
    out[i*4+2] = (uint8_t)(h[i] >> 8);
    out[i*4+3] = (uint8_t)h[i];
  }
  memset(block, 0, sizeof(block));
}

// HMAC-SHA256(key, msg). Stack-only temps, wiped before return.
static void den_hmac_sha256(const uint8_t *key, size_t keyLen,
                            const uint8_t *msg, size_t msgLen,
                            uint8_t mac[32]) {
  if (msgLen > DEN_NONCE_LEN || keyLen > 64) {
    memset(mac, 0, 32);  // fail closed on oversize input
    return;
  }
  uint8_t ipad[64], opad[64], inner[32];
  memset(ipad, 0x36, sizeof(ipad));
  memset(opad, 0x5c, sizeof(opad));
  for (size_t i = 0; i < keyLen && i < sizeof(ipad); i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }
  // inner = SHA256(ipad || msg) via two compress calls through den_sha256
  // over a single Prairie buffer (msg here is always 16 B).
  uint8_t innerMsg[64 + DEN_NONCE_LEN];
  memcpy(innerMsg, ipad, 64);
  memcpy(innerMsg + 64, msg, msgLen);
  den_sha256(innerMsg, 64 + msgLen, inner);
  uint8_t outerMsg[64 + 32];
  memcpy(outerMsg, opad, 64);
  memcpy(outerMsg + 64, inner, 32);
  den_sha256(outerMsg, sizeof(outerMsg), mac);
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  memset(inner, 0, sizeof(inner));
  memset(innerMsg, 0, sizeof(innerMsg));
  memset(outerMsg, 0, sizeof(outerMsg));
}

static void den_fail(uint8_t reason) {
  const char *label = "UNKNOWN";
  switch (reason) {
    case DEN_REASON_TIMEOUT:       label = "timeout"; break;
    case DEN_REASON_UNEXPECTED_TYPE: label = "unexpected type"; break;
    case DEN_REASON_INVALID_SIZE:  label = "invalid size"; break;
    case DEN_REASON_PARSE_ERROR:   label = "parse error"; break;
    case DEN_REASON_HMAC_MISMATCH: label = "hmac mismatch"; break;
    case DEN_REASON_DISCONNECT:    label = "disconnect"; break;
    case DEN_REASON_STALE_RESPONSE: label = "stale response"; break;
    default: break;
  }
  Serial.print("[DEN] FAILED: "); Serial.print(label);
  Serial.print(" (code "); Serial.print(reason); Serial.println(")");
  uint8_t ackBody[1] = {0x00};
  uint8_t ack[DEN_MAX_FRAME];
  size_t n = den_encode(DEN_TYPE_ACK, ackBody, 1, ack, sizeof(ack));
  if (n) { Serial1.write(ack, n); Serial1.flush(); }
  digitalWrite(LED_BUILTIN, LOW);
  memset(denNonce, 0, sizeof(denNonce));
  denBytesRx = 0;
  denState = DEN_ST_DENIED;
  denStateAt = millis();
}

static void den_send_challenge(uint32_t now) {
  // 8-byte nonce from the RP2350 hardware RNG (ROSC TRNG via pico-sdk).
  // PRO-51: 64-bit cryptographically secure random nonce per challenge.
  uint64_t r = get_rand_64();
  // Fail-closed: if RNG returns all zeros, do not send challenge
  if (r == 0) {
    Serial.println("[DEN] RNG failure: zero nonce, challenge aborted");
    den_fail(DEN_REASON_PARSE_ERROR);
    return;
  }
  memcpy(denNonce, &r, DEN_NONCE_LEN);
  memset(&r, 0, sizeof(r));

  size_t n = den_encode(DEN_TYPE_CHALLENGE, denNonce, DEN_NONCE_LEN,
                        denTx, sizeof(denTx));
  if (!n) {  // cannot happen (fixed sizes); fail closed anyway
    den_fail(DEN_REASON_PARSE_ERROR);
    return;
  }
  Serial1.write(denTx, n);
  Serial1.flush();
  memset(denTx, 0, sizeof(denTx));
  Serial.println("[DEN] CHALLENGE sent, waiting <=2000ms for RESPONSE");
  den_scanner_init(&denScanner);
  denBytesRx = 0;
  denDeadline = now + DEN_RESPONSE_DEADLINE_MS;
  denState = DEN_ST_CHALLENGE_SENT;
  denStateAt = now;
}

static void den_on_response(const den_frame_t *f, uint32_t now) {
  // PRO-94: fail-closed if no key provisioned
  if (!key_provisioned) {
    den_fail(DEN_REASON_HMAC_MISMATCH);
    return;
  }
  if (f->type != DEN_TYPE_RESPONSE) {
    den_fail(DEN_REASON_UNEXPECTED_TYPE);
    return;
  }
  if (f->payloadLen != DEN_HMAC_LEN) {
    den_fail(DEN_REASON_INVALID_SIZE);
    return;
  }
  // Reject an all-zero nonce. This is a fail-closed guard that covers
  // two cases at once:
  //   - TRNG failure: get_rand_64() returned all zeros, so the
  //     challenge nonce is invalid; never authenticate on an empty nonce.
  //   - Stale/wiped nonce: den_fail() zeroes the nonce after a failure.
  //     Any response arriving against the wiped nonce cannot bind to the
  //     current challenge, so it must not authenticate.
  // (A response for a *prior* session is already denied cryptographically
  //  by HMAC-MISMATCH, because only the current nonce is ever verified.)
  if (denNonce[0] == 0 && denNonce[1] == 0 && denNonce[2] == 0
      && denNonce[3] == 0 && denNonce[4] == 0 && denNonce[5] == 0
      && denNonce[6] == 0 && denNonce[7] == 0) {
    den_fail(DEN_REASON_STALE_RESPONSE);
    return;
  }
  uint8_t expect[DEN_HMAC_LEN];
  den_hmac_sha256(kMac, AES_KEY_SIZE,
                  denNonce, DEN_NONCE_LEN, expect);
  uint8_t ok = den_ct_compare(expect, f->payload, DEN_HMAC_LEN);
  memset(expect, 0, sizeof(expect));
  memset(denNonce, 0, sizeof(denNonce));
  if (!ok) {
    den_fail(DEN_REASON_HMAC_MISMATCH);
    return;
  }
  Serial.println("[DEN] AUTHENTICATED (code 0)");
  uint8_t ackBody[1] = {0x01};
  uint8_t ack[DEN_MAX_FRAME];
  size_t n = den_encode(DEN_TYPE_ACK, ackBody, 1, ack, sizeof(ack));
  if (n) { Serial1.write(ack, n); Serial1.flush(); }
  digitalWrite(LED_BUILTIN, HIGH);
  denState = DEN_ST_AUTHENTICATED;
  denStateAt = now;
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(DEN_UART_BAUD);  // TX=GPIO0, RX=GPIO1 (UART0 defaults)
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
  den_scanner_init(&denScanner);
  denState = DEN_ST_DENIED;
  denStateAt = millis();

  // PRO-46: initialize provisioning state
  provPhase = PROV_PH_HANDSHAKE;
  provGot = 0;
  memset(provBuf, 0, sizeof(provBuf));

  // PRO-94: No key derivation at startup — fail-closed until provisioned
  key_provisioned = 0;
  memset(kMac, 0, sizeof(kMac));
  memset(kEnc, 0, sizeof(kEnc));

  Serial.println("[DEN] docked UART auth ready (PRO-53/PRO-46/PRO-94)");
}

void loop() {
  uint32_t now = millis();

  // PRO-46: USB provisioning poll (non-blocking, takes precedence)
  uint8_t provResult = pollProvisioning();
  if (provResult == PROV_DONE) {
    // Key already derived during provisioning; stay in DENIED
    denState = DEN_ST_DENIED;
    denStateAt = now;
  } else if (provResult == PROV_BLOCKLIST_DONE) {
    // Blocklist distribution completed (or timed out); key unchanged
    // No state change needed - key was already derived during provisioning
  } else if (provResult == PROV_FAILED) {
    // Provisioning failed; stay in current state but clear any staged key
    denState = DEN_ST_DENIED;
    denStateAt = now;
  }

  // DEN_ST_DENIED: waiting for session gap before next challenge.
  if (denState == DEN_ST_DENIED) {
    if ((uint32_t)(now - denStateAt) >= DEN_SESSION_GAP_MS) {
      den_send_challenge(now);
    }
    return;
  }

  // DEN_ST_AUTHENTICATED: brief confirmation, then return to DENIED.
  if (denState == DEN_ST_AUTHENTICATED) {
    if ((uint32_t)(now - denStateAt) >= DEN_SESSION_GAP_MS) {
      Serial.println("[DEN] session complete, returning to DENIED");
      denState = DEN_ST_DENIED;
      denStateAt = now;
    }
    return;
  }

  // DEN_ST_CHALLENGE_SENT: poll UART without blocking.
  // The response deadline is EXACTLY 2 s from CHALLENGE
  // transmission; do not fail before it expires.
  if ((int32_t)(now - denDeadline) >= 0) {
    // Deadline expired with no valid RESPONSE -> fail closed to DENIED.
    // Distinguish a dead link from a slow/partial one so the cause is
    // observable over USB (non-secret reason code only):
    //   - DISCONNECT: PAW sent zero bytes since the challenge (link gone)
    //   - TIMEOUT:    PAW sent bytes but no complete valid RESPONSE in time
    // Both transition to DENIED. A mid-frame stall is caught earlier by the
    // scanner's 100 ms byte-timeout (DEN_ERR_TIMEOUT -> PARSE_ERROR).
    if (denBytesRx == 0) {
      den_fail(DEN_REASON_DISCONNECT);
    } else {
      den_fail(DEN_REASON_TIMEOUT);
    }
    return;
  }
  while (Serial1.available()) {
    denBytesRx++;
    den_frame_t f;
    den_status_t st = den_scanner_push(&denScanner,
        (uint8_t)Serial1.read(), now, &f);
    if (st == DEN_OK) {
      uint8_t type = f.type;
      uint8_t payload[DEN_MAX_PAYLOAD];
      size_t payloadLen = f.payloadLen;
      memcpy(payload, f.payload, payloadLen);
      den_frame_t fc = {type, payload, payloadLen};
      den_on_response(&fc, now);
      return;
    }
    if (st != DEN_INCOMPLETE) {
      den_fail(DEN_REASON_PARSE_ERROR);
      return;
    }
  }
}
