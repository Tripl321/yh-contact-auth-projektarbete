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
 * USB Serial carries logs, PRO-46/PRO-98 binary frames and the PRO-97
 * service console (strict ASCII lines, idle only — never during a
 * provisioning ceremony). Non-blocking: loop polls Serial1.available
 * against millis() deadlines; only short bounded ops (SHA/HMAC ~100us,
 * 24-byte UART write ~2ms) ever run to completion inline.
 *
 * Out of scope: LoRa, e-paper, pogo detection, PAW firmware.
 */

#include <Arduino.h>
#include "pico/rand.h"
#include <DenUartProtocol.h>
#include <Ed25519.h>
#include <ShallotCrypto.h>  // PRO-49: SHA/HMAC/KDF/wipe from shared module

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

// PRO-49: K_mac derivation lives in <ShallotCrypto.h>
// (shalot_derive_k_mac) — single shared implementation.

// PRO-47: secure wipe using volatile store to prevent compiler optimization
static void secure_clear_key() {
    volatile uint8_t* d = (volatile uint8_t*)denDevKey;
    for (int i = 0; i < 16; i++) d[i] = 0;
    volatile uint8_t* k = (volatile uint8_t*)kMac;
    for (int i = 0; i < 16; i++) k[i] = 0;
    volatile uint8_t* e = (volatile uint8_t*)kEnc;
    for (int i = 0; i < 16; i++) e[i] = 0;
    key_provisioned = 0;
}

// Validated retrieval: a stored key is usable only when the flag is set
// AND the master buffer is non-zero. An all-zero master is
// indistinguishable from unprovisioned/wiped SRAM, so it must never
// authenticate (fail closed on corrupt key).
static uint8_t den_key_valid() {
    if (!key_provisioned) return 0;
    for (int i = 0; i < 16; i++) {
        if (denDevKey[i] != 0) return 1;
    }
    return 0;
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
//
// PLACEHOLDER TRUST ROOT (deliberately scoped): this array is all zeros
// until a production public key is pinned here at build time. No signature
// verifies against it, so no list can become valid and den_on_response
// denies every session with DEN_REASON_BLOCKLISTED (fail closed). Bench or
// test builds may pin a TEST-ONLY key, but such builds must never be
// deployed: grep for "TEST-ONLY trust root" before any production flash.
// See docs/17 §11.6.
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
                // PRO-47: new provisioning session starts - clear any
                // previously stored key (SRAM hygiene, fail-closed).
                secure_clear_key();
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
            // PRO-47: timeout -> clear stored key (fail-closed).
            secure_clear_key();
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

        // Fail-closed: an all-zero master is indistinguishable from
        // unprovisioned/wiped SRAM — reject it as corrupt (never store).
        {
            uint8_t allZero = 1;
            for (int i = 0; i < AES_KEY_SIZE; i++) {
                if (provBuf[2 + i] != 0) { allZero = 0; break; }
            }
            if (allZero) {
#if SECURE_DEBUG
                Serial.println("[PRO-46] Zero key rejected.");
#endif
                Serial.write(MSG_ERROR);
                break;
            }
        }

        // Store key securely in denDevKey
        memcpy((uint8_t*)denDevKey, provBuf + 2, AES_KEY_SIZE);

        // Derive K_mac from the new master key
        shalot_derive_k_mac((uint8_t*)denDevKey, kMac);
        key_provisioned = 1;

        // Send confirmation with hash (fingerprint only, never key bytes)
        uint8_t fullHash[32];
        shalot_sha256((uint8_t*)denDevKey, AES_KEY_SIZE, fullHash);
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
        // PRO-47: on any failure, ensure no stale key remains in SRAM.
        secure_clear_key();
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

    // Issuer must be exactly SHALLOT-AUTH (zero-padded): a validly signed
    // list from any other issuer is not ours -> reject (fail closed).
    // Plain byte loop here; constant-time compare stays reserved for secrets.
    static const char kExpectedIssuer[16] = BLOCKLIST_ISSUER;
    {
        uint8_t issuerOk = 1;
        for (uint8_t i = 0; i < 16; i++) {
            if (issuer[i] != kExpectedIssuer[i]) { issuerOk = 0; break; }
        }
        if (!issuerOk) {
#if SECURE_DEBUG
            Serial.println("[PRO-98] Blocklist issuer mismatch");
#endif
            return 0;
        }
    }

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
  DEN_ST_AUTHENTICATED,   // HMAC verified; brief confirmation then DENIED
  DEN_ST_BG_ARMED,        // PRO-97: ticket issued, awaiting CONFIRM
  DEN_ST_BG_GRANTED       // PRO-97: supervised service access inside window
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
  DEN_REASON_BLOCKLISTED,         // PRO-98: revoked fp, or no valid list (unknown status)
  DEN_REASON_BG_ARMED = 9,        // PRO-97: break-glass ticket issued
  DEN_REASON_BG_GRANTED = 10,     // PRO-97: supervised service access granted
  DEN_REASON_BG_DENIED = 11,      // PRO-97: break-glass attempt denied/expired
} DenReason;

// =============================================================
// Break-glass service access (PRO-97)
// =============================================================
//
// Separate, time-limited service flow for supervised recovery when
// ordinary challenge-response is unavailable. It NEVER creates a
// permanent bypass: no flash, no persistent flags, no change to the
// ordinary auth path (den_on_response runs only in CHALLENGE_SENT,
// which break-glass never enters).
//
// Ceremony — two operators, fresh ticket, short windows:
//   1. Operator A at the DEN USB console (physical presence) sends
//      "BG ARM". Accepted only from idle DENIED with no provisioning
//      in flight. DEN draws a fresh 4-byte ticket from the RP2350
//      TRNG, prints it, enters BG_ARMED for BG_ARM_WINDOW_MS and
//      audit-logs the event. Operator B confirms with
//      "BG CONFIRM <8 hex>" inside the window: a correct ticket grants
//      BG_GRANTED for BG_GRANT_WINDOW_MS with alarm; anything else
//      denies, audit-logs and relocks to DENIED. "BG ABORT" relocks
//      early from ARMED or GRANTED.
//
// Scoped service mode (not general unlock): inside GRANTED only the
// defined actions run — "BG STATUS" (read-only flags + audit dump,
// every invocation audit-logged) and "BG ABORT". Any other line is
// denied and audit-logged without effect. Break-glass is NOT process
// access and NEVER a substitute for emergency stop or other physical
// process safety; it only supervises DEN-local recovery.
//
// Fail-closed exits (all audit-logged, all to DENIED): arm/grant
// windows expire, malformed input, confirm without arm, arm outside
// idle, restart (SRAM-only state). Input bytes are never echoed —
// the wire also carries key material, so only fixed strings print.
//
// Shared-wire note: USB Serial also carries PRO-46/PRO-98 binary
// frames. The console engages only on a leading 'B' while
// provPhase == PROV_PH_HANDSHAKE; binary MSG bytes (0xA1..0xA7) never
// trigger it. A stray byte can at most arm — never grant — and the
// arm expires audit-logged.

#define BG_ARM_WINDOW_MS   60000   // 60 s to confirm after ARM
#define BG_GRANT_WINDOW_MS 120000  // 120 s supervised service access
#define BG_LINE_MAX        40      // longest accepted service line
#define BG_LINE_TIMEOUT_MS 1000    // line must complete within 1 s

#define BG_EV_BOOT     0
#define BG_EV_ARMED    1
#define BG_EV_GRANTED  2
#define BG_EV_DENIED   3
#define BG_EV_EXPIRED  4
#define BG_EV_ENDED    5
#define BG_EV_STATUS   6  // PRO-97: defined-action read (STATUS), granted mode
#define BG_AUDIT_N     16  // SRAM ring; oldest overwritten, console captures

typedef struct { uint32_t seq; uint32_t t; uint8_t ev; } bg_audit_t;
static bg_audit_t bgAudit[BG_AUDIT_N];
static uint8_t bgAuditNext = 0;
static uint32_t bgAuditSeq = 0;

static uint8_t bgTicket[4];
static uint8_t bgHaveTicket = 0;
static char bgLine[BG_LINE_MAX + 1];
static uint8_t bgLineLen = 0;
static uint32_t bgLineT0 = 0;
static uint32_t bgBlinkAt = 0;
static uint8_t bgBlinkOn = 0;

static void bg_audit(uint8_t ev) {
  bgAudit[bgAuditNext].seq = ++bgAuditSeq;
  bgAudit[bgAuditNext].t = millis();
  bgAudit[bgAuditNext].ev = ev;
  bgAuditNext = (bgAuditNext + 1) % BG_AUDIT_N;
  Serial.print("[AUDIT] seq "); Serial.print(bgAuditSeq);
  Serial.print(" t "); Serial.print(millis());
  Serial.print(" ev "); Serial.println(ev);
}

// Relock to DENIED from any break-glass state. Wipes the ticket,
// clears the line buffer, parks the LED off. Audit + reason logged.
static void bg_relock(uint8_t ev, uint8_t code, const char *msg) {
  memset(bgTicket, 0, sizeof(bgTicket));
  bgHaveTicket = 0;
  bgLineLen = 0;
  denState = DEN_ST_DENIED;
  denStateAt = millis();
  digitalWrite(LED_BUILTIN, LOW);
  bg_audit(ev);
  Serial.print(msg);
  Serial.print(" (code "); Serial.print(code); Serial.println(")");
}

static void bg_hex4(const uint8_t *b) {
  static const char H[] = "0123456789ABCDEF";
  for (int i = 0; i < 4; i++) {
    Serial.print(H[(b[i] >> 4) & 0x0F]);
    Serial.print(H[b[i] & 0x0F]);
  }
}

static int bg_hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static void bg_arm(uint32_t now) {
  if (denState != DEN_ST_DENIED) return;  // idle only, never mid-session
  uint64_t r = get_rand_64();
  if (r == 0) r = get_rand_64();  // single redraw, like den_send_challenge
  if (r == 0) {
    Serial.println("[BG] RNG failure, arm aborted");
    bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: rng failure");
    return;
  }
  memcpy(bgTicket, &r, 4);
  memset(&r, 0, sizeof(r));
  bgHaveTicket = 1;
  denState = DEN_ST_BG_ARMED;
  denStateAt = now;
  bg_audit(BG_EV_ARMED);
  Serial.print("[BG] ARMED (code ");
  Serial.print(DEN_REASON_BG_ARMED);
  Serial.print(") ticket ");
  bg_hex4(bgTicket);
  Serial.println(" — confirm within 60 s: BG CONFIRM <ticket>");
}

static void bg_confirm(const char *hex, uint32_t now) {
  (void)now;
  if (denState != DEN_ST_BG_ARMED || !bgHaveTicket) {
    bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: no open arm");
    return;
  }
  uint8_t cand[4];
  for (int i = 0; i < 4; i++) {
    int hi = bg_hexval(hex[2 * i]);
    int lo = bg_hexval(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      memset(cand, 0, sizeof(cand));
      bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: malformed ticket");
      return;
    }
    cand[i] = (uint8_t)((hi << 4) | lo);
  }
  volatile uint8_t diff = 0;  // constant-time compare, codebase convention
  for (int i = 0; i < 4; i++) diff |= (uint8_t)(cand[i] ^ bgTicket[i]);
  memset(cand, 0, sizeof(cand));
  if (diff != 0) {
    bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: wrong ticket");
    return;
  }
  denState = DEN_ST_BG_GRANTED;
  denStateAt = millis();
  bg_audit(BG_EV_GRANTED);
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.print("!!! BREAKGLASS GRANTED — SERVICE MODE (code ");
  Serial.print(DEN_REASON_BG_GRANTED);
  Serial.println(") !!!");
  Serial.println("!!! Defined actions only: BG STATUS, BG ABORT.");
  Serial.println("!!! NOT process access, NOT an emergency stop.  !!!");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

// PRO-97 defined action: read-only service status. Flags only, never
// secrets. Every invocation is audit-logged so all use stays traceable.
static void bg_status(void) {
  bg_audit(BG_EV_STATUS);
  Serial.print("[BG] STATUS key_provisioned=");
  Serial.print(key_provisioned);
  Serial.print(" blocklist_valid=");
  Serial.print(blocklist_valid);
  Serial.print(" state=");
  Serial.print(denState == DEN_ST_BG_GRANTED ? "GRANTED" : "ARMED");
  Serial.print(" audit_seq=");
  Serial.println(bgAuditSeq);
  Serial.println("[BG] AUDIT-DUMP (seq t ev, oldest first):");
  for (uint8_t k = 0; k < BG_AUDIT_N; k++) {
    uint8_t idx = (bgAuditNext + k) % BG_AUDIT_N;
    if (bgAudit[idx].seq == 0) continue;
    Serial.print("  ");
    Serial.print(bgAudit[idx].seq);
    Serial.print(" ");
    Serial.print(bgAudit[idx].t);
    Serial.print(" ");
    Serial.println(bgAudit[idx].ev);
  }
}

// Strict line protocol: "BG ARM" | "BG CONFIRM <8hex>" | "BG ABORT"
// | "BG STATUS". Runs before provisioning poll; engages only on leading
// 'B' while no ceremony is in flight, so binary PRO-46/PRO-98 bytes
// pass through. In GRANTED only the defined actions run — anything else
// is denied and audit-logged without effect (the window bounds all).
static void bg_poll_console(uint32_t now) {
  if (provPhase != PROV_PH_HANDSHAKE) { bgLineLen = 0; return; }
  if (bgLineLen == 0) {
    if (Serial.available() == 0 || Serial.peek() != 'B') return;
    bgLineT0 = now;
  } else if (now - bgLineT0 > BG_LINE_TIMEOUT_MS) {
    bgLineLen = 0;  // stale partial line dropped, bytes already consumed
    if (denState == DEN_ST_BG_ARMED || denState == DEN_ST_BG_GRANTED) {
      bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: input timeout");
    }
    return;
  }
  while (Serial.available() && bgLineLen < BG_LINE_MAX) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') goto process;
    bgLine[bgLineLen++] = c;
  }
  if (bgLineLen >= BG_LINE_MAX) {  // overlong line: malformed input
    bgLineLen = 0;
    while (Serial.available()) {  // drain to newline, never echo
      if ((char)Serial.read() == '\n') break;
    }
    if (denState == DEN_ST_BG_ARMED || denState == DEN_ST_BG_GRANTED) {
      bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: malformed input");
    }
    return;
  }
  return;
process:
  bgLine[bgLineLen] = '\0';
  bgLineLen = 0;
  if (strcmp(bgLine, "BG ARM") == 0) {
    bg_arm(now);
  } else if (strncmp(bgLine, "BG CONFIRM ", 11) == 0 && strlen(bgLine) == 19) {
    bg_confirm(bgLine + 11, now);
  } else if (strcmp(bgLine, "BG ABORT") == 0) {
    if (denState == DEN_ST_BG_ARMED || denState == DEN_ST_BG_GRANTED) {
      bg_relock(BG_EV_ENDED, DEN_REASON_BG_DENIED, "[BG] ABORTED by operator");
    }
  } else if (strcmp(bgLine, "BG STATUS") == 0) {
    if (denState == DEN_ST_BG_ARMED || denState == DEN_ST_BG_GRANTED) {
      bg_status();  // defined action: read-only, always audit-logged
    }
  } else if (denState == DEN_ST_BG_ARMED) {
    bg_relock(BG_EV_DENIED, DEN_REASON_BG_DENIED, "[BG] DENIED: malformed input");
  } else if (denState == DEN_ST_BG_GRANTED) {
    // Defined-actions-only: deny + audit, stay inside the bounding window.
    bg_audit(BG_EV_DENIED);
    Serial.print("[BG] DENIED: unknown command");
    Serial.print(" (code "); Serial.print(DEN_REASON_BG_DENIED); Serial.println(")");
  }
  // Idle DENIED + unknown line: ignored (provisioning framing untouched).
}

// SHA-256, HMAC-SHA256 and KDF live in <ShallotCrypto.h>
// (single shared implementation, KAT-verified). Local copies
// removed (ticket 03).

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
    case DEN_REASON_BLOCKLISTED:  label = "blocked"; break;
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
  // PRO-94: fail-closed if no valid key provisioned (missing or corrupt).
  if (!den_key_valid()) {
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
  shalot_hmac_sha256(kMac, AES_KEY_SIZE,
                  denNonce, DEN_NONCE_LEN, expect);
  uint8_t ok = den_ct_compare(expect, f->payload, DEN_HMAC_LEN);
  memset(expect, 0, sizeof(expect));
  memset(denNonce, 0, sizeof(denNonce));
  if (!ok) {
    den_fail(DEN_REASON_HMAC_MISMATCH);
    return;
  }
  // PRO-98 revocation gate. Fail closed in both directions, before any
  // grant (no ACK 0x01, no LED, no AUTHENTICATED, no display change beyond
  // the deny ACK 0x00 that den_fail sends):
  //   - no valid signed list -> revocation status unknown -> deny;
  //   - fingerprint on a valid list -> revoked -> deny.
  // An unknown fingerprint under a valid list is known-good -> grant
  // (deny-list semantics; see docs/17).
  if (!blocklist_valid) {
    den_fail(DEN_REASON_BLOCKLISTED);
    return;
  }
  uint8_t fp[KEY_HASH_SIZE];
  uint8_t kh[32];
  shalot_sha256(denDevKey, AES_KEY_SIZE, kh);
  memcpy(fp, kh, KEY_HASH_SIZE);
  memset(kh, 0, sizeof(kh));
  uint8_t blocked = 0;
  for (uint8_t i = 0; i < current_blocklist.entry_count; i++) {
    uint8_t diff = 0;
    for (uint8_t j = 0; j < KEY_HASH_SIZE; j++) {
      diff |= (uint8_t)(fp[j] ^ current_blocklist.entries[i][j]);
    }
    if (diff == 0) { blocked = 1; break; }
  }
  memset(fp, 0, sizeof(fp));
  if (blocked) {
    den_fail(DEN_REASON_BLOCKLISTED);
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
  // PRO-97: boot is always locked; SRAM-only break-glass state dies here.
  bg_audit(BG_EV_BOOT);
  Serial.println("[DEN] BOOT locked (DENIED); break-glass cleared (fail-closed)");
}

void loop() {
  uint32_t now = millis();

  // PRO-97: service console first (idle only, leading 'B'); it never
  // consumes binary provisioning bytes, so pollProvisioning below is
  // unaffected.
  bg_poll_console(now);

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

  // PRO-97: break-glass states own the pass — no challenge traffic, no
  // ordinary auth while armed or granted. Every exit relocks to DENIED.
  if (denState == DEN_ST_BG_ARMED) {
    if ((uint32_t)(now - denStateAt) >= BG_ARM_WINDOW_MS) {
      bg_relock(BG_EV_EXPIRED, DEN_REASON_BG_DENIED, "[BG] DENIED: arm expired");
    } else if (now - bgBlinkAt >= 500) {  // slow blink: awaiting confirm
      bgBlinkAt = now;
      bgBlinkOn = !bgBlinkOn;
      digitalWrite(LED_BUILTIN, bgBlinkOn ? HIGH : LOW);
    }
    return;
  }
  if (denState == DEN_ST_BG_GRANTED) {
    if ((uint32_t)(now - denStateAt) >= BG_GRANT_WINDOW_MS) {
      bg_relock(BG_EV_ENDED, DEN_REASON_BG_DENIED, "[BG] ENDED: window elapsed — DENIED");
    } else if (now - bgBlinkAt >= 150) {  // fast blink: alarm active
      bgBlinkAt = now;
      bgBlinkOn = !bgBlinkOn;
      digitalWrite(LED_BUILTIN, bgBlinkOn ? HIGH : LOW);
    }
    return;
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
