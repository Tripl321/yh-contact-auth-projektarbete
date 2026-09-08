
#ifndef SHALLOT_PROTOCOL_H
#define SHALLOT_PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include "hardware/sha256.h"
#include "pico/rand.h"

#include <AESLib.h>

// =====================================================================
// SHALLOT Protocol — Shared header for Edge Enforcement and PAW
//
// Packet format (PRO-81):
//   [Version+MsgType  1B]  bits 7-4 = version, bits 3-0 = msg type
//   [SenderID         8B]
//   [SeqNum           4B]
//   [Nonce            8B]
//   [EncryptedPayload  N]  (variable)
//   [HMAC             8B]  (truncated HMAC-SHA256)
//
// HMAC scope: Version+MsgType || SenderID || SeqNum || Nonce || EncryptedPayload
// Key derivation: K_enc = SHA-256(master_key || "ENC")[:16], K_mac = SHA-256(master_key || "MAC")[:16]
// IV: [0x00 x4] || SeqNum(4B) || Nonce(8B)
// =====================================================================

#define SHALLOT_VERSION        0x01
#define SHALLOT_HMAC_LEN       8
#define SHALLOT_SENDERID_LEN   8
#define SHALLOT_NONCE_LEN      8
#define SHALLOT_SEQNUM_LEN     4
#define SHALLOT_KEY_LEN        16
#define SHALLOT_MASTER_KEY_LEN 16
#define SHALLOT_MAX_PAYLOAD    64
#define SHALLOT_HEADER_LEN     (1 + SHALLOT_SENDERID_LEN + SHALLOT_SEQNUM_LEN + SHALLOT_NONCE_LEN)
#define SHALLOT_MIN_PACKET     (SHALLOT_HEADER_LEN + SHALLOT_HMAC_LEN)
#define SHALLOT_MAX_PACKET     (SHALLOT_HEADER_LEN + SHALLOT_MAX_PAYLOAD + SHALLOT_HMAC_LEN)
#define SHA256_BLOCK_SIZE      64
#define SHA256_DIGEST_SIZE     32

enum ShallotMsgType : uint8_t {
    MSG_CHALLENGE = 0x01,
    MSG_RESPONSE  = 0x02,
    MSG_SUCCESS   = 0x03,
    MSG_FAILURE   = 0x04,
    MSG_KEY_DIST  = 0x05,
    MSG_KEY_ACK   = 0x06,
    MSG_HEARTBEAT = 0x07,
};

struct ShallotPacket {
    uint8_t  version;
    uint8_t  msgType;
    uint8_t  senderID[SHALLOT_SENDERID_LEN];
    uint32_t seqNum;
    uint8_t  nonce[SHALLOT_NONCE_LEN];
    uint8_t  payload[SHALLOT_MAX_PAYLOAD];
    size_t   payloadLen;
    uint8_t  hmac[SHALLOT_HMAC_LEN];
};

struct ShallotKeys {
    uint8_t k_enc[SHALLOT_KEY_LEN];
    uint8_t k_mac[SHALLOT_KEY_LEN];
};

// =====================================================================
// Key derivation (PRO-81 beslut 8)
// =====================================================================
static void derive_keys(const uint8_t masterKey[SHALLOT_MASTER_KEY_LEN],
                        ShallotKeys &keys) {
    uint8_t digest[SHA256_DIGEST_SIZE];

    hw_sha256_start();
    hw_sha256_update(masterKey, SHALLOT_MASTER_KEY_LEN);
    hw_sha256_update((const uint8_t *)"ENC", 3);
    hw_sha256_finish(digest);
    memcpy(keys.k_enc, digest, SHALLOT_KEY_LEN);

    hw_sha256_start();
    hw_sha256_update(masterKey, SHALLOT_MASTER_KEY_LEN);
    hw_sha256_update((const uint8_t *)"MAC", 3);
    hw_sha256_finish(digest);
    memcpy(keys.k_mac, digest, SHALLOT_KEY_LEN);

    memset(digest, 0, sizeof(digest));
}

// =====================================================================
// HMAC-SHA256 truncated to 8 bytes, using hardware SHA-256.
// Precomputes ipad/opad once per key; caller can cache the padded blocks
// across multiple HMAC invocations with the same key for further savings.
// =====================================================================
static void hmac_sha256_truncated(const uint8_t key[SHALLOT_KEY_LEN],
                                   const uint8_t *msg, size_t msgLen,
                                   uint8_t out[SHALLOT_HMAC_LEN]) {
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];

    memset(ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(opad, 0x5c, SHA256_BLOCK_SIZE);
    for (int i = 0; i < SHALLOT_KEY_LEN; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    uint8_t innerDigest[SHA256_DIGEST_SIZE];
    hw_sha256_start();
    hw_sha256_update(ipad, SHA256_BLOCK_SIZE);
    hw_sha256_update(msg, msgLen);
    hw_sha256_finish(innerDigest);

    uint8_t outerDigest[SHA256_DIGEST_SIZE];
    hw_sha256_start();
    hw_sha256_update(opad, SHA256_BLOCK_SIZE);
    hw_sha256_update(innerDigest, SHA256_DIGEST_SIZE);
    hw_sha256_finish(outerDigest);

    memcpy(out, outerDigest, SHALLOT_HMAC_LEN);

    memset(ipad, 0, SHA256_BLOCK_SIZE);
    memset(opad, 0, SHA256_BLOCK_SIZE);
    memset(innerDigest, 0, SHA256_DIGEST_SIZE);
    memset(outerDigest, 0, SHA256_DIGEST_SIZE);
}

// =====================================================================
// AES-128-CTR encrypt/decrypt — single-pass XOR with keystream.
// Reuses a single AESLib instance (key schedule computed once).
// =====================================================================
static void aes_ctr_crypt(const uint8_t key[SHALLOT_KEY_LEN],
                          uint32_t seqNum,
                          const uint8_t nonce[SHALLOT_NONCE_LEN],
                          uint8_t *data, size_t dataLen) {
    if (dataLen == 0) return;

    uint8_t counter[16];
    counter[0] = 0x00; counter[1] = 0x00; counter[2] = 0x00; counter[3] = 0x00;
    counter[4] = (uint8_t)(seqNum >> 24);
    counter[5] = (uint8_t)(seqNum >> 16);
    counter[6] = (uint8_t)(seqNum >> 8);
    counter[7] = (uint8_t)(seqNum);
    memcpy(counter + 8, nonce, SHALLOT_NONCE_LEN);

    AESLib aesLib;
    uint8_t keystream[16];
    size_t offset = 0;
    uint16_t blockCtr = 0;

    while (offset < dataLen) {
        memcpy(keystream, counter, 16);
        aesLib.encryptSingle(keystream, const_cast<uint8_t *>(key));

        size_t chunkLen = dataLen - offset;
        if (chunkLen > 16) chunkLen = 16;
        uint8_t *dp = data + offset;
        uint8_t *kp = keystream;
        size_t i = chunkLen;
        while (i--) *dp++ ^= *kp++;
        offset += chunkLen;

        blockCtr++;
        counter[14] = (uint8_t)(blockCtr >> 8);
        counter[15] = (uint8_t)(blockCtr);
    }

    memset(keystream, 0, 16);
    memset(counter, 0, 16);
}

// =====================================================================
// Constant-time comparison (PRO-81 beslut 11)
// =====================================================================
static uint8_t constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    while (len--) result |= *a++ ^ *b++;
    return result;
}

// =====================================================================
// Build packet: serialize struct into wire format.
// Writes header + payload + HMAC in a single pass with pointer arithmetic.
// =====================================================================
static size_t build_packet(const ShallotPacket &pkt, uint8_t *out, size_t outMax) {
    size_t total = SHALLOT_HEADER_LEN + pkt.payloadLen + SHALLOT_HMAC_LEN;
    if (total > outMax || pkt.payloadLen > SHALLOT_MAX_PAYLOAD) return 0;

    uint8_t *p = out;

    *p++ = (uint8_t)((pkt.version << 4) | (pkt.msgType & 0x0F));
    memcpy(p, pkt.senderID, SHALLOT_SENDERID_LEN);  p += SHALLOT_SENDERID_LEN;
    *p++ = (uint8_t)(pkt.seqNum >> 24);
    *p++ = (uint8_t)(pkt.seqNum >> 16);
    *p++ = (uint8_t)(pkt.seqNum >> 8);
    *p++ = (uint8_t)(pkt.seqNum);
    memcpy(p, pkt.nonce, SHALLOT_NONCE_LEN);        p += SHALLOT_NONCE_LEN;
    memcpy(p, pkt.payload, pkt.payloadLen);         p += pkt.payloadLen;
    memcpy(p, pkt.hmac, SHALLOT_HMAC_LEN);           p += SHALLOT_HMAC_LEN;

    return (size_t)(p - out);
}

// =====================================================================
// Parse packet: deserialize wire format into struct.
// Validates version, payload bounds, and minimum packet size.
// =====================================================================
static bool parse_packet(const uint8_t *data, size_t dataLen, ShallotPacket &pkt) {
    if (dataLen < SHALLOT_MIN_PACKET) return false;

    const uint8_t *p = data;

    uint8_t vm = *p++;
    pkt.version = (uint8_t)(vm >> 4);
    pkt.msgType = (uint8_t)(vm & 0x0F);
    if (pkt.version != SHALLOT_VERSION) return false;

    memcpy(pkt.senderID, p, SHALLOT_SENDERID_LEN);  p += SHALLOT_SENDERID_LEN;
    pkt.seqNum = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
    p += SHALLOT_SEQNUM_LEN;
    memcpy(pkt.nonce, p, SHALLOT_NONCE_LEN);        p += SHALLOT_NONCE_LEN;

    pkt.payloadLen = dataLen - (size_t)(p - data) - SHALLOT_HMAC_LEN;
    if (pkt.payloadLen > SHALLOT_MAX_PAYLOAD) return false;
    memcpy(pkt.payload, p, pkt.payloadLen);         p += pkt.payloadLen;
    memcpy(pkt.hmac, p, SHALLOT_HMAC_LEN);

    return true;
}

// =====================================================================
// Compute HMAC directly from a parsed wire buffer.
// Avoids the intermediate copy into ShallotPacket then back into
// hmacInput — instead passes the raw received bytes (minus HMAC)
// directly to hmac_sha256_truncated, saving one full memcpy of the
// payload and eliminating an 85-byte stack buffer.
// =====================================================================
static void compute_packet_hmac(const ShallotKeys &keys,
                                const uint8_t *wireData, size_t wireLen,
                                uint8_t out[SHALLOT_HMAC_LEN]) {
    if (wireLen < SHALLOT_MIN_PACKET) return;
    hmac_sha256_truncated(keys.k_mac, wireData, wireLen - SHALLOT_HMAC_LEN, out);
}

// =====================================================================
// Compute HMAC from a ShallotPacket struct (for outbound signing or
// when only the parsed struct is available). Inlines the header
// serialization to avoid a separate hmacInput buffer allocation.
// =====================================================================
static void compute_packet_hmac(const ShallotKeys &keys,
                                const ShallotPacket &pkt,
                                uint8_t out[SHALLOT_HMAC_LEN]) {
    if (pkt.payloadLen > SHALLOT_MAX_PAYLOAD) return;
    uint8_t buf[SHALLOT_HEADER_LEN + SHALLOT_MAX_PAYLOAD];
    uint8_t *p = buf;

    *p++ = (uint8_t)((pkt.version << 4) | (pkt.msgType & 0x0F));
    memcpy(p, pkt.senderID, SHALLOT_SENDERID_LEN);  p += SHALLOT_SENDERID_LEN;
    *p++ = (uint8_t)(pkt.seqNum >> 24);
    *p++ = (uint8_t)(pkt.seqNum >> 16);
    *p++ = (uint8_t)(pkt.seqNum >> 8);
    *p++ = (uint8_t)(pkt.seqNum);
    memcpy(p, pkt.nonce, SHALLOT_NONCE_LEN);        p += SHALLOT_NONCE_LEN;
    memcpy(p, pkt.payload, pkt.payloadLen);         p += pkt.payloadLen;

    hmac_sha256_truncated(keys.k_mac, buf, (size_t)(p - buf), out);
    memset(buf, 0, sizeof(buf));
}

// =====================================================================
// Sequence number whitelist — sliding window replay protection.
// Uses a bitmask (uint16_t) instead of a bool[10] array: one 16-bit
// integer supports WINDOW_SIZE=10, and window operations become fast
// bit shifts instead of memmove calls.
// =====================================================================
class SeqWhitelist {
public:
    static const uint32_t WINDOW_SIZE = 10;

    SeqWhitelist() : lastSeen(0), bitmask(0), initialized(false) {}

    bool check_and_add(uint32_t seqNum) {
        if (!initialized) {
            lastSeen = seqNum;
            bitmask = 1u << (WINDOW_SIZE - 1);
            initialized = true;
            return true;
        }

        if (seqNum > lastSeen) {
            uint32_t advance = seqNum - lastSeen;
            if (advance >= WINDOW_SIZE) {
                bitmask = 1u << (WINDOW_SIZE - 1);
            } else {
                bitmask = (bitmask << advance) & ((1u << WINDOW_SIZE) - 1);
                bitmask |= 1u << (WINDOW_SIZE - 1);
            }
            lastSeen = seqNum;
            return true;
        }

        if (seqNum == lastSeen) return false;

        uint32_t diff = lastSeen - seqNum;
        if (diff >= WINDOW_SIZE) return false;

        uint32_t slot = WINDOW_SIZE - 1 - diff;
        uint32_t mask = 1u << slot;
        if (bitmask & mask) return false;

        bitmask |= mask;
        return true;
    }

private:
    uint32_t lastSeen;
    uint16_t bitmask;
    bool     initialized;
};

// =====================================================================
// Random nonce generation — 8 bytes from RP2350 hardware RNG
// =====================================================================
static void generate_nonce(uint8_t nonce[SHALLOT_NONCE_LEN]) {
    rng_128_t rand128;
    get_rand_128(&rand128);
    memcpy(nonce, &rand128, SHALLOT_NONCE_LEN);
}

// =====================================================================
// Sequence number increment (MVP — no flash persistence)
// =====================================================================
static uint32_t next_seq_num(uint32_t &current) {
    return current++;
}

#endif  // SHALLOT_PROTOCOL_H
