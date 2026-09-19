/*
 * SHALLOT — shared crypto primitives (PRO-49, ticket 01)
 *
 * Header-only, transport-free module owned by PAW, DEN and UNO-Q
 * firmware. Single home for SHA-256, HMAC-SHA256, K_mac/K_enc
 * derivation and volatile wipe — previously copied into every sketch.
 *
 * Constant-time compare is NOT duplicated here: use den_ct_compare
 * from DenUartProtocol (single owner, reused).
 *
 * No Arduino dependency (only stddef/stdint/string) so the same file
 * compiles on host for KAT (tests/test_shallot_crypto_kat.py).
 *
 * Fail-closed throughout: oversize inputs zero the output and return.
 */

#ifndef SHALLOT_CRYPTO_H
#define SHALLOT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHALOT_SHA256_LEN 32
#define SHALOT_HMAC_MAX_MSG 64  // all firmware uses are nonces (<= 32 B)
#define SHALOT_KEY_LEN 16       // AES-128 master / derived keys

// =============================================================
// Volatile wipe — the module owns clearing, callers cannot forget.
// =============================================================
static inline void shalot_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

// =============================================================
// SHA-256 (stack-only, no heap). Canonical port of the KAT-verified
// firmware implementation shared by all nodes.
// =============================================================
static const uint32_t shalot_shaK[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHALOT_ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void shalot_compress(const uint8_t b[64], uint32_t h[8]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) |
               ((uint32_t)b[i*4+2] << 8) | (uint32_t)b[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SHALOT_ROR(w[i-15],7) ^ SHALOT_ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = SHALOT_ROR(w[i-2],17) ^ SHALOT_ROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SHALOT_ROR(e,6) ^ SHALOT_ROR(e,11) ^ SHALOT_ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + shalot_shaK[i] + w[i];
        uint32_t S0 = SHALOT_ROR(a,2) ^ SHALOT_ROR(a,13) ^ SHALOT_ROR(a,22);
        uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=bb; bb=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=bb; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    shalot_wipe(w, sizeof(w));
}

static inline void shalot_sha256(const uint8_t *data, size_t len,
                                 uint8_t out[SHALOT_SHA256_LEN]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint64_t bitLen = (uint64_t)len * 8;
    size_t pos = 0;
    uint8_t block[64];
    while (len - pos >= 64) {
        shalot_compress(data + pos, h);
        pos += 64;
    }
    size_t rem = len - pos;
    memcpy(block, data + pos, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        shalot_compress(block, h);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bitLen >> (56 - 8 * i));
    shalot_compress(block, h);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)h[i];
    }
    shalot_wipe(block, sizeof(block));
    shalot_wipe(h, sizeof(h));
}

// =============================================================
// HMAC-SHA256, full 32-byte output. Stack-only temps, wiped.
// Oversize key/message: output zeroed (fail closed).
// =============================================================
static inline void shalot_hmac_sha256(const uint8_t *key, size_t keyLen,
                                      const uint8_t *msg, size_t msgLen,
                                      uint8_t mac[SHALOT_SHA256_LEN]) {
    if (keyLen > 64 || msgLen > SHALOT_HMAC_MAX_MSG) {
        memset(mac, 0, SHALOT_SHA256_LEN);
        return;
    }
    uint8_t ipad[64], opad[64], inner[32];
    uint8_t innerMsg[64 + SHALOT_HMAC_MAX_MSG];
    uint8_t outerMsg[64 + 32];
    memset(ipad, 0x36, sizeof(ipad));
    memset(opad, 0x5c, sizeof(opad));
    for (size_t i = 0; i < keyLen; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    memcpy(innerMsg, ipad, 64);
    memcpy(innerMsg + 64, msg, msgLen);
    shalot_sha256(innerMsg, 64 + msgLen, inner);
    memcpy(outerMsg, opad, 64);
    memcpy(outerMsg + 64, inner, 32);
    shalot_sha256(outerMsg, sizeof(outerMsg), mac);
    shalot_wipe(ipad, sizeof(ipad));
    shalot_wipe(opad, sizeof(opad));
    shalot_wipe(inner, sizeof(inner));
    shalot_wipe(innerMsg, sizeof(innerMsg));
    shalot_wipe(outerMsg, sizeof(outerMsg));
}

// =============================================================
// Key derivation: K = SHA-256(master || label)[:16].
// =============================================================
static inline void shalot_derive_key(const uint8_t master[SHALOT_KEY_LEN],
                                     const char *label3,
                                     uint8_t out[SHALOT_KEY_LEN]) {
    uint8_t full[32];
    uint8_t msg[SHALOT_KEY_LEN + 3];
    memcpy(msg, master, SHALOT_KEY_LEN);
    memcpy(msg + SHALOT_KEY_LEN, label3, 3);
    shalot_sha256(msg, sizeof(msg), full);
    memcpy(out, full, SHALOT_KEY_LEN);
    shalot_wipe(full, sizeof(full));
    shalot_wipe(msg, sizeof(msg));
}

static inline void shalot_derive_k_mac(const uint8_t master[SHALOT_KEY_LEN],
                                       uint8_t k_mac[SHALOT_KEY_LEN]) {
    shalot_derive_key(master, "MAC", k_mac);
}

static inline void shalot_derive_k_enc(const uint8_t master[SHALOT_KEY_LEN],
                                       uint8_t k_enc[SHALOT_KEY_LEN]) {
    shalot_derive_key(master, "ENC", k_enc);
}

#endif  // SHALLOT_CRYPTO_H
