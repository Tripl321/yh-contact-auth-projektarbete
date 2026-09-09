/*
 * SHALLOT — Shared crypto primitives implementation.
 * SHA-256 + HMAC-SHA256 + constant-time compare.
 * No dynamic allocation; all buffers are stack-local.
 */

#include "ShallotCrypto.h"
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t shallot_sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void shallot_sha256_transform(uint32_t state[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) |
           ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) |
           (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + EP1(e) + CH(e, f, g) + shallot_sha256_k[i] + w[i];
    uint32_t t2 = EP0(a) + MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void shallot_sha256(const uint8_t* data, size_t len, uint8_t* hash) {
  uint32_t state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  uint8_t block[64];
  size_t offset = 0;
  while (len >= 64) {
    shallot_sha256_transform(state, data + offset);
    offset += 64;
    len -= 64;
  }

  memset(block, 0, sizeof(block));
  if (len > 0) {
    memcpy(block, data + offset, len);
  }
  block[len] = 0x80;

  uint64_t bitLen = ((uint64_t)(offset + len)) * 8;
  if (len <= 55) {
    for (int i = 0; i < 8; i++) {
      block[63 - i] = (uint8_t)(bitLen >> (i * 8));
    }
    shallot_sha256_transform(state, block);
  } else {
    shallot_sha256_transform(state, block);
    memset(block, 0, sizeof(block));
    for (int i = 0; i < 8; i++) {
      block[63 - i] = (uint8_t)(bitLen >> (i * 8));
    }
    shallot_sha256_transform(state, block);
  }

  for (int i = 0; i < 8; i++) {
    hash[i * 4]     = (uint8_t)(state[i] >> 24);
    hash[i * 4 + 1] = (uint8_t)(state[i] >> 16);
    hash[i * 4 + 2] = (uint8_t)(state[i] >> 8);
    hash[i * 4 + 3] = (uint8_t)(state[i]);
  }

  memset(state, 0, sizeof(state));
  memset(block, 0, sizeof(block));
}

void shallot_hmac_sha256(const uint8_t* key, size_t keyLen,
                         const uint8_t* msg, size_t msgLen,
                         uint8_t* mac) {
  uint8_t k_ipad[SHALLOT_CRYPTO_BLOCK_SIZE];
  uint8_t k_opad[SHALLOT_CRYPTO_BLOCK_SIZE];
  uint8_t innerHash[SHALLOT_CRYPTO_SHA256_SIZE];
  uint8_t outerMsg[SHALLOT_CRYPTO_BLOCK_SIZE + SHALLOT_CRYPTO_SHA256_SIZE];

  memset(k_ipad, 0x36, sizeof(k_ipad));
  memset(k_opad, 0x5c, sizeof(k_opad));

  for (size_t i = 0; i < keyLen && i < SHALLOT_CRYPTO_BLOCK_SIZE; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  uint8_t innerMsg[SHALLOT_CRYPTO_BLOCK_SIZE + msgLen];
  memcpy(innerMsg, k_ipad, SHALLOT_CRYPTO_BLOCK_SIZE);
  memcpy(innerMsg + SHALLOT_CRYPTO_BLOCK_SIZE, msg, msgLen);
  shallot_sha256(innerMsg, SHALLOT_CRYPTO_BLOCK_SIZE + msgLen, innerHash);

  memcpy(outerMsg, k_opad, SHALLOT_CRYPTO_BLOCK_SIZE);
  memcpy(outerMsg + SHALLOT_CRYPTO_BLOCK_SIZE, innerHash, SHALLOT_CRYPTO_SHA256_SIZE);
  shallot_sha256(outerMsg, sizeof(outerMsg), mac);

  memset(k_ipad, 0, sizeof(k_ipad));
  memset(k_opad, 0, sizeof(k_opad));
  memset(innerHash, 0, sizeof(innerHash));
  memset(innerMsg, 0, sizeof(innerMsg));
  memset(outerMsg, 0, sizeof(outerMsg));
}

uint8_t shallot_const_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return (diff == 0) ? 1 : 0;
}
