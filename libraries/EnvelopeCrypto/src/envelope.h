// SHALLOT wrapped-key envelope — shared firmware header (spec v0.2).
//
// Used by the UNO Q MCU (wrap) and the PAW (open) behind ENVELOPE_PHASE2.
// Header-only, stack-only, no heap, no Serial dependency: the caller owns
// randomness (TRNG), transport framing, epoch state, and the fixture
// interlock. All crypto comes from the vetted BearSSL subset in this library.
//
// Wire constants and the key schedule mirror docs/12-envelope-protocol.md
// and tests/_envelope_lib.py byte-for-byte; the golden vector in
// tests/test_envelope.py is the cross-check.
#ifndef SHALLOT_ENVELOPE_H
#define SHALLOT_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bearssl_hash.h"
#include "bearssl_hmac.h"
#include "bearssl_block.h"
#include "bearssl_aead.h"
#include "bearssl_ec.h"
#include "bearssl_kdf.h"

#define ENV_VER        0x01
#define ENV_E1_TAG     0xB1
#define ENV_E2_TAG     0xB2
#define ENV_SEC_LEN    32
#define ENV_PUB_LEN    32
#define ENV_NONCE_P    8
#define ENV_NONCE_M    12
#define ENV_EPOCH_LEN  4
#define ENV_OPKEY_LEN  16
#define ENV_TAG_LEN    16
#define ENV_AAD_LEN    106
#define ENV_E1_LEN     45
#define ENV_E2_LEN     81
#define ENV_SALT_LEN   32
#define ENV_VERIFY_LEN 16  // hex chars, 64 bits

// "SHALLOT-ENV1" (12 bytes, no NUL).
static const uint8_t ENV_DOMAIN[12] = {
  'S','H','A','L','L','O','T','-','E','N','V','1'
};
// Distinct v0.2 KDF label (spec §5): never collides with the retired v0.1 label.
static const uint8_t ENV_KEK_INFO[] = "SHALLOT-ENV1/KEK-v2";
#define ENV_KEK_INFO_LEN 19

// Data-independent all-zero check (RFC 7748 §6 guidance). Returns 1 if zero.
static inline int env_is_all_zero(const uint8_t *buf, size_t len) {
  uint8_t acc = 0;
  for (size_t i = 0; i < len; i++) acc |= buf[i];
  // Constant-time select without branching on secret data.
  uint8_t x = acc;
  x |= (uint8_t)(x >> 4); x |= (uint8_t)(x >> 2); x |= (uint8_t)(x >> 1);
  return (int)((x & 1) ^ 1);
}

static inline int env_x25519_pub(const uint8_t sec[ENV_SEC_LEN],
                                 uint8_t pub_out[ENV_PUB_LEN]) {
  static const uint8_t base[32] = { 9 };
  uint8_t s[32], g[32];
  memcpy(s, sec, 32);
  memcpy(g, base, 32);
  uint32_t r = br_ec_c25519_i15.mul(g, 32, s, 32, BR_EC_curve25519);
  memcpy(pub_out, g, 32);
  memset(s, 0, 32);
  memset(g, 0, 32);
  return r == 1 ? 1 : 0;
}

static inline int env_x25519_dh(const uint8_t sec[ENV_SEC_LEN],
                                const uint8_t peer[ENV_PUB_LEN],
                                uint8_t shared_out[ENV_SEC_LEN]) {
  uint8_t s[32], g[32];
  memcpy(s, sec, 32);
  memcpy(g, peer, 32);
  uint32_t r = br_ec_c25519_i15.mul(g, 32, s, 32, BR_EC_curve25519);
  memcpy(shared_out, g, 32);
  memset(s, 0, 32);
  memset(g, 0, 32);
  return r == 1 ? 1 : 0;
}

// AAD = DOMAIN || VER || target || device_id(4) || epoch_be4 || pub_P ||
//       pub_M || nonce_P(8) || nonce_M(12). Always exactly 106 bytes.
static inline void env_build_aad(uint8_t target_id, const uint8_t device_id[4],
                                 uint32_t epoch,
                                 const uint8_t pub_p[ENV_PUB_LEN],
                                 const uint8_t pub_m[ENV_PUB_LEN],
                                 const uint8_t nonce_p[ENV_NONCE_P],
                                 const uint8_t nonce_m[ENV_NONCE_M],
                                 uint8_t aad_out[ENV_AAD_LEN]) {
  uint8_t *p = aad_out;
  memcpy(p, ENV_DOMAIN, 12); p += 12;
  *p++ = ENV_VER;
  *p++ = target_id;
  memcpy(p, device_id, 4); p += 4;
  p[0] = (uint8_t)(epoch >> 24); p[1] = (uint8_t)(epoch >> 16);
  p[2] = (uint8_t)(epoch >> 8);  p[3] = (uint8_t)(epoch); p += 4;
  memcpy(p, pub_p, 32); p += 32;
  memcpy(p, pub_m, 32); p += 32;
  memcpy(p, nonce_p, 8); p += 8;
  memcpy(p, nonce_m, 12);
}

// salt = SHA256(AAD): transcript-bound, never zero in practice, and any
// session change re-salts the KDF (spec §5).
static inline void env_kek_salt(const uint8_t aad[ENV_AAD_LEN],
                                uint8_t salt_out[ENV_SALT_LEN]) {
  br_sha256_context sc;
  br_sha256_init(&sc);
  br_sha256_update(&sc, aad, ENV_AAD_LEN);
  br_sha256_out(&sc, salt_out);
  memset(&sc, 0, sizeof(sc));
}

// KEK = HKDF-SHA256(shared, salt, info=v2 label)[0:16].
static inline void env_derive_kek(const uint8_t shared[ENV_SEC_LEN],
                                  const uint8_t salt[ENV_SALT_LEN],
                                  uint8_t kek_out[ENV_OPKEY_LEN]) {
  br_hkdf_context hc;
  br_hkdf_init(&hc, &br_sha256_vtable, salt, ENV_SALT_LEN);
  br_hkdf_inject(&hc, shared, ENV_SEC_LEN);
  br_hkdf_flip(&hc);
  br_hkdf_produce(&hc, ENV_KEK_INFO, ENV_KEK_INFO_LEN, kek_out, ENV_OPKEY_LEN);
  memset(&hc, 0, sizeof(hc));
}

static inline void env_seal(const uint8_t kek[ENV_OPKEY_LEN],
                            const uint8_t iv[ENV_NONCE_M],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t pt[ENV_OPKEY_LEN],
                            uint8_t ct[ENV_OPKEY_LEN],
                            uint8_t tag[ENV_TAG_LEN]) {
  br_aes_ct_ctr_keys bc;
  br_aes_ct_ctr_init(&bc, kek, 16);
  br_gcm_context gc;
  br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
  br_gcm_reset(&gc, iv, ENV_NONCE_M);
  if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
  br_gcm_flip(&gc);
  memcpy(ct, pt, ENV_OPKEY_LEN);
  br_gcm_run(&gc, 1, ct, ENV_OPKEY_LEN);
  br_gcm_get_tag(&gc, tag);
  memset(&bc, 0, sizeof(bc));
  memset(&gc, 0, sizeof(gc));
}

// Returns 1 and writes pt on tag success, else 0 (pt left untouched).
static inline int env_open(const uint8_t kek[ENV_OPKEY_LEN],
                           const uint8_t iv[ENV_NONCE_M],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t ct[ENV_OPKEY_LEN],
                           const uint8_t tag[ENV_TAG_LEN],
                           uint8_t pt[ENV_OPKEY_LEN]) {
  uint8_t tmp[ENV_OPKEY_LEN];
  br_aes_ct_ctr_keys bc;
  br_aes_ct_ctr_init(&bc, kek, 16);
  br_gcm_context gc;
  br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
  br_gcm_reset(&gc, iv, ENV_NONCE_M);
  if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
  br_gcm_flip(&gc);
  memcpy(tmp, ct, ENV_OPKEY_LEN);
  br_gcm_run(&gc, 0, tmp, ENV_OPKEY_LEN);
  uint32_t ok = br_gcm_check_tag(&gc, tag);
  memset(&bc, 0, sizeof(bc));
  memset(&gc, 0, sizeof(gc));
  if (!ok) {
    memset(tmp, 0, sizeof(tmp));
    return 0;
  }
  memcpy(pt, tmp, ENV_OPKEY_LEN);
  memset(tmp, 0, sizeof(tmp));
  return 1;
}

// VERIFY = hex(SHA256(0xB1 || pub_P || pub_M))[0:16]. Output is 16 hex chars
// plus NUL (caller provides >= 17 bytes).
static inline void env_verify_hex(const uint8_t pub_p[ENV_PUB_LEN],
                                  const uint8_t pub_m[ENV_PUB_LEN],
                                  char out17[ENV_VERIFY_LEN + 1]) {
  static const char HEXDIGITS[] = "0123456789abcdef";
  uint8_t digest[32];
  br_sha256_context sc;
  br_sha256_init(&sc);
  uint8_t tag = ENV_E1_TAG;
  br_sha256_update(&sc, &tag, 1);
  br_sha256_update(&sc, pub_p, ENV_PUB_LEN);
  br_sha256_update(&sc, pub_m, ENV_PUB_LEN);
  br_sha256_out(&sc, digest);
  memset(&sc, 0, sizeof(sc));
  for (int i = 0; i < 8; i++) {
    out17[2 * i]     = HEXDIGITS[(digest[i] >> 4) & 0xF];
    out17[2 * i + 1] = HEXDIGITS[digest[i] & 0xF];
  }
  out17[ENV_VERIFY_LEN] = '\0';
  memset(digest, 0, sizeof(digest));
}

// E1 = [0xB1][device_id 4][pub_P 32][nonce_P 8]. The PAW asserts its own
// device_id here so the MCU can bind it into the AAD (§6); the PAW
// re-checks with its true id at open, so a swapped E1 fails the tag.
// Returns 1 on success.
static inline int env_encode_e1(const uint8_t device_id[4],
                                const uint8_t pub_p[ENV_PUB_LEN],
                                const uint8_t nonce_p[ENV_NONCE_P],
                                uint8_t e1_out[ENV_E1_LEN]) {
  e1_out[0] = ENV_E1_TAG;
  memcpy(e1_out + 1, device_id, 4);
  memcpy(e1_out + 5, pub_p, ENV_PUB_LEN);
  memcpy(e1_out + 37, nonce_p, ENV_NONCE_P);
  return 1;
}

// Strict E1 parse. Returns 1 and fills device_id/pub_p/nonce_p, else 0.
static inline int env_parse_e1(const uint8_t *frame, size_t len,
                               uint8_t device_id[4],
                               uint8_t pub_p[ENV_PUB_LEN],
                               uint8_t nonce_p[ENV_NONCE_P]) {
  if (len != ENV_E1_LEN || frame[0] != ENV_E1_TAG) return 0;
  memcpy(device_id, frame + 1, 4);
  memcpy(pub_p, frame + 5, ENV_PUB_LEN);
  memcpy(nonce_p, frame + 37, ENV_NONCE_P);
  return 1;
}

// E2 = [0xB2][epoch_be4][pub_M 32][nonce_M 12][ct 16][tag 16].
static inline int env_encode_e2(uint32_t epoch,
                                const uint8_t pub_m[ENV_PUB_LEN],
                                const uint8_t nonce_m[ENV_NONCE_M],
                                const uint8_t ct[ENV_OPKEY_LEN],
                                const uint8_t tag[ENV_TAG_LEN],
                                uint8_t e2_out[ENV_E2_LEN]) {
  e2_out[0] = ENV_E2_TAG;
  e2_out[1] = (uint8_t)(epoch >> 24); e2_out[2] = (uint8_t)(epoch >> 16);
  e2_out[3] = (uint8_t)(epoch >> 8);  e2_out[4] = (uint8_t)(epoch);
  memcpy(e2_out + 5, pub_m, ENV_PUB_LEN);
  memcpy(e2_out + 37, nonce_m, ENV_NONCE_M);
  memcpy(e2_out + 49, ct, ENV_OPKEY_LEN);
  memcpy(e2_out + 65, tag, ENV_TAG_LEN);
  return 1;
}

// Strict E2 parse. Returns 1 on success, else 0 (nothing written).
static inline int env_parse_e2(const uint8_t *frame, size_t len,
                               uint32_t *epoch,
                               uint8_t pub_m[ENV_PUB_LEN],
                               uint8_t nonce_m[ENV_NONCE_M],
                               uint8_t ct[ENV_OPKEY_LEN],
                               uint8_t tag[ENV_TAG_LEN]) {
  if (len != ENV_E2_LEN || frame[0] != ENV_E2_TAG) return 0;
  *epoch = ((uint32_t)frame[1] << 24) | ((uint32_t)frame[2] << 16) |
           ((uint32_t)frame[3] << 8) | (uint32_t)frame[4];
  memcpy(pub_m, frame + 5, ENV_PUB_LEN);
  memcpy(nonce_m, frame + 37, ENV_NONCE_M);
  memcpy(ct, frame + 49, ENV_OPKEY_LEN);
  memcpy(tag, frame + 65, ENV_TAG_LEN);
  return 1;
}

#endif  // SHALLOT_ENVELOPE_H
