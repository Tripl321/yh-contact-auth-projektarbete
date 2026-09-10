/* Test-only flat wrapper over the vendored BearSSL subset (NOT for firmware).
 * Exposes envelope primitives to pytest via ctypes. Firmware uses the
 * br_ APIs directly with identical semantics. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "bearssl_hash.h"
#include "bearssl_hmac.h"
#include "bearssl_block.h"
#include "bearssl_aead.h"
#include "bearssl_ec.h"
#include "bearssl_kdf.h"

extern const br_ec_impl br_ec_c25519_i15;

/* X25519: out_pub = sec*G (u=9 base). Returns 1 on success. */
uint32_t env_x25519_pub(uint8_t out_pub[32], const uint8_t sec[32]) {
    static const uint8_t base[32] = {9};
    uint8_t s[32], g[32];
    memcpy(s, sec, 32);
    memcpy(g, base, 32);
    uint32_t r = br_ec_c25519_i15.mul(g, 32, s, 32, BR_EC_curve25519);
    memcpy(out_pub, g, 32);
    memset(s, 0, 32);
    memset(g, 0, 32);
    return r;
}

/* X25519: out_shared = sec*peer. Returns 1 on success (peer manages
 * low-order-point safety via caller's all-zero check). */
uint32_t env_x25519_dh(uint8_t out_shared[32], const uint8_t sec[32],
                       const uint8_t peer[32]) {
    uint8_t s[32], g[32];
    memcpy(s, sec, 32);
    memcpy(g, peer, 32);
    uint32_t r = br_ec_c25519_i15.mul(g, 32, s, 32, BR_EC_curve25519);
    memcpy(out_shared, g, 32);
    memset(s, 0, 32);
    memset(g, 0, 32);
    return r;
}

/* AES-128-GCM seal: ct = enc(pt), tag out. Returns 0 ok. */
int env_gcm_seal(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *pt, uint8_t *ct, size_t len,
                 uint8_t tag[16]) {
    br_aes_ct_ctr_keys bc;
    br_aes_ct_ctr_init(&bc, key, 16);
    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
    br_gcm_reset(&gc, iv, 12);
    if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
    br_gcm_flip(&gc);
    memcpy(ct, pt, len);
    br_gcm_run(&gc, 1, ct, len);
    br_gcm_get_tag(&gc, tag);
    memset(&bc, 0, sizeof(bc));
    memset(&gc, 0, sizeof(gc));
    return 0;
}

/* AES-128-GCM open: returns 1 if tag verifies (pt out), else 0. */
int env_gcm_open(const uint8_t key[16], const uint8_t iv[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, uint8_t *pt, size_t len,
                 const uint8_t tag[16]) {
    br_aes_ct_ctr_keys bc;
    br_aes_ct_ctr_init(&bc, key, 16);
    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
    br_gcm_reset(&gc, iv, 12);
    if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
    br_gcm_flip(&gc);
    memcpy(pt, ct, len);
    br_gcm_run(&gc, 0, pt, len);
    uint32_t ok = br_gcm_check_tag(&gc, tag);
    memset(&bc, 0, sizeof(bc));
    memset(&gc, 0, sizeof(gc));
    return ok ? 1 : 0;
}

/* HKDF-SHA256 general (test vectors): OKM[0:L] = HKDF(salt, ikm, info). */
void env_hkdf(uint8_t *okm, size_t L,
              const uint8_t *salt, size_t salt_len,
              const uint8_t *ikm, size_t ikm_len,
              const uint8_t *info, size_t info_len) {
    br_hkdf_context hc;
    br_hkdf_init(&hc, &br_sha256_vtable, salt, salt_len);
    br_hkdf_inject(&hc, ikm, ikm_len);
    br_hkdf_flip(&hc);
    br_hkdf_produce(&hc, info, info_len, okm, L);
}

/* HKDF-SHA256 expand to 16 bytes (KEK). Salt fixed 32 zero bytes. */
void env_hkdf_kek(uint8_t kek[16], const uint8_t shared[32],
                  const uint8_t *info, size_t info_len) {
    static const uint8_t salt[32] = {0};
    br_hkdf_context hc;
    br_hkdf_init(&hc, &br_sha256_vtable, salt, 32);
    br_hkdf_inject(&hc, shared, 32);
    br_hkdf_flip(&hc);
    br_hkdf_produce(&hc, info, info_len, kek, 16);
}
