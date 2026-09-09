/*
 * SHALLOT — Shared crypto primitives for the UART dock-auth pivot slice.
 *
 * Provides SHA-256, HMAC-SHA256 and a constant-time byte comparator used by
 * the contact-based challenge-response path (DEN <-> PAW over Serial1).
 *
 * Development-only key: the fixed key below is a lab placeholder and MUST be
 * replaced by a provisioned per-device key before any non-lab use. It is never
 * transmitted over UART; only the derived HMAC is sent.
 */

#ifndef SHALLOT_CRYPTO_H
#define SHALLOT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define SHALLOT_CRYPTO_KEY_SIZE      32
#define SHALLOT_CRYPTO_SHA256_SIZE   32
#define SHALLOT_CRYPTO_HMAC_SIZE     32
#define SHALLOT_CRYPTO_BLOCK_SIZE    64

/*
 * DEVELOPMENT-ONLY PLACEHOLDER KEY.
 * Replace with a provisioned per-device key before any non-lab use.
 * This key is shared by DEN and PAW in the lab pivot slice.
 */
static const uint8_t SHALLOT_CRYPTO_DEV_KEY[SHALLOT_CRYPTO_KEY_SIZE] = {
  0x53, 0x48, 0x41, 0x4c, 0x4c, 0x4f, 0x54, 0x5f,
  0x44, 0x45, 0x56, 0x5f, 0x4b, 0x45, 0x59, 0x5f,
  0x32, 0x30, 0x32, 0x36, 0x5f, 0x50, 0x49, 0x56,
  0x4f, 0x54, 0x5f, 0x53, 0x4c, 0x49, 0x43, 0x45
};

/* Compute SHA-256(data, len) -> hash[32]. */
void shallot_sha256(const uint8_t* data, size_t len, uint8_t* hash);

/* Compute HMAC-SHA256(key, keyLen, msg, msgLen) -> mac[32]. */
void shallot_hmac_sha256(const uint8_t* key, size_t keyLen,
                         const uint8_t* msg, size_t msgLen,
                         uint8_t* mac);

/* Constant-time comparison. Returns 1 when equal, 0 otherwise.
 * Always walks the full length; never early-exits. */
uint8_t shallot_const_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

#endif  /* SHALLOT_CRYPTO_H */
