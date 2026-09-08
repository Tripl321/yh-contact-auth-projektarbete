/*
 * SHALLOT — Key Envelope Crypto (prototype)
 *
 * Provides a simple stream cipher based on SHA-256 in CTR mode for
 * encrypting key envelopes between MCU and PLC/PAW. The transport key
 * is derived via HMAC-SHA256 from the device identity key and a fresh
 * session nonce.
 *
 * Security properties (prototype level):
 * - Fresh nonce per envelope prevents keystream reuse
 * - Transport key is device-specific (derived from device identity)
 * - HMAC-SHA256 provides key derivation
 * - SHA-256 CTR mode provides confidentiality (not AES, but adequate
 *   for prototype where the threat model excludes sophisticated attacks)
 *
 * In production, replace with AES-128-GCM using hardware crypto on STM32U585.
 *
 * Header-only: no .cpp needed. Include with:
 *   #include <ShallotEnvelope.h>
 */

#ifndef SHALLOT_ENVELOPE_H
#define SHALLOT_ENVELOPE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Envelope sizes
#define SHALLOT_ENVELOPE_NONCE_SIZE  4    // Random per envelope
#define SHALLOT_ENVELOPE_PLAINTEXT_SIZE (SHALLOT_AES_KEY_SIZE + SHALLOT_EPOCH_SIZE + 4) // key(16) + epoch(4) + CRC32(4) = 24
#define SHALLOT_ENVELOPE_CIPHERTEXT_SIZE SHALLOT_ENVELOPE_PLAINTEXT_SIZE

// Envelope wire format:
// [0xA3][len(1)][ciphertext(24)][nonce(4)][epoch_be4(4)][seq(1)]
// Total: 1 + 1 + 24 + 4 + 4 + 1 = 35 bytes
#define SHALLOT_ENVELOPE_FRAME_LEN (2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + SHALLOT_EPOCH_SIZE + 1)

// Label for HKDF-like derivation
#define SHALLOT_ENVELOPE_LABEL "SHALLOT_KEY_ENVELOPE_v1"

// SHA-256, HMAC-SHA256, and CRC32 functions are provided by each platform
// (MCU, PLC, PAW all implement them). They are NOT declared extern here
// to avoid conflicting with platform-specific static definitions.
// Include this header AFTER the platform's crypto functions are defined.

/*
 * Derive per-device transport key from device identity key and session nonce.
 *
 * transport_key = HMAC-SHA256(device_identity_key, label || nonce)
 *
 * This produces a 32-byte key, of which we use the first 16 bytes.
 */
static inline void shallot_derive_transport_key(
    const uint8_t* deviceIdentityKey, size_t keyLen,
    const uint8_t* nonce, size_t nonceLen,
    uint8_t* transportKey /* 32 bytes */)
{
    // Build message: label || nonce
    size_t msgLen = sizeof(SHALLOT_ENVELOPE_LABEL) - 1 + nonceLen;
    uint8_t msg[64];
    memcpy(msg, SHALLOT_ENVELOPE_LABEL, sizeof(SHALLOT_ENVELOPE_LABEL) - 1);
    memcpy(msg + sizeof(SHALLOT_ENVELOPE_LABEL) - 1, nonce, nonceLen);
    hmac_sha256(deviceIdentityKey, keyLen, msg, msgLen, transportKey);
    memset(msg, 0, sizeof(msg));
}

/*
 * Generate keystream block for SHA-256 CTR mode.
 *
 * block = SHA-256(transport_key[0:16] || counter_be4)
 */
static inline void shallot_keystream_block(
    const uint8_t* transportKey, /* 32 bytes, use first 16 */
    uint32_t counter,
    uint8_t* out /* 32 bytes */)
{
    uint8_t input[20];
    memcpy(input, transportKey, 16);
    input[16] = (counter >> 24) & 0xFF;
    input[17] = (counter >> 16) & 0xFF;
    input[18] = (counter >> 8) & 0xFF;
    input[19] = counter & 0xFF;
    sha256(input, 20, out);
    memset(input, 0, sizeof(input));
}

/*
 * Encrypt or decrypt (XOR stream cipher, same operation).
 *
 * plaintext/ciphertext: 24 bytes (key(16) + epoch(4) + CRC32(4))
 * transport_key: 32 bytes (from shallot_derive_transport_key)
 * nonce: 4 bytes
 */
static inline void shallot_envelope_crypt(
    const uint8_t* transportKey, /* 32 bytes */
    const uint8_t* input,  /* 24 bytes */
    uint8_t* output,       /* 24 bytes */
    size_t len)
{
    uint32_t counter = 0;
    size_t offset = 0;
    uint8_t keystream[32];

    while (offset < len) {
        shallot_keystream_block(transportKey, counter, keystream);
        size_t blockLen = (len - offset < 32) ? (len - offset) : 32;
        for (size_t i = 0; i < blockLen; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
        offset += blockLen;
        counter++;
    }
    memset(keystream, 0, sizeof(keystream));
}

/*
 * Build encrypted envelope frame.
 *
 * Inputs:
 *   key:          16-byte AES key (plaintext, will be zeroed after)
 *   epoch:        32-bit epoch number
 *   deviceIdentityKey: device-specific key for transport encryption
 *   deviceIdentityKeyLen: length of deviceIdentityKey
 *   nonce:        4-byte random nonce
 *   seq:          sequence number
 *
 * Output:
 *   frame:        SHALLOT_ENVELOPE_FRAME_LEN bytes
 */
static inline void shallot_build_envelope(
    const uint8_t* key, /* 16 bytes */
    uint32_t epoch,
    const uint8_t* deviceIdentityKey, size_t deviceIdentityKeyLen,
    const uint8_t* nonce, /* 4 bytes */
    uint8_t seq,
    uint8_t* frame /* SHALLOT_ENVELOPE_FRAME_LEN bytes */)
{
    // Build plaintext: key(16) + epoch_be4(4) + CRC32(4) = 24 bytes
    uint8_t plaintext[SHALLOT_ENVELOPE_PLAINTEXT_SIZE];
    memcpy(plaintext, key, SHALLOT_AES_KEY_SIZE);
    plaintext[16] = (epoch >> 24) & 0xFF;
    plaintext[17] = (epoch >> 16) & 0xFF;
    plaintext[18] = (epoch >> 8) & 0xFF;
    plaintext[19] = epoch & 0xFF;
    uint32_t crc = crc32(plaintext, 20); // CRC over key + epoch
    plaintext[20] = (crc >> 24) & 0xFF;
    plaintext[21] = (crc >> 16) & 0xFF;
    plaintext[22] = (crc >> 8) & 0xFF;
    plaintext[23] = crc & 0xFF;

    // Derive transport key
    uint8_t transportKey[32];
    shallot_derive_transport_key(deviceIdentityKey, deviceIdentityKeyLen,
                                 nonce, SHALLOT_ENVELOPE_NONCE_SIZE, transportKey);

    // Encrypt
    uint8_t ciphertext[SHALLOT_ENVELOPE_CIPHERTEXT_SIZE];
    shallot_envelope_crypt(transportKey, plaintext, ciphertext, SHALLOT_ENVELOPE_CIPHERTEXT_SIZE);

    // Build frame
    frame[0] = 0xA3; // SHALLOT_MSG_KEY_DATA (now carries ciphertext)
    frame[1] = (uint8_t)SHALLOT_ENVELOPE_CIPHERTEXT_SIZE;
    memcpy(&frame[2], ciphertext, SHALLOT_ENVELOPE_CIPHERTEXT_SIZE);
    memcpy(&frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE], nonce, SHALLOT_ENVELOPE_NONCE_SIZE);
    frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE] = (epoch >> 24) & 0xFF;
    frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 1] = (epoch >> 16) & 0xFF;
    frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 2] = (epoch >> 8) & 0xFF;
    frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 3] = epoch & 0xFF;
    frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 4] = seq;

    // Zero sensitive data
    memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(transportKey, 0, sizeof(transportKey));
}

/*
 * Open (decrypt) envelope frame.
 *
 * Inputs:
 *   frame:        SHALLOT_ENVELOPE_FRAME_LEN bytes
 *   deviceIdentityKey: device-specific key for transport decryption
 *   deviceIdentityKeyLen: length of deviceIdentityKey
 *
 * Outputs:
 *   key:          16-byte AES key (plaintext)
 *   epoch:        32-bit epoch number
 *   seq:          sequence number
 *
 * Returns true on success (CRC32 verified), false on failure.
 */
static inline bool shallot_open_envelope(
    const uint8_t* frame, /* SHALLOT_ENVELOPE_FRAME_LEN bytes */
    const uint8_t* deviceIdentityKey, size_t deviceIdentityKeyLen,
    uint8_t* key, /* 16 bytes */
    uint32_t* epoch,
    uint8_t* seq)
{
    if (frame[0] != 0xA3) return false;
    if (frame[1] != SHALLOT_ENVELOPE_CIPHERTEXT_SIZE) return false;

    // Extract nonce and epoch from frame
    const uint8_t* nonce = &frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE];
    uint32_t frameEpoch = ((uint32_t)frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE] << 24)
                        | ((uint32_t)frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 1] << 16)
                        | ((uint32_t)frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 2] << 8)
                        |  (uint32_t)frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 3];
    *seq = frame[2 + SHALLOT_ENVELOPE_CIPHERTEXT_SIZE + SHALLOT_ENVELOPE_NONCE_SIZE + 4];

    // Derive transport key
    uint8_t transportKey[32];
    shallot_derive_transport_key(deviceIdentityKey, deviceIdentityKeyLen,
                                 nonce, SHALLOT_ENVELOPE_NONCE_SIZE, transportKey);

    // Decrypt
    uint8_t plaintext[SHALLOT_ENVELOPE_PLAINTEXT_SIZE];
    const uint8_t* ciphertext = &frame[2];
    shallot_envelope_crypt(transportKey, ciphertext, plaintext, SHALLOT_ENVELOPE_CIPHERTEXT_SIZE);

    // Verify CRC32
    uint32_t expectedCrc = crc32(plaintext, 20);
    uint32_t gotCrc = ((uint32_t)plaintext[20] << 24)
                    | ((uint32_t)plaintext[21] << 16)
                    | ((uint32_t)plaintext[22] << 8)
                    |  (uint32_t)plaintext[23];

    if (expectedCrc != gotCrc) {
        memset(plaintext, 0, sizeof(plaintext));
        memset(transportKey, 0, sizeof(transportKey));
        return false;
    }

    // Extract key and epoch
    memcpy(key, plaintext, SHALLOT_AES_KEY_SIZE);
    *epoch = ((uint32_t)plaintext[16] << 24)
           | ((uint32_t)plaintext[17] << 16)
           | ((uint32_t)plaintext[18] << 8)
           |  (uint32_t)plaintext[19];

    if (*epoch != frameEpoch) {
        memset(plaintext, 0, sizeof(plaintext));
        memset(transportKey, 0, sizeof(transportKey));
        memset(key, 0, SHALLOT_AES_KEY_SIZE);
        return false;
    }

    // Zero sensitive data
    memset(plaintext, 0, sizeof(plaintext));
    memset(transportKey, 0, sizeof(transportKey));
    return true;
}

#endif // SHALLOT_ENVELOPE_H
