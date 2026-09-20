/*
 * SHALLOT — USB provisioning wire protocol (PRO-46), shared constants
 * and packet shape for the 0xA-series (HANDSHAKE/READY/KEY_DATA/STORED/
 * ERROR). Single home — previously copied into five sketches with two
 * drifted variants.
 *
 * Transport-free: no Serial dependency. Host-compilable (KAT corpus:
 * tests/vectors/provisioning.json). CRC32 comes from ShallotCrypto.
 *
 * Packet shapes:
 *   UNO Q -> target: MSG_HANDSHAKE (0xA1) + target_id (1B)
 *   target -> UNO Q: MSG_READY (0xA2) + device_id (4B)
 *   UNO Q -> target: MSG_KEY_DATA (0xA3) + key_len (1B) + key (16B)
 *                    + CRC32 (4B, big-endian over key only) = 22 B
 *   target -> UNO Q: MSG_STORED (0xA4) + stored_hash (4B)
 *   target -> UNO Q: MSG_ERROR (0xA5) on rejection (fail closed)
 */

#ifndef PROVISIONING_PROTOCOL_H
#define PROVISIONING_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ShallotCrypto.h"

#define PROV_MSG_HANDSHAKE 0xA1
#define PROV_MSG_READY     0xA2
#define PROV_MSG_KEY_DATA  0xA3
#define PROV_MSG_STORED    0xA4
#define PROV_MSG_ERROR     0xA5

#define PROV_KEY_LEN       16
#define PROV_KEYDATA_LEN   22   // type(1) + len(1) + key(16) + crc(4)
#define PROV_DEVICE_ID_LEN 4
#define PROV_STORED_LEN    5    // type(1) + hash(4)
#define PROV_HANDSHAKE_LEN 2    // type(1) + target_id(1)

// Target ids (UNO Q side sends; receivers compare).
#define PROV_TARGET_PLC 0x01
#define PROV_TARGET_PAW 0x02

// Build the 22-byte KEY_DATA packet. crc = shalot_crc32(key, PROV_KEY_LEN),
// big-endian (matches the firmwares' wire format).
static inline void prov_build_key_data(uint8_t *out /* PROV_KEYDATA_LEN */,
                                       const uint8_t *key /* PROV_KEY_LEN */) {
    uint32_t crc = shalot_crc32(key, PROV_KEY_LEN);
    out[0] = PROV_MSG_KEY_DATA;
    out[1] = PROV_KEY_LEN;
    memcpy(out + 2, key, PROV_KEY_LEN);
    out[18] = (uint8_t)(crc >> 24);
    out[19] = (uint8_t)(crc >> 16);
    out[20] = (uint8_t)(crc >> 8);
    out[21] = (uint8_t)(crc & 0xFF);
}

// Verify a received KEY_DATA packet. Returns true when type/len match
// and the CRC over the key verifies (fail closed otherwise).
static inline bool prov_verify_key_data(const uint8_t *pkt /* PROV_KEYDATA_LEN */) {
    if (pkt[0] != PROV_MSG_KEY_DATA || pkt[1] != PROV_KEY_LEN) return false;
    uint32_t want = ((uint32_t)pkt[18] << 24) | ((uint32_t)pkt[19] << 16)
                  | ((uint32_t)pkt[20] << 8) | (uint32_t)pkt[21];
    return shalot_crc32(pkt + 2, PROV_KEY_LEN) == want;
}

#endif  // PROVISIONING_PROTOCOL_H
