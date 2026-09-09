/*
 * SHALLOT — Shared LoRa Protocol Definitions (PAW + PLC)
 *
 * Single source of truth for the over-the-air challenge-response protocol
 * plus the message types, sizes, timeouts and device identities that PAW
 * (Adafruit Feather RP2350) and PLC (Raspberry Pi Pico 2) share.
 *
 * Scope:
 *   - LoRa P2P (868 MHz): CHALLENGE (0xB1) / RESPONSE (0xB2) / RESULT (0xB3)
 *   - Shared key-distribution (USB) and identity message types both sides
 *     already implement, so neither sketch keeps a private copy.
 *
 * Wire compatibility: all numeric values match the protocol both firmwares
 * shipped with. Only names are new (SHALLOT_ prefix).
 *
 * Header-only: no .cpp needed. Include with:
 *   #include <ShallotLoRaProtocol.h>
 * Build with the library on the search path, e.g.:
 *   arduino-cli compile --library libraries/ShallotLoRa ...
 */

#ifndef SHALLOT_LORA_PROTOCOL_H
#define SHALLOT_LORA_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// =============================================================
// Message types — key distribution (USB, UNO Q <-> PAW/PLC)
// =============================================================

#define SHALLOT_MSG_HANDSHAKE 0xA1
#define SHALLOT_MSG_READY     0xA2
#define SHALLOT_MSG_KEY_DATA  0xA3
#define SHALLOT_MSG_STORED    0xA4
#define SHALLOT_MSG_ERROR     0xA5
#define SHALLOT_MSG_COMMIT    0xA6
#define SHALLOT_MSG_CANCEL    0xA7

// =============================================================
// Message types — LoRa P2P challenge-response (PAW <-> PLC)
// =============================================================

#define SHALLOT_MSG_CHALLENGE 0xB1
#define SHALLOT_MSG_RESPONSE  0xB2
#define SHALLOT_MSG_RESULT    0xB3

// =============================================================
// Message types — device identity challenge-response (USB)
// =============================================================

#define SHALLOT_MSG_ID_CHALLENGE 0xB4
#define SHALLOT_MSG_ID_RESPONSE  0xB5

// =============================================================
// Targets and device identities
// =============================================================

#define SHALLOT_TARGET_PLC 0x01
#define SHALLOT_TARGET_PAW 0x02

// 4-byte device IDs, also used as deterministic identity seeds.
static const uint8_t SHALLOT_DEVICE_ID_PLC[4] = { 0x50, 0x4C, 0x43, 0x01 }; // "PLC\x01"
static const uint8_t SHALLOT_DEVICE_ID_PAW[4] = { 0x50, 0x41, 0x57, 0x01 }; // "PAW\x01"

// =============================================================
// Crypto and field sizes (bytes)
// =============================================================

#define SHALLOT_AES_KEY_SIZE   16
#define SHALLOT_KEY_HASH_SIZE   4
#define SHALLOT_CHALLENGE_SIZE 16  // LoRa nonce size
#define SHALLOT_HMAC_SIZE      32  // HMAC-SHA256 output
#define SHALLOT_SHA256_SIZE    32
#define SHALLOT_HMAC_BLOCK_SIZE 64
#define SHALLOT_EPOCH_SIZE      4
#define SHALLOT_P256_PRIVATE_KEY_SIZE 32
#define SHALLOT_P256_PUBLIC_KEY_SIZE  65  // Uncompressed: 0x04 + x[32] + y[32]
#define SHALLOT_P256_COMPRESSED_PUB_SIZE 33  // Compressed: 0x02/0x03 + x[32]
#define SHALLOT_P256_SIGNATURE_SIZE   64  // r[32] + s[32]

// =============================================================
// LoRa packet layouts (multi-byte integers big-endian)
//   CHALLENGE: type[1] + nonce[16] + epoch_be4[4]             = 21
//   RESPONSE:  type[1] + nonce[16] + epoch_be4[4] + hmac[32]  = 53
//   RESULT:    type[1] + result[1]                            = 2
// =============================================================

#define SHALLOT_LORA_CHALLENGE_LEN 21
#define SHALLOT_LORA_RESPONSE_LEN  53
#define SHALLOT_LORA_RESULT_LEN     2

// =============================================================
// Identity frame layouts (USB)
//   ID_CHALLENGE: type[1] + challenge[32] + op[1] + target[1] + epoch_be4[4] = 39
//   ID_RESPONSE:  type[1] + signature[64] + devHash[4]                       = 69
// =============================================================

#define SHALLOT_ID_CHALLENGE_FRAME_LEN 39
#define SHALLOT_ID_RESPONSE_FRAME_LEN  69

// =============================================================
// Key-distribution frame layouts (USB, UNO Q <-> PAW/PLC)
// Multi-byte integers big-endian. epoch = session ID for the
// provisioning round; seq = UNO Q retry counter within the round
// (receivers answer repeats idempotently, keyed on epoch + seq).
//   HANDSHAKE: type[1] + target[1] + epoch_be4[4] + seq[1]                  = 7
//   READY:     type[1] + deviceId[4] + epoch_be4[4]                         = 9
//   KEY_DATA:  type[1] + len[1] + key[16] + crc32[4] + epoch_be4[4] + seq[1] = 27
//   STORED:    type[1] + hash[4] + epoch_be4[4]                             = 9
//   COMMIT:    type[1] + target[1] + epoch_be4[4]                           = 6
// =============================================================

#define SHALLOT_KD_HANDSHAKE_LEN 7
#define SHALLOT_KD_READY_LEN 9
#define SHALLOT_KD_KEY_DATA_LEN 27
#define SHALLOT_KD_STORED_LEN 9
#define SHALLOT_KD_COMMIT_LEN 6

// Resync budget: max stray bytes dropped while scanning for a frame
// tag before the round fails. Bounds recovery after partial frames.
#define SHALLOT_KD_MAX_RESYNC_SKIPS 64

// =============================================================
// Timeouts (ms) and radio gate
// =============================================================

#define SHALLOT_KEY_DIST_TIMEOUT_MS            10000
#define SHALLOT_CHALLENGE_TIMEOUT_MS           30000  // PAW: wait for result
#define SHALLOT_CHALLENGE_INTERVAL_MS           5000  // PLC: pace between challenges
#define SHALLOT_CHALLENGE_RESPONSE_TIMEOUT_MS  30000  // PLC: re-issue stale challenge

// Packets below this RSSI are discarded fail-closed (both sides).
#define SHALLOT_RSSI_MIN_DBM (-70.0f)

// =============================================================
// Result codes (MSG_RESULT payload byte)
// =============================================================

#define SHALLOT_RESULT_SUCCESS 0x01
#define SHALLOT_RESULT_FAILURE 0x00

// =============================================================
// Validation status codes (internal, never on the wire)
// =============================================================

typedef enum {
  SHALLOT_PROTO_OK = 0,
  SHALLOT_PROTO_ERR_BAD_TYPE,      // unexpected message type tag
  SHALLOT_PROTO_ERR_SHORT_PACKET,  // packet shorter than the layout requires
  SHALLOT_PROTO_ERR_EPOCH_MISMATCH, // epoch does not match the active epoch
  SHALLOT_PROTO_ERR_NONCE_MISMATCH, // response does not echo the live challenge
  SHALLOT_PROTO_ERR_WEAK_RSSI      // signal below SHALLOT_RSSI_MIN_DBM
} shallot_proto_status_t;

// =============================================================
// Packet-length validation (fail-closed: undersized rejected)
// =============================================================

static inline shallot_proto_status_t shallot_check_challenge_packet(uint8_t msgType, size_t len) {
  if (msgType != SHALLOT_MSG_CHALLENGE) return SHALLOT_PROTO_ERR_BAD_TYPE;
  if (len < SHALLOT_LORA_CHALLENGE_LEN) return SHALLOT_PROTO_ERR_SHORT_PACKET;
  return SHALLOT_PROTO_OK;
}

static inline shallot_proto_status_t shallot_check_response_packet(uint8_t msgType, size_t len) {
  if (msgType != SHALLOT_MSG_RESPONSE) return SHALLOT_PROTO_ERR_BAD_TYPE;
  if (len < SHALLOT_LORA_RESPONSE_LEN) return SHALLOT_PROTO_ERR_SHORT_PACKET;
  return SHALLOT_PROTO_OK;
}

static inline shallot_proto_status_t shallot_check_result_packet(uint8_t msgType, size_t len) {
  if (msgType != SHALLOT_MSG_RESULT) return SHALLOT_PROTO_ERR_BAD_TYPE;
  if (len < SHALLOT_LORA_RESULT_LEN) return SHALLOT_PROTO_ERR_SHORT_PACKET;
  return SHALLOT_PROTO_OK;
}

// =============================================================
// Challenge/response correlation
//
// The responder must echo the exact live nonce and the active epoch.
// The nonce compare is constant-time so a wrong guess leaks nothing
// about the expected value through timing.
// =============================================================

static inline shallot_proto_status_t shallot_check_correlation(
    const uint8_t* sentNonce, const uint8_t* echoedNonce,
    uint32_t sentEpoch, uint32_t echoedEpoch) {
  if (sentEpoch != echoedEpoch) return SHALLOT_PROTO_ERR_EPOCH_MISMATCH;
  volatile uint8_t diff = 0;
  for (uint8_t i = 0; i < SHALLOT_CHALLENGE_SIZE; i++) {
    diff |= (uint8_t)(sentNonce[i] ^ echoedNonce[i]);
  }
  if (diff != 0) return SHALLOT_PROTO_ERR_NONCE_MISMATCH;
  return SHALLOT_PROTO_OK;
}

// Epoch binding for an incoming challenge (PAW side).
static inline shallot_proto_status_t shallot_check_epoch(uint32_t echoedEpoch, uint32_t activeEpoch) {
  return (echoedEpoch == activeEpoch) ? SHALLOT_PROTO_OK : SHALLOT_PROTO_ERR_EPOCH_MISMATCH;
}

// Radio gate for incoming packets (both sides). Returns 1 when acceptable.
static inline uint8_t shallot_rssi_ok(float rssiDbm) {
  return (rssiDbm >= SHALLOT_RSSI_MIN_DBM) ? 1 : 0;
}

// =============================================================
// Big-endian frame codec (key-distribution frames, all sides)
// =============================================================

static inline uint32_t shallot_get_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void shallot_put_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

// =============================================================
// Key-material validation (PAW + PLC, before staging/committing)
//
// Rejects uninitialized (all-zero) and degenerate (all-same-byte)
// keys in a single pass, mirroring the UNO Q TRNG health check.
// Returns 1 when the key may be stored, 0 when it must be refused.
// =============================================================

static inline uint8_t shallot_key_looks_valid(const uint8_t* key) {
  uint8_t first = key[0];
  uint8_t allSame = 1;
  uint8_t anyNonZero = 0;
  for (uint8_t i = 0; i < SHALLOT_AES_KEY_SIZE; i++) {
    if (key[i] != 0x00) anyNonZero = 1;
    if (key[i] != first) allSame = 0;
    if (anyNonZero && !allSame) break;  // decided: accept
  }
  return (uint8_t)(anyNonZero && !allSame);
}

#endif  // SHALLOT_LORA_PROTOCOL_H
