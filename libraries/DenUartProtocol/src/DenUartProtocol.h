/*
 * SHALLOT — PAW<->DEN docked UART protocol (PRO-87)
 *
 * Header-only, transport-free shared module skeleton. Both sides (DEN
 * firmware PRO-88, PAW firmware PRO-84) include this file; the actual
 * dock UART TX/RX lives in those firmwares, not here.
 *
 * Frame: SYNC 0xAA | LEN u16 LE | TYPE u8 | PAYLOAD 0-64B | CRC32 u32 LE
 * CRC32 scope: LEN + TYPE + PAYLOAD (IEEE 802.3; CRC32("123456789") =
 * 0xCBF43926). Full spec: docs/11-dockat-uart-protokoll.md
 *
 * Fail-closed throughout: any error means "discard, store nothing".
 */

#ifndef DEN_UART_PROTOCOL_H
#define DEN_UART_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// =============================================================
// Wire constants
// =============================================================

#define DEN_SYNC              0xAA

#define DEN_TYPE_CHALLENGE    0x01
#define DEN_TYPE_RESPONSE     0x02
#define DEN_TYPE_HEARTBEAT    0x03
#define DEN_TYPE_ALARM        0x04
#define DEN_TYPE_ACK          0xFF

#define DEN_NONCE_LEN         16
#define DEN_HMAC_LEN          32
#define DEN_STATUS_LEN        1
#define DEN_ALARM_LEN         1

#define DEN_MAX_PAYLOAD       64
#define DEN_HEADER_LEN        4   // SYNC + LEN16 + TYPE
#define DEN_CRC_LEN           4
#define DEN_MAX_FRAME         (DEN_HEADER_LEN + DEN_MAX_PAYLOAD + DEN_CRC_LEN)

#define DEN_BYTE_TIMEOUT_MS       100   // stall mid-frame -> discard
#define DEN_RESPONSE_DEADLINE_MS  2000  // session rule (DEN side)
#define DEN_MAX_RESYNC_SKIPS      64    // stray bytes before SYNC

// =============================================================
// Status codes (internal, never on the wire)
// =============================================================

typedef enum {
  DEN_OK = 0,
  DEN_INCOMPLETE,     // need more bytes (not an error)
  DEN_ERR_CRC,        // CRC32 mismatch -> discard frame
  DEN_ERR_LENGTH,     // LEN > MAX or payload size != type size
  DEN_ERR_TYPE,       // unknown message type
  DEN_ERR_TIMEOUT,    // byte stall mid-frame -> discard partial
  DEN_ERR_RESYNC      // resync budget exhausted
} den_status_t;

// =============================================================
// Payload size table (exact sizes, 0 = unknown type -> reject)
// =============================================================

static inline size_t den_payload_len_for_type(uint8_t type) {
  switch (type) {
    case DEN_TYPE_CHALLENGE: return DEN_NONCE_LEN;
    case DEN_TYPE_RESPONSE:  return DEN_HMAC_LEN;
    case DEN_TYPE_HEARTBEAT: return 0;
    case DEN_TYPE_ALARM:     return DEN_ALARM_LEN;
    case DEN_TYPE_ACK:       return DEN_STATUS_LEN;
    default:                 return 0;  // unknown handled by caller check
  }
}

static inline uint8_t den_type_known(uint8_t type) {
  return (uint8_t)(type == DEN_TYPE_CHALLENGE || type == DEN_TYPE_RESPONSE ||
                   type == DEN_TYPE_HEARTBEAT || type == DEN_TYPE_ALARM ||
                   type == DEN_TYPE_ACK);
}

// =============================================================
// IEEE 802.3 CRC32 (no table: small, portable, bit-by-bit)
// =============================================================

static inline uint32_t den_crc32(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFFUL;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint8_t b = 0; b < 8; b++) {
      crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320UL : (crc >> 1);
    }
  }
  return crc ^ 0xFFFFFFFFUL;
}

// =============================================================
// Constant-time comparison (response HMAC on DEN side; early-exit
// comparisons must never be used on secrets here)
// =============================================================

static inline uint8_t den_ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  return (uint8_t)(diff == 0);
}

// =============================================================
// Frame codec (caller-owned buffers, no allocation)
// =============================================================

// Encode: returns total frame bytes, or 0 when the payload length does
// not match the type or outMax is too small.
static inline size_t den_encode(uint8_t type, const uint8_t *payload,
                                size_t payloadLen, uint8_t *out, size_t outMax) {
  if (!den_type_known(type)) return 0;
  if (payloadLen != den_payload_len_for_type(type)) return 0;
  size_t total = DEN_HEADER_LEN + payloadLen + DEN_CRC_LEN;
  if (total > outMax || total > DEN_MAX_FRAME) return 0;
  out[0] = DEN_SYNC;
  out[1] = (uint8_t)(payloadLen & 0xFF);
  out[2] = (uint8_t)((payloadLen >> 8) & 0xFF);
  out[3] = type;
  if (payloadLen) memcpy(out + 4, payload, payloadLen);
  uint32_t crc = den_crc32(out + 1, 2 + 1 + payloadLen);  // LEN+TYPE+PAYLOAD
  out[4 + payloadLen + 0] = (uint8_t)(crc & 0xFF);
  out[4 + payloadLen + 1] = (uint8_t)((crc >> 8) & 0xFF);
  out[4 + payloadLen + 2] = (uint8_t)((crc >> 16) & 0xFF);
  out[4 + payloadLen + 3] = (uint8_t)((crc >> 24) & 0xFF);
  return total;
}

// Decoded view into the caller's frame buffer (no copy).
typedef struct {
  uint8_t type;
  const uint8_t *payload;
  size_t payloadLen;
} den_frame_t;

// Decode one complete candidate frame. Fails closed on any violation.
static inline den_status_t den_decode(const uint8_t *data, size_t dataLen,
                                      den_frame_t *frame) {
  if (dataLen < DEN_HEADER_LEN + DEN_CRC_LEN) return DEN_INCOMPLETE;
  if (data[0] != DEN_SYNC) return DEN_ERR_TYPE;
  uint16_t len = (uint16_t)((uint16_t)data[1] | ((uint16_t)data[2] << 8));
  if (len > DEN_MAX_PAYLOAD) return DEN_ERR_LENGTH;
  size_t total = DEN_HEADER_LEN + len + DEN_CRC_LEN;
  if (dataLen < total) return DEN_INCOMPLETE;
  uint8_t type = data[3];
  if (!den_type_known(type)) return DEN_ERR_TYPE;
  if (len != den_payload_len_for_type(type)) return DEN_ERR_LENGTH;
  uint32_t want = (uint32_t)data[4 + len + 0] |
                  ((uint32_t)data[4 + len + 1] << 8) |
                  ((uint32_t)data[4 + len + 2] << 16) |
                  ((uint32_t)data[4 + len + 3] << 24);
  if (den_crc32(data + 1, (size_t)2 + 1 + len) != want) return DEN_ERR_CRC;
  frame->type = type;
  frame->payload = data + 4;
  frame->payloadLen = len;
  return DEN_OK;
}

// =============================================================
// Resync scanner: byte-stream -> frames with timeout policy.
// Feed bytes + caller millis(); never blocks, never allocates.
// =============================================================

typedef struct {
  uint8_t buf[DEN_MAX_FRAME];
  size_t count;        // bytes buffered
  size_t want;         // total frame bytes once LEN known (0 = unknown)
  uint32_t lastMs;     // last byte timestamp
  uint16_t skipped;    // stray bytes dropped while seeking SYNC
  uint8_t haveTime;    // lastMs valid
} den_scanner_t;

static inline void den_scanner_init(den_scanner_t *s) {
  memset(s, 0, sizeof(*s));
}

static inline void den_scanner_reset(den_scanner_t *s) {
  s->count = 0;
  s->want = 0;
  s->skipped = 0;
}

// Push one byte. Returns DEN_OK with *frame set on a complete valid
// frame, DEN_INCOMPLETE while gathering, or an error (state reset to
// seek the next SYNC).
// Lifetime: frame->payload views the scanner's internal buffer and stays
// valid until the next push call — copy it out before pushing further.
static inline den_status_t den_scanner_push(den_scanner_t *s, uint8_t byte,
                                            uint32_t nowMs, den_frame_t *frame) {
  if (s->haveTime && s->count > 0 && (uint32_t)(nowMs - s->lastMs) > DEN_BYTE_TIMEOUT_MS) {
    den_scanner_reset(s);  // stale partial frame: discard (fail-closed)
    s->haveTime = 0;
    return DEN_ERR_TIMEOUT;
  }
  s->lastMs = nowMs;
  s->haveTime = 1;

  if (s->count == 0) {
    if (byte != DEN_SYNC) {
      if (++s->skipped > DEN_MAX_RESYNC_SKIPS) {
        den_scanner_reset(s);
        return DEN_ERR_RESYNC;
      }
      return DEN_INCOMPLETE;  // stray byte dropped, keep seeking
    }
  }
  if (s->count >= DEN_MAX_FRAME) {  // cannot happen via want-gating; guard anyway
    den_scanner_reset(s);
    return DEN_ERR_LENGTH;
  }
  s->buf[s->count++] = byte;

  if (s->count == 3) {
    uint16_t len = (uint16_t)((uint16_t)s->buf[1] | ((uint16_t)s->buf[2] << 8));
    if (len > DEN_MAX_PAYLOAD) {
      // Oversize declared: drop the whole candidate and resume seeking.
      // (A SYNC inside the dropped bytes is lost with it; senders never
      // emit such frames, so overlap-salvage is not worth the complexity.)
      den_scanner_reset(s);
      s->lastMs = nowMs;
      return DEN_ERR_LENGTH;
    }
    s->want = DEN_HEADER_LEN + len + DEN_CRC_LEN;
  }
  if (s->want && s->count >= s->want) {
    den_frame_t f;
    den_status_t st = den_decode(s->buf, s->want, &f);
    // Reset counters only (buffer bytes persist for the frame view).
    s->count = 0;
    s->want = 0;
    s->skipped = 0;
    s->lastMs = nowMs;
    if (st == DEN_OK) {
      *frame = f;  // valid until the next push call (see above)
      return DEN_OK;
    }
    return st;
  }
  return DEN_INCOMPLETE;
}

#endif  // DEN_UART_PROTOCOL_H
