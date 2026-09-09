/*
 * SHALLOT — Shared UART frame protocol for the dock-auth pivot slice.
 *
 * Frame layout (all multi-byte integers little-endian):
 *   SYNC      1 byte   0xAA
 *   LENGTH    2 bytes  payload byte count (uint16 LE)
 *   TYPE      1 byte   CHALLENGE / RESPONSE / HEARTBEAT / ALARM / ACK
 *   PAYLOAD   N bytes
 *   CRC32     4 bytes  CRC over LENGTH + TYPE + PAYLOAD (uint32 LE)
 *
 * Parser is non-blocking and bounded: poll() consumes at most one byte from
 * the serial RX buffer per call, validates LENGTH against a hard cap, rejects
 * bad CRC, and re-syncs by scanning for the next SYNC after any bad frame.
 */

#ifndef SHALLOT_UART_H
#define SHALLOT_UART_H

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

#define SHALLOT_UART_SYNC        0xAA
#define SHALLOT_UART_MAX_PAYLOAD 256
#define SHALLOT_UART_CRC_SIZE    4
#define SHALLOT_UART_OVERHEAD    8   /* SYNC + LENGTH(2) + TYPE + CRC32(4) */

#define SHALLOT_UART_CHALLENGE 0x01
#define SHALLOT_UART_RESPONSE  0x02
#define SHALLOT_UART_HEARTBEAT 0x03
#define SHALLOT_UART_ALARM     0x04
#define SHALLOT_UART_ACK       0xFF

typedef enum {
  SHALLOT_UART_OK = 0,
  SHALLOT_UART_ERR_NO_FRAME,
  SHALLOT_UART_ERR_BAD_CRC,
  SHALLOT_UART_ERR_BAD_LENGTH,
  SHALLOT_UART_ERR_TRUNCATED,
  SHALLOT_UART_ERR_NOISE
} shallot_uart_status_t;

class ShallotUart {
public:
  ShallotUart(HardwareSerial& serial);

  /* Non-blocking: returns true if a complete valid frame was received.
   * On success, *type and *payloadLen are filled and payload contains the
   * frame payload bytes. Returns false if no complete frame is available. */
  bool poll(uint8_t* type, uint8_t* payload, size_t* payloadLen, size_t maxPayload);

  /* Send a framed message. Returns true on success. */
  bool send(uint8_t type, const uint8_t* payload, size_t payloadLen);

  /* Re-sync: discard any partial frame state and rescan for SYNC. */
  void resync();

  /* Raw CRC32 helper (standard CRC-32/ISO-HDLC, init 0xFFFFFFFF, xorout
   * 0xFFFFFFFF). Exposed for protocol test vectors. */
  static uint32_t crc32(const uint8_t* data, size_t len);

private:
  HardwareSerial& _serial;
  uint8_t _rxBuf[SHALLOT_UART_MAX_PAYLOAD];
  size_t _rxLen;
  uint8_t _state;
  uint16_t _expectedLen;
  uint32_t _crc;
  uint8_t _type;
  uint8_t _crcBytes[SHALLOT_UART_CRC_SIZE];
  uint8_t _crcIdx;

  void resetParser();
  void feedCrc(uint8_t b);
};

#endif  /* SHALLOT_UART_H */
