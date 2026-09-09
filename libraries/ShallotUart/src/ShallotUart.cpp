/*
 * SHALLOT — Shared UART frame protocol implementation.
 */

#include "ShallotUart.h"
#include <string.h>

#define STATE_WAIT_SYNC      0
#define STATE_READ_LEN_LO    1
#define STATE_READ_LEN_HI    2
#define STATE_READ_TYPE      3
#define STATE_READ_PAYLOAD   4
#define STATE_READ_CRC       5

ShallotUart::ShallotUart(HardwareSerial& serial)
    : _serial(serial), _rxLen(0), _state(STATE_WAIT_SYNC),
      _expectedLen(0), _crc(0), _type(0), _crcIdx(0) {
  memset(_rxBuf, 0, sizeof(_rxBuf));
  memset(_crcBytes, 0, sizeof(_crcBytes));
}

void ShallotUart::resetParser() {
  _rxLen = 0;
  _state = STATE_WAIT_SYNC;
  _expectedLen = 0;
  _crc = 0;
  _type = 0;
  _crcIdx = 0;
  memset(_rxBuf, 0, sizeof(_rxBuf));
  memset(_crcBytes, 0, sizeof(_crcBytes));
}

void ShallotUart::feedCrc(uint8_t b) {
  _crc ^= b;
  for (int i = 0; i < 8; i++) {
    if (_crc & 1) {
      _crc = (_crc >> 1) ^ 0xEDB88320UL;
    } else {
      _crc >>= 1;
    }
  }
}

uint32_t ShallotUart::crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFFUL;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320UL;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc ^ 0xFFFFFFFFUL;
}

void ShallotUart::resync() {
  resetParser();
}

bool ShallotUart::poll(uint8_t* type, uint8_t* payload,
                       size_t* payloadLen, size_t maxPayload) {
  while (_serial.available() > 0) {
    uint8_t b = (uint8_t)_serial.read();

    switch (_state) {
      case STATE_WAIT_SYNC:
        if (b == SHALLOT_UART_SYNC) {
          _state = STATE_READ_LEN_LO;
        }
        break;

      case STATE_READ_LEN_LO:
        _expectedLen = b;
        _state = STATE_READ_LEN_HI;
        break;

      case STATE_READ_LEN_HI:
        _expectedLen |= ((uint16_t)b << 8);
        if (_expectedLen > SHALLOT_UART_MAX_PAYLOAD ||
            _expectedLen > maxPayload) {
          /* Oversized or caller-rejected frame: drop and re-sync. */
          resync();
          break;
        }
        _rxLen = 0;
        _crc = 0xFFFFFFFFUL;
        feedCrc((uint8_t)(_expectedLen & 0xFF));
        feedCrc((uint8_t)(_expectedLen >> 8));
        _state = STATE_READ_TYPE;
        break;

      case STATE_READ_TYPE:
        _type = b;
        feedCrc(b);
        _state = (_expectedLen == 0) ? STATE_READ_CRC : STATE_READ_PAYLOAD;
        break;

      case STATE_READ_PAYLOAD:
        _rxBuf[_rxLen++] = b;
        feedCrc(b);
        if (_rxLen >= _expectedLen) {
          _state = STATE_READ_CRC;
        }
        break;

      case STATE_READ_CRC: {
        _crcBytes[_crcIdx++] = b;
        if (_crcIdx >= SHALLOT_UART_CRC_SIZE) {
          uint32_t received = ((uint32_t)_crcBytes[0]) |
                              ((uint32_t)_crcBytes[1] << 8) |
                              ((uint32_t)_crcBytes[2] << 16) |
                              ((uint32_t)_crcBytes[3] << 24);
          uint32_t expected = _crc ^ 0xFFFFFFFFUL;
          _crcIdx = 0;
          if (received == expected) {
            /* Valid frame: deliver payload to caller. */
            *type = _type;
            *payloadLen = _rxLen;
            if (_rxLen > 0) {
              memcpy(payload, _rxBuf, _rxLen);
            }
            resetParser();
            return true;
          }
          /* Bad CRC: drop frame and re-sync. */
          resync();
        }
        break;
      }

      default:
        resync();
        break;
    }
  }
  return false;
}

bool ShallotUart::send(uint8_t type, const uint8_t* payload, size_t payloadLen) {
  if (payloadLen > SHALLOT_UART_MAX_PAYLOAD) {
    return false;
  }

  _serial.write(SHALLOT_UART_SYNC);

  uint16_t len = (uint16_t)payloadLen;
  _serial.write((uint8_t)(len & 0xFF));
  _serial.write((uint8_t)(len >> 8));
  _serial.write(type);

  uint32_t crc = 0xFFFFFFFFUL;
  auto feed = [&](uint8_t x) {
    crc ^= x;
    for (int i = 0; i < 8; i++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320UL;
      } else {
        crc >>= 1;
      }
    }
  };

  feed((uint8_t)(len & 0xFF));
  feed((uint8_t)(len >> 8));
  feed(type);
  for (size_t i = 0; i < payloadLen; i++) {
    _serial.write(payload[i]);
    feed(payload[i]);
  }

  uint32_t out = crc ^ 0xFFFFFFFFUL;
  _serial.write((uint8_t)(out & 0xFF));
  _serial.write((uint8_t)((out >> 8) & 0xFF));
  _serial.write((uint8_t)((out >> 16) & 0xFF));
  _serial.write((uint8_t)((out >> 24) & 0xFF));

  _serial.flush();
  return true;
}
