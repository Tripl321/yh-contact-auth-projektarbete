/*
 * SHALLOT — DEN docked UART challenge-response (PRO-88)
 * Firmware entry point: Pico 2 (RP2350). Session master for the
 * PAW<->DEN docked link defined in docs/11-dockat-uart-protokoll.md.
 *
 * Framing, CRC and parser come from the shared DenUartProtocol module
 * (no duplication here). This file owns: session state machine,
 * RP2350-TRNG nonce, local HMAC-SHA256, constant-time compare and ACK.
 *
 * Session: CHALLENGE(16B nonce) -> wait <=2000ms for RESPONSE(32B HMAC)
 * -> verify -> ACK(0x01/0x00) + AUTHENTICATED/FAILED log. Every failure
 * mode fails closed (deny, no retry inside the session).
 *
 * Transport: Serial1 @115200, TX=GPIO0, RX=GPIO1 (RP2350 UART0 defaults).
 * USB Serial is logs only. Non-blocking: loop polls Serial1.available
 * against millis() deadlines; only short bounded ops (SHA/HMAC ~100us,
 * 24-byte UART write ~2ms) ever run to completion inline.
 *
 * Out of scope: LoRa, e-paper, pogo detection, PAW firmware.
 */

#include <Arduino.h>
#include "pico/rand.h"
#include <DenUartProtocol.h>

// =============================================================
// DEVELOPMENT-ONLY shared key. This is a stub for bring-up and
// physical-loop testing. NEVER ship production with this key:
// replace with the provisioned per-device key (PRO-45 flow) and
// remove this warning.
// =============================================================
#warning "PRO-88 development shared key - replace before production"
static const uint8_t DEN_DEV_KEY[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

#define DEN_UART_BAUD      115200
#define DEN_SESSION_GAP_MS 1000  // pacing between sessions

// =============================================================
// Minimal SHA-256 (public-domain style, stack-only, no heap)
// =============================================================

static const uint32_t den_shaK[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define DEN_ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void den_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint64_t bitLen = (uint64_t)len * 8;
  size_t pos = 0;
  uint8_t block[64];
  // Full 64-byte blocks straight from input.
  while (len - pos >= 64) {
    const uint8_t *b = data + pos;
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) |
             ((uint32_t)b[i*4+2] << 8) | (uint32_t)b[i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
      uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
      uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
      uint32_t t2 = S0 + mj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    pos += 64;
  }
  // Final block(s) with padding.
  size_t rem = len - pos;
  memcpy(block, data + pos, rem);
  block[rem++] = 0x80;
  if (rem > 56) {
    memset(block + rem, 0, 64 - rem);
    // compress padding-only block (duplicate of above with w from block)
    {
      uint32_t w[64];
      for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
      for (int i = 16; i < 64; i++) {
        uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
      }
      uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
      for (int i = 0; i < 64; i++) {
        uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
        uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
        uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
      }
      h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    rem = 0;
  }
  memset(block + rem, 0, 56 - rem);
  for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bitLen >> (56 - 8 * i));
  {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
             ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = DEN_ROR(w[i-15],7) ^ DEN_ROR(w[i-15],18) ^ (w[i-15] >> 3);
      uint32_t s1 = DEN_ROR(w[i-2],17) ^ DEN_ROR(w[i-2],19) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = DEN_ROR(e,6) ^ DEN_ROR(e,11) ^ DEN_ROR(e,25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + den_shaK[i] + w[i];
      uint32_t S0 = DEN_ROR(a,2) ^ DEN_ROR(a,13) ^ DEN_ROR(a,22);
      uint32_t mj = (a & b2) ^ (a & c) ^ (b2 & c);
      uint32_t t2 = S0 + mj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b2; b2=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }
  for (int i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(h[i] >> 24);
    out[i*4+1] = (uint8_t)(h[i] >> 16);
    out[i*4+2] = (uint8_t)(h[i] >> 8);
    out[i*4+3] = (uint8_t)h[i];
  }
  memset(block, 0, sizeof(block));
}

// HMAC-SHA256(key, msg). Stack-only temps, wiped before return.
static void den_hmac_sha256(const uint8_t *key, size_t keyLen,
                            const uint8_t *msg, size_t msgLen,
                            uint8_t mac[32]) {
  if (msgLen > DEN_NONCE_LEN || keyLen > 64) {
    memset(mac, 0, 32);  // fail closed on oversize input
    return;
  }
  uint8_t ipad[64], opad[64], inner[32];
  memset(ipad, 0x36, sizeof(ipad));
  memset(opad, 0x5c, sizeof(opad));
  for (size_t i = 0; i < keyLen && i < sizeof(ipad); i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }
  // inner = SHA256(ipad || msg) via two compress calls through den_sha256
  // over a single Prairie buffer (msg here is always 16 B).
  uint8_t innerMsg[64 + DEN_NONCE_LEN];
  memcpy(innerMsg, ipad, 64);
  memcpy(innerMsg + 64, msg, msgLen);
  den_sha256(innerMsg, 64 + msgLen, inner);
  uint8_t outerMsg[64 + 32];
  memcpy(outerMsg, opad, 64);
  memcpy(outerMsg + 64, inner, 32);
  den_sha256(outerMsg, sizeof(outerMsg), mac);
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));
  memset(inner, 0, sizeof(inner));
  memset(innerMsg, 0, sizeof(innerMsg));
  memset(outerMsg, 0, sizeof(outerMsg));
}

// =============================================================
// Session state machine (non-blocking, fail-closed)
//
// States: DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED
//
// DEN starts in DENIED after boot, reset, disconnect, malformed
// input, or session expiry. Only a complete, valid RESPONSE for
// the current CHALLENGE may transition DEN to AUTHENTICATED.
// ACK is informational; the access decision is made before ACK
// and never depends on it. PAW display/UI and other peripherals
// do not alter the DEN decision or deadline.
// =============================================================

enum DenSession : uint8_t {
  DEN_ST_DENIED,          // initial / fail-closed; after gap, sends CHALLENGE
  DEN_ST_CHALLENGE_SENT,  // challenge sent, awaiting RESPONSE (deadline)
  DEN_ST_AUTHENTICATED    // HMAC verified; brief confirmation then DENIED
};

static DenSession denState = DEN_ST_DENIED;
static uint32_t denStateAt = 0;      // state entry timestamp (millis)
static uint32_t denDeadline = 0;     // response deadline (millis)
static uint8_t denNonce[DEN_NONCE_LEN];
static den_scanner_t denScanner;
static uint8_t denTx[DEN_MAX_FRAME];

// Non-secret reason codes for USB serial observation.
// These are audit/log codes only — never on the wire, never
// secret material.
enum DenReason : uint8_t {
  DEN_REASON_OK = 0,              // authenticated
  DEN_REASON_TIMEOUT,             // response deadline exceeded
  DEN_REASON_UNEXPECTED_TYPE,     // frame type != RESPONSE
  DEN_REASON_INVALID_SIZE,        // payload length mismatch
  DEN_REASON_PARSE_ERROR,         // CRC, length, type, or resync failure
  DEN_REASON_HMAC_MISMATCH,       // constant-time compare failed
  DEN_REASON_DISCONNECT,          // PAW UART disconnect detected
  DEN_REASON_STALE_RESPONSE,      // response for a prior nonce
};

static void den_fail(DenReason reason) {
  const char *label = "UNKNOWN";
  switch (reason) {
    case DEN_REASON_TIMEOUT:       label = "timeout"; break;
    case DEN_REASON_UNEXPECTED_TYPE: label = "unexpected type"; break;
    case DEN_REASON_INVALID_SIZE:  label = "invalid size"; break;
    case DEN_REASON_PARSE_ERROR:   label = "parse error"; break;
    case DEN_REASON_HMAC_MISMATCH: label = "hmac mismatch"; break;
    case DEN_REASON_DISCONNECT:    label = "disconnect"; break;
    case DEN_REASON_STALE_RESPONSE: label = "stale response"; break;
    default: break;
  }
  Serial.print("[DEN] FAILED: "); Serial.print(label);
  Serial.print(" (code "); Serial.print(reason); Serial.println(")");
  uint8_t ackBody[1] = {0x00};
  uint8_t ack[DEN_MAX_FRAME];
  size_t n = den_encode(DEN_TYPE_ACK, ackBody, 1, ack, sizeof(ack));
  if (n) { Serial1.write(ack, n); Serial1.flush(); }
  digitalWrite(LED_BUILTIN, LOW);
  memset(denNonce, 0, sizeof(denNonce));
  denState = DEN_ST_DENIED;
  denStateAt = millis();
}

static void den_send_challenge(uint32_t now) {
  // 16-byte nonce from the RP2350 hardware RNG (ROSC TRNG via pico-sdk).
  rng_128_t r;
  get_rand_128(&r);
  memcpy(denNonce, &r, DEN_NONCE_LEN);
  memset(&r, 0, sizeof(r));

  size_t n = den_encode(DEN_TYPE_CHALLENGE, denNonce, DEN_NONCE_LEN,
                        denTx, sizeof(denTx));
  if (!n) {  // cannot happen (fixed sizes); fail closed anyway
    den_fail(DEN_REASON_PARSE_ERROR);
    return;
  }
  Serial1.write(denTx, n);
  Serial1.flush();
  memset(denTx, 0, sizeof(denTx));
  Serial.println("[DEN] CHALLENGE sent, waiting <=2000ms for RESPONSE");
  den_scanner_init(&denScanner);
  denDeadline = now + DEN_RESPONSE_DEADLINE_MS;
  denState = DEN_ST_CHALLENGE_SENT;
  denStateAt = now;
}

static void den_on_response(const den_frame_t *f, uint32_t now) {
  if (f->type != DEN_TYPE_RESPONSE) {
    den_fail(DEN_REASON_UNEXPECTED_TYPE);
    return;
  }
  if (f->payloadLen != DEN_HMAC_LEN) {
    den_fail(DEN_REASON_INVALID_SIZE);
    return;
  }
  // Stale-response check: nonce must match the current session.
  // If the scanner was reset (e.g., byte timeout or resync),
  // the nonce was already wiped by den_fail(). A response
  // arriving after the nonce was wiped is stale.
  if (denNonce[0] == 0 && denNonce[1] == 0 && denNonce[2] == 0
      && denNonce[3] == 0 && denNonce[4] == 0 && denNonce[5] == 0
      && denNonce[6] == 0 && denNonce[7] == 0 && denNonce[8] == 0
      && denNonce[9] == 0 && denNonce[10] == 0 && denNonce[11] == 0
      && denNonce[12] == 0 && denNonce[13] == 0 && denNonce[14] == 0
      && denNonce[15] == 0) {
    den_fail(DEN_REASON_STALE_RESPONSE);
    return;
  }
  uint8_t expect[DEN_HMAC_LEN];
  den_hmac_sha256(DEN_DEV_KEY, sizeof(DEN_DEV_KEY),
                  denNonce, DEN_NONCE_LEN, expect);
  uint8_t ok = den_ct_compare(expect, f->payload, DEN_HMAC_LEN);
  memset(expect, 0, sizeof(expect));
  memset(denNonce, 0, sizeof(denNonce));
  if (!ok) {
    den_fail(DEN_REASON_HMAC_MISMATCH);
    return;
  }
  Serial.println("[DEN] AUTHENTICATED (code 0)");
  uint8_t ackBody[1] = {0x01};
  uint8_t ack[DEN_MAX_FRAME];
  size_t n = den_encode(DEN_TYPE_ACK, ackBody, 1, ack, sizeof(ack));
  if (n) { Serial1.write(ack, n); Serial1.flush(); }
  digitalWrite(LED_BUILTIN, HIGH);
  denState = DEN_ST_AUTHENTICATED;
  denStateAt = now;
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(DEN_UART_BAUD);  // TX=GPIO0, RX=GPIO1 (UART0 defaults)
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
  den_scanner_init(&denScanner);
  denState = DEN_ST_DENIED;
  denStateAt = millis();
  Serial.println("[DEN] docked UART auth ready (PRO-53)");
}

void loop() {
  uint32_t now = millis();

  // DEN_ST_DENIED: waiting for session gap before next challenge.
  if (denState == DEN_ST_DENIED) {
    if ((uint32_t)(now - denStateAt) >= DEN_SESSION_GAP_MS) {
      den_send_challenge(now);
    }
    return;
  }

  // DEN_ST_AUTHENTICATED: brief confirmation, then return to DENIED.
  if (denState == DEN_ST_AUTHENTICATED) {
    if ((uint32_t)(now - denStateAt) >= DEN_SESSION_GAP_MS) {
      Serial.println("[DEN] session complete, returning to DENIED");
      denState = DEN_ST_DENIED;
      denStateAt = now;
    }
    return;
  }

  // DEN_ST_CHALLENGE_SENT: poll UART without blocking.
  // Check deadline first (timeout → DENIED).
  if ((int32_t)(now - denDeadline) >= 0) {
    den_fail(DEN_REASON_TIMEOUT);
    return;
  }
  // Detect PAW disconnect: no bytes arriving for an extended
  // period while in CHALLENGE_SENT. The scanner byte-timeout
  // handles mid-frame stalls; here we detect the case where
  // no bytes arrive at all.
  if (!Serial1.available() && (uint32_t)(now - denStateAt) > 3000) {
    den_fail(DEN_REASON_DISCONNECT);
    return;
  }
  while (Serial1.available()) {
    den_frame_t f;
    den_status_t st = den_scanner_push(&denScanner,
        (uint8_t)Serial1.read(), now, &f);
    if (st == DEN_OK) {
      uint8_t type = f.type;
      uint8_t payload[DEN_MAX_PAYLOAD];
      size_t payloadLen = f.payloadLen;
      memcpy(payload, f.payload, payloadLen);
      den_frame_t fc = {type, payload, payloadLen};
      den_on_response(&fc, now);
      return;
    }
    if (st != DEN_INCOMPLETE) {
      den_fail(DEN_REASON_PARSE_ERROR);
      return;
    }
  }
}
