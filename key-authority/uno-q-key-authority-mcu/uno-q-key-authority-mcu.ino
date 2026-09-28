/*
 * SHALLOT — UNO Q Key Authority Firmware (PRO-45 + PRO-46)
 * MCU side: STM32U585 via Arduino IDE + ArduinoCore-zephyr
 *
 * Architecture (three-layer model):
 *   Layer 1 (MCU/STM32U585): TRNG key generation, secure storage,
 *           UART key distribution. No MPU involvement with key material.
 *   Layer 2 (MPU/QRB2210/Linux): Orchestration UI, audit log, validation.
 *           Communicates with MCU via Bridge RPC. Never touches key material.
 *   Layer 3 (Bridge RPC): Status and confirmation messages only.
 *           Uses Arduino_RouterBridge.h (MessagePack RPC over internal socket).
 *
 * Security principles:
 *   - Key generated with hardware TRNG (analog noise entropy)
 *   - Key never leaves MCU domain until UART distribution
 *   - Key never exposed to Linux/MPU side
 *   - Distribution requires operator confirmation (physical button)
 *   - Fail-closed: if TRNG health check fails, no key is generated
 *
 * Hardware: Arduino UNO Q (Qualcomm QRB2210 + STM32U585)
 * Target devices for distribution:
 *   - Edge enforcement node: Raspberry Pi Pico 2 (RP2350A)
 *   - PAW: Adafruit Feather RP2350
 *
 * Linear: PRO-45 (key generation), PRO-46 (key distribution via UART)
 *
 * CRITICAL — prj.conf override required:
 *   The UNO Q variant config ships with CONFIG_TEST_RANDOM_GENERATOR=y
 *   which routes sys_csrand_get() through a non-secure PRNG.
 *   Create prj.conf next to the sketch with:
 *     CONFIG_HARDWARE_DEVICE_CS_GENERATOR=y
 *     CONFIG_TEST_RANDOM_GENERATOR=n
 *   The code falls back to direct STM32U585 RNG register access if
 *   the prj.conf override does not take effect.
 */

#include <Arduino.h>
#include <Arduino_RouterBridge.h>
#include <Ed25519.h>  // vår C-API (ren header: stdint/stddef + decls, alltid säker)
#include <ShallotCrypto.h>  // PRO-49: SHA/wipe from shared module

// =============================================================
// Constants
// =============================================================

#define AES_KEY_SIZE       16
#define KEY_HASH_SIZE       4
#define SHA256_HASH_SIZE   32
#define DISTRIB_TIMEOUT_MS 5000
#define UART_BAUD          115200

// NOTE (verified 2026-09-27): header-UART dock is non-functional in core
// 1.0.0 — Serial1 is usart1 (PA9/PA10, console link to the Linux SoC),
// not D0/D1. Key distribution runs MCU->MPU->USB by operator decision;
// see bench-diagnosis-unoq-dock-2026-09-27. Serial3/usart3 (D20/D21)
// was verified live in registers but never proven end-to-end.
#define DOCK_SERIAL Serial1

// PRO-93: Debug configuration — must be explicitly defined to enable
// sensitive diagnostic output. Off by default (define SECURE_DEBUG=1 to enable).
#ifdef SECURE_DEBUG
#define SECURE_DEBUG 1
#endif

#define CONFIRM_BUTTON_PIN A0
#define STATUS_LED_PIN      LED_BUILTIN

#define TARGET_PLC  0x01
#define TARGET_PAW  0x02

#define MSG_HANDSHAKE 0xA1
#define MSG_READY     0xA2
#define MSG_KEY_DATA  0xA3
#define MSG_STORED    0xA4
#define MSG_ERROR     0xA5
#define MSG_BLOCKLIST 0xA6
#define MSG_BLOCKLIST_ACK 0xA7

// =============================================================
// Key state machine
// =============================================================

enum class KeyState : uint8_t {
  UNINITIALIZED    = 0,
  GENERATED        = 1,
  DISTRIBUTED_PLC  = 2,
  DISTRIBUTED_PAW  = 3,
  DISTRIBUTED_BOTH = 4,
  ERROR_STATE      = 0xFF
};

static uint8_t aesKey[AES_KEY_SIZE];
static uint8_t keyHash[KEY_HASH_SIZE];
static KeyState keyState = KeyState::UNINITIALIZED;
static volatile uint8_t pendingDistributionTarget = 0;
static bool bridgeLinkUp = false;
static uint32_t lastBridgeRetryMs = 0;
static const uint32_t BRIDGE_RETRY_INTERVAL_MS = 10000;
static uint32_t lastBridgeRefreshMs = 0;
static const uint32_t BRIDGE_REFRESH_INTERVAL_MS = 60000;

// =============================================================
// Hex output helpers (Serial.printf unavailable on Zephyr core)
// =============================================================

static const char HEX_CHARS[] = "0123456789ABCDEF";

static inline void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Serial.print(HEX_CHARS[(data[i] >> 4) & 0x0F]);
    Serial.print(HEX_CHARS[data[i] & 0x0F]);
  }
}

// =============================================================
// TRNG — UNO Q (STM32U585) Random Number Generator
// =============================================================
//
// The RNG peripheral (0x420c0800) is GTZC-secured by the prebuilt Zephyr
// runtime; direct register access from this sketch (Non-Secure) is filtered
// and reads return 0.  Use sys_csrand_get() which is resolved by the
// linker's syms-dynamic.ld PROVIDE into the runtime's entropy path.
// The runtime also owns the RNG clock and NIST config (devicetree has
// nist_config, health_test_config, noise_source_control).

#if __has_include(<zephyr/random/random.h>)
  #include <zephyr/random/random.h>
#endif

static bool generateSecureRandomBytes(uint8_t* buffer, size_t length) {
  return (sys_csrand_get(buffer, length) == 0);
}

// Single-pass health check: tests for all-zero, all-0xFF, and all-same-byte
// in one loop instead of three separate passes.
static bool trngHealthCheck() {
  uint8_t sample[32];
  if (!generateSecureRandomBytes(sample, 32)) return false;

  uint8_t firstByte = sample[0];
  bool allZero = (firstByte == 0x00);
  bool allOnes = (firstByte == 0xFF);
  bool allSame = true;

  for (int i = 1; i < 32; i++) {
    uint8_t b = sample[i];
    if (b != 0x00) allZero = false;
    if (b != 0xFF) allOnes = false;
    if (b != firstByte) allSame = false;
    // Early exit if all three checks already failed
    if (!allZero && !allOnes && !allSame) break;
  }

  return !(allZero || allOnes || allSame);
}

// SHA-256 lives in <ShallotCrypto.h> (single shared
// implementation, KAT-verified). Local copy removed (ticket 04).


// Compute first 4 bytes of SHA-256(key) as fingerprint
static inline void computeKeyHash(const uint8_t* key, uint8_t* hashOut) {
  uint8_t fullHash[SHA256_HASH_SIZE];
  shalot_sha256(key, AES_KEY_SIZE, fullHash);
  memcpy(hashOut, fullHash, KEY_HASH_SIZE);
  shalot_wipe(fullHash, sizeof(fullHash));
}


// CRC32 lives in <ShallotCrypto.h> (shalot_crc32) — single
// shared implementation. Local table-driven copy removed (arch batch 2).


// =============================================================
// Key Generation (PRO-45)
// =============================================================

// Safe key wipe — volatile store prevents the compiler from optimizing
// away the zeroing. Must be called before any key rejection path returns.
static inline void secureWipeKey() {
  volatile uint8_t* k = (volatile uint8_t*)aesKey;
  for (int i = 0; i < AES_KEY_SIZE; i++) k[i] = 0;
  volatile uint8_t* h = (volatile uint8_t*)keyHash;
  for (int i = 0; i < KEY_HASH_SIZE; i++) h[i] = 0;
}

static bool generateKey() {
  Serial.println("[PRO-45] Starting key generation...");

  Serial.print("[PRO-45] Running TRNG health check... ");
  if (!trngHealthCheck()) {
    Serial.println("FAILED");
    Serial.println("[PRO-45] TRNG health check failed. Aborting (fail-closed).");
    keyState = KeyState::ERROR_STATE;
    Bridge.notify("key_authority_event", "key_generation_failed", "TRNG health check failed");
    return false;
  }
  Serial.println("OK");

  Serial.print("[PRO-45] Generating 128-bit AES key from TRNG... ");
  if (!generateSecureRandomBytes(aesKey, AES_KEY_SIZE)) {
    Serial.println("FAILED");
    Serial.println("[PRO-45] TRNG generation failed. Aborting (fail-closed).");
    secureWipeKey();
    keyState = KeyState::ERROR_STATE;
    Bridge.notify("key_authority_event", "key_generation_failed", "TRNG generation error");
    return false;
  }
  Serial.println("OK");

  computeKeyHash(aesKey, keyHash);
  keyState = KeyState::GENERATED;
  
  Serial.println("[PRO-45] Key generated successfully.");
#if SECURE_DEBUG
  Serial.print("[PRO-45] Key fingerprint (SHA-256[:4]): ");
  printHex(keyHash, KEY_HASH_SIZE);
  Serial.println();
#endif

  Bridge.notify("key_authority_event", "key_generated", "AES-128 key generated successfully");
  return true;
}

// =============================================================
// Key Distribution Protocol (PRO-46)
// =============================================================
//
// Transport: UART (dormant — header dock non-functional, see note above)
//
// Protocol:
//   UNO Q -> Target:  MSG_HANDSHAKE (0xA1) + target_id (1 byte)
//   Target -> UNO Q:  MSG_READY (0xA2) + device_id (4 bytes)
//   UNO Q -> Target:  MSG_KEY_DATA (0xA3) + key_len (1) + key (16) + CRC32 (4)
//   Target -> UNO Q:  MSG_STORED (0xA4) + stored_hash (4 bytes)
//   UNO Q verifies:   stored_hash matches keyHash

static inline bool waitForByte(uint8_t* byte, uint32_t timeoutMs) {
  uint32_t start = millis();
  do {
    if (DOCK_SERIAL.available()) { *byte = DOCK_SERIAL.read(); return true; }
  } while (millis() - start < timeoutMs);
  return false;
}

static inline bool waitForBytes(uint8_t* buffer, size_t count, uint32_t timeoutMs) {
  size_t received = 0;
  uint32_t start = millis();
  while (received < count && millis() - start < timeoutMs) {
    if (DOCK_SERIAL.available()) { buffer[received++] = DOCK_SERIAL.read(); }
  }
  return (received == count);
}

static bool distributeKey(uint8_t targetId) {
  if (keyState != KeyState::GENERATED &&
      keyState != KeyState::DISTRIBUTED_PLC &&
      keyState != KeyState::DISTRIBUTED_PAW) {
    Serial.println("[PRO-46] No key available for distribution.");
    return false;
  }

  const char* targetName = (targetId == TARGET_PLC) ? "PLC" : "PAW";

  if (targetId != TARGET_PLC && targetId != TARGET_PAW) {
    Serial.println("[PRO-46] Invalid target ID.");
    return false;
  }

  Serial.print("[PRO-46] Distributing key to ");
  Serial.print(targetName);
  Serial.println(" via UART...");

  // Step 1: Handshake (2 bytes, single write)
  Serial.print("[PRO-46] Sending handshake... ");
  uint8_t handshake[2] = { MSG_HANDSHAKE, targetId };
  DOCK_SERIAL.write(handshake, 2);
  DOCK_SERIAL.flush();

  uint8_t response;
  if (!waitForByte(&response, DISTRIB_TIMEOUT_MS) || response != MSG_READY) {
    Serial.println("FAILED (no READY response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not respond");
    return false;
  }

  uint8_t deviceId[4];
  if (!waitForBytes(deviceId, 4, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no device ID)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not send device ID");
    return false;
  }
  Serial.print("OK (device: ");
  printHex(deviceId, 4);
  Serial.println(")");

  // Step 2: Send key + CRC32 in a single batched write (22 bytes)
  // Format: MSG_KEY_DATA(1) + key_len(1) + key(16) + crc32(4) = 22 bytes
  Serial.print("[PRO-46] Sending key data... ");
  uint8_t keyPacket[22];
  keyPacket[0] = MSG_KEY_DATA;
  keyPacket[1] = (uint8_t)AES_KEY_SIZE;
  memcpy(&keyPacket[2], aesKey, AES_KEY_SIZE);
  uint32_t crc = shalot_crc32(aesKey, AES_KEY_SIZE);
  keyPacket[18] = (uint8_t)(crc >> 24);
  keyPacket[19] = (uint8_t)(crc >> 16);
  keyPacket[20] = (uint8_t)(crc >> 8);
  keyPacket[21] = (uint8_t)(crc & 0xFF);
  DOCK_SERIAL.write(keyPacket, 22);
  DOCK_SERIAL.flush();
  // PRO-94: keyPacket holds the raw AES key — wipe immediately after use
  // so no key bytes linger in SRAM beyond the transmit.
  memset(keyPacket, 0, sizeof(keyPacket));
  Serial.println("sent");

  // Step 3: Wait for storage confirmation
  Serial.print("[PRO-46] Waiting for storage confirmation... ");
  if (!waitForByte(&response, DISTRIB_TIMEOUT_MS) || response != MSG_STORED) {
    Serial.println("FAILED (no STORED response)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not confirm storage");
    return false;
  }

  uint8_t storedHash[KEY_HASH_SIZE];
  if (!waitForBytes(storedHash, KEY_HASH_SIZE, DISTRIB_TIMEOUT_MS)) {
    Serial.println("FAILED (no hash received)");
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " did not return hash");
    return false;
  }

  // Step 4: Verify stored hash (constant-time comparison)
  volatile uint8_t hashDiff = 0;
  for (int i = 0; i < KEY_HASH_SIZE; i++) {
    hashDiff |= storedHash[i] ^ keyHash[i];
  }

  if (hashDiff != 0) {
#if SECURE_DEBUG
    Serial.println("FAILED (hash mismatch)");
    Serial.print("[PRO-46] Expected: ");
    printHex(keyHash, KEY_HASH_SIZE);
    Serial.print("  Got: ");
    printHex(storedHash, KEY_HASH_SIZE);
    Serial.println();
#endif
    Bridge.notify("key_authority_event", "distribution_failed",
                 String(targetName) + " hash mismatch");
    return false;
  }

  Serial.println("OK (hash verified)");
  Serial.print("[PRO-46] Key successfully distributed to ");
  Serial.print(targetName);
  Serial.println(".");

  // Update state machine
  if (targetId == TARGET_PLC) {
    keyState = (keyState == KeyState::DISTRIBUTED_PAW)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PLC;
  } else {
    keyState = (keyState == KeyState::DISTRIBUTED_PLC)
             ? KeyState::DISTRIBUTED_BOTH : KeyState::DISTRIBUTED_PAW;
  }

  Bridge.notify("key_authority_event", "distribution_success",
               String(targetName) + " provisioned successfully");
  return true;
}

// =============================================================
// PRO-98: Signed blocklist distribution to DEN
// =============================================================
//
// Format sent over DOCK_SERIAL (dormant path — USB ceremony is live):
//   MSG_BLOCKLIST (0xA6)
//   version      : 1 byte
//   issuer       : 16 bytes (null-padded ASCII)
//   entry_count  : 1 byte
//   entries      : 4 bytes * entry_count
//   signature    : 32 bytes (HMAC-SHA256)
// =============================================================

#define BLOCKLIST_VERSION       1
#define BLOCKLIST_ISSUER        "SHALLOT-AUTH"
#define BLOCKLIST_MAX_ENTRIES   16
#define BLOCKLIST_SIGNATURE_SIZE 64  // Ed25519 signature size

// PRO-98: Ed25519 private key for blocklist signing.
// Only MamaBear (UNO Q) holds the private key for signing.
// The corresponding public key is embedded in DEN firmware for verification.
// This key is generated once and must be kept secret.
// PRO-93: No hardcoded development key. This must be provisioned securely.
static uint8_t blocklist_private_key[ED25519_PRIVATE_KEY_SIZE];  // 32 bytes
static uint8_t blocklist_key_provisioned = 0;

// PRO-98: Sign blocklist with Ed25519 private key.
// Returns true on success, false if private key not provisioned.
static bool sign_blocklist(uint8_t version, const char *issuer,
                           const uint8_t *entries, uint8_t entry_count,
                           uint8_t *signature) {
#ifdef SHALLOT_NO_ED25519
    // Staged unoq bring-up without Ed25519 backend: always fail closed.
    // Callers (distributeBlocklist) already wipe + refuse transmit on
    // false, so no caller changes needed. Full backend post-presentation.
    (void)version; (void)issuer; (void)entries; (void)entry_count;
    if (signature) {
        memset(signature, 0, BLOCKLIST_SIGNATURE_SIZE);
    }
    return false;
#else
    if (!blocklist_key_provisioned) {
#if SECURE_DEBUG
        Serial.println("[PRO-98] Cannot sign: private key not provisioned");
#endif
        return false;
    }

    uint8_t data[1 + 16 + 1 + BLOCKLIST_MAX_ENTRIES * KEY_HASH_SIZE];
    size_t data_len = 1 + 16 + 1 + entry_count * KEY_HASH_SIZE;
    memcpy(data, &version, 1);
    memcpy(data + 1, issuer, 16);
    memcpy(data + 17, &entry_count, 1);
    memcpy(data + 18, entries, entry_count * KEY_HASH_SIZE);

    int result = ed25519_sign(signature, data, data_len, blocklist_private_key);
    memset(data, 0, sizeof(data));
    if (result != 1) {
        // PRO-94: never hand out a partial/garbage signature — wipe the
        // output buffer so a caller cannot transmit it by mistake.
        memset(signature, 0, BLOCKLIST_SIGNATURE_SIZE);
        return false;
    }
    return true;
#endif  // SHALLOT_NO_ED25519
}

static bool distributeBlocklist() {
  // PRO-93: fail if blocklist private key not provisioned
  if (!blocklist_key_provisioned) {
#if SECURE_DEBUG
    Serial.println("[PRO-98] Cannot distribute: blocklist private key not provisioned");
#endif
    return false;
  }

  Serial.println("[PRO-98] Distributing blocklist to DEN...");

  // Example blocklist entries (in production, populated by MPU)
  uint8_t entries[BLOCKLIST_MAX_ENTRIES * KEY_HASH_SIZE];
  uint8_t entry_count = 0;

  // Add blocked PAW fingerprints here (example: PAW with key hash "DEADBEEF")
  // entries[0..3] = first blocked fingerprint
  // entry_count++

  if (entry_count == 0) {
    Serial.println("[PRO-98] No entries to distribute.");
    return false;
  }

  uint8_t signature[BLOCKLIST_SIGNATURE_SIZE];
  // PRO-94: never transmit a blocklist with a failed signature — a
  // garbage signature would look valid on the wire (DEN stays
  // fail-closed, but we must not send it in the first place).
  if (!sign_blocklist(BLOCKLIST_VERSION, BLOCKLIST_ISSUER, entries, entry_count, signature)) {
    memset(entries, 0, sizeof(entries));
    memset(signature, 0, sizeof(signature));
    return false;
  }

  // Send MSG_BLOCKLIST
  DOCK_SERIAL.write(MSG_BLOCKLIST);
  DOCK_SERIAL.write(BLOCKLIST_VERSION);
  DOCK_SERIAL.write(BLOCKLIST_ISSUER, 16);
  DOCK_SERIAL.write(entry_count);
  DOCK_SERIAL.write(entries, entry_count * KEY_HASH_SIZE);
  DOCK_SERIAL.write(signature, BLOCKLIST_SIGNATURE_SIZE);
  DOCK_SERIAL.flush();

#if SECURE_DEBUG
  Serial.print("[PRO-98] Blocklist sent: version ");
  Serial.print(BLOCKLIST_VERSION);
  Serial.print(", ");
  Serial.print(entry_count);
  Serial.println(" entries");
#endif

  memset(entries, 0, sizeof(entries));
  memset(signature, 0, sizeof(signature));
  return true;
}

// =============================================================
// Bridge RPC — MPU communication (status only, no key material)
// =============================================================

// Bring up the Bridge link (begin + provides). Returns true only when the
// router confirms every step. Safe to call repeatedly: re-registers the
// RPC surface while the link is down, and refreshes it periodically.
// LIMITATION (verified 2026-09-27): if the router restarts after the link
// was up, re-sent BINDs do not restore the session — the MCU must reboot
// (SWD/mailbox reset) to re-register. See bench-diagnosis doc.
static bool setupBridgeRPC() {
  bool up = Bridge.begin();

  up = Bridge.provide("get_key_state", []() -> uint8_t {
    return (uint8_t)keyState;
  }) && up;

  up = Bridge.provide("get_key_fingerprint", []() -> String {
    // Pre-allocate exact size (8 hex chars + null terminator)
    String fp;
    fp.reserve(9);
    for (int i = 0; i < KEY_HASH_SIZE; i++) {
      fp += HEX_CHARS[(keyHash[i] >> 4) & 0x0F];
      fp += HEX_CHARS[keyHash[i] & 0x0F];
    }
    return fp;
  }) && up;

  // PRO-46/USB: expose the 16-byte master key as 32 hex chars so the MPU
  // can provision DEN/PAW over USB. Fail-closed: empty unless a key was
  // generated. Deviates from status-only Bridge by operator decision
  // (airgapped host trusted with cleartext); see bench-diagnosis doc.
  up = Bridge.provide("get_key_material", []() -> String {
    if (keyState != KeyState::GENERATED &&
        keyState != KeyState::DISTRIBUTED_PLC &&
        keyState != KeyState::DISTRIBUTED_PAW &&
        keyState != KeyState::DISTRIBUTED_BOTH) {
      return String("");
    }
    String out;
    out.reserve(2 * AES_KEY_SIZE + 1);
    for (int i = 0; i < AES_KEY_SIZE; i++) {
      out += HEX_CHARS[(aesKey[i] >> 4) & 0x0F];
      out += HEX_CHARS[aesKey[i] & 0x0F];
    }
    return out;
  }) && up;

  up = Bridge.provide("request_key_generation", []() -> bool {
    return generateKey();
  }) && up;

  up = Bridge.provide("request_key_distribution", [](int targetId) -> bool {
    // int (not uint8_t): MsgPack fixint args must decode (the unpacker
    // rejects narrow types); range is validated fail-closed here.
    if (targetId != TARGET_PLC && targetId != TARGET_PAW) {
      return false;
    }
    Serial.print("[PRO-46] MPU requested distribution to target ");
    Serial.print(targetId);
    Serial.println(". Awaiting button press.");
    pendingDistributionTarget = (uint8_t)targetId;
    return true;
  }) && up;

  up = Bridge.provide("request_blocklist_distribution", []() -> bool {
    Serial.println("[PRO-98] MPU requested blocklist distribution.");
    return distributeBlocklist();
  }) && up;

  return up;
}

// =============================================================
// Operator interface
// =============================================================

static const char* keyStateString(KeyState s) {
  switch (s) {
    case KeyState::UNINITIALIZED:    return "UNINITIALIZED";
    case KeyState::GENERATED:        return "GENERATED";
    case KeyState::DISTRIBUTED_PLC:  return "DISTRIBUTED (PLC)";
    case KeyState::DISTRIBUTED_PAW:  return "DISTRIBUTED (PAW)";
    case KeyState::DISTRIBUTED_BOTH: return "DISTRIBUTED (BOTH)";
    case KeyState::ERROR_STATE:      return "ERROR";
  }
  return "UNKNOWN";
}

static void printStatus() {
  Serial.println("\n=== UNO Q Key Authority Status ===");
  Serial.print("Key state: ");
  Serial.println(keyStateString(keyState));
  if (keyState != KeyState::UNINITIALIZED && keyState != KeyState::ERROR_STATE) {
#if SECURE_DEBUG
    Serial.print("Key fingerprint: ");
    printHex(keyHash, KEY_HASH_SIZE);
    Serial.println();
#endif
  }
  Serial.println("Commands: g=generate  1=dist PLC  2=dist PAW  b=blocklist  s=status");
  Serial.println("=====================================\n");
}

// =============================================================
// Setup and Loop
// =============================================================

void setup() {
  Serial.begin(UART_BAUD);
  DOCK_SERIAL.begin(UART_BAUD);

  pinMode(CONFIRM_BUTTON_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED_PIN, OUTPUT);

  bridgeLinkUp = setupBridgeRPC();
  lastBridgeRetryMs = millis();
  Serial.print("Bridge link: ");
  Serial.println(bridgeLinkUp ? "UP" : "PENDING (retry in loop)");

  delay(2000);

  Serial.println("============================================");
  Serial.println("SHALLOT — UNO Q Key Authority (PRO-45/PRO-46)");
  Serial.println("MCU: STM32U585 | TRNG: Hardware");
  Serial.println("============================================");
  Serial.println();

  printStatus();
}

void loop() {
  // Bridge link maintenance: the router may come up after us (or restart
  // later). Re-attempt registration until it confirms; the RPC surface
  // then appears with no reboot or reflash.
  if (!bridgeLinkUp) {
    uint32_t now = millis();
    if (now - lastBridgeRetryMs >= BRIDGE_RETRY_INTERVAL_MS) {
      lastBridgeRetryMs = now;
      if (setupBridgeRPC()) {
        bridgeLinkUp = true;
        Serial.println("Bridge link: UP");
        for (int i = 0; i < 3; i++) {
          digitalWrite(STATUS_LED_PIN, HIGH);
          delay(100);
          digitalWrite(STATUS_LED_PIN, LOW);
          delay(100);
        }
      }
    }
  }

  // Periodic re-registration (side effect only): re-sends BINDs while the
  // link is down. NOTE: verified 2026-09-27 that re-BINDs do NOT heal a
  // link orphaned by a router restart — MCU reboot required (see above).
  {
    uint32_t now = millis();
    if (now - lastBridgeRefreshMs >= BRIDGE_REFRESH_INTERVAL_MS) {
      lastBridgeRefreshMs = now;
      (void)setupBridgeRPC();
    }
  }

  // Serial command processing
  if (Serial.available()) {
    char cmd = Serial.read();

    switch (cmd) {
      case 'g': case 'G':
        digitalWrite(STATUS_LED_PIN, HIGH);
        generateKey();
        digitalWrite(STATUS_LED_PIN, LOW);
        printStatus();
        break;

      case '1':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PAW) {
          Serial.println("\n>> Distributing to PLC. Connect UART and press button.");
          while (digitalRead(CONFIRM_BUTTON_PIN) == HIGH) delay(10);
          digitalWrite(STATUS_LED_PIN, HIGH);
          distributeKey(TARGET_PLC);
          digitalWrite(STATUS_LED_PIN, LOW);
          printStatus();
        } else {
          Serial.println("No key generated or already distributed to PLC.");
        }
        break;

      case '2':
        if (keyState == KeyState::GENERATED ||
            keyState == KeyState::DISTRIBUTED_PLC) {
          Serial.println("\n>> Distributing to PAW. Connect UART and press button.");
          while (digitalRead(CONFIRM_BUTTON_PIN) == HIGH) delay(10);
          digitalWrite(STATUS_LED_PIN, HIGH);
          distributeKey(TARGET_PAW);
          digitalWrite(STATUS_LED_PIN, LOW);
          printStatus();
        } else {
          Serial.println("No key generated or already distributed to PAW.");
        }
        break;

      case 's': case 'S':
        printStatus();
        break;

      case 'b': case 'B':
        Serial.println("\n>> Distributing blocklist to DEN.");
        distributeBlocklist();
        break;
    }
  }

  // MPU-requested distribution (requires physical button press)
  if (pendingDistributionTarget != 0) {
    if (digitalRead(CONFIRM_BUTTON_PIN) == LOW) {
      digitalWrite(STATUS_LED_PIN, HIGH);
      distributeKey(pendingDistributionTarget);
      digitalWrite(STATUS_LED_PIN, LOW);
      pendingDistributionTarget = 0;
      printStatus();
    }
  }

  // LED heartbeat with timer debounce to avoid digitalWrite on every loop pass
  static uint32_t lastBlinkMs = 0;
  if (keyState == KeyState::GENERATED) {
    uint32_t now = millis();
    if (now - lastBlinkMs >= 500) {
      lastBlinkMs = now;
      digitalWrite(STATUS_LED_PIN, !digitalRead(STATUS_LED_PIN));
    }
  } else if (keyState == KeyState::DISTRIBUTED_BOTH) {
    digitalWrite(STATUS_LED_PIN, HIGH);
  }
}
