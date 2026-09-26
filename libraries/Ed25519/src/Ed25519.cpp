// libraries/Ed25519/src/Ed25519.cpp — thin adapter, no crypto of its own.
//
// Implements the C API from Ed25519.h by forwarding to the mature
// rweather "Crypto" library (MIT). History, recorded 2026-09-15 (UART
// review): the previously vendored implementation never compiled
// (missing sha512 definition, undeclared identifiers, oversized K-table)
// and its field arithmetic operated on 16-byte limbs, which cannot
// implement Ed25519 — repairing it in place would have meant authoring
// new curve code. Delegating the primitive keeps firmware call sites
// untouched and was proven by host-compiled KAT (RFC 8032-style vectors
// cross-checked against Python cryptography + repo blocklist vector;
// see PR description).
//
// Build requirement: "Crypto" library, tested v0.4.0
// (Arduino Library Manager: arduino-cli lib install "Crypto@0.4.0").
//
// Staged bring-up: define SHALLOT_NO_ED25519 to compile WITHOUT the
// Crypto backend (its RNG.cpp TU does not compile for the unoq target:
// macro collision with the U5 CMSIS headers). With the flag set this TU
// emits no code; callers must be guarded to never reference the symbols
// (uno-q key-authority stubs sign_blocklist fail-closed). Default (flag
// absent): full backend, byte-identical behavior. Full backend on unoq
// = vendored SHA-512/Ed25519 (post-presentation track), never toolchain
// surgery.
#ifdef SHALLOT_NO_ED25519
// No backend: intentionally empty translation unit.
#else
// NOTE on includes: this file must NOT #include <Ed25519.h> from the
// Crypto library (same filename as ours; ours wins by --libraries order).
// The class is therefore redeclared below with signatures copied verbatim
// from Crypto 0.4.0 src/Ed25519.h. Any upstream signature drift fails
// loudly at link time (C++ mangled names), never silently.
// The #include <SHA512.h> below marks the Crypto library as used so the
// builder compiles and links its Ed25519 implementation.

#include "Ed25519.h"  // our C API (sizes + decls); resolved to this library
#include <string.h>
#include <SHA512.h>  // rweather Crypto (marks dependency used; see note above)

// Verbatim redeclaration from Crypto 0.4.0 src/Ed25519.h (MIT,
// Rhys Weatherley). See note above.
class Ed25519 {
public:
    static void sign(uint8_t signature[64], const uint8_t privateKey[32],
                     const uint8_t publicKey[32], const void *message,
                     size_t len);
    static bool verify(const uint8_t signature[64], const uint8_t publicKey[32],
                       const void *message, size_t len);
    static void derivePublicKey(uint8_t publicKey[32], const uint8_t privateKey[32]);
};

int ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *private_key) {
    if (!signature || !message || !private_key) return 0;
    uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
    Ed25519::derivePublicKey(public_key, private_key);
    Ed25519::sign(signature, private_key, public_key, message, message_len);
    memset(public_key, 0, sizeof(public_key));
    return 1;
}

int ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    if (!signature || !message || !public_key) return 0;
    return Ed25519::verify(signature, public_key, message, message_len) ? 1 : 0;
}

int ed25519_public_key(uint8_t *public_key, const uint8_t *private_key) {
    if (!public_key || !private_key) return 0;
    Ed25519::derivePublicKey(public_key, private_key);
    return 1;
}

#endif  // SHALLOT_NO_ED25519
