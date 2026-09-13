#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>
#include <stddef.h>

#define ED25519_PRIVATE_KEY_SIZE 32
#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

int ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *private_key);
int ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *public_key);
int ed25519_public_key(uint8_t *public_key, const uint8_t *private_key);

#ifdef __cplusplus
}
#endif

#endif