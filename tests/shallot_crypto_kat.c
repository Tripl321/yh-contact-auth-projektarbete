/* KAT harness for libraries/ShallotCrypto (host-compiled, ticket 01).
 * Prints "<name> <hex>" lines; the pytest driver asserts them. */
#include <stdio.h>
#include <string.h>
#include "ShallotCrypto.h"

static void print_hex(const char *name, const uint8_t *b, size_t n) {
    printf("%s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t out[32], mac[32], k[16];

    /* CRC32 reference: "123456789" -> 0xCBF43926 */
    printf("crc_ref %x\n", (unsigned)shalot_crc32((const uint8_t *)"123456789", 9));

    shalot_sha256((const uint8_t *)"", 0, out);
    print_hex("sha_empty", out, 32);
    shalot_sha256((const uint8_t *)"abc", 3, out);
    print_hex("sha_abc", out, 32);
    shalot_sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                  56, out);
    print_hex("sha_56", out, 32);

    /* RFC 4231 case 1: key 20x0x0b, "Hi There" */
    uint8_t k1[20];
    memset(k1, 0x0b, sizeof(k1));
    shalot_hmac_sha256(k1, sizeof(k1), (const uint8_t *)"Hi There", 8, mac);
    print_hex("hmac_rfc1", mac, 32);
    /* RFC 4231 case 2: key "Jefe" */
    shalot_hmac_sha256((const uint8_t *)"Jefe", 4,
                       (const uint8_t *)"what do ya want for nothing?", 28, mac);
    print_hex("hmac_rfc2", mac, 32);
    /* RFC 4231 case 3: key 20x0xaa, 50x0xdd */
    uint8_t k3[20], m3[50];
    memset(k3, 0xaa, sizeof(k3));
    memset(m3, 0xdd, sizeof(m3));
    shalot_hmac_sha256(k3, sizeof(k3), m3, sizeof(m3), mac);
    print_hex("hmac_rfc3", mac, 32);

    /* Repo DEV vectors: master 00..0F, nonce 0x10..0x17 */
    uint8_t master[16], nonce[8];
    for (int i = 0; i < 16; i++) master[i] = (uint8_t)i;
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(0x10 + i);
    shalot_derive_k_mac(master, k);
    print_hex("dev_kmac", k, 16);
    shalot_derive_k_enc(master, k);
    print_hex("dev_kenc", k, 16);
    shalot_derive_k_mac(master, k);
    shalot_hmac_sha256(k, 16, nonce, 8, mac);
    print_hex("dev_hmac", mac, 32);

    /* Fail-closed: oversize inputs zero the output */
    uint8_t big[65];
    memset(big, 0x55, sizeof(big));
    shalot_hmac_sha256(master, 16, big, 65, mac);
    print_hex("fail_msg", mac, 32);
    shalot_hmac_sha256(big, 65, nonce, 8, mac);
    print_hex("fail_key", mac, 32);
    return 0;
}
