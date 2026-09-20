/* Host harness for libraries/ProvisioningProtocol.
 * Usage: pvect keydata <keyhex>   -> prints 22-byte packet hex
 *        pvect verify <keyhex> <crc-be-hex> -> prints OK or ERR
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "ProvisioningProtocol.h"

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t fromhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return (size_t)-1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

int main(int argc, char **argv) {
    uint8_t key[PROV_KEY_LEN], pkt[PROV_KEYDATA_LEN];
    if (argc == 3 && strcmp(argv[1], "keydata") == 0) {
        if (fromhex(argv[2], key, sizeof(key)) != PROV_KEY_LEN) {
            printf("ERR badhex\n"); return 1;
        }
        prov_build_key_data(pkt, key);
        for (size_t i = 0; i < PROV_KEYDATA_LEN; i++) printf("%02x", pkt[i]);
        printf("\n");
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "verify") == 0) {
        uint32_t want;
        if (fromhex(argv[2], key, sizeof(key)) != PROV_KEY_LEN) {
            printf("ERR badhex\n"); return 1;
        }
        want = (uint32_t)strtoul(argv[3], NULL, 16);
        prov_build_key_data(pkt, key);
        /* overwrite CRC field with the candidate and verify */
        pkt[18] = (uint8_t)(want >> 24);
        pkt[19] = (uint8_t)(want >> 16);
        pkt[20] = (uint8_t)(want >> 8);
        pkt[21] = (uint8_t)(want & 0xFF);
        if (prov_verify_key_data(pkt)) { printf("OK\n"); return 0; }
        printf("ERR crc\n"); return 1;
    }
    printf("ERR usage\n");
    return 2;
}
