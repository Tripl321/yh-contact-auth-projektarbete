/* Host harness for libraries/DenUartProtocol (ticket 06).
 * Usage: uvect encode <type-dec> <payloadhex>  -> prints frame hex
 *        uvect decode <framehex>               -> prints "<type-dec> <payloadhex>"
 * Nonzero exit + "ERR" line on failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "DenUartProtocol.h"

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
    uint8_t buf[DEN_MAX_FRAME], payload[DEN_MAX_PAYLOAD];
    if (argc == 4 && strcmp(argv[1], "encode") == 0) {
        size_t plen = fromhex(argv[3], payload, sizeof(payload));
        if (plen == (size_t)-1) { printf("ERR badhex\n"); return 1; }
        size_t n = den_encode((uint8_t)atoi(argv[2]), payload, plen, buf, sizeof(buf));
        if (!n) { printf("ERR encode\n"); return 1; }
        for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
        printf("\n");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "decode") == 0) {
        size_t flen = fromhex(argv[2], buf, sizeof(buf));
        if (flen == (size_t)-1) { printf("ERR badhex\n"); return 1; }
        den_frame_t f;
        if (den_decode(buf, flen, &f) != DEN_OK) { printf("ERR decode\n"); return 1; }
        printf("%u ", f.type);
        for (size_t i = 0; i < f.payloadLen; i++) printf("%02x", f.payload[i]);
        printf("\n");
        return 0;
    }
    printf("ERR usage\n");
    return 2;
}
