#include "Ed25519.h"
#include <string.h>

#define FOR(i,n) for (size_t i = 0; i < n; ++i)
#define sv static void

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

sv cswap(u8 *x, u8 *y, u8 c) {
    FOR(i, 32) {
        u8 t = x[i];
        x[i] = (c & y[i]) | (~c & t);
        y[i] = (c & t) | (~c & y[i]);
    }
}

static const u8 gf121666[16] = {0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
                                0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};

sv add(u8 *r, const u8 *x, const u8 *y) {
    u64 c = 0;
    FOR(i, 16) {
        u64 n = (u64)x[i] + (u64)y[i] + c;
        r[i] = (u8)n;
        c = n >> 8;
    }
}

sv sub(u8 *r, const u8 *x, const u8 *y) {
    u64 c = 1;
    FOR(i, 16) {
        u64 n = (u64)x[i] + 255 - (u64)y[i] + c;
        r[i] = (u8)n;
        c = n >> 8;
    }
}

sv mul(u8 *r, const u8 *x, const u8 *y) {
    u32 t[31] = {0};
    FOR(i, 16) {
        u64 c = 0;
        FOR(j, 16) {
            u64 n = t[i+j] + (u64)x[i] * (u64)y[j] + c;
            t[i+j] = (u32)n;
            c = n >> 32;
        }
        t[i+16] = (u32)c;
    }
    FOR(i, 15) {
        t[i] += 38 * t[i+16];
    }
    u64 c = 0;
    FOR(i, 16) {
        u64 n = (u64)t[i] + c;
        r[i] = (u8)n;
        c = n >> 8;
    }
}

sv sqr(u8 *r, const u8 *x) { mul(r, x, x); }

sv inv(u8 *r, const u8 *x) {
    u8 a[16];
    memcpy(a, x, 16);
    u8 t0[16], t1[16];
    FOR(i, 254) {
        if (i == 1) memcpy(t0, a, 16);
        if (i == 2) memcpy(t1, a, 16);
        sqr(a, a);
        mul(a, a, x);
    }
    mul(a, a, t0);
    sqr(a, a);
    mul(a, a, t1);
    sqr(a, a);
    mul(a, a, x);
    memcpy(r, a, 16);
}

static const u8 Base[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

sv base_mul(u8 *r, const u8 *x) {
    u8 a[16];
    memcpy(a, Base, 16);
    u8 res[16] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    FOR(i, 16) {
        u8 b = x[i];
        FOR(j, 8) {
            u8 bit = b & 1;
            u8 neg = bit ^ 1;
            cswap(res, a, neg);
            add(res, res, a);
            cswap(res, a, neg);
            sqr(a, a);
            b >>= 1;
        }
    }
    memcpy(r, res, 16);
}

sv hash_pubkey(u8 *out, const u8 *pubkey) {
    u8 h[64];
    sha512(h, pubkey, 32);
    memcpy(out, h, 32);
}

sv scalar_mult(u8 *r, const u8 *scalar, const u8 *point) {
    u8 res[16] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    u8 a[16];
    memcpy(a, point, 16);
    for (int i = 255; i >= 0; --i) {
        u8 bit = (scalar[i >> 3] >> (i & 7)) & 1;
        u8 neg = bit ^ 1;
        cswap(res, a, neg);
        add(res, res, a);
        cswap(res, a, neg);
        sqr(a, a);
    }
    memcpy(r, res, 16);
}

int ed25519_public_key(uint8_t *public_key, const uint8_t *private_key) {
    u8 az[64];
    sha512(az, private_key, 32);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;
    base_mul(public_key, az);
    return 1;
}

static const u8 L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
};

sv sc_reduce(u8 *s) {
    u64 c = 0;
    FOR(i, 32) {
        u64 n = (u64)s[i] + c;
        s[i] = (u8)n;
        c = n >> 8;
    }
    u64 carry = 0;
    FOR(i, 32) {
        u64 n = (u64)s[i] + carry * 38;
        s[i] = (u8)n;
        carry = n >> 8;
    }
}

int ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *private_key) {
    u8 az[64];
    sha512(az, private_key, 32);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;

    u8 nonce[64];
    sha512(nonce, az + 32, 32);
    for (size_t i = 0; i < message_len; ++i) {
        nonce[i] ^= message[i];
    }
    sha512(nonce, nonce, 64);
    u8 r[32];
    FOR(i, 32) r[i] = nonce[i];
    r[31] &= 127;
    r[31] |= 64;

    u8 R[32];
    base_mul(R, r);

    u8 h[64];
    u8 hram[64];
    memcpy(hram, R, 32);
    FOR(i, 32) hram[32+i] = public_key[i];
    FOR(i, message_len) hram[64+i] = message[i];
    sha512(h, hram, 64 + message_len);
    FOR(i, 32) h[i] &= 63;

    u8 s[64];
    memcpy(s, r, 32);
    FOR(i, 32) {
        u64 c = 0;
        FOR(j, 32) {
            u64 n = (u64)s[i+j] + (u64)h[i] * (u64)az[j] + c;
            if (i+j < 64) s[i+j] = (u8)n;
            c = n >> 8;
        }
    }
    sc_reduce(s);
    FOR(i, 32) signature[i] = R[i];
    FOR(i, 32) signature[32+i] = s[i];
    return 1;
}

int ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    u8 R[32], s[32];
    memcpy(R, signature, 32);
    memcpy(s, signature + 32, 32);

    if (R[31] & 224) return 0;
    FOR(i, 32) if (s[i] >= 128) return 0;

    u8 A[32];
    memcpy(A, public_key, 32);
    if (A[31] & 224) return 0;

    u8 h[64];
    u8 hram[64];
    memcpy(hram, R, 32);
    FOR(i, 32) hram[32+i] = public_key[i];
    FOR(i, message_len) hram[64+i] = message[i];
    sha512(h, hram, 64 + message_len);
    FOR(i, 32) h[i] &= 63;

    u8 Rcheck[32];
    u8 v1[32], v2[32];
    memcpy(v1, s, 32);
    scalar_mult(v1, s, Base);
    scalar_mult(v2, h, A);
    add(v1, v1, v2);
    FOR(i, 16) Rcheck[i] = v1[i];

    if (memcmp(Rcheck, R, 32) != 0) return 0;
    return 1;
}

sv sha512(u8 *out, const u8 *in, size_t len) {
    static const u64 K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139b95c42dULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d9f8974eULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774c54c5b7c6ULL, 0x288a38b26917c0e2ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
        0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
        0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd192e819d6990624ULL, 0xd69906245565a910ULL,
        0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
        0x2748774c54c5b7c6ULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139b95c42dULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d9f8974eULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL
    };

    u64 h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fa75e3049ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    size_t blocks = (len + 127) / 128;
    u8 buf[128];
    size_t pos = 0;

    while (len >= 128) {
        u64 w[16];
        FOR(i, 16) {
            w[i] = ((u64)in[pos+8*i] << 56) | ((u64)in[pos+8*i+1] << 48) |
                   ((u64)in[pos+8*i+2] << 40) | ((u64)in[pos+8*i+3] << 32) |
                   ((u64)in[pos+8*i+4] << 24) | ((u64)in[pos+8*i+5] << 16) |
                   ((u64)in[pos+8*i+6] << 8) | (u64)in[pos+8*i+7];
        }
        u64 a = h[0], b = h[1], c = h[2], d = h[3];
        u64 e = h[4], f = h[5], g = h[6], h0 = h[7];
        FOR(i, 80) {
            u64 S1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h0 + S1 + ch + K[i] + w[i % 16];
            u64 S0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = S0 + maj;
            h0 = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            if (i < 15) w[i+16] = w[i] + ((w[(i+1)%16] >> 1) | (w[(i+1)%16] << 63)) + ((w[(i+14)%16] >> 1) | (w[(i+14)%16] << 63)) + ((w[(i+9)%16] >> 7) | (w[(i+9)%16] << 57));
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h0;
        pos += 128;
        len -= 128;
    }

    memcpy(buf, in + pos, len);
    buf[len++] = 0x80;
    if (len > 111) {
        memset(buf + len, 0, 128 - len);
        u64 w[16];
        FOR(i, 16) {
            w[i] = ((u64)buf[8*i] << 56) | ((u64)buf[8*i+1] << 48) |
                   ((u64)buf[8*i+2] << 40) | ((u64)buf[8*i+3] << 32) |
                   ((u64)buf[8*i+4] << 24) | ((u64)buf[8*i+5] << 16) |
                   ((u64)buf[8*i+6] << 8) | (u64)buf[8*i+7];
        }
        u64 a = h[0], b = h[1], c = h[2], d = h[3];
        u64 e = h[4], f = h[5], g = h[6], h0 = h[7];
        FOR(i, 80) {
            u64 S1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h0 + S1 + ch + K[i] + w[i % 16];
            u64 S0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = S0 + maj;
            h0 = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            if (i < 15) w[i+16] = w[i] + ((w[(i+1)%16] >> 1) | (w[(i+1)%16] << 63)) + ((w[(i+14)%16] >> 1) | (w[(i+14)%16] << 63)) + ((w[(i+9)%16] >> 7) | (w[(i+9)%16] << 57));
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h0;
        len = 0;
    }
    memset(buf + len, 0, 112 - len);
    u64 bitlen = (u64)(len + pos) * 8;
    FOR(i, 8) buf[120+i] = (u8)(bitlen >> (56 - 8*i));
    u64 w[16];
    FOR(i, 16) {
        w[i] = ((u64)buf[8*i] << 56) | ((u64)buf[8*i+1] << 48) |
               ((u64)buf[8*i+2] << 40) | ((u64)buf[8*i+3] << 32) |
               ((u64)buf[8*i+4] << 24) | ((u64)buf[8*i+5] << 16) |
               ((u64)buf[8*i+6] << 8) | (u64)buf[8*i+7];
    }
    u64 a = h[0], b = h[1], c = h[2], d = h[3];
    u64 e = h[4], f = h[5], g = h[6], h0 = h[7];
    FOR(i, 80) {
        u64 S1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
        u64 ch = (e & f) ^ (~e & g);
        u64 t1 = h0 + S1 + ch + K[i] + w[i % 16];
        u64 S0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
        u64 maj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = S0 + maj;
        h0 = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        if (i < 15) w[i+16] = w[i] + ((w[(i+1)%16] >> 1) | (w[(i+1)%16] << 63)) + ((w[(i+14)%16] >> 1) | (w[(i+14)%16] << 63)) + ((w[(i+9)%16] >> 7) | (w[(i+9)%16] << 57));
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h0;

    FOR(i, 8) {
        out[8*i] = (u8)(h[i] >> 56);
        out[8*i+1] = (u8)(h[i] >> 48);
        out[8*i+2] = (u8)(h[i] >> 40);
        out[8*i+3] = (u8)(h[i] >> 32);
        out[8*i+4] = (u8)(h[i] >> 24);
        out[8*i+5] = (u8)(h[i] >> 16);
        out[8*i+6] = (u8)(h[i] >> 8);
        out[8*i+7] = (u8)h[i];
    }
}