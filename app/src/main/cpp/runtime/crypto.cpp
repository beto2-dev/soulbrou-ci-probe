/*
 * Cryptographic primitives used by the Soulbrou runtime: XXTEA for the
 * bytecode blob, SHA-256 for integrity fingerprints and CRC32 for the
 * tampering checks.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/crypto.h"

#include <string.h>

#define DELTA 0x9E3779B9u
#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))

void sb_xxtea_decrypt(uint32_t *data, size_t word_count, const uint32_t key[4]) {
    if (word_count < 2) {
        return;
    }
    size_t n = word_count - 1;
    uint32_t y;
    uint32_t z = data[n];
    uint32_t sum;
    uint32_t e;
    size_t p;
    size_t q = 6 + 52 / word_count;

    if (key == NULL) {
        return;
    }

    sum = (uint32_t) (q * DELTA);
    while (sum != 0) {
        e = sum >> 2 & 3;
        for (p = n; p > 0; p--) {
            z = data[p - 1];
            y = data[p];
            data[p] -= MX;
        }
        z = data[n];
        y = data[0];
        data[0] -= MX;
        sum -= DELTA;
    }
}

void sb_xxtea_encrypt(uint32_t *data, size_t word_count, const uint32_t key[4]) {
    if (word_count < 2) {
        return;
    }
    size_t n = word_count - 1;
    uint32_t y = data[0];
    uint32_t z;
    uint32_t sum = 0;
    uint32_t e;
    size_t p;
    size_t q = 6 + 52 / word_count;

    if (key == NULL) {
        return;
    }

    for (size_t round = 0; round < q; round++) {
        sum += DELTA;
        e = sum >> 2 & 3;
        for (p = 0; p < n; p++) {
            y = data[p + 1];
            z = data[p];
            data[p] += MX;
        }
        y = data[0];
        z = data[n];
        data[n] += MX;
    }
}

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

void sb_sha256(const uint8_t *data, size_t length, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    size_t padded_length = ((length + 8) / 64 + 1) * 64;
    uint8_t padded[128];
    size_t position = 0;
    int done = 0;

    while (!done) {
        size_t remaining = length - position;
        size_t take = remaining > 64 ? 64 : remaining;
        memset(padded, 0, sizeof(padded));
        if (take > 0) {
            memcpy(padded, data + position, take);
        }
        if (remaining < 64) {
            padded[remaining] = 0x80;
            uint64_t bit_length = (uint64_t) length * 8;
            for (int i = 0; i < 8; i++) {
                padded[padded_length - 1 - i] = (uint8_t) (bit_length >> (i * 8));
            }
            done = 1;
        }

        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t) padded[i * 4] << 24) | ((uint32_t) padded[i * 4 + 1] << 16) |
                   ((uint32_t) padded[i * 4 + 2] << 8) | (uint32_t) padded[i * 4 + 3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + s1 + ch + SHA256_K[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

        position += take;
        if (remaining < 64) {
            padded_length = 0; // silence unused warnings in release builds
        }
    }

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t) (h[i] >> 24);
        out[i * 4 + 1] = (uint8_t) (h[i] >> 16);
        out[i * 4 + 2] = (uint8_t) (h[i] >> 8);
        out[i * 4 + 3] = (uint8_t) h[i];
    }
}

void sb_sha256_hmac(const uint8_t *key, size_t key_length,
                    const uint8_t *data, size_t data_length,
                    uint8_t out[32]) {
    uint8_t block[64];
    uint8_t inner[64 + 32];
    uint8_t key_hash[32];

    if (key_length > 64) {
        sb_sha256(key, key_length, key_hash);
        key = key_hash;
        key_length = 32;
    }

    memset(block, 0, sizeof(block));
    memcpy(block, key, key_length);

    for (int i = 0; i < 64; i++) {
        inner[i] = block[i] ^ 0x36;
    }
    memcpy(inner + 64, data, data_length);
    uint8_t inner_hash[32];
    sb_sha256(inner, 64 + data_length, inner_hash);

    for (int i = 0; i < 64; i++) {
        block[i] ^= 0x5c;
    }
    uint8_t outer[64 + 32];
    memcpy(outer, block, 64);
    memcpy(outer + 64, inner_hash, 32);
    sb_sha256(outer, 64 + 32, out);
}

uint32_t sb_crc32(const uint8_t *data, size_t length) {
    static uint32_t table[256];
    static int table_ready = 0;
    if (!table_ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        table_ready = 1;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; i++) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}
