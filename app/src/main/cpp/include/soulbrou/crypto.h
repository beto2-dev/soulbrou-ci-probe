/*
 * Cryptographic primitives exposed to the Soulbrou native components.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef SOULBROU_CRYPTO_H
#define SOULBROU_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sb_xxtea_decrypt(uint32_t *data, size_t word_count, const uint32_t key[4]);
void sb_xxtea_encrypt(uint32_t *data, size_t word_count, const uint32_t key[4]);
void sb_sha256(const uint8_t *data, size_t length, uint8_t out[32]);
void sb_sha256_hmac(const uint8_t *key, size_t key_length,
                    const uint8_t *data, size_t data_length,
                    uint8_t out[32]);
uint32_t sb_crc32(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* SOULBROU_CRYPTO_H */
