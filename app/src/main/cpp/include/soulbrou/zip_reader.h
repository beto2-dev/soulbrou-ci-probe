/*
 * Minimal zip (APK) reader used by the anti-tampering checks.
 *
 * Supports: central directory iteration, local header reading, raw entry
 * CRC extraction and the APK Signing Block v2/v3 certificate finder.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef SOULBROU_ZIP_READER_H
#define SOULBROU_ZIP_READER_H

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_zip_file {
    FILE *handle;
    uint64_t local_header_offset;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint32_t crc32;
    uint16_t method;
} sb_zip_file;

/* Opens [entry_name] inside the zip at [path]. Returns 1 on success. */
int sb_zip_open(sb_zip_file *out, const char *path, const char *entry_name);

/* Reads the whole stored entry into a caller provided buffer. */
size_t sb_zip_read(sb_zip_file *file, uint8_t *buffer, size_t capacity);

/* Returns the entry CRC recorded in the central directory. */
uint32_t sb_zip_entry_crc(sb_zip_file *file);

/* Closes the underlying handle. */
void sb_zip_close(sb_zip_file *file);

/* Extracts the first signer certificate of the v2/v3 signing block. */
int sb_zip_extract_v2_certificate(const char *apk_path, uint8_t *certificate, size_t *length);

/* Returns the ABI directory name of the current build. */
const char *sb_current_abi(void);

#ifdef __cplusplus
}
#endif

#endif /* SOULBROU_ZIP_READER_H */
