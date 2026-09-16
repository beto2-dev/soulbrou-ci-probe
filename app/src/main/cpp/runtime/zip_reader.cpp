/*
 * Minimal zip (APK) reader implementation.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/zip_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__)
#define SB_ABI "arm64-v8a"
#elif defined(__arm__)
#define SB_ABI "armeabi-v7a"
#else
#define SB_ABI "x86_64"
#endif

static uint16_t read_u16(const uint8_t *data, size_t offset) {
    return (uint16_t) (data[offset] | (data[offset + 1] << 8));
}

static uint32_t read_u32(const uint8_t *data, size_t offset) {
    return (uint32_t) data[offset] | ((uint32_t) data[offset + 1] << 8) |
           ((uint32_t) data[offset + 2] << 16) | ((uint32_t) data[offset + 3] << 24);
}

static uint64_t read_u64(const uint8_t *data, size_t offset) {
    return (uint64_t) read_u32(data, offset) | ((uint64_t) read_u32(data, offset + 4) << 32);
}

static uint32_t f_read_u32(FILE *file, long offset) {
    uint8_t raw[4];
    fseek(file, offset, SEEK_SET);
    if (fread(raw, 1, 4, file) != 4) {
        return 0;
    }
    return read_u32(raw, 0);
}

const char *sb_current_abi(void) {
    return SB_ABI;
}

int sb_zip_open(sb_zip_file *out, const char *path, const char *entry_name) {
    memset(out, 0, sizeof(*out));

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < 22) {
        fclose(file);
        return 0;
    }

    // Locate the end of central directory record.
    long window_start = file_size - 65557;
    if (window_start < 0) {
        window_start = 0;
    }
    uint8_t *window = (uint8_t *) malloc((size_t) (file_size - window_start));
    if (window == NULL) {
        fclose(file);
        return 0;
    }
    fseek(file, window_start, SEEK_SET);
    size_t window_size = (size_t) (file_size - window_start);
    if (fread(window, 1, window_size, file) != window_size) {
        free(window);
        fclose(file);
        return 0;
    }

    long eocd_offset = -1;
    for (long i = (long) window_size - 22; i >= 0; i--) {
        if (read_u32(window, (size_t) i) == 0x06054b50) {
            eocd_offset = i;
            break;
        }
    }
    if (eocd_offset < 0) {
        free(window);
        fclose(file);
        return 0;
    }

    uint16_t entry_count = read_u16(window, (size_t) eocd_offset + 10);
    uint32_t cd_offset = read_u32(window, (size_t) eocd_offset + 16);
    free(window);

    uint8_t entry[64];
    size_t name_length = strlen(entry_name);
    for (uint16_t i = 0; i < entry_count; i++) {
        fseek(file, (long) cd_offset, SEEK_SET);
        if (fread(entry, 1, 46, file) != 46 || read_u32(entry, 0) != 0x02014b50) {
            break;
        }
        uint16_t this_name_length = read_u16(entry, 28);
        uint16_t extra_length = read_u16(entry, 30);
        uint16_t comment_length = read_u16(entry, 32);
        if (this_name_length == name_length && this_name_length < sizeof(entry)) {
            uint8_t name[256];
            if (fread(name, 1, this_name_length, file) == this_name_length &&
                memcmp(name, entry_name, this_name_length) == 0) {
                out->handle = file;
                out->local_header_offset = read_u32(entry, 42);
                out->crc32 = read_u32(entry, 16);
                out->compressed_size = read_u32(entry, 20);
                out->uncompressed_size = read_u32(entry, 24);
                out->method = read_u16(entry, 10);
                return 1;
            }
        } else {
            fseek(file, this_name_length + extra_length + comment_length, SEEK_CUR);
        }
        cd_offset += 46 + this_name_length + extra_length + comment_length;
    }

    fclose(file);
    return 0;
}

size_t sb_zip_read(sb_zip_file *file, uint8_t *buffer, size_t capacity) {
    if (file->handle == NULL || file->method != 0) {
        return 0; // Only stored entries are supported.
    }
    uint8_t local[30];
    fseek(file->handle, (long) file->local_header_offset, SEEK_SET);
    if (fread(local, 1, 30, file->handle) != 30 || read_u32(local, 0) != 0x04034b50) {
        return 0;
    }
    uint16_t name_length = read_u16(local, 26);
    uint16_t extra_length = read_u16(local, 28);
    fseek(file->handle, name_length + extra_length, SEEK_CUR);

    size_t to_read = (size_t) file->uncompressed_size;
    if (to_read > capacity) {
        to_read = capacity;
    }
    return fread(buffer, 1, to_read, file->handle);
}

uint32_t sb_zip_entry_crc(sb_zip_file *file) {
    return file->crc32;
}

void sb_zip_close(sb_zip_file *file) {
    if (file->handle != NULL) {
        fclose(file->handle);
        file->handle = NULL;
    }
}

int sb_zip_extract_v2_certificate(const char *apk_path, uint8_t *certificate, size_t *length) {
    FILE *file = fopen(apk_path, "rb");
    if (file == NULL) {
        return 0;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    // Find the end of central directory to locate the central directory.
    long window_start = file_size - 65557;
    if (window_start < 0) {
        window_start = 0;
    }
    uint8_t *window = (uint8_t *) malloc((size_t) (file_size - window_start));
    if (window == NULL) {
        fclose(file);
        return 0;
    }
    fseek(file, window_start, SEEK_SET);
    size_t window_size = (size_t) (file_size - window_start);
    if (fread(window, 1, window_size, file) != window_size) {
        free(window);
        fclose(file);
        return 0;
    }
    long eocd_offset = -1;
    for (long i = (long) window_size - 22; i >= 0; i--) {
        if (read_u32(window, (size_t) i) == 0x06054b50) {
            eocd_offset = i;
            break;
        }
    }
    free(window);
    if (eocd_offset < 0) {
        fclose(file);
        return 0;
    }
    uint32_t cd_offset = f_read_u32(file, window_start + eocd_offset + 16);
    if (cd_offset == 0 || cd_offset >= (uint32_t) file_size) {
        fclose(file);
        return 0;
    }

    // The signing block ends 16 bytes before the central directory header:
    // [size u64][... pairs ...][size u64]["APK Sig Block 42" 16 bytes] [CD]
    const char magic[17] = "APK Sig Block 42";
    uint8_t trailer[24];
    if (cd_offset < 24) {
        fclose(file);
        return 0;
    }
    fseek(file, (long) cd_offset - 24, SEEK_SET);
    if (fread(trailer, 1, 24, file) != 24 || memcmp(trailer + 8, magic, 16) != 0) {
        fclose(file);
        return 0;
    }
    uint64_t block_size = read_u64(trailer, 0);
    if (block_size < 32 || (uint64_t) cd_offset < block_size + 8) {
        fclose(file);
        return 0;
    }
    uint64_t block_start = (uint64_t) cd_offset - block_size - 8;

    // Walk the id-value pairs looking for the v2 signature scheme.
    uint8_t pair_header[12];
    uint64_t cursor = block_start + 8;
    uint64_t pairs_end = (uint64_t) cd_offset - 24;
    while (cursor + 12 <= pairs_end) {
        fseek(file, (long) cursor, SEEK_SET);
        if (fread(pair_header, 1, 12, file) != 12) {
            break;
        }
        uint64_t pair_length = read_u64(pair_header, 0);
        if (pair_length < 4 || cursor + 8 + pair_length > pairs_end + 8) {
            break;
        }
        uint32_t pair_id = read_u32(pair_header, 8);
        if (pair_id == 0x7109871a) {
            // v2 signer sequence: [len][signers]. Each signer:
            // [len][signed data][len][signatures][len][public key].
            // The signed data contains [len][digests][len][certificates].
            uint64_t data_start = cursor + 12;
            uint64_t data_length = pair_length - 4;
            uint8_t *data = (uint8_t *) malloc((size_t) data_length);
            if (data == NULL) {
                fclose(file);
                return 0;
            }
            fseek(file, (long) data_start, SEEK_SET);
            if (fread(data, 1, (size_t) data_length, file) != (size_t) data_length) {
                free(data);
                fclose(file);
                return 0;
            }
            uint64_t position = 0;
            uint64_t signers_length = read_u32(data, 0);
            position = 4;
            uint64_t signer_length = read_u32(data, position);
            position += 4;
            uint64_t signed_data_length = read_u32(data, position);
            position += 4 + signed_data_length;
            uint64_t signatures_length = read_u32(data, position);
            position += 4 + signatures_length;
            uint64_t public_key_length = read_u32(data, position);
            (void) public_key_length;

            // position now points to the end of the first signer record.
            uint64_t signer_start = 8;
            uint64_t sd_start = signer_start + 4;
            uint64_t digests_length = read_u32(data, sd_start);
            uint64_t certificates_offset = sd_start + 4 + digests_length;
            uint32_t certificates_length = read_u32(data, certificates_offset);
            uint32_t certificate_length = read_u32(data, certificates_offset + 4);
            if (certificate_length > 0 && certificates_offset + 8 + certificate_length <= data_length &&
                certificate_length <= 8192) {
                memcpy(certificate, data + certificates_offset + 8, certificate_length);
                *length = certificate_length;
                free(data);
                fclose(file);
                return 1;
            }
            free(data);
            fclose(file);
            return 0;
        }
        cursor += 8 + pair_length;
    }

    fclose(file);
    return 0;
}
