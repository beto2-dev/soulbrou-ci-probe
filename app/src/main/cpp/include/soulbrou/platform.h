/*
 * Platform abstraction used by the protection checks.
 *
 * All environment access goes through this layer so the host unit tests can
 * substitute deterministic fixtures without touching the real filesystem or
 * system properties.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef SOULBROU_PLATFORM_H
#define SOULBROU_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sb_platform {
    int (*file_exists)(const char *path);
    int (*file_contains)(const char *path, const char *needle);
    long (*file_size)(const char *path);
    int (*read_file)(const char *path, uint8_t *buffer, size_t capacity);
    int (*system_property)(const char *key, char *value, size_t capacity);
    uint64_t (*monotonic_ms)(void);
} sb_platform;

/* The active platform implementation. */
extern sb_platform sb_active_platform;

/* Installs a platform override; returns the previous one. */
sb_platform sb_platform_override(sb_platform replacement);

#ifdef __cplusplus
}
#endif

#endif /* SOULBROU_PLATFORM_H */
