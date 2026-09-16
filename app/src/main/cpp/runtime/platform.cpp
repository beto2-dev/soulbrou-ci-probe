/*
 * Default platform implementation backed by the real filesystem and system
 * properties. The host tests replace it through sb_platform_override.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/platform.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern "C" {

static int default_file_exists(const char *path) {
    struct stat info;
    return stat(path, &info) == 0;
}

static int default_file_contains(const char *path, const char *needle) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    char line[512];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, needle) != NULL) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

static long default_file_size(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    return size;
}

static int default_read_file(const char *path, uint8_t *buffer, size_t capacity) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }
    size_t read = fread(buffer, 1, capacity, file);
    fclose(file);
    return (int) read;
}

static int default_system_property(const char *key, char *value, size_t capacity) {
    typedef int (*prop_get_fn)(const char *, char *, const char *);
    static prop_get_fn getter = NULL;
    if (getter == NULL) {
        void *handle = dlopen("libc.so", RTLD_NOW);
        if (handle == NULL) {
            return -1;
        }
        getter = (prop_get_fn) dlsym(handle, "__system_property_get");
        if (getter == NULL) {
            return -1;
        }
    }
    int length = getter(key, value, "");
    if (length < 0) {
        return -1;
    }
    if ((size_t) length >= capacity) {
        length = (int) capacity - 1;
    }
    value[length] = '\0';
    return length;
}

static uint64_t default_monotonic_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t) now.tv_sec * 1000u + (uint64_t) now.tv_nsec / 1000000u;
}

sb_platform sb_active_platform = {
    .file_exists = default_file_exists,
    .file_contains = default_file_contains,
    .file_size = default_file_size,
    .read_file = default_read_file,
    .system_property = default_system_property,
    .monotonic_ms = default_monotonic_ms,
};

sb_platform sb_platform_override(sb_platform replacement) {
    sb_platform previous = sb_active_platform;
    sb_active_platform = replacement;
    return previous;
}

} /* extern "C" */
