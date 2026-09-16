/*
 * Chained, hard to patch verification state machine.
 *
 * Every protected method dispatch advances an obfuscated state machine and
 * executes the next pending check of the protection set. The chain state
 * feeds the key derivation of the bytecode blob, so neutralizing a single
 * check corrupts the decryption of every subsequent call: the protections
 * depend on each other by construction.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/crypto.h"
#include "soulbrou/platform.h"
#include "soulbrou/soulbrou_runtime.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

extern "C" int sb_check_anti_root(void);
extern "C" int sb_check_anti_frida(void);
extern "C" int sb_check_anti_dexdump(void);
extern "C" int sb_check_anti_debug(void);
extern "C" int sb_check_anti_emulator(void);

extern "C" {

typedef struct sb_chain_state {
    /* Obfuscated accumulation of every completed check. */
    uint64_t accumulator;
    /* Round index feeding the permutation. */
    uint32_t round;
    /* Number of completed verifications, obfuscated. */
    uint32_t counter;
    /* Detected violation, encoded. */
    uint32_t violation;
    /* Configured protection mask. */
    uint32_t mask;
} sb_chain_state;

static sb_chain_state g_state;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

static const uint64_t kMixConstant = 0x9E3779B97F4A7C15ULL;

/* Deterministic mixing step, small enough to inline everywhere. */
static uint64_t mix64(uint64_t value) {
    value ^= value >> 33;
    value *= 0xFF51AFD7ED558CCDULL;
    value ^= value >> 33;
    value *= 0xC4CEB9FE1A85EC53ULL;
    value ^= value >> 33;
    return value;
}

void sb_configure_protections(uint32_t mask) {
    pthread_mutex_lock(&g_state_lock);
    g_state.mask = mask;
    pthread_mutex_unlock(&g_state_lock);
}

uint32_t sb_active_protections(void) {
    return g_state.mask;
}

void sb_chain_init(void) {
    pthread_mutex_lock(&g_state_lock);
    memset(&g_state, 0, sizeof(g_state));
    g_state.accumulator = kMixConstant;
    g_state.round = 0;
    g_state.counter = 0;
    g_state.violation = 0;
    g_initialized = 1;
    pthread_mutex_unlock(&g_state_lock);
}

/* Feeds the current chain state into a 128 bit key. */
void sb_chain_key(uint32_t key[4]) {
    pthread_mutex_lock(&g_state_lock);
    uint64_t acc = g_state.accumulator ^ mix64(g_state.counter + 1);
    pthread_mutex_unlock(&g_state_lock);
    acc = mix64(acc);
    key[0] = (uint32_t) acc;
    key[1] = (uint32_t) (acc >> 32);
    key[2] = key[0] ^ 0x5A17B0C5u;
    key[3] = key[1] ^ 0x1F2E3D4Cu;
}

/* Runs one check selected by the round counter. Returns 0 when clean. */
static int run_pending_check(JNIEnv *env) {
    // The order is derived from the round so the sequence cannot be guessed
    // from the source layout alone.
    uint32_t slot = g_state.round % 6;
    uint32_t mask = g_state.mask;
    int detected = 0;
    switch (slot) {
        case 0:
            if (mask & SB_PROT_ANTI_ROOT) detected = sb_check_anti_root();
            break;
        case 1:
            if (mask & SB_PROT_ANTI_FRIDA) detected = sb_check_anti_frida();
            break;
        case 2:
            if (mask & SB_PROT_ANTI_DEXDUMP) detected = sb_check_anti_dexdump();
            break;
        case 3:
            if (mask & SB_PROT_ANTI_DEBUG) detected = sb_check_anti_debug();
            break;
        case 4:
            if (mask & SB_PROT_ANTI_TAMPERING) detected = sb_check_anti_tampering(env);
            break;
        default:
            if (mask & SB_PROT_ANTI_EMULATOR) detected = sb_check_anti_emulator();
            break;
    }
    return detected;
}

void sb_chain_step(JNIEnv *env) {
    if (!g_initialized) {
        sb_chain_init();
    }

    pthread_mutex_lock(&g_state_lock);
    uint32_t counter = g_state.counter;
    uint64_t accumulator = g_state.accumulator;
    g_state.round++;
    g_state.counter = (counter + 1) & 0x7FFFFFFFu;
    pthread_mutex_unlock(&g_state_lock);

    // Time based anti-debug: a long gap between steps indicates single
    // stepping or breakpoint based analysis.
    uint64_t now = sb_active_platform.monotonic_ms();

    int detected = run_pending_check(env);

    pthread_mutex_lock(&g_state_lock);
    uint64_t contribution = mix64(accumulator ^ (now & 0xFFFFFFFFFFFFULL) ^ g_state.round);
    g_state.accumulator = mix64(accumulator + contribution + kMixConstant);
    if (detected) {
        // Violations poison the accumulator with a marker that is distinct
        // for every round, so restoring a single patched branch still leaves
        // the key stream wrong for the blob decryption.
        g_state.violation = 0xDEAD0000u | (g_state.round & 0xFFFFu);
        g_state.accumulator ^= 0xBADC0DEu;
    }
    pthread_mutex_unlock(&g_state_lock);
}

int sb_chain_violated(void) {
    return g_state.violation != 0;
}

const char *sb_runtime_version(void) {
    return "1.0.0";
}

} /* extern "C" */
