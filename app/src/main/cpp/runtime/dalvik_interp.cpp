/*
 * Dalvik bytecode interpreter of the Soulbrou runtime.
 *
 * Executes the protected method bodies stored in the encrypted blob inside
 * the target APK. Every dispatch advances the protection chain and the
 * decryption key is bound to the signing certificate, so a re-signed or
 * tampered APK cannot execute the protected code.
 *
 * The interpreter implements the same instruction subset accepted by the
 * smali to C translator, guaranteeing identical semantics between both
 * execution modes.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/crypto.h"
#include "soulbrou/soulbrou_runtime.h"
#include "soulbrou/zip_reader.h"

#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <jni.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "soulbrou-rt"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define MAX_REGISTERS 512
#define MAX_PAYLOADS 32
#define MAX_TRIES 32

namespace {

struct BlobMethod {
    char *key;
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    char *signature;
    uint8_t is_static;
    uint16_t *insns;
    uint32_t insns_size;
    struct TryRegion {
        uint32_t start;
        uint32_t count;
        int handler;
    } tries[MAX_TRIES];
    uint32_t try_count;
    struct Handler {
        struct Entry {
            char *type;
            uint32_t address;
        } entries[8];
        uint32_t entry_count;
        uint32_t catch_all;
        uint8_t has_catch_all;
    } handlers[16];
    uint32_t handler_count;
    char **strings;
    uint32_t string_count;
    struct MethodRef {
        char *class_name;
        char *name;
        char *signature;
    } *method_refs;
    uint32_t method_ref_count;
    struct FieldRef {
        char *class_name;
        char *name;
        char *type;
    } *field_refs;
    uint32_t field_ref_count;
    char **types;
    uint32_t type_count;
    struct Payload {
        uint32_t address;
        uint32_t length;
        uint16_t *data;
    } payloads[MAX_PAYLOADS];
    uint32_t payload_count;
};

struct BlobIndexEntry {
    uint32_t key_hash;
    uint64_t offset;
    uint32_t length;
};

struct LoadedBlob {
    uint8_t *data;
    uint64_t length;
    BlobIndexEntry *index;
    uint32_t index_count;
    uint32_t protection_mask;
    uint8_t salt[16];
    uint32_t expected_dex_crc;
    int loaded;
    int key_ready;
    uint32_t blob_key[4];
};

LoadedBlob g_blob;
pthread_mutex_t g_blob_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t hash_key(const char *key) {
    // FNV-1a, 32 bit.
    uint32_t hash = 2166136261u;
    while (*key) {
        hash ^= (uint8_t) *key++;
        hash *= 16777619u;
    }
    return hash;
}

/* ---- Blob parsing helpers ---------------------------------------- */

uint32_t read_u32_at(const uint8_t *data, size_t *cursor) {
    uint32_t value = (uint32_t) data[*cursor] | ((uint32_t) data[*cursor + 1] << 8) |
                     ((uint32_t) data[*cursor + 2] << 16) | ((uint32_t) data[*cursor + 3] << 24);
    *cursor += 4;
    return value;
}

uint16_t read_u16_at(const uint8_t *data, size_t *cursor) {
    uint16_t value = (uint16_t) (data[*cursor] | (data[*cursor + 1] << 8));
    *cursor += 2;
    return value;
}

char *read_string_at(const uint8_t *data, size_t *cursor) {
    uint16_t length = read_u16_at(data, cursor);
    char *value = (char *) malloc(length + 1);
    if (value == NULL) {
        *cursor += length;
        return NULL;
    }
    memcpy(value, data + *cursor, length);
    value[length] = '\0';
    *cursor += length;
    return value;
}

void free_method(BlobMethod *method) {
    free(method->key);
    free(method->signature);
    free(method->insns);
    for (uint32_t i = 0; i < method->handler_count; i++) {
        for (uint32_t j = 0; j < method->handlers[i].entry_count; j++) {
            free(method->handlers[i].entries[j].type);
        }
    }
    for (uint32_t i = 0; i < method->string_count; i++) {
        free(method->strings[i]);
    }
    free(method->strings);
    for (uint32_t i = 0; i < method->method_ref_count; i++) {
        free(method->method_refs[i].class_name);
        free(method->method_refs[i].name);
        free(method->method_refs[i].signature);
    }
    free(method->method_refs);
    for (uint32_t i = 0; i < method->field_ref_count; i++) {
        free(method->field_refs[i].class_name);
        free(method->field_refs[i].name);
        free(method->field_refs[i].type);
    }
    free(method->field_refs);
    for (uint32_t i = 0; i < method->type_count; i++) {
        free(method->types[i]);
    }
    free(method->types);
    for (uint32_t i = 0; i < method->payload_count; i++) {
        free(method->payloads[i].data);
    }
}

/* Decodes one method block from decrypted bytes. Returns 0 on success. */
int parse_method(const uint8_t *data, size_t length, BlobMethod *method) {
    memset(method, 0, sizeof(*method));
    size_t cursor = 0;
    if (length < 8) {
        return -1;
    }
    method->key = read_string_at(data, &cursor);
    method->registers_size = read_u16_at(data, &cursor);
    method->ins_size = read_u16_at(data, &cursor);
    method->outs_size = read_u16_at(data, &cursor);
    method->signature = read_string_at(data, &cursor);
    method->is_static = data[cursor++];
    method->insns_size = read_u32_at(data, &cursor);
    if (cursor + method->insns_size * 2 > length) {
        return -1;
    }
    method->insns = (uint16_t *) malloc(method->insns_size * 2);
    if (method->insns == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < method->insns_size; i++) {
        method->insns[i] = read_u16_at(data, &cursor);
    }

    method->try_count = read_u32_at(data, &cursor);
    if (method->try_count > MAX_TRIES) {
        return -1;
    }
    for (uint32_t i = 0; i < method->try_count; i++) {
        method->tries[i].start = read_u32_at(data, &cursor);
        method->tries[i].count = read_u16_at(data, &cursor);
        method->tries[i].handler = read_u16_at(data, &cursor);
    }

    method->handler_count = read_u32_at(data, &cursor);
    if (method->handler_count > 16) {
        return -1;
    }
    for (uint32_t i = 0; i < method->handler_count; i++) {
        uint8_t encoded = data[cursor++];
        method->handlers[i].has_catch_all = encoded & 0x80 ? 1 : 0;
        method->handlers[i].entry_count = encoded & 0x7F;
        if (method->handlers[i].entry_count > 8) {
            return -1;
        }
        for (uint32_t j = 0; j < method->handlers[i].entry_count; j++) {
            method->handlers[i].entries[j].type = read_string_at(data, &cursor);
            method->handlers[i].entries[j].address = read_u32_at(data, &cursor);
        }
        if (method->handlers[i].has_catch_all) {
            method->handlers[i].catch_all = read_u32_at(data, &cursor);
        }
    }

    method->string_count = read_u32_at(data, &cursor);
    method->strings = (char **) calloc(method->string_count + 1, sizeof(char *));
    for (uint32_t i = 0; i < method->string_count; i++) {
        method->strings[i] = read_string_at(data, &cursor);
    }

    method->method_ref_count = read_u32_at(data, &cursor);
    method->method_refs = (BlobMethod::MethodRef *) calloc(method->method_ref_count + 1, sizeof(*method->method_refs));
    for (uint32_t i = 0; i < method->method_ref_count; i++) {
        method->method_refs[i].class_name = read_string_at(data, &cursor);
        method->method_refs[i].name = read_string_at(data, &cursor);
        method->method_refs[i].signature = read_string_at(data, &cursor);
    }

    method->field_ref_count = read_u32_at(data, &cursor);
    method->field_refs = (BlobMethod::FieldRef *) calloc(method->field_ref_count + 1, sizeof(*method->field_refs));
    for (uint32_t i = 0; i < method->field_ref_count; i++) {
        method->field_refs[i].class_name = read_string_at(data, &cursor);
        method->field_refs[i].name = read_string_at(data, &cursor);
        method->field_refs[i].type = read_string_at(data, &cursor);
    }

    method->type_count = read_u32_at(data, &cursor);
    method->types = (char **) calloc(method->type_count + 1, sizeof(char *));
    for (uint32_t i = 0; i < method->type_count; i++) {
        method->types[i] = read_string_at(data, &cursor);
    }

    method->payload_count = read_u32_at(data, &cursor);
    if (method->payload_count > MAX_PAYLOADS) {
        return -1;
    }
    for (uint32_t i = 0; i < method->payload_count; i++) {
        method->payloads[i].address = read_u32_at(data, &cursor);
        method->payloads[i].length = read_u32_at(data, &cursor);
        method->payloads[i].data = (uint16_t *) malloc(method->payloads[i].length);
        for (uint32_t u = 0; u < method->payloads[i].length / 2; u++) {
            method->payloads[i].data[u] = read_u16_at(data, &cursor);
        }
    }
    return 0;
}

/* Locates the payload that starts at the given address. */
const BlobMethod::Payload *find_payload(const BlobMethod *method, uint32_t address) {
    for (uint32_t i = 0; i < method->payload_count; i++) {
        if (method->payloads[i].address == address) {
            return &method->payloads[i];
        }
    }
    return NULL;
}

/* Instruction size table for the supported subset. */
int insn_size(uint16_t opcode) {
    switch (opcode) {
        case 0x00: case 0x01: case 0x04: case 0x07: case 0x0a: case 0x0b: case 0x0c:
        case 0x0d: case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12:
        case 0x1d: case 0x1e: case 0x21: case 0x27: case 0x28:
        case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f: case 0x80:
        case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
        case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c:
        case 0x8d: case 0x8e: case 0x8f:
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5:
        case 0xb6: case 0xb7: case 0xb8: case 0xb9: case 0xba: case 0xbb:
        case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
        case 0xc2: case 0xc3: case 0xc4: case 0xc5: case 0xc6: case 0xc7:
        case 0xc8: case 0xc9: case 0xca: case 0xcb: case 0xcc: case 0xcd:
        case 0xce: case 0xcf:
            return 1;
        case 0x02: case 0x05: case 0x08: case 0x13: case 0x15: case 0x16:
        case 0x19: case 0x1a: case 0x1c: case 0x1f: case 0x22:
        case 0x29: case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d:
        case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
        case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66:
        case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d:
        case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5:
        case 0xd6: case 0xd7: case 0xd8: case 0xd9: case 0xda: case 0xdb:
        case 0xdc: case 0xdd: case 0xde: case 0xdf: case 0xe0: case 0xe1: case 0xe2:
        case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x20: case 0x23:
            return 2;
        case 0x03: case 0x06: case 0x09: case 0x6e: case 0x6f: case 0x70:
        case 0x71: case 0x72: case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
        case 0x14: case 0x17: case 0x24: case 0x25: case 0x26: case 0x2b: case 0x2c:
        case 0x2a:
            return 3;
        case 0x18:
            return 5;
        default:
            return -1;
    }
}

struct InterpState {
    JNIEnv *env;
    BlobMethod *method;
    SB regs[MAX_REGISTERS];
    SB ret;
    uint32_t pc;
};

/* Runs the handler dispatch for the current pending exception. */
int dispatch_exception(InterpState *state, jthrowable exception) {
    BlobMethod *method = state->method;
    state->env->ExceptionClear();
    for (uint32_t i = 0; i < method->try_count; i++) {
        const BlobMethod::TryRegion &region = method->tries[i];
        if (state->pc >= region.start && state->pc < region.start + region.count) {
            const BlobMethod::Handler &handler = method->handlers[region.handler];
            for (uint32_t j = 0; j < handler.entry_count; j++) {
                if (sb_is_a(state->env, exception, handler.entries[j].type)) {
                    state->pc = handler.entries[j].address;
                    return 0;
                }
            }
            if (handler.has_catch_all) {
                state->pc = handler.catch_all;
                return 0;
            }
        }
    }
    // Not handled: rethrow to the caller.
    state->env->Throw(exception);
    return -1;
}

/* Complex opcode executor: arithmetic, branches, invokes, fields, arrays. */
int execute_complex(
    InterpState *state, uint16_t opcode, uint8_t a4, uint8_t a8, uint8_t b4,
    uint16_t u1, uint16_t u2, uint16_t u3, int32_t i32, uint32_t *pc,
    jvalue *call_args, SB *values);

/* Main interpreter loop. Returns the boxed result or NULL. */
jobject interpret(InterpState *state) {
    JNIEnv *env = state->env;
    BlobMethod *method = state->method;
    uint32_t pc = 0;
    const uint16_t *insns = method->insns;
    jvalue call_args[8];
    SB values[8];

    while (pc < method->insns_size) {
        uint16_t unit = insns[pc];
        uint16_t opcode = unit & 0xFF;
        uint8_t a8 = (unit >> 8) & 0xFF;
        uint8_t a4 = (unit >> 8) & 0xF;
        uint8_t b4 = (unit >> 12) & 0xF;
        int size = insn_size(opcode);
        if (size < 0) {
            LOGE("unsupported opcode 0x%02x at %u", opcode, pc);
            jclass cls = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(cls, "soulbrou: unsupported opcode");
            return NULL;
        }
        uint16_t u1 = (size > 1 && pc + 1 < method->insns_size) ? insns[pc + 1] : 0;
        uint16_t u2 = (size > 2 && pc + 2 < method->insns_size) ? insns[pc + 2] : 0;
        uint16_t u3 = (size > 3 && pc + 3 < method->insns_size) ? insns[pc + 3] : 0;
        int32_t i32 = (int32_t) (((uint32_t) u1) | (((uint32_t) (size > 2 ? insns[pc + 2] : 0)) << 16));

        switch (opcode) {
            case 0x00: /* nop */ break;
            case 0x01: case 0x04: case 0x07: /* move */ state->regs[a4] = state->regs[b4]; break;
            case 0x02: case 0x05: case 0x08: state->regs[a8] = state->regs[u1]; break;
            case 0x03: case 0x06: case 0x09: state->regs[a8] = state->regs[u1]; break;
            case 0x0a: case 0x0b: case 0x0c: state->regs[a8] = state->ret; break;
            case 0x0d: state->regs[a8] = SB_O(sb_move_exception(env)); break;
            case 0x0e: return NULL;
            case 0x0f: case 0x10: case 0x11: {
                const char *sig = method->signature;
                const char *ret = strrchr(sig, ')');
                char ret_kind = ret != NULL && ret[1] != '\0' ? ret[1] : 'V';
                return sb_box(env, state->regs[a8], ret_kind == 'V' ? 'I' : ret_kind);
            }
            case 0x12: case 0x13: {
                int32_t value = opcode == 0x12 ? ((int32_t) ((int8_t) b4)) : (int16_t) u1;
                state->regs[a8] = SB_I(value);
                break;
            }
            case 0x14: state->regs[a8] = SB_I(i32); break;
            case 0x15: state->regs[a8] = SB_I(((int32_t) ((int16_t) u1)) << 16); break;
            case 0x16: state->regs[a8] = SB_I(((int32_t) ((int16_t) u1)) << 16); break;
            case 0x17: {
                int64_t value = (int64_t) ((int32_t) ((int16_t) u1));
                state->regs[a8] = SB_J(value);
                break;
            }
            case 0x18: {
                uint64_t raw = 0;
                for (int i = 0; i < 4; i++) {
                    raw |= ((uint64_t) insns[pc + 1 + i]) << (i * 16);
                }
                state->regs[a8] = SB_J((int64_t) raw);
                break;
            }
            case 0x19: {
                int64_t value = (int64_t) ((int32_t) ((int16_t) u1));
                state->regs[a8] = SB_J(value << 48);
                break;
            }
            case 0x1a: case 0x1b: {
                const char *text = method->strings[u1];
                state->regs[a8] = SB_O(sb_new_string(env, text != NULL ? text : ""));
                break;
            }
            case 0x1c: {
                state->regs[a8] = SB_O(sb_const_class(env, method->types[u1]));
                break;
            }
            case 0x1d: sb_monitor(env, state->regs[a8].o, 1); break;
            case 0x1e: sb_monitor(env, state->regs[a8].o, 0); break;
            case 0x1f: {
                state->regs[a8] = SB_O(sb_check_cast(env, state->regs[a8].o, method->types[u1]));
                break;
            }
            case 0x20: {
                state->regs[a4] = SB_I(sb_instance_of(env, state->regs[b4].o, method->types[u1]));
                break;
            }
            case 0x21: {
                state->regs[a4] = SB_I(sb_array_length(env, state->regs[b4].o));
                break;
            }
            case 0x22: {
                state->regs[a4] = SB_O(sb_new_instance(env, method->types[u1]));
                break;
            }
            case 0x23: {
                const char *type = method->types[u1];
                char kind = type[0] == '[' ? type[1] : 'L';
                state->regs[a4] = SB_O(sb_new_array(env, state->regs[b4].i, kind));
                break;
            }
            case 0x28: {
                pc = (uint32_t) ((int32_t) pc + (int8_t) a8);
                continue;
            }
            case 0x29: {
                pc = (uint32_t) ((int32_t) pc + (int16_t) u1);
                continue;
            }
            case 0x2a: {
                pc = (uint32_t) ((int32_t) pc + i32);
                continue;
            }
            default: {
                /* Complex ops are handled through the shared executor. */
                if (!execute_complex(state, opcode, a4, a8, b4, u1, u2, u3, i32, &pc, call_args, values)) {
                    return NULL;
                }
                if (env->ExceptionCheck()) {
                    jthrowable pending = env->ExceptionOccurred();
                    if (dispatch_exception(state, pending) != 0) {
                        return NULL;
                    }
                    continue;
                }
                break;
            }
        }
        pc += (uint32_t) size;
    }
    return NULL;
}

/* Complex opcode executor: arithmetic, branches, invokes, fields, arrays. */
int execute_complex(
    InterpState *state, uint16_t opcode, uint8_t a4, uint8_t a8, uint8_t b4,
    uint16_t u1, uint16_t u2, uint16_t u3, int32_t i32, uint32_t *pc,
    jvalue *call_args, SB *values) {
    JNIEnv *env = state->env;
    BlobMethod *method = state->method;
    SB *regs = state->regs;

    switch (opcode) {
        case 0x2b: case 0x2c: {
            /* packed-switch / sparse-switch */
            const uint32_t payload_addr = (uint32_t) ((int32_t) *pc + i32);
            const BlobMethod::Payload *payload = find_payload(method, payload_addr);
            if (payload == NULL) {
                jclass cls = env->FindClass("java/lang/RuntimeException");
                env->ThrowNew(cls, "soulbrou: missing switch payload");
                return 0;
            }
            uint16_t ident = payload->data[0];
            const uint16_t *data = payload->data;
            if (ident == 0x0100) {
                uint16_t count = data[1];
                int32_t first_key = (int32_t) (((uint32_t) data[2]) | (((uint32_t) data[3]) << 16));
                int32_t key = regs[a8].i - first_key;
                if (key >= 0 && key < count) {
                    uint32_t target = (uint32_t) (((uint32_t) data[4 + key * 2]) | (((uint32_t) data[5 + key * 2]) << 16));
                    *pc = target;
                    return 1;
                }
            } else if (ident == 0x0200) {
                uint16_t count = data[1];
                for (uint16_t i = 0; i < count; i++) {
                    if ((uint16_t) regs[a8].i == data[2 + i]) {
                        uint32_t target = (uint32_t) (((uint32_t) data[2 + count + i * 2]) |
                                                      (((uint32_t) data[3 + count + i * 2]) << 16));
                        *pc = target;
                        return 1;
                    }
                }
            }
            return 1; /* no match: fall through */
        }
        case 0x2d: case 0x2e: {
            jint result = opcode == 0x2d ? sb_cmpl_float(regs[b4].f, regs[u1 & 0xFF].f)
                                       : sb_cmpg_float(regs[b4].f, regs[u1 & 0xFF].f);
            regs[a8] = SB_I(result);
            return 1;
        }
        case 0x2f: case 0x30: {
            jint result = opcode == 0x2f ? sb_cmpl_double(regs[b4].d, regs[u1 & 0xFF].d)
                                         : sb_cmpg_double(regs[b4].d, regs[u1 & 0xFF].d);
            regs[a8] = SB_I(result);
            return 1;
        }
        case 0x31: {
            jlong x = regs[b4].j, y = regs[u1 & 0xFF].j;
            regs[a8] = SB_I(x < y ? -1 : (x > y ? 1 : 0));
            return 1;
        }
        case 0x32: if (regs[a4].i == regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x33: if (regs[a4].i != regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x34: if (regs[a4].i < regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x35: if (regs[a4].i >= regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x36: if (regs[a4].i > regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x37: if (regs[a4].i <= regs[b4].i) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x38: if (regs[a8].i == 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x39: if (regs[a8].i != 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x3a: if (regs[a8].i < 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x3b: if (regs[a8].i >= 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x3c: if (regs[a8].i > 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;
        case 0x3d: if (regs[a8].i <= 0) { *pc = (uint32_t) ((int32_t) *pc + (int16_t) u1); } return 1;

        case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
            char kind = opcode == 0x45 ? 'J' : (opcode == 0x46 ? 'L' : 'I');
            regs[a8] = sb_aget(env, regs[u1 & 0xFF].o, regs[(u1 >> 8) & 0xFF].i, kind);
            return 1;
        }
        case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
            char kind = opcode == 0x4c ? 'J' : (opcode == 0x4d ? 'L' : 'I');
            sb_aput(env, regs[u1 & 0xFF].o, regs[(u1 >> 8) & 0xFF].i, kind, regs[a8]);
            return 1;
        }
        case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
            const BlobMethod::FieldRef &field = method->field_refs[u1];
            regs[a4] = sb_iget(env, regs[b4].o, field.class_name, field.name, field.type);
            return 1;
        }
        case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
            const BlobMethod::FieldRef &field = method->field_refs[u1];
            sb_iput(env, regs[b4].o, field.class_name, field.name, field.type, regs[a4]);
            return 1;
        }
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
            const BlobMethod::FieldRef &field = method->field_refs[u1];
            regs[a8] = sb_sget(env, field.class_name, field.name, field.type);
            return 1;
        }
        case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
            const BlobMethod::FieldRef &field = method->field_refs[u1];
            sb_sput(env, field.class_name, field.name, field.type, regs[a8]);
            return 1;
        }
        case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:
        case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
            int kind = SB_INVOKE_VIRTUAL;
            switch (opcode & 0x07) {
                case 0x06: kind = SB_INVOKE_STATIC; break;
                case 0x07: kind = SB_INVOKE_DIRECT; break;
                default: break;
            }
            if (opcode == 0x6f || opcode == 0x75) kind = SB_INVOKE_SUPER;
            if (opcode == 0x72 || opcode == 0x78) kind = SB_INVOKE_INTERFACE;

            const BlobMethod::MethodRef &target = method->method_refs[u1];
            char ret_kind = 'V';
            const char *close = strrchr(target.signature, ')');
            if (close != NULL && close[1] != '\0') {
                ret_kind = close[1] == '[' ? 'L' : close[1];
            }

            int count = (opcode == 0x24) ? 0 : 0;
            (void) count;
            int arg_count = a4; /* 35c: A = count */
            if (opcode >= 0x74) {
                arg_count = a8; /* 3rc: AA = count */
            }

            /* Build the argument list from the register window. */
            int first = 0;
            jobject receiver = NULL;
            if (kind != SB_INVOKE_STATIC) {
                first = 1;
            }
            /* Parse parameter types to advance wide registers. */
            const char *sig = target.signature;
            int reg_cursor = 0;
            int arg_index = 0;
            int list_base[8];
            if (opcode >= 0x74) {
                for (int i = 0; i < arg_count; i++) list_base[i] = u2 + i;
            } else {
                uint16_t packed = u2;
                for (int i = 0; i < arg_count && i < 4; i++) {
                    list_base[i] = (packed >> (i * 4)) & 0xF;
                }
                if (arg_count == 5) {
                    list_base[4] = b4;
                }
            }
            /* Receiver first for instance calls. */
            if (kind != SB_INVOKE_STATIC) {
                receiver = regs[list_base[0]].o;
                reg_cursor = 1;
            }
            while (sig[arg_index] != '(') arg_index++;
            arg_index++;
            int out_index = 0;
            while (sig[arg_index] != ')' && sig[arg_index] != '\0') {
                char type = sig[arg_index];
                int width = 1;
                if (type == 'L') {
                    while (sig[arg_index] != ';') arg_index++;
                    arg_index++;
                    type = 'L';
                } else if (type == '[') {
                    while (sig[arg_index] == '[') arg_index++;
                    if (sig[arg_index] == 'L') {
                        while (sig[arg_index] != ';') arg_index++;
                    }
                    arg_index++;
                    type = 'L';
                } else {
                    arg_index++;
                }
                if (type == 'J') {
                    call_args[out_index].j = regs[list_base[reg_cursor]].j;
                    width = 2;
                } else if (type == 'F') {
                    call_args[out_index].f = regs[list_base[reg_cursor]].f;
                } else if (type == 'D') {
                    call_args[out_index].d = regs[list_base[reg_cursor]].d;
                    width = 2;
                } else if (type == 'L') {
                    call_args[out_index].l = regs[list_base[reg_cursor]].o;
                } else {
                    call_args[out_index].i = regs[list_base[reg_cursor]].i;
                }
                out_index++;
                reg_cursor += width;
            }
            state->ret = sb_invoke(env, kind, receiver, target.class_name, target.name,
                                   target.signature, ret_kind, call_args);
            return 1;
        }
        case 0x24: case 0x25: {
            /* filled-new-array: gather values from the register list. */
            int count = a4;
            const char *type = method->types[u1];
            char kind = type[0] == '[' ? type[1] : 'L';
            if (opcode == 0x25) count = a8;
            for (int i = 0; i < count && i < 8; i++) {
                int register_index = opcode == 0x24
                    ? ((u2 >> (i * 4)) & 0xF)
                    : u2 + i;
                if (opcode == 0x24 && i == 4) register_index = b4;
                values[i] = regs[register_index];
            }
            state->ret = SB_O(sb_filled_new_array(env, type, values, count, kind));
            return 1;
        }
        case 0x26: {
            /* fill-array-data */
            const uint32_t payload_addr = (uint32_t) ((int32_t) *pc + i32);
            const BlobMethod::Payload *payload = find_payload(method, payload_addr);
            if (payload == NULL) {
                jclass cls = env->FindClass("java/lang/RuntimeException");
                env->ThrowNew(cls, "soulbrou: missing array payload");
                return 0;
            }
            uint16_t width = payload->data[1];
            uint32_t count = (uint32_t) (((uint32_t) payload->data[2]) | (((uint32_t) payload->data[3]) << 16));
            sb_fill_array_data(env, regs[a8].o, (const unsigned char *) (payload->data + 4),
                               (jint) (count * width), width);
            return 1;
        }
        case 0x27: {
            sb_throw(env, regs[a8].o);
            return 0;
        }
        case 0x7b: regs[a8] = SB_I(-regs[b4].i); return 1;
        case 0x7c: regs[a8] = SB_I(~regs[b4].i); return 1;
        case 0x7d: regs[a8] = SB_J(-regs[b4].j); return 1;
        case 0x7e: regs[a8] = SB_J(~regs[b4].j); return 1;
        case 0x7f: regs[a8] = SB_F(-regs[b4].f); return 1;
        case 0x80: regs[a8] = SB_D(-regs[b4].d); return 1;
        case 0x81: regs[a8] = SB_J((jlong) regs[b4].i); return 1;
        case 0x82: regs[a8] = SB_F((jfloat) regs[b4].i); return 1;
        case 0x83: regs[a8] = SB_D((jdouble) regs[b4].i); return 1;
        case 0x84: regs[a8] = SB_I((jint) regs[b4].j); return 1;
        case 0x85: regs[a8] = SB_F(sb_l2f(regs[b4].j)); return 1;
        case 0x86: regs[a8] = SB_D((jdouble) regs[b4].j); return 1;
        case 0x87: regs[a8] = SB_I(sb_f2i(regs[b4].f)); return 1;
        case 0x88: regs[a8] = SB_J(sb_f2l(regs[b4].f)); return 1;
        case 0x89: regs[a8] = SB_D((jdouble) regs[b4].f); return 1;
        case 0x8a: regs[a8] = SB_I(sb_d2i(regs[b4].d)); return 1;
        case 0x8b: regs[a8] = SB_J(sb_d2l(regs[b4].d)); return 1;
        case 0x8c: regs[a8] = SB_F((jfloat) regs[b4].d); return 1;
        case 0x8d: regs[a8] = SB_I((jint) (jbyte) regs[b4].i); return 1;
        case 0x8e: regs[a8] = SB_I((jint) (jchar) regs[b4].i); return 1;
        case 0x8f: regs[a8] = SB_I((jint) (jshort) regs[b4].i); return 1;
        default: break;
    }

    if (opcode >= 0x90 && opcode <= 0xaf) {
        /* Three address arithmetic. */
        jint x = regs[b4].i;
        jint y = regs[(u1 >> 8) & 0xFF].i;
        jlong xl = regs[b4].j;
        jlong yl = regs[(u1 >> 8) & 0xFF].j;
        jfloat xf = regs[b4].f;
        jfloat yf = regs[(u1 >> 8) & 0xFF].f;
        jdouble xd = regs[b4].d;
        jdouble yd = regs[(u1 >> 8) & 0xFF].d;
        switch (opcode) {
            case 0x90: regs[a8] = SB_I(sb_add_i(x, y)); return 1;
            case 0x91: regs[a8] = SB_I(sb_sub_i(x, y)); return 1;
            case 0x92: regs[a8] = SB_I(sb_mul_i(x, y)); return 1;
            case 0x93: regs[a8] = SB_I(sb_div_i(env, x, y)); return 1;
            case 0x94: regs[a8] = SB_I(sb_rem_i(env, x, y)); return 1;
            case 0x95: regs[a8] = SB_I(sb_and_i(x, y)); return 1;
            case 0x96: regs[a8] = SB_I(sb_or_i(x, y)); return 1;
            case 0x97: regs[a8] = SB_I(sb_xor_i(x, y)); return 1;
            case 0x98: regs[a8] = SB_I(sb_shl_i(x, y)); return 1;
            case 0x99: regs[a8] = SB_I(sb_shr_i(x, y)); return 1;
            case 0x9a: regs[a8] = SB_I(sb_ushr_i(x, y)); return 1;
            case 0x9b: regs[a8] = SB_J(sb_add_l(xl, yl)); return 1;
            case 0x9c: regs[a8] = SB_J(sb_sub_l(xl, yl)); return 1;
            case 0x9d: regs[a8] = SB_J(sb_mul_l(xl, yl)); return 1;
            case 0x9e: regs[a8] = SB_J(sb_div_l(env, xl, yl)); return 1;
            case 0x9f: regs[a8] = SB_J(sb_rem_l(env, xl, yl)); return 1;
            case 0xa0: regs[a8] = SB_J(sb_and_l(xl, yl)); return 1;
            case 0xa1: regs[a8] = SB_J(sb_or_l(xl, yl)); return 1;
            case 0xa2: regs[a8] = SB_J(sb_xor_l(xl, yl)); return 1;
            case 0xa3: regs[a8] = SB_J(sb_shl_l(xl, yl)); return 1;
            case 0xa4: regs[a8] = SB_J(sb_shr_l(xl, yl)); return 1;
            case 0xa5: regs[a8] = SB_J(sb_ushr_l(xl, yl)); return 1;
            case 0xa6: regs[a8] = SB_F(sb_add_f(xf, yf)); return 1;
            case 0xa7: regs[a8] = SB_F(sb_sub_f(xf, yf)); return 1;
            case 0xa8: regs[a8] = SB_F(sb_mul_f(xf, yf)); return 1;
            case 0xa9: regs[a8] = SB_F(sb_div_f(xf, yf)); return 1;
            case 0xaa: regs[a8] = SB_F(sb_rem_f(xf, yf)); return 1;
            case 0xab: regs[a8] = SB_D(sb_add_d(xd, yd)); return 1;
            case 0xac: regs[a8] = SB_D(sb_sub_d(xd, yd)); return 1;
            case 0xad: regs[a8] = SB_D(sb_mul_d(xd, yd)); return 1;
            case 0xae: regs[a8] = SB_D(sb_div_d(xd, yd)); return 1;
            default: regs[a8] = SB_D(sb_rem_d(xd, yd)); return 1;
        }
    }

    if (opcode >= 0xb0 && opcode <= 0xcf) {
        /* Two address arithmetic: vA = vA op vB. */
        return execute_complex(state, (uint16_t) (opcode - 0x20), a8, a8, b4, u1, u2, u3, i32, pc, call_args, values);
    }

    if (opcode >= 0xd0 && opcode <= 0xe2) {
        /* Literal arithmetic: vA = vB op literal. */
        jint literal = opcode <= 0xd7 ? (jint) (int16_t) u1 : (jint) (int8_t) u1;
        jint x = regs[a8].i;
        jint result;
        switch (opcode) {
            case 0xd0: case 0xd8: result = sb_add_i(x, literal); break;
            case 0xd1: case 0xd9: result = sb_sub_i(literal, x); break; /* rsub */
            case 0xd2: case 0xda: result = sb_mul_i(x, literal); break;
            case 0xd3: case 0xdb: result = sb_div_i(env, x, literal); break;
            case 0xd4: case 0xdc: result = sb_rem_i(env, x, literal); break;
            case 0xd5: case 0xdd: result = sb_and_i(x, literal); break;
            case 0xd6: case 0xde: result = sb_or_i(x, literal); break;
            case 0xd7: case 0xdf: result = sb_xor_i(x, literal); break;
            case 0xe0: result = sb_shl_i(x, literal); break;
            case 0xe1: result = sb_shr_i(x, literal); break;
            default: result = sb_ushr_i(x, literal); break;
        }
        regs[b4] = SB_I(result);
        return 1;
    }

    jclass cls = env->FindClass("java/lang/RuntimeException");
    env->ThrowNew(cls, "soulbrou: unsupported opcode");
    return 0;
}

} /* namespace */

/* Public entry used by the injected Sb helper class. */
extern "C" jobject sb_interpret(JNIEnv *env, const char *key, jobjectArray args) {
    pthread_mutex_lock(&g_blob_lock);
    if (!g_blob.loaded || !g_blob.key_ready) {
        pthread_mutex_unlock(&g_blob_lock);
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        env->ThrowNew(cls, "soulbrou: runtime blob not initialized");
        return NULL;
    }
    uint32_t hash = hash_key(key);
    const uint8_t *block = NULL;
    uint32_t block_length = 0;
    for (uint32_t i = 0; i < g_blob.index_count; i++) {
        if (g_blob.index[i].key_hash == hash) {
            block = g_blob.data + g_blob.index[i].offset;
            block_length = g_blob.index[i].length;
            break;
        }
    }
    pthread_mutex_unlock(&g_blob_lock);

    if (block == NULL) {
        jclass cls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(cls, "soulbrou: unknown method key");
        return NULL;
    }

    /* Decrypt: the block includes its own padding to a 4 byte multiple. */
    uint8_t *plain = (uint8_t *) malloc(block_length);
    if (plain == NULL) {
        jclass cls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(cls, "soulbrou: out of memory");
        return NULL;
    }
    memcpy(plain, block, block_length);
    sb_xxtea_decrypt((uint32_t *) plain, block_length / 4, g_blob.blob_key);

    BlobMethod method;
    if (parse_method(plain, block_length, &method) != 0) {
        free(plain);
        jclass cls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(cls, "soulbrou: corrupted method blob");
        return NULL;
    }

    InterpState state;
    state.env = env;
    state.method = &method;
    state.pc = 0;
    if (method.registers_size > MAX_REGISTERS) {
        free(plain);
        free_method(&method);
        jclass cls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(cls, "soulbrou: register limit");
        return NULL;
    }

    /* Map the boxed arguments onto the register window. */
    jsize arg_count = args != NULL ? env->GetArrayLength(args) : 0;
    const char *sig = method.signature;
    int sig_index = 0;
    while (sig[sig_index] != '(') sig_index++;
    sig_index++;
    int register_cursor = method.registers_size - method.ins_size;
    if (!method.is_static) {
        state.regs[register_cursor] = SB_O(env->GetObjectArrayElement(args, 0));
        register_cursor += 1;
        arg_count = arg_count;
    }
    int arg_position = method.is_static ? 0 : 1;
    while (sig[sig_index] != ')' && sig[sig_index] != '\0') {
        char type = sig[sig_index];
        if (type == 'L') {
            while (sig[sig_index] != ';') sig_index++;
            sig_index++;
            type = 'L';
        } else if (type == '[') {
            while (sig[sig_index] == '[') sig_index++;
            if (sig[sig_index] == 'L') {
                while (sig[sig_index] != ';') sig_index++;
            }
            sig_index++;
            type = 'L';
        } else {
            sig_index++;
        }
        jobject boxed = env->GetObjectArrayElement(args, arg_position);
        state.regs[register_cursor] = sb_unbox(env, boxed, type);
        register_cursor += (type == 'J' || type == 'D') ? 2 : 1;
        arg_position++;
    }

    jobject result = interpret(&state);

    free(plain);
    free_method(&method);
    return result;
}

/* Installs the blob previously read from the APK assets. */
extern "C" int sb_install_blob(const uint8_t *data, uint64_t length, const uint8_t *certificate_sha256) {
    if (length < 40) {
        return 0;
    }
    if (memcmp(data, "SBBL", 4) != 0) {
        return 0;
    }
    size_t cursor = 4;
    uint32_t version = read_u32_at(data, &cursor);
    if (version != 1) {
        return 0;
    }
    uint32_t mask = read_u32_at(data, &cursor);
    memcpy(g_blob.salt, data + cursor, 16);
    cursor += 16;
    uint32_t expected_crc = read_u32_at(data, &cursor);
    uint32_t index_count = read_u32_at(data, &cursor);
    uint32_t index_offset = read_u32_at(data, &cursor);

    g_blob.protection_mask = mask;
    g_blob.expected_dex_crc = expected_crc;
    g_blob.index_count = index_count;
    g_blob.index = (BlobIndexEntry *) malloc(sizeof(BlobIndexEntry) * index_count);
    if (g_blob.index == NULL) {
        return 0;
    }
    size_t index_cursor = index_offset;
    for (uint32_t i = 0; i < index_count; i++) {
        g_blob.index[i].key_hash = read_u32_at(data, &index_cursor);
        g_blob.index[i].offset = ((uint64_t) read_u32_at(data, &index_cursor)) |
                                 (((uint64_t) read_u32_at(data, &index_cursor)) << 32);
        g_blob.index[i].length = read_u32_at(data, &index_cursor);
    }

    g_blob.data = (uint8_t *) malloc((size_t) length);
    if (g_blob.data == NULL) {
        free(g_blob.index);
        g_blob.index = NULL;
        return 0;
    }
    memcpy(g_blob.data, data, (size_t) length);
    g_blob.length = length;

    /* Derive the blob key from the certificate fingerprint and salt. */
    uint8_t material[48];
    memcpy(material, certificate_sha256, 32);
    memcpy(material + 32, g_blob.salt, 16);
    uint8_t digest[32];
    sb_sha256_hmac(material, 48, (const uint8_t *) "soulbrou-blob-v1", 16, digest);
    memcpy(g_blob.blob_key, digest, 16);
    g_blob.key_ready = 1;
    g_blob.loaded = 1;
    return 1;
}

/* Reads the blob and certificate from the APK that contains this library. */
extern "C" int sb_load_blob_from_apk(void) {
    char apk_path[512];
    Dl_info info;
    if (dladdr((void *) &sb_load_blob_from_apk, &info) == 0 || info.dli_fname == NULL) {
        return 0;
    }
    const char *path = info.dli_fname;
    if (strstr(path, ".apk") != NULL) {
        snprintf(apk_path, sizeof(apk_path), "%s", path);
        char *bang = strchr(apk_path, '!');
        if (bang != NULL) {
            *bang = '\0';
        }
    } else {
        const char *lib = strstr(path, "/lib/");
        if (lib == NULL) {
            return 0;
        }
        size_t base = (size_t) (lib - path);
        if (base + 16 >= sizeof(apk_path)) {
            return 0;
        }
        memcpy(apk_path, path, base);
        memcpy(apk_path + base, "/base.apk", 10);
    }

    sb_zip_file entry;
    if (!sb_zip_open(&entry, apk_path, "assets/soulbrou_blob.bin")) {
        return 0;
    }
    size_t capacity = (size_t) entry.uncompressed_size;
    uint8_t *data = (uint8_t *) malloc(capacity);
    if (data == NULL || sb_zip_read(&entry, data, capacity) != capacity) {
        free(data);
        sb_zip_close(&entry);
        return 0;
    }
    sb_zip_close(&entry);

    uint8_t certificate[64];
    size_t certificate_length = 0;
    if (!sb_zip_extract_v2_certificate(apk_path, certificate, &certificate_length)) {
        free(data);
        return 0;
    }
    uint8_t cert_hash[32];
    sb_sha256(certificate, certificate_length, cert_hash);

    int installed = sb_install_blob(data, capacity, cert_hash);
    free(data);
    return installed;
}

extern "C" uint32_t sb_blob_protection_mask(void) {
    return g_blob.protection_mask;
}
