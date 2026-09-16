/*
 * JNI bridge of the Soulbrou runtime.
 *
 * Exposes the interpreter entry point consumed by the injected Sb helper
 * class plus introspection helpers used by the Soulbrou application for
 * engine self tests.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/soulbrou_runtime.h"
#include "soulbrou/crypto.h"

#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <string.h>

#define LOG_TAG "soulbrou-rt"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {
int sb_load_blob_from_apk(void);
uint32_t sb_blob_protection_mask(void);
int sb_chain_violated(void);
void sb_chain_key(uint32_t key[4]);
jobject sb_interpret(JNIEnv *env, const char *key, jobjectArray args);
}

/* ------------------------------------------------------------------ */
/* Entry points invoked by the generated Sb class                      */
/* ------------------------------------------------------------------ */

static jobject JNICALL sb_invoke_bridge(JNIEnv *env, jclass clazz, jstring key, jobjectArray args) {
    (void) clazz;

    // Advance the protection chain before every dispatch.
    sb_chain_step(env);
    if (sb_chain_violated()) {
        jclass violation = env->FindClass("java/lang/SecurityException");
        env->ThrowNew(violation, "soulbrou: environment check failed");
        return NULL;
    }

    const char *key_chars = env->GetStringUTFChars(key, NULL);
    if (key_chars == NULL) {
        return NULL;
    }
    jobject result = sb_interpret(env, key_chars, args);
    env->ReleaseStringUTFChars(key, key_chars);
    return result;
}

static void JNICALL sb_init_bridge(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    sb_chain_init();
    sb_load_blob_from_apk();
}

/* ------------------------------------------------------------------ */
/* Introspection used by the Soulbrou application                      */
/* ------------------------------------------------------------------ */

static jstring JNICALL sb_version_bridge(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return env->NewStringUTF(sb_runtime_version());
}

static jboolean JNICALL sb_self_test_bridge(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;

    // Cryptographic primitives round trip.
    uint32_t data[4] = {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00};
    uint32_t key[4] = {1, 2, 3, 4};
    uint32_t original[4];
    memcpy(original, data, sizeof(data));

    sb_xxtea_encrypt(data, 4, key);
    sb_xxtea_decrypt(data, 4, key);
    if (memcmp(original, data, sizeof(data)) != 0) {
        return JNI_FALSE;
    }

    // SHA-256 known answer ("abc").
    uint8_t digest[32];
    sb_sha256((const uint8_t *) "abc", 3, digest);
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    if (memcmp(digest, expected, 32) != 0) {
        return JNI_FALSE;
    }

    // CRC32 known answer ("123456789" -> 0xCBF43926).
    if (sb_crc32((const uint8_t *) "123456789", 9) != 0xCBF43926u) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static JNINativeMethod kBridgeMethods[] = {
    {"invoke", "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;", (void *) sb_invoke_bridge},
    {"initRuntime", "()V", (void *) sb_init_bridge},
};

static JNINativeMethod kAppMethods[] = {
    {"nativeVersion", "()Ljava/lang/String;", (void *) sb_version_bridge},
    {"nativeSelfTest", "()Z", (void *) sb_self_test_bridge},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // The generated helper class of protected APKs.
    jclass sbClass = env->FindClass("com/soulbrou/sb/Sb");
    if (sbClass != NULL) {
        env->RegisterNatives(sbClass, kBridgeMethods, 2);
        env->ExceptionClear();
        env->DeleteLocalRef(sbClass);
    } else {
        env->ExceptionClear();
    }

    // The Soulbrou application itself (self tests and version info).
    jclass appClass = env->FindClass("com/soulbrou/engine/NativeEngine");
    if (appClass != NULL) {
        env->RegisterNatives(appClass, kAppMethods, 2);
        env->ExceptionClear();
        env->DeleteLocalRef(appClass);
    } else {
        env->ExceptionClear();
    }

    LOGI("soulbrou runtime %s loaded", sb_runtime_version());
    return JNI_VERSION_1_6;
}
