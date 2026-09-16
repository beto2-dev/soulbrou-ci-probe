/*
 * Soulbrou native runtime core.
 *
 * Implements the object model bridge (try frames, reflection cached JNI
 * operations, arithmetic with Java edge case semantics) shared by translated
 * code and the bytecode interpreter.
 *
 * Copyright 2025-2026 beto2-dev
 * Licensed under the Apache License, Version 2.0.
 */

#include "soulbrou/soulbrou_runtime.h"

#include <android/log.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "soulbrou-rt"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

pthread_key_t g_frame_key;
pthread_once_t g_frame_once = PTHREAD_ONCE_INIT;

void sb_frame_init() {
    pthread_key_create(&g_frame_key, NULL);
}

sb_frame *current_top() {
    pthread_once(&g_frame_once, sb_frame_init);
    return static_cast<sb_frame *>(pthread_getspecific(g_frame_key));
}

void set_top(sb_frame *frame) {
    pthread_setspecific(g_frame_key, frame);
}

void throw_class(JNIEnv *env, const char *class_name, const char *message) {
    jclass cls = env->FindClass(class_name);
    if (cls != NULL) {
        env->ThrowNew(cls, message);
    }
}

} // namespace

extern "C" {

/* ------------------------------------------------------------------ */
/* Try frames                                                          */
/* ------------------------------------------------------------------ */

int sb_try_enter(sb_frame *frame) {
    frame->next = current_top();
    frame->active = 1;
    set_top(frame);
    return setjmp(frame->buf) == 0;
}

void sb_try_exit(sb_frame *frame) {
    if (current_top() == frame) {
        set_top(frame->next);
        frame->active = 0;
    }
}

void sb_try_exit_frame() {
    sb_frame *top = current_top();
    if (top != NULL) {
        set_top(top->next);
        top->active = 0;
    }
}

sb_frame *sb_frame_push() {
    return static_cast<sb_frame *>(calloc(1, sizeof(sb_frame)));
}

void sb_try_unwind(int keep_depth) {
    int depth = 0;
    sb_frame *cursor = current_top();
    while (cursor != NULL) {
        depth++;
        cursor = cursor->next;
    }
    while (depth > keep_depth && current_top() != NULL) {
        sb_frame *top = current_top();
        set_top(top->next);
        top->active = 0;
        depth--;
    }
}

jint sb_try_depth() {
    int depth = 0;
    sb_frame *cursor = current_top();
    while (cursor != NULL) {
        depth++;
        cursor = cursor->next;
    }
    return depth;
}

void sb_throw_pending(JNIEnv *env) {
    if (env->ExceptionCheck()) {
        sb_propagate(env);
    }
}

void sb_propagate(JNIEnv *env) {
    sb_frame *top = current_top();
    if (top == NULL) {
        // No frame installed: the pending exception propagates naturally
        // when the native method returns.
        return;
    }
    set_top(top->next);
    top->active = 0;
    longjmp(top->buf, 1);
}

jobject sb_exception(JNIEnv *env) {
    jthrowable pending = env->ExceptionOccurred();
    if (pending == NULL) {
        return NULL;
    }
    env->ExceptionClear();
    return pending;
}

int sb_is_a(JNIEnv *env, jobject exception, const char *descriptor) {
    if (exception == NULL) {
        return 0;
    }
    char binary[512];
    size_t n = strlen(descriptor);
    if (n >= 2 && descriptor[0] == 'L' && descriptor[n - 1] == ';') {
        memcpy(binary, descriptor + 1, n - 2);
        binary[n - 2] = '\0';
    } else {
        strncpy(binary, descriptor, sizeof(binary) - 1);
        binary[sizeof(binary) - 1] = '\0';
    }
    jclass cls = env->FindClass(binary);
    if (cls == NULL) {
        env->ExceptionClear();
        return 0;
    }
    int result = env->IsInstanceOf(exception, cls);
    env->DeleteLocalRef(cls);
    return result;
}

/* ------------------------------------------------------------------ */
/* Object model                                                        */
/* ------------------------------------------------------------------ */

jobject sb_new_string(JNIEnv *env, const char *utf8) {
    jstring result = env->NewStringUTF(utf8);
    if (result == NULL) {
        sb_propagate(env);
    }
    return result;
}

jobject sb_const_class(JNIEnv *env, const char *descriptor) {
    char binary[512];
    size_t n = strlen(descriptor);
    if (n >= 2 && descriptor[0] == 'L' && descriptor[n - 1] == ';') {
        memcpy(binary, descriptor + 1, n - 2);
        binary[n - 2] = '\0';
    } else {
        strncpy(binary, descriptor, sizeof(binary) - 1);
        binary[sizeof(binary) - 1] = '\0';
    }
    jclass result = env->FindClass(binary);
    if (result == NULL) {
        sb_propagate(env);
    }
    return result;
}

jobject sb_new_instance(JNIEnv *env, const char *descriptor) {
    jclass cls = (jclass) sb_const_class(env, descriptor);
    jmethodID ctor = env->GetMethodID(cls, "<init>", "()V");
    if (ctor == NULL) {
        sb_propagate(env);
    }
    jobject result = env->NewObject(cls, ctor);
    env->DeleteLocalRef(cls);
    if (result == NULL) {
        sb_propagate(env);
    }
    return result;
}

jobject sb_check_cast(JNIEnv *env, jobject obj, const char *descriptor) {
    if (obj == NULL) {
        return NULL;
    }
    jclass cls = (jclass) sb_const_class(env, descriptor);
    if (env->IsInstanceOf(obj, cls)) {
        env->DeleteLocalRef(cls);
        return obj;
    }
    jclass cce = env->FindClass("java/lang/ClassCastException");
    if (cce != NULL) {
        env->ThrowNew(cce, descriptor);
    }
    env->DeleteLocalRef(cls);
    sb_propagate(env);
    return obj;
}

jint sb_instance_of(JNIEnv *env, jobject obj, const char *descriptor) {
    if (obj == NULL) {
        return 0;
    }
    jclass cls = (jclass) sb_const_class(env, descriptor);
    int result = env->IsInstanceOf(obj, cls);
    env->DeleteLocalRef(cls);
    return result;
}

jint sb_array_length(JNIEnv *env, jobject array) {
    if (array == NULL) {
        throw_class(env, "java/lang/NullPointerException", "array is null");
        sb_propagate(env);
        return 0;
    }
    return env->GetArrayLength((jarray) array);
}

jobject sb_new_array(JNIEnv *env, jint length, char kind) {
    if (length < 0) {
        throw_class(env, "java/lang/NegativeArraySizeException", "array size is negative");
        sb_propagate(env);
    }
    jobject objectClass = NULL;
    jobject result = NULL;
    switch (kind) {
        case 'I': result = env->NewIntArray(length); break;
        case 'J': result = env->NewLongArray(length); break;
        case 'F': result = env->NewFloatArray(length); break;
        case 'D': result = env->NewDoubleArray(length); break;
        case 'Z': result = env->NewBooleanArray(length); break;
        case 'B': result = env->NewByteArray(length); break;
        case 'C': result = env->NewCharArray(length); break;
        case 'S': result = env->NewShortArray(length); break;
        default:
            objectClass = env->FindClass("java/lang/Object");
            result = env->NewObjectArray(length, (jclass) objectClass, NULL);
            break;
    }
    if (result == NULL) {
        sb_propagate(env);
    }
    if (objectClass != NULL) {
        env->DeleteLocalRef(objectClass);
    }
    return result;
}

static void check_array_bounds(JNIEnv *env, jobject array, jint index) {
    if (array == NULL) {
        throw_class(env, "java/lang/NullPointerException", "array is null");
        sb_propagate(env);
        return;
    }
    if (index < 0 || index >= env->GetArrayLength((jarray) array)) {
        throw_class(env, "java/lang/ArrayIndexOutOfBoundsException", "index out of bounds");
        sb_propagate(env);
    }
}

SB sb_aget(JNIEnv *env, jobject array, jint index, char kind) {
    SB result = {0};
    check_array_bounds(env, array, index);
    switch (kind) {
        case 'I': env->GetIntArrayRegion((jintArray) array, index, 1, &result.i); break;
        case 'J': env->GetLongArrayRegion((jlongArray) array, index, 1, &result.j); break;
        case 'F': env->GetFloatArrayRegion((jfloatArray) array, index, 1, &result.f); break;
        case 'D': env->GetDoubleArrayRegion((jdoubleArray) array, index, 1, &result.d); break;
        default: result.o = env->GetObjectArrayElement((jobjectArray) array, index); break;
    }
    return result;
}

void sb_aput(JNIEnv *env, jobject array, jint index, char kind, SB value) {
    check_array_bounds(env, array, index);
    switch (kind) {
        case 'I': env->SetIntArrayRegion((jintArray) array, index, 1, &value.i); break;
        case 'J': env->SetLongArrayRegion((jlongArray) array, index, 1, &value.j); break;
        case 'F': env->SetFloatArrayRegion((jfloatArray) array, index, 1, &value.f); break;
        case 'D': env->SetDoubleArrayRegion((jdoubleArray) array, index, 1, &value.d); break;
        default: env->SetObjectArrayElement((jobjectArray) array, index, value.o); break;
    }
}

jobject sb_filled_new_array(JNIEnv *env, const char *descriptor, SB *values, jint count, char kind) {
    jobject array = sb_new_array(env, count, kind);
    for (jint i = 0; i < count; i++) {
        sb_aput(env, array, i, kind, values[i]);
        if (env->ExceptionCheck()) {
            sb_propagate(env);
        }
    }
    (void) descriptor;
    return array;
}

void sb_fill_array_data(JNIEnv *env, jobject array, const unsigned char *data, jint length, jint width) {
    if (array == NULL) {
        throw_class(env, "java/lang/NullPointerException", "array is null");
        sb_propagate(env);
        return;
    }
    jint count = length / width;
    for (jint i = 0; i < count; i++) {
        jlong raw = 0;
        for (int b = 0; b < width; b++) {
            raw |= ((jlong) (data[i * width + b] & 0xFF)) << (b * 8);
        }
        SB value = {0};
        switch (width) {
            case 1: value.i = (jint) (int8_t) (raw & 0xFF); break;
            case 2: value.i = (jint) (int16_t) (raw & 0xFFFF); break;
            case 4: value.i = (jint) (raw & 0xFFFFFFFF); break;
            case 8: value.j = raw; break;
            default: value.i = (jint) raw; break;
        }
        sb_aput(env, array, i, width == 8 ? 'J' : 'I', value);
        if (env->ExceptionCheck()) {
            sb_propagate(env);
            return;
        }
    }
}

void sb_monitor(JNIEnv *env, jobject obj, int enter) {
    if (obj == NULL) {
        throw_class(env, "java/lang/NullPointerException", "monitor object is null");
        sb_propagate(env);
        return;
    }
    if (enter) {
        if (env->MonitorEnter(obj) != JNI_OK) {
            sb_propagate(env);
        }
    } else {
        if (env->MonitorExit(obj) != JNI_OK) {
            sb_propagate(env);
        }
    }
}

void sb_throw(JNIEnv *env, jobject exception) {
    env->Throw((jthrowable) exception);
    sb_propagate(env);
}

jobject sb_move_exception(JNIEnv *env) {
    return sb_exception(env);
}

/* ------------------------------------------------------------------ */
/* Field access                                                        */
/* ------------------------------------------------------------------ */

SB sb_iget(JNIEnv *env, jobject obj, const char *class_desc, const char *name, const char *type) {
    SB result = {0};
    if (obj == NULL) {
        throw_class(env, "java/lang/NullPointerException", "object is null");
        sb_propagate(env);
        return result;
    }
    jclass cls = (jclass) sb_const_class(env, class_desc);
    jfieldID field = env->GetFieldID(cls, name, type);
    if (field == NULL) {
        env->ExceptionClear();
        jclass objectClass = env->GetObjectClass(obj);
        field = env->GetFieldID(objectClass, name, type);
        env->DeleteLocalRef(objectClass);
        if (field == NULL) {
            sb_propagate(env);
            return result;
        }
    }
    switch (type[0]) {
        case 'J': result.j = env->GetLongField(obj, field); break;
        case 'F': result.f = env->GetFloatField(obj, field); break;
        case 'D': result.d = env->GetDoubleField(obj, field); break;
        case 'L': case '[': result.o = env->GetObjectField(obj, field); break;
        default: result.i = env->GetIntField(obj, field); break;
    }
    env->DeleteLocalRef(cls);
    return result;
}

void sb_iput(JNIEnv *env, jobject obj, const char *class_desc, const char *name, const char *type, SB value) {
    if (obj == NULL) {
        throw_class(env, "java/lang/NullPointerException", "object is null");
        sb_propagate(env);
        return;
    }
    jclass cls = (jclass) sb_const_class(env, class_desc);
    jfieldID field = env->GetFieldID(cls, name, type);
    if (field == NULL) {
        env->ExceptionClear();
        jclass objectClass = env->GetObjectClass(obj);
        field = env->GetFieldID(objectClass, name, type);
        env->DeleteLocalRef(objectClass);
        if (field == NULL) {
            sb_propagate(env);
            return;
        }
    }
    switch (type[0]) {
        case 'J': env->SetLongField(obj, field, value.j); break;
        case 'F': env->SetFloatField(obj, field, value.f); break;
        case 'D': env->SetDoubleField(obj, field, value.d); break;
        case 'L': case '[': env->SetObjectField(obj, field, value.o); break;
        default: env->SetIntField(obj, field, value.i); break;
    }
    env->DeleteLocalRef(cls);
}

SB sb_sget(JNIEnv *env, const char *class_desc, const char *name, const char *type) {
    SB result = {0};
    jclass cls = (jclass) sb_const_class(env, class_desc);
    jfieldID field = env->GetStaticFieldID(cls, name, type);
    if (field == NULL) {
        sb_propagate(env);
        return result;
    }
    switch (type[0]) {
        case 'J': result.j = env->GetStaticLongField(cls, field); break;
        case 'F': result.f = env->GetStaticFloatField(cls, field); break;
        case 'D': result.d = env->GetStaticDoubleField(cls, field); break;
        case 'L': case '[': result.o = env->GetStaticObjectField(cls, field); break;
        default: result.i = env->GetStaticIntField(cls, field); break;
    }
    env->DeleteLocalRef(cls);
    return result;
}

void sb_sput(JNIEnv *env, const char *class_desc, const char *name, const char *type, SB value) {
    jclass cls = (jclass) sb_const_class(env, class_desc);
    jfieldID field = env->GetStaticFieldID(cls, name, type);
    if (field == NULL) {
        sb_propagate(env);
        return;
    }
    switch (type[0]) {
        case 'J': env->SetStaticLongField(cls, field, value.j); break;
        case 'F': env->SetStaticFloatField(cls, field, value.f); break;
        case 'D': env->SetStaticDoubleField(cls, field, value.d); break;
        case 'L': case '[': env->SetStaticObjectField(cls, field, value.o); break;
        default: env->SetStaticIntField(cls, field, value.i); break;
    }
    env->DeleteLocalRef(cls);
}

/* ------------------------------------------------------------------ */
/* Invocation                                                          */
/* ------------------------------------------------------------------ */

SB sb_invoke(JNIEnv *env, int kind, jobject receiver, const char *class_desc,
             const char *name, const char *signature, char ret_kind, jvalue *args) {
    SB result = {0};
    if (kind != SB_INVOKE_STATIC && receiver == NULL) {
        throw_class(env, "java/lang/NullPointerException", "receiver is null");
        sb_propagate(env);
        return result;
    }

    jclass cls = (jclass) sb_const_class(env, class_desc);

    switch (kind) {
        case SB_INVOKE_STATIC: {
            jmethodID method = env->GetStaticMethodID(cls, name, signature);
            if (method == NULL) {
                sb_propagate(env);
                return result;
            }
            switch (ret_kind) {
                case 'J': result.j = env->CallStaticLongMethodA(cls, method, args); break;
                case 'F': result.f = env->CallStaticFloatMethodA(cls, method, args); break;
                case 'D': result.d = env->CallStaticDoubleMethodA(cls, method, args); break;
                case 'V': env->CallStaticVoidMethodA(cls, method, args); break;
                case 'L': case '[': result.o = env->CallStaticObjectMethodA(cls, method, args); break;
                default: result.i = env->CallStaticIntMethodA(cls, method, args); break;
            }
            break;
        }
        case SB_INVOKE_DIRECT:
        case SB_INVOKE_SUPER: {
            jmethodID method = env->GetMethodID(cls, name, signature);
            if (method == NULL) {
                sb_propagate(env);
                return result;
            }
            switch (ret_kind) {
                case 'J': result.j = env->CallNonvirtualLongMethodA(receiver, cls, method, args); break;
                case 'F': result.f = env->CallNonvirtualFloatMethodA(receiver, cls, method, args); break;
                case 'D': result.d = env->CallNonvirtualDoubleMethodA(receiver, cls, method, args); break;
                case 'V': env->CallNonvirtualVoidMethodA(receiver, cls, method, args); break;
                case 'L': case '[': result.o = env->CallNonvirtualObjectMethodA(receiver, cls, method, args); break;
                default: result.i = env->CallNonvirtualIntMethodA(receiver, cls, method, args); break;
            }
            break;
        }
        default: {
            jmethodID method = env->GetMethodID(cls, name, signature);
            if (method == NULL) {
                sb_propagate(env);
                return result;
            }
            switch (ret_kind) {
                case 'J': result.j = env->CallLongMethodA(receiver, method, args); break;
                case 'F': result.f = env->CallFloatMethodA(receiver, method, args); break;
                case 'D': result.d = env->CallDoubleMethodA(receiver, method, args); break;
                case 'V': env->CallVoidMethodA(receiver, method, args); break;
                case 'L': case '[': result.o = env->CallObjectMethodA(receiver, method, args); break;
                default: result.i = env->CallIntMethodA(receiver, method, args); break;
            }
            break;
        }
    }

    env->DeleteLocalRef(cls);

    if (env->ExceptionCheck()) {
        sb_propagate(env);
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* Boxing helpers                                                      */
/* ------------------------------------------------------------------ */

jobject sb_box(JNIEnv *env, SB value, char kind) {
    switch (kind) {
        case 'J': {
            jclass cls = env->FindClass("java/lang/Long");
            jmethodID method = env->GetStaticMethodID(cls, "valueOf", "(J)Ljava/lang/Long;");
            jobject result = env->CallStaticObjectMethod(cls, method, value.j);
            env->DeleteLocalRef(cls);
            return result;
        }
        case 'F': {
            jclass cls = env->FindClass("java/lang/Float");
            jmethodID method = env->GetStaticMethodID(cls, "valueOf", "(F)Ljava/lang/Float;");
            jobject result = env->CallStaticObjectMethod(cls, method, value.f);
            env->DeleteLocalRef(cls);
            return result;
        }
        case 'D': {
            jclass cls = env->FindClass("java/lang/Double");
            jmethodID method = env->GetStaticMethodID(cls, "valueOf", "(D)Ljava/lang/Double;");
            jobject result = env->CallStaticObjectMethod(cls, method, value.d);
            env->DeleteLocalRef(cls);
            return result;
        }
        case 'L': case '[':
            return value.o;
        default: {
            jclass cls = env->FindClass("java/lang/Integer");
            jmethodID method = env->GetStaticMethodID(cls, "valueOf", "(I)Ljava/lang/Integer;");
            jobject result = env->CallStaticObjectMethod(cls, method, value.i);
            env->DeleteLocalRef(cls);
            return result;
        }
    }
}

SB sb_unbox(JNIEnv *env, jobject box, char kind) {
    SB result = {0};
    if (box == NULL) {
        return result;
    }
    if (kind == 'L' || kind == '[') {
        result.o = box;
        return result;
    }
    jclass cls = env->GetObjectClass(box);
    if (kind == 'J') {
        jmethodID method = env->GetMethodID(cls, "longValue", "()J");
        result.j = env->CallLongMethod(box, method);
    } else if (kind == 'F') {
        jmethodID method = env->GetMethodID(cls, "floatValue", "()F");
        result.f = env->CallFloatMethod(box, method);
    } else if (kind == 'D') {
        jmethodID method = env->GetMethodID(cls, "doubleValue", "()D");
        result.d = env->CallDoubleMethod(box, method);
    } else {
        jmethodID method = env->GetMethodID(cls, "intValue", "()I");
        result.i = env->CallIntMethod(box, method);
    }
    env->DeleteLocalRef(cls);
    return result;
}

/* ------------------------------------------------------------------ */
/* Arithmetic with Java edge cases                                     */
/* ------------------------------------------------------------------ */

jint sb_add_i(jint a, jint b) { return (jint) ((uint32_t) a + (uint32_t) b); }
jint sb_sub_i(jint a, jint b) { return (jint) ((uint32_t) a - (uint32_t) b); }
jint sb_mul_i(jint a, jint b) { return (jint) ((uint32_t) a * (uint32_t) b); }

jint sb_div_i(JNIEnv *env, jint a, jint b) {
    if (b == 0) {
        throw_class(env, "java/lang/ArithmeticException", "divide by zero");
        sb_propagate(env);
        return 0;
    }
    if (a == INT32_MIN && b == -1) {
        return INT32_MIN;
    }
    return a / b;
}

jint sb_rem_i(JNIEnv *env, jint a, jint b) {
    if (b == 0) {
        throw_class(env, "java/lang/ArithmeticException", "divide by zero");
        sb_propagate(env);
        return 0;
    }
    if (a == INT32_MIN && b == -1) {
        return 0;
    }
    return a % b;
}

jint sb_and_i(jint a, jint b) { return a & b; }
jint sb_or_i(jint a, jint b) { return a | b; }
jint sb_xor_i(jint a, jint b) { return a ^ b; }
jint sb_shl_i(jint a, jint b) { return (jint) ((uint32_t) a << ((uint32_t) b & 31)); }
jint sb_shr_i(jint a, jint b) { return a >> (b & 31); }
jint sb_ushr_i(jint a, jint b) { return (jint) ((uint32_t) a >> ((uint32_t) b & 31)); }

jlong sb_add_l(jlong a, jlong b) { return (jlong) ((uint64_t) a + (uint64_t) b); }
jlong sb_sub_l(jlong a, jlong b) { return (jlong) ((uint64_t) a - (uint64_t) b); }
jlong sb_mul_l(jlong a, jlong b) { return (jlong) ((uint64_t) a * (uint64_t) b); }

jlong sb_div_l(JNIEnv *env, jlong a, jlong b) {
    if (b == 0) {
        throw_class(env, "java/lang/ArithmeticException", "divide by zero");
        sb_propagate(env);
        return 0;
    }
    if (a == INT64_MIN && b == -1) {
        return INT64_MIN;
    }
    return a / b;
}

jlong sb_rem_l(JNIEnv *env, jlong a, jlong b) {
    if (b == 0) {
        throw_class(env, "java/lang/ArithmeticException", "divide by zero");
        sb_propagate(env);
        return 0;
    }
    if (a == INT64_MIN && b == -1) {
        return 0;
    }
    return a % b;
}

jlong sb_and_l(jlong a, jlong b) { return a & b; }
jlong sb_or_l(jlong a, jlong b) { return a | b; }
jlong sb_xor_l(jlong a, jlong b) { return a ^ b; }
jlong sb_shl_l(jlong a, jlong b) { return (jlong) ((uint64_t) a << ((uint64_t) b & 63)); }
jlong sb_shr_l(jlong a, jlong b) { return a >> (b & 63); }
jlong sb_ushr_l(jlong a, jlong b) { return (jlong) ((uint64_t) a >> ((uint64_t) b & 63)); }

jfloat sb_add_f(jfloat a, jfloat b) { return a + b; }
jfloat sb_sub_f(jfloat a, jfloat b) { return a - b; }
jfloat sb_mul_f(jfloat a, jfloat b) { return a * b; }
jfloat sb_div_f(jfloat a, jfloat b) { return a / b; }
jfloat sb_rem_f(jfloat a, jfloat b) { return fmodf(a, b); }

jdouble sb_add_d(jdouble a, jdouble b) { return a + b; }
jdouble sb_sub_d(jdouble a, jdouble b) { return a - b; }
jdouble sb_mul_d(jdouble a, jdouble b) { return a * b; }
jdouble sb_div_d(jdouble a, jdouble b) { return a / b; }
jdouble sb_rem_d(jdouble a, jdouble b) { return fmod(a, b); }

jint sb_cmpl_float(jfloat a, jfloat b) {
    if (isnan(a) || isnan(b)) return -1;
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

jint sb_cmpg_float(jfloat a, jfloat b) {
    if (isnan(a) || isnan(b)) return 1;
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

jint sb_cmpl_double(jdouble a, jdouble b) {
    if (isnan(a) || isnan(b)) return -1;
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

jint sb_cmpg_double(jdouble a, jdouble b) {
    if (isnan(a) || isnan(b)) return 1;
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

jfloat sb_l2f(jlong a) { return (jfloat) a; }

jint sb_f2i(jfloat a) {
    if (isnan(a)) return 0;
    if (a >= 2147483647.0f) return INT32_MAX;
    if (a <= -2147483648.0f) return INT32_MIN;
    return (jint) a;
}

jlong sb_f2l(jfloat a) {
    if (isnan(a)) return 0;
    if (a >= 9223372036854775807.0f) return INT64_MAX;
    if (a <= -9223372036854775808.0f) return INT64_MIN;
    return (jlong) a;
}

jint sb_d2i(jdouble a) {
    if (isnan(a)) return 0;
    if (a >= 2147483647.0) return INT32_MAX;
    if (a <= -2147483648.0) return INT32_MIN;
    return (jint) a;
}

jlong sb_d2l(jdouble a) {
    if (isnan(a)) return 0;
    if (a >= 9223372036854775807.0) return INT64_MAX;
    if (a <= -9223372036854775808.0) return INT64_MIN;
    return (jlong) a;
}

} /* extern "C" */
