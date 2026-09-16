#include <jni.h>

/**
 * Minimal JNI entry point for the initial project skeleton.
 * Extended by the protection runtime and engine bridge modules.
 */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /*reserved */) {
    (void)vm;
    return JNI_VERSION_1_6;
}
