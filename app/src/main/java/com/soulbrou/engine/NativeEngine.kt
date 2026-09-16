package com.soulbrou.engine

/**
 * Bridge to the native runtime library bundled with the application. Used
 * for engine self tests and version reporting; the protected APKs talk to
 * their own injected copy of the library.
 */
object NativeEngine {

    init {
        System.loadLibrary("soulbrou")
    }

    /** Version of the native runtime. */
    external fun nativeVersion(): String

    /** Runs the cryptographic and integrity self tests of the runtime. */
    external fun nativeSelfTest(): Boolean
}
