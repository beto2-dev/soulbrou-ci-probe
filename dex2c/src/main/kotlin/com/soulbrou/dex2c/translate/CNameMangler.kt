package com.soulbrou.dex2c.translate

/**
 * JNI symbol name mangling following the exact algorithm used by the Android
 * runtime (see MangleForJni in libdexfile/dex/descriptors_names.cc).
 *
 * Short name:  Java_ + mangle(class descriptor without L ;) + _ + mangle(name)
 * Long name:   short name + __ + mangle(parameter types, without parens or
 *              return type)
 *
 * The runtime resolves a native method by trying the short name first and
 * the long name second, so emitting only long names disambiguates overloads
 * on every Android version supported by the tool.
 */
object CNameMangler {

    /** Mangles a single UTF-16 code unit sequence per the JNI rules. */
    fun mangle(text: String): String {
        val out = StringBuilder(text.length + 8)
        for (ch in text) {
            when {
                ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' -> out.append(ch)
                ch == '.' || ch == '/' -> out.append('_')
                ch == '_' -> out.append("_1")
                ch == ';' -> out.append("_2")
                ch == '[' -> out.append("_3")
                else -> out.append("_0").append(String.format("%04x", ch.code))
            }
        }
        return out.toString()
    }

    /** Mangles a class descriptor such as "Lcom/example/Foo$Bar;". */
    fun mangleClassName(classDescriptor: String): String {
        require(classDescriptor.startsWith("L") && classDescriptor.endsWith(";")) {
            "Not an object class descriptor: $classDescriptor"
        }
        return mangle(classDescriptor.substring(1, classDescriptor.length - 1))
    }

    /**
     * Builds the full (long) JNI export name for a method. Example:
     * class Lcom/example/Foo; method bar with parameters (Ljava/lang/String;[I)
     * yields Java_com_example_Foo_bar__Ljava_lang_String_2_3I.
     */
    fun jniLongName(classDescriptor: String, methodName: String, parameterDescriptors: String): String {
        val short = jniShortName(classDescriptor, methodName)
        return short + "__" + mangle(parameterDescriptors)
    }

    /** Builds the short JNI export name for a method. */
    fun jniShortName(classDescriptor: String, methodName: String): String {
        return "Java_" + mangleClassName(classDescriptor) + "_" + mangle(methodName)
    }
}
