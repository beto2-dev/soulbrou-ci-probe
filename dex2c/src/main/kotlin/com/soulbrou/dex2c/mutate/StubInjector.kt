package com.soulbrou.dex2c.mutate

import com.soulbrou.dex2c.code.DexCode
import com.soulbrou.dex2c.code.DexInsn
import com.soulbrou.dex2c.code.InsnFormat
import com.soulbrou.dex2c.model.AccessFlags
import com.soulbrou.dex2c.model.DexClassData
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedMethod

/**
 * Replaces the body of a converted method with a compact dispatch stub that
 * forwards the boxed arguments to the injected helper class, and injects the
 * helper class itself. The original body is serialized into the encrypted
 * runtime blob by the pipeline before the replacement happens.
 *
 * The helper class shape (registered through RegisterNatives at load time):
 *
 *   package com.soulbrou.sb;
 *   public final class Sb {
 *       static { initRuntime(); }
 *       private static native void initRuntime();
 *       public static native Object invoke(String key, Object[] args);
 *   }
 */
class StubInjector(private val document: DexDocument) {

    class StubException(message: String) : Exception(message)

    /** The document this injector mutates. */
    fun documentOf(): DexDocument = document

    companion object {
        const val HELPER_DESCRIPTOR = "Lcom/soulbrou/sb/Sb;"
        const val HELPER_CLASS_NAME = "com.soulbrou.sb.Sb"
    }

    /** Installs the helper class with its native bridge methods. */
    fun injectHelperClass() {
        document.unseal()
        val objectType = document.internType("Ljava/lang/Object;")
        val helperType = document.internType(HELPER_DESCRIPTOR)

        // Do not duplicate the helper when several dex files share a writer.
        if (document.classes.firstOrNull { it.type.descriptor.value == HELPER_DESCRIPTOR } != null) {
            return
        }

        val voidProto = document.internProto("V", document.internType("V"), emptyList())

        // initRuntime()V
        val initRuntime = document.internMethod(
            declaringClass = helperType,
            name = "initRuntime",
            proto = voidProto,
        )
        // invoke(String, Object[])Object
        val stringType = document.internType("Ljava/lang/String;")
        val objectArrayType = document.internType("[Ljava/lang/Object;")
        val invokeProto = document.internProto("VLL", objectType, listOf(stringType, objectArrayType))
        val invokeMethod = document.internMethod(
            declaringClass = helperType,
            name = "invoke",
            proto = invokeProto,
        )
        val clinit = document.staticInitializerOf(helperType)

        val clinitCode = DexCode(
            registersSize = 0,
            insSize = 0,
            outsSize = 0,
            debugInfo = null,
            insns = ArrayList(),
            tries = emptyList(),
        )
        clinitCode.insns.add(
            DexInsn(
                opcode = 0x71, // invoke-static
                format = InsnFormat.F35C,
                a = 0,
                regs = IntArray(0),
                ref = initRuntime,
            ),
        )
        clinitCode.insns.add(DexInsn(0x0e, InsnFormat.F10X)) // return-void

        val objectProto = document.internProto("V", objectType, emptyList())

        val directMethods = ArrayList<DexEncodedMethod>()
        directMethods.add(
            DexEncodedMethod(
                method = clinit,
                accessFlags = AccessFlags.ACC_STATIC or AccessFlags.ACC_CONSTRUCTOR,
                code = clinitCode,
            ),
        )
        directMethods.add(
            DexEncodedMethod(
                method = initRuntime,
                accessFlags = AccessFlags.ACC_STATIC or AccessFlags.ACC_PRIVATE or AccessFlags.ACC_NATIVE,
                code = null,
            ),
        )
        directMethods.add(
            DexEncodedMethod(
                method = invokeMethod,
                accessFlags = AccessFlags.ACC_STATIC or AccessFlags.ACC_PUBLIC or AccessFlags.ACC_NATIVE,
                code = null,
            ),
        )

        val classData = DexClassData(
            staticFields = emptyList(),
            instanceFields = emptyList(),
            directMethods = directMethods,
            virtualMethods = ArrayList(),
        )

        val classDef = DexClassDef(
            type = helperType,
            accessFlags = AccessFlags.ACC_PUBLIC or AccessFlags.ACC_FINAL,
            superclass = objectType,
            interfaces = emptyList(),
            sourceFile = null,
            annotationsDirectory = null,
            staticValues = null,
            classData = classData,
        )
        document.classes.intern(classDef)
        document.unseal()
    }

    /**
     * Replaces the method body with the dispatch stub. The method keeps its
     * flags (it stays a normal Java method), only the body changes.
     */
    fun replaceMethodWithStub(classDef: DexClassDef, method: DexEncodedMethod, key: String) {
        document.unseal()
        val m = method.method
        val paramDescriptors = m.proto.parameterDescriptors
        val returnDescriptor = m.proto.returnType.descriptor.value
        val isStatic = method.isStatic

        // ---- Intern the required references ----
        val keyString = document.internString(key)
        val objectArrayType = document.internType("[Ljava/lang/Object;")
        val stringType = document.internType("Ljava/lang/String;")
        val objectType = document.internType("Ljava/lang/Object;")
        val invokeProto = document.internProto("VLL", objectType, listOf(stringType, objectArrayType))
        val invokeMethod = document.internMethod(
            declaringClass = document.internType(HELPER_DESCRIPTOR),
            name = "invoke",
            proto = invokeProto,
        )

        val paramTypes = parseTypes(paramDescriptors)
        val arraySize = paramTypes.size + (if (isStatic) 0 else 1)
        if (arraySize > 15) {
            throw StubException("Too many parameters for the dispatch stub")
        }

        // Boxing and unboxing references resolved on demand.
        fun boxMethodFor(type: String): com.soulbrou.dex2c.model.DexMethod {
            return when (type) {
                "J" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Long;"),
                    name = "valueOf",
                    proto = document.internProto("VL", document.internType("Ljava/lang/Long;"), listOf(document.internType("J"))),
                )
                "F" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Float;"),
                    name = "valueOf",
                    proto = document.internProto("VL", document.internType("Ljava/lang/Float;"), listOf(document.internType("F"))),
                )
                "D" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Double;"),
                    name = "valueOf",
                    proto = document.internProto("VL", document.internType("Ljava/lang/Double;"), listOf(document.internType("D"))),
                )
                "L", "[" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Object;"),
                    name = "identity",
                    proto = document.internProto("VL", document.internType("Ljava/lang/Object;"), listOf(objectType)),
                )
                else -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Integer;"),
                    name = "valueOf",
                    proto = document.internProto("VL", document.internType("Ljava/lang/Integer;"), listOf(document.internType("I"))),
                )
            }
        }

        fun unboxMethodFor(type: String): com.soulbrou.dex2c.model.DexMethod {
            return when (type) {
                "J" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Long;"),
                    name = "longValue",
                    proto = document.internProto("VL", document.internType("J"), emptyList()),
                )
                "F" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Float;"),
                    name = "floatValue",
                    proto = document.internProto("VF", document.internType("F"), emptyList()),
                )
                "D" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Double;"),
                    name = "doubleValue",
                    proto = document.internProto("VD", document.internType("D"), emptyList()),
                )
                "L", "[" -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Object;"),
                    name = "identity",
                    proto = document.internProto("VL", objectType, emptyList()),
                )
                else -> document.internMethod(
                    declaringClass = document.internType("Ljava/lang/Integer;"),
                    name = "intValue",
                    proto = document.internProto("VI", document.internType("I"), emptyList()),
                )
            }
        }

        fun unboxClassFor(type: String): com.soulbrou.dex2c.model.DexType = when (type) {
            "J" -> document.internType("Ljava/lang/Long;")
            "F" -> document.internType("Ljava/lang/Float;")
            "D" -> document.internType("Ljava/lang/Double;")
            "L", "[" -> document.internType("Ljava/lang/Object;")
            else -> document.internType("Ljava/lang/Integer;")
        }

        // ---- Build the stub body ----
        val insns = ArrayList<DexInsn>(16 + paramTypes.size * 3)
        val insSize = method.insCount()
        val scratchKey = 0
        val scratchArray = 1
        val scratchValue = 2
        val scratchIndex = 3
        val registersSize = insSize + 4
        val paramBase = registersSize - insSize

        // const-string/jumbo v0, key
        insns.add(
            DexInsn(0x1b, InsnFormat.F31C, a = scratchKey, ref = keyString),
        )
        // const/4 v3, arraySize
        insns.add(
            DexInsn(0x12, InsnFormat.F11N, a = scratchIndex, b = arraySize),
        )
        // new-array v1, v3, [Ljava/lang/Object;
        insns.add(
            DexInsn(0x23, InsnFormat.F22C, a = scratchArray, b = scratchIndex, ref = objectArrayType),
        )

        var cursor = paramBase
        var arrayIndex = 0
        if (!isStatic) {
            // aput-object p0(the instance), v1, 0
            insns.add(
                DexInsn(0x12, InsnFormat.F11N, a = scratchIndex, b = arrayIndex),
            )
            insns.add(
                DexInsn(
                    0x4d, InsnFormat.F23X,
                    a = cursor, // value register (the receiver)
                    b = scratchArray,
                    c = scratchIndex.toLong(),
                ),
            )
            arrayIndex += 1
            cursor += 1
        }

        for (type in paramTypes) {
            if (type == "L" || type == "[") {
                // move-object v2, pN
                insns.add(
                    DexInsn(0x07, InsnFormat.F12X, a = scratchValue, b = cursor),
                )
            } else {
                // invoke-static {pN}, Box.valueOf(...)
                insns.add(
                    DexInsn(
                        0x71, InsnFormat.F35C,
                        a = 1,
                        regs = intArrayOf(cursor),
                        ref = boxMethodFor(type),
                    ),
                )
                // move-result-object v2
                insns.add(DexInsn(0x0c, InsnFormat.F11X, a = scratchValue))
            }
            // const/4 v3, index
            insns.add(
                DexInsn(0x12, InsnFormat.F11N, a = scratchIndex, b = arrayIndex),
            )
            // aput-object v2, v1, v3
            insns.add(
                DexInsn(
                    0x4d, InsnFormat.F23X,
                    a = scratchValue,
                    b = scratchArray,
                    c = scratchIndex.toLong(),
                ),
            )
            arrayIndex += 1
            cursor += if (type == "J" || type == "D") 2 else 1
        }

        // invoke-static {v0, v1}, Sb.invoke
        insns.add(
            DexInsn(
                0x71, InsnFormat.F35C,
                a = 2,
                regs = intArrayOf(scratchKey, scratchArray),
                ref = invokeMethod,
            ),
        )
        // move-result-object v2
        insns.add(DexInsn(0x0c, InsnFormat.F11X, a = scratchValue))

        // Unbox the result according to the return type.
        when {
            returnDescriptor == "V" -> Unit
            returnDescriptor == "L" || returnDescriptor == "[" -> {
                // check-cast v2, R (only when a precise reference type exists)
                insns.add(
                    DexInsn(0x1f, InsnFormat.F21C, a = scratchValue, ref = m.proto.returnType),
                )
            }
            else -> {
                insns.add(
                    DexInsn(0x1f, InsnFormat.F21C, a = scratchValue, ref = unboxClassFor(returnDescriptor)),
                )
                insns.add(
                    DexInsn(
                        0x6e, InsnFormat.F35C,
                        a = 1,
                        regs = intArrayOf(scratchValue),
                        ref = unboxMethodFor(returnDescriptor),
                    ),
                )
                // move-result v0 / move-result-wide v0
                val wide = returnDescriptor == "J" || returnDescriptor == "D"
                insns.add(DexInsn(if (wide) 0x0b else 0x0a, InsnFormat.F11X, a = scratchKey))
            }
        }

        // Final return per type.
        insns.add(
            when {
                returnDescriptor == "V" -> DexInsn(0x0e, InsnFormat.F10X)
                returnDescriptor == "J" -> DexInsn(0x10, InsnFormat.F11X, a = scratchKey)
                returnDescriptor == "F" || returnDescriptor == "D" -> DexInsn(0x10, InsnFormat.F11X, a = scratchKey)
                returnDescriptor == "L" || returnDescriptor == "[" -> DexInsn(0x11, InsnFormat.F11X, a = scratchValue)
                else -> DexInsn(0x0f, InsnFormat.F11X, a = scratchKey)
            },
        )

        val outsSize = when {
            paramTypes.any { it == "L" || it == "[" } -> 2
            else -> 2
        }

        method.code = DexCode(
            registersSize = registersSize,
            insSize = insSize,
            outsSize = outsSize,
            debugInfo = null,
            insns = insns,
            tries = emptyList(),
        )
    }

    private fun DexEncodedMethod.insCount(): Int {
        // ins_size is recomputed from the prototype: static methods take the
        // parameter registers, instance methods add the receiver.
        val code = this.code
        val fromCode = code?.insSize ?: 0
        if (fromCode != 0 || code != null) {
            return fromCode
        }
        var count = if (this.isStatic) 0 else 1
        for (type in parseTypes(method.proto.parameterDescriptors)) {
            count += if (type == "J" || type == "D") 2 else 1
        }
        return count
    }

    private fun parseTypes(descriptor: String): List<String> {
        if (descriptor.isEmpty()) return emptyList()
        val types = ArrayList<String>()
        var i = 0
        while (i < descriptor.length) {
            when (descriptor[i]) {
                '[' -> {
                    val start = i
                    while (i < descriptor.length && descriptor[i] == '[') i++
                    if (i < descriptor.length && descriptor[i] == 'L') {
                        while (i < descriptor.length && descriptor[i] != ';') i++
                        i++
                    } else if (i < descriptor.length) {
                        i++
                    }
                    types.add(descriptor.substring(start, i))
                }
                'L' -> {
                    val start = i
                    while (i < descriptor.length && descriptor[i] != ';') i++
                    i++
                    types.add(descriptor.substring(start, i))
                }
                else -> {
                    types.add(descriptor[i].toString())
                    i++
                }
            }
        }
        return types
    }
}
