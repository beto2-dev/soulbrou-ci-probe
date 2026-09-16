package com.soulbrou.dex2c

import com.soulbrou.dex2c.code.DexCode
import com.soulbrou.dex2c.code.DexInsn
import com.soulbrou.dex2c.code.InsnFormat
import com.soulbrou.dex2c.model.DexClassData
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexEncodedMethod
import com.soulbrou.dex2c.model.DexType
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexProto
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.writer.DexWriter
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Builds the small DEX documents and APK archives used by the unit tests.
 * The fixtures intentionally stay minimal: one class, one or two methods with
 * tiny bodies, enough to exercise every stage of the engine.
 */
object TestDexFactory {

    const val CLASS_DESCRIPTOR = "Lcom/example/target/Calculator;"
    const val METHOD_NAME = "add"
    const val METHOD_PROTO = "II" + "I"

    /** A document with one class holding a static int add(int,int) method. */
    fun document(): DexDocument {
        val document = DexDocument()

        val stringType = document.internType("Ljava/lang/String;")
        val objectType = document.internType("Ljava/lang/Object;")
        val integerType = document.internType("Ljava/lang/Integer;")
        val stringBuilderType = document.internType("Ljava/lang/StringBuilder;")

        val calculatorType = document.internType(CLASS_DESCRIPTOR)
        val voidType = document.internType("V")

        val clinitProto = document.internProto("V", voidType, emptyList())
        document.internMethod(
            declaringClass = calculatorType,
            name = "<clinit>",
            proto = clinitProto,
        )

        val addProto = document.internProto(
            shorty = "III",
            returnType = document.internType("I"),
            parameters = listOf(document.internType("I"), document.internType("I")),
        )
        val addMethod = document.internMethod(
            declaringClass = calculatorType,
            name = METHOD_NAME,
            proto = addProto,
        )

        val boxValueOf = document.internMethod(
            declaringClass = integerType,
            name = "valueOf",
            proto = document.internProto(
                shorty = "LI",
                returnType = integerType,
                parameters = listOf(document.internType("I")),
            ),
        )
        val toStringMethod = document.internMethod(
            declaringClass = objectType,
            name = "toString",
            proto = document.internProto(
                shorty = "L",
                returnType = stringType,
                parameters = emptyList(),
            ),
        )
        val sbAppend = document.internMethod(
            declaringClass = stringBuilderType,
            name = "append",
            proto = document.internProto(
                shorty = "LL",
                returnType = stringBuilderType,
                parameters = listOf(stringType),
            ),
        )
        document.internMethod(
            declaringClass = stringBuilderType,
            name = "toString",
            proto = document.internProto(
                shorty = "L",
                returnType = stringType,
                parameters = emptyList(),
            ),
        )
        document.internString("Calculator ready")

        val staticBody = DexCode(
            registersSize = 1,
            insSize = 0,
            outsSize = 0,
            debugInfo = null,
            insns = mutableListOf(
                DexInsn(opcode = 0x1a, format = InsnFormat.F21C, a = 0, ref = document.strings.find("Calculator ready")!!),
                DexInsn(opcode = 0x71, format = InsnFormat.F35C, ref = toStringMethod, regs = intArrayOf(1)),
            ),
            tries = emptyList(),
        )
        // The static initializer keeps the fixture close to real classes.
        staticBody.insns.clear()
        staticBody.insns.add(DexInsn(opcode = 0x00, format = InsnFormat.F10X))
        staticBody.insns.add(DexInsn(opcode = 0x0e, format = InsnFormat.F10X))

        val addBody = DexCode(
            registersSize = 4,
            insSize = 2,
            outsSize = 2,
            debugInfo = null,
            insns = mutableListOf(
                DexInsn(opcode = 0x90, format = InsnFormat.F23X, a = 0, b = 2, c = 3),
                DexInsn(opcode = 0x12, format = InsnFormat.F11N, a = 1, b = 7),
                DexInsn(opcode = 0x0f, format = InsnFormat.F11X, a = 1),
            ),
            tries = emptyList(),
        )
        val unusedBody = DexCode(
            registersSize = 2,
            insSize = 1,
            outsSize = 1,
            debugInfo = null,
            insns = mutableListOf(
                DexInsn(opcode = 0x12, format = InsnFormat.F11N, a = 0, b = 1),
                DexInsn(opcode = 0x0f, format = InsnFormat.F11X, a = 0),
            ),
            tries = emptyList(),
        )

        val classData = DexClassData(
            staticFields = emptyList(),
            instanceFields = emptyList(),
            directMethods = mutableListOf(
                DexEncodedMethod(
                    method = document.methods.find("$CLASS_DESCRIPTOR-><clinit>()V")!!,
                    accessFlags = 0x10008,
                    code = staticBody,
                ),
                DexEncodedMethod(
                    method = addMethod,
                    accessFlags = 0x00008,
                    code = addBody,
                ),
                DexEncodedMethod(
                    method = document.internMethod(
                        declaringClass = calculatorType,
                        name = "double",
                        proto = document.internProto(
                            shorty = "II",
                            returnType = document.internType("I"),
                            parameters = listOf(document.internType("I")),
                        ),
                    ),
                    accessFlags = 0x00008,
                    code = unusedBody,
                ),
            ),
            virtualMethods = mutableListOf(),
        )

        val classDef = DexClassDef(
            type = calculatorType,
            accessFlags = 0x00008,
            superclass = document.internType("Ljava/lang/Object;"),
            interfaces = emptyList(),
            sourceFile = document.internString("Calculator.java"),
            annotationsDirectory = null,
            staticValues = emptyList(),
            classData = classData,
        )
        document.classes.add(classDef)
        return document
    }

    /** Serialized DEX of [document]. */
    fun dexBytes(): ByteArray = DexWriter(document()).write()

    /** A minimal in memory APK holding the fixture dex and a raw manifest. */
    fun apkBytes(manifest: ByteArray = byteArrayOf(1, 2, 3)): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(manifest)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes())
            zip.closeEntry()
        }
        return output.toByteArray()
    }

    /** The canonical key of the add(II)I method. */
    fun addMethodKey(): MethodKey = MethodKey(
        dexName = "classes.dex",
        classDescriptor = CLASS_DESCRIPTOR,
        methodName = METHOD_NAME,
        proto = METHOD_PROTO,
    )
}
