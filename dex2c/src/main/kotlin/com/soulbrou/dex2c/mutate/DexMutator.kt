package com.soulbrou.dex2c.mutate

import com.soulbrou.dex2c.code.DexCatchEntry
import com.soulbrou.dex2c.code.DexCatchHandler
import com.soulbrou.dex2c.code.DexCode
import com.soulbrou.dex2c.code.DexInsn
import com.soulbrou.dex2c.code.DexTry
import com.soulbrou.dex2c.code.InsnFormat
import com.soulbrou.dex2c.model.AccessFlags
import com.soulbrou.dex2c.model.DexClassData
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedMethod

/**
 * Applies structural mutations to a parsed [DexDocument]:
 *
 * - converts selected methods to native (ACC_NATIVE) removing their code,
 * - ensures the owning class initializes the native runtime by prepending a
 *   System.loadLibrary call to its static initializer,
 * - keeps every index consistent by operating on the symbolic model so the
 *   writer can rebuild sorted tables safely.
 *
 * The runtime library injected into the target APK exports the long JNI
 * names of every converted method, so no RegisterNatives bookkeeping is
 * required at load time.
 */
class DexMutator(private val document: DexDocument) {

    class MutationException(message: String) : Exception(message)

    /** Maximum method ids addressable by 35c invoke instructions. */
    private val maxMethodIds = 65535

    /** Ensures new references still fit the instruction operand limits. */
    fun checkCapacity() {
        if (document.methods.size + 2 > maxMethodIds) {
            throw MutationException(
                "Method id table too large for new references (${document.methods.size})",
            )
        }
    }

    /**
     * Converts one method to native. The runtime library must export the long
     * JNI name of this method. Throws [MutationException] when the document
     * cannot absorb the new references.
     */
    fun convertToNative(classDef: DexClassDef, method: DexEncodedMethod) {
        checkCapacity()

        method.accessFlags = method.accessFlags or AccessFlags.ACC_NATIVE
        method.code = null

        ensureRuntimeLoad(classDef)
    }

    /**
     * Ensures the class static initializer loads the runtime library before
     * any native method is resolved. When the class has no initializer a
     * minimal one is created.
     */
    fun ensureRuntimeLoad(classDef: DexClassDef) {
        val method = document.staticInitializerOf(classDef.type)
        var classData = classDef.classData
        if (classData == null) {
            classData = DexClassData(
                staticFields = emptyList(),
                instanceFields = emptyList(),
                directMethods = ArrayList(),
                virtualMethods = ArrayList(),
            )
            classDef.classData = classData
        }

        val existing = classData.directMethods.firstOrNull { it.method === method }
        if (existing != null) {
            val existingCode = existing.code
            if (existingCode == null) {
                existing.code = buildInitializerCode()
            } else {
                prependLoadLibrary(existingCode)
            }
        } else {
            val clinit = DexEncodedMethod(
                method = method,
                accessFlags = AccessFlags.ACC_STATIC or AccessFlags.ACC_CONSTRUCTOR,
                code = buildInitializerCode(),
            )
            classData.directMethods.add(clinit)
        }
    }

    /** Builds a fresh clinit body that only loads the runtime library. */
    private fun buildInitializerCode(): DexCode {
        val insns = ArrayList<DexInsn>(3)
        insns.add(constStringJumbo(0, RUNTIME_LIB_NAME))
        insns.add(invokeStaticLoadLibrary(0))
        insns.add(DexInsn(0x0e, InsnFormat.F10X)) // return-void
        return DexCode(
            registersSize = 1,
            insSize = 0,
            outsSize = 1,
            debugInfo = null,
            insns = insns,
            tries = emptyList(),
        )
    }

    /**
     * Prepends the load library call to an existing static initializer,
     * shifting try regions and catch handler addresses by the size of the
     * inserted prefix. Branch targets and payload references are stored as
     * object links in the symbolic model, so they need no fixup.
     */
    private fun prependLoadLibrary(code: DexCode) {
        if (code.insns.isEmpty()) {
            val rebuilt = buildInitializerCode()
            code.insns.addAll(rebuilt.insns)
            code.registersSize = maxOf(code.registersSize, rebuilt.registersSize)
            code.outsSize = maxOf(code.outsSize, rebuilt.outsSize)
            return
        }

        // A static initializer has no parameters, so every register is a
        // local: register zero is a safe scratch register. The verifier
        // requires definition before use, so clobbering it is invisible to
        // valid bytecode.
        if (code.registersSize == 0) {
            code.registersSize = 1
        }
        code.outsSize = maxOf(code.outsSize, 1)

        val prefix = listOf(
            constStringJumbo(0, RUNTIME_LIB_NAME),
            invokeStaticLoadLibrary(0),
        )
        val prefixUnits = prefix.sumOf { it.format.size }
        code.insns.addAll(0, prefix)

        // Shift try regions and rebuild handler objects with shifted
        // addresses. Handlers may be shared between tries; rebuilding them
        // per try keeps the shift uniform without double mutation.
        code.tries = code.tries.map { tryItem ->
            val handler = tryItem.handler
            val newHandler = DexCatchHandler(
                entries = handler.entries.map { DexCatchEntry(it.type, it.address + prefixUnits) },
                catchAllAddress = handler.catchAllAddress?.plus(prefixUnits),
            )
            DexTry(tryItem.startAddress + prefixUnits, tryItem.instructionCount, newHandler)
        }

        // Reindex ordinals.
        code.insns.forEachIndexed { index, insn -> insn.index = index }
    }

    private fun constStringJumbo(register: Int, value: String): DexInsn {
        val string = document.internString(value)
        return DexInsn(
            opcode = 0x1b, // const-string/jumbo
            format = InsnFormat.F31C,
            a = register,
            ref = string,
        )
    }

    private fun invokeStaticLoadLibrary(register: Int): DexInsn {
        val method = document.systemLoadLibraryMethod()
        return DexInsn(
            opcode = 0x71, // invoke-static
            format = InsnFormat.F35C,
            a = 1,
            regs = intArrayOf(register),
            ref = method,
        )
    }

    companion object {
        const val RUNTIME_LIB_NAME = "soulbrou"
    }
}
