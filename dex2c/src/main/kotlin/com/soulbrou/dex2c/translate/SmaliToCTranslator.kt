package com.soulbrou.dex2c.translate

import com.soulbrou.dex2c.code.DexCode
import com.soulbrou.dex2c.code.DexInsn
import com.soulbrou.dex2c.code.PayloadKind
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedMethod
import com.soulbrou.dex2c.model.DexField
import com.soulbrou.dex2c.model.DexMethod
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.model.DexType
import kotlin.random.Random

/**
 * Translates the bytecode of a method into an equivalent C function that
 * calls the Soulbrou native runtime for every operation that touches the
 * Java world. The generated function receives the JNI arguments, maps them
 * onto the Dalvik register file and executes the translated instruction
 * stream under the runtime try frame machinery so exception semantics match
 * the virtual machine.
 *
 * The translator covers the standard Dalvik instruction set emitted by all
 * mainstream compilers (javac, kotlinc, d8, R8). Constructs that cannot be
 * represented (invoke-polymorphic, invoke-custom, odex specific opcodes and
 * non nested try regions) raise a [TranslationException] which the engine
 * treats as "keep this method in the DEX".
 */
class SmaliToCTranslator(
    private val document: DexDocument,
    private val obfuscationLevel: Int = 0,
) {

    class TranslationException(message: String) : Exception(message)

    /** Result of translating one method. */
    data class GeneratedFunction(
        val classDescriptor: String,
        val methodName: String,
        val jniName: String,
        val source: String,
    )

    fun translate(classDef: DexClassDef, method: DexEncodedMethod): GeneratedFunction {
        val code = method.code ?: throw TranslationException("Method has no code")
        val m = method.method
        val jniName = CNameMangler.jniLongName(
            classDescriptor = classDef.type.descriptor.value,
            methodName = m.name.value,
            parameterDescriptors = m.proto.parameterDescriptors,
        )
        validateTryNesting(code)
        val body = FunctionBody(classDef, method, code, jniName, obfuscationLevel).build()
        return GeneratedFunction(
            classDescriptor = classDef.type.descriptor.value,
            methodName = m.name.value,
            jniName = jniName,
            source = body,
        )
    }

    /**
     * setjmp based regions require properly nested try ranges. Overlapping
     * but non nested ranges (legal but not produced by mainstream compilers)
     * reject the method so it stays in the DEX.
     */
    private fun validateTryNesting(code: DexCode) {
        val ranges = code.tries
            .map { it.startAddress to (it.startAddress + it.instructionCount) }
            .sortedWith(compareBy({ it.first }, { it.second }))
        for (i in ranges.indices) {
            for (j in i + 1 until ranges.size) {
                val (a1, b1) = ranges[i]
                val (a2, b2) = ranges[j]
                if (a2 >= b1) break // disjoint, and so are the rest
                if (b2 > b1) {
                    throw TranslationException("Non nested try regions in method")
                }
            }
        }
    }
}

/**
 * Stateful writer for a single translated function.
 */
private class FunctionBody(
    private val classDef: DexClassDef,
    private val encodedMethod: DexEncodedMethod,
    private val code: DexCode,
    private val jniName: String,
    private val obfuscationLevel: Int,
) {

    private val method: DexMethod = encodedMethod.method
    private val out = StringBuilder(4096)
    private val random = Random(jniName.hashCode().toLong() xor 0x5B0D1F9L)
    private val dataBlobs = ArrayList<Pair<String, ByteArray>>()

    /** Try regions keyed by their first covered instruction index. */
    private val regionsByStart = HashMap<Int, TryRegion>()

    /** Maps code unit addresses to instruction ordinals. */
    private val addrToIndex = HashMap<Int, Int>()

    private class TryRegion(
        val startInsn: Int,
        val endInsn: Int,
        val handlerEntries: List<Pair<DexType, Int>>,
        val catchAll: Int?,
    )

    fun build(): String {
        prepareRegions()
        emitHeader()
        emitSignature()
        emitLocals()
        emitParameterMapping()
        emitBody()
        emitBlobs()
        return out.toString()
    }

    private fun prepareRegions() {
        for (insn in code.insns) {
            addrToIndex[insn.address] = insn.index
        }
        for (tryItem in code.tries) {
            val startIndex = addrToIndex[tryItem.startAddress] ?: continue
            val endAddress = tryItem.startAddress + tryItem.instructionCount
            var endIndex = code.insns.size
            for (insn in code.insns) {
                if (insn.address >= endAddress) {
                    endIndex = insn.index
                    break
                }
            }
            regionsByStart[startIndex] = TryRegion(
                startIndex,
                endIndex,
                tryItem.handler.entries.map { it.type to addrToIndex.getValue(it.address) },
                tryItem.handler.catchAllAddress?.let { addrToIndex[it] },
            )
        }
    }

    /** Number of try regions covering the given instruction index. */
    private fun coverCount(index: Int): Int {
        var count = 0
        for (region in regionsByStart.values) {
            if (index >= region.startInsn && index < region.endInsn) count++
        }
        return count
    }

    // ------------------------------------------------------------------
    // Structure
    // ------------------------------------------------------------------

    private fun emitHeader() {
        out.append("/*\n")
        out.append(" * Generated by the Soulbrou dex2c engine.\n")
        out.append(" * Class:  ").append(classDef.type.descriptor.value).append('\n')
        out.append(" * Method: ").append(method.name.value).append('(')
            .append(method.proto.parameterDescriptors).append(')')
            .append(method.proto.returnType.descriptor.value).append('\n')
        out.append(" */\n")
    }

    private fun cReturnKind(): String {
        val descriptor = method.proto.returnType.descriptor.value
        return when (descriptor) {
            "V" -> "void"
            "J" -> "jlong"
            "F" -> "jfloat"
            "D" -> "jdouble"
            "I" -> "jint"
            "Z" -> "jboolean"
            "B" -> "jbyte"
            "C" -> "jchar"
            "S" -> "jshort"
            else -> "jobject"
        }
    }

    private fun cDefaultReturn(): String {
        val descriptor = method.proto.returnType.descriptor.value
        return when (descriptor) {
            "V" -> "return;"
            "J" -> "return (jlong)0;"
            "F" -> "return (jfloat)0;"
            "D" -> "return (jdouble)0;"
            "I" -> "return (jint)0;"
            "Z" -> "return (jboolean)0;"
            "B" -> "return (jbyte)0;"
            "C" -> "return (jchar)0;"
            "S" -> "return (jshort)0;"
            else -> "return (jobject)0;"
        }
    }

    private fun emitSignature() {
        out.append("JNIEXPORT ").append(cReturnKind()).append(" JNICALL\n")
        out.append(jniName).append("(JNIEnv *env")
        if (encodedMethod.isStatic) {
            out.append(", jclass thiz")
        } else {
            out.append(", jobject thiz")
        }
        val paramTypes = parseTypes(method.proto.parameterDescriptors)
        paramTypes.forEachIndexed { index, type ->
            out.append(", ").append(cTypeOf(type)).append(" p").append(index)
        }
        out.append(")\n{\n")
    }

    private fun emitLocals() {
        out.append("    (void)thiz;\n")
        for (register in 0 until code.registersSize) {
            out.append("    volatile SB v").append(register).append(";\n")
        }
        out.append("    volatile SB sb_ret;\n")
        out.append("    (void)sb_ret;\n")
    }

    private fun emitParameterMapping() {
        val paramTypes = parseTypes(method.proto.parameterDescriptors)
        var cursor = code.registersSize - code.insSize
        if (!encodedMethod.isStatic) {
            out.append("    v").append(cursor).append(" = SB_O(thiz);\n")
            cursor += 1
        }
        paramTypes.forEachIndexed { index, type ->
            out.append("    v").append(cursor).append(" = ")
            when (type) {
                "J" -> out.append("SB_J(p").append(index).append(")")
                "F" -> out.append("SB_F(p").append(index).append(")")
                "D" -> out.append("SB_D(p").append(index).append(")")
                "L", "[" -> out.append("SB_O(p").append(index).append(")")
                else -> out.append("SB_I(p").append(index).append(")")
            }
            out.append(";\n")
            cursor += if (type == "J" || type == "D") 2 else 1
        }
    }

    private fun label(index: Int): String {
        if (obfuscationLevel > 0) {
            return "x" + Integer.toUnsignedString(random.nextInt(), 36) + "_" + index
        }
        return "L$index"
    }

    /** Emits the frame unwind needed before jumping to [targetIndex]. */
    private fun emitUnwindForJump(fromIndex: Int, targetIndex: Int) {
        val current = coverCount(fromIndex)
        val target = coverCount(targetIndex)
        if (current > target) {
            out.append("    sb_try_unwind(").append(target + 1).append(");\n")
        }
    }

    private fun emitReturnUnwind(fromIndex: Int) {
        if (coverCount(fromIndex) > 0) {
            out.append("    sb_try_unwind(1);\n")
        }
    }

    private fun emitBody() {
        out.append("    struct sb_frame sb_top;\n")
        out.append("    if (sb_try_enter(&sb_top)) {\n")
        emitRange(0, code.insns.size)
        out.append("        sb_try_exit(&sb_top);\n")
        out.append("    }\n")
        out.append("    ").append(cDefaultReturn()).append('\n')
        out.append("}\n")
    }

    /**
     * Emits instructions [start, end) opening try regions recursively as
     * they appear in the stream.
     */
    private fun emitRange(start: Int, end: Int) {
        var i = start
        while (i < end) {
            val insn = code.insns[i]
            if (insn.isPayload) {
                i++
                continue
            }
            val region = regionsByStart[insn.index]
            if (region != null) {
                out.append("        if (sb_try_enter(sb_frame_push())) {\n")
                emitRange(region.startInsn, region.endInsn)
                out.append("            sb_try_exit_frame();\n")
                out.append("        } else {\n")
                emitHandler(region)
                out.append("        }\n")
                i = region.endInsn
            } else {
                out.append("    ").append(label(insn.index)).append(":;\n")
                emitInsn(insn)
                i++
            }
        }
    }

    /** Emits the else branch of a try region. */
    private fun emitHandler(region: TryRegion) {
        if (region.handlerEntries.isEmpty() && region.catchAll == null) {
            out.append("            sb_propagate(env);\n")
            return
        }
        for ((type, target) in region.handlerEntries) {
            out.append("            if (sb_is_a(env, sb_exception(env), \"")
                .append(escape(type.descriptor.value)).append("\")) goto ")
                .append(label(target)).append(";\n")
        }
        if (region.catchAll != null) {
            out.append("            goto ").append(label(region.catchAll)).append(";\n")
        } else {
            out.append("            sb_propagate(env);\n")
        }
    }

    // ------------------------------------------------------------------
    // Instructions
    // ------------------------------------------------------------------

    private fun emitInsn(insn: DexInsn) {
        when (insn.opcode) {
            0x00 -> Unit // nop

            // ---- moves ----
            in 0x01..0x09 -> out.append(reg(insn.a)).append(" = ").append(reg(insn.b)).append(";\n")
            in 0x0a..0x0c -> out.append(reg(insn.a)).append(" = sb_ret;\n")

            0x0d -> out.append(reg(insn.a)).append(" = SB_O(sb_move_exception(env));\n")

            0x0e -> {
                emitReturnUnwind(insn.index)
                out.append("return;\n")
            }
            in 0x0f..0x11 -> {
                emitReturnUnwind(insn.index)
                out.append(returnOf(insn))
            }

            // ---- consts ----
            0x12, 0x13, 0x14 -> out.append(reg(insn.a)).append(" = SB_I(").append(insn.b.toString()).append(");\n")
            0x15, 0x16 -> out.append(reg(insn.a)).append(" = SB_I(").append(insn.c.toInt().toString()).append(");\n")
            0x17 -> out.append(reg(insn.a)).append(" = SB_J(").append(insn.b.toString()).append("L);\n")
            0x18, 0x19 -> out.append(reg(insn.a)).append(" = SB_J(").append(insn.c.toString()).append("L);\n")
            0x1a, 0x1b -> out.append(reg(insn.a)).append(" = SB_O(sb_new_string(env, \"")
                .append(escape((insn.ref as DexString).value)).append("\"));\n")
            0x1c -> out.append(reg(insn.a)).append(" = SB_O(sb_const_class(env, \"")
                .append(escape((insn.ref as DexType).descriptor.value)).append("\"));\n")

            // ---- monitor / casts / arrays ----
            0x1d -> out.append("sb_monitor(env, ").append(reg(insn.a)).append(", 1);\n")
            0x1e -> out.append("sb_monitor(env, ").append(reg(insn.a)).append(", 0);\n")
            0x1f -> out.append(reg(insn.a)).append(" = SB_O(sb_check_cast(env, ")
                .append(reg(insn.a)).append(".o, \"")
                .append(escape((insn.ref as DexType).descriptor.value)).append("\"));\n")
            0x20 -> out.append(reg(insn.a)).append(" = SB_I(sb_instance_of(env, ")
                .append(reg(insn.b)).append(".o, \"")
                .append(escape((insn.ref as DexType).descriptor.value)).append("\"));\n")
            0x21 -> out.append(reg(insn.a)).append(" = SB_I(sb_array_length(env, ")
                .append(reg(insn.b)).append(".o));\n")
            0x22 -> out.append(reg(insn.a)).append(" = SB_O(sb_new_instance(env, \"")
                .append(escape((insn.ref as DexType).descriptor.value)).append("\"));\n")
            0x23 -> out.append(reg(insn.a)).append(" = SB_O(sb_new_array(env, ")
                .append(reg(insn.b)).append(".i, '")
                .append(arrayKind((insn.ref as DexType).descriptor.value)).append("'));\n")

            0x24, 0x25 -> emitFilledNewArray(insn)

            0x26 -> emitFillArrayData(insn)

            0x27 -> out.append("sb_throw(env, ").append(reg(insn.a)).append(".o);\n")

            // ---- branches ----
            in 0x28..0x2a -> {
                emitUnwindForJump(insn.index, insn.branchTarget!!.index)
                out.append("goto ").append(label(insn.branchTarget!!.index)).append(";\n")
            }
            0x2b -> emitSwitch(insn, true)
            0x2c -> emitSwitch(insn, false)

            // ---- compares ----
            0x2d -> out.append(reg(insn.a)).append(" = SB_I(sb_cmpl_float(")
                .append(reg(insn.b)).append(".f, ").append(reg(insn.c.toInt())).append(".f));\n")
            0x2e -> out.append(reg(insn.a)).append(" = SB_I(sb_cmpg_float(")
                .append(reg(insn.b)).append(".f, ").append(reg(insn.c.toInt())).append(".f));\n")
            0x2f -> out.append(reg(insn.a)).append(" = SB_I(sb_cmpl_double(")
                .append(reg(insn.b)).append(".d, ").append(reg(insn.c.toInt())).append(".d));\n")
            0x30 -> out.append(reg(insn.a)).append(" = SB_I(sb_cmpg_double(")
                .append(reg(insn.b)).append(".d, ").append(reg(insn.c.toInt())).append(".d));\n")
            0x31 -> out.append(reg(insn.a)).append(" = SB_I((jint)(")
                .append(reg(insn.b)).append(".j < ").append(reg(insn.c.toInt())).append(".j ? -1 : (")
                .append(reg(insn.b)).append(".j > ").append(reg(insn.c.toInt())).append(".j ? 1 : 0)));\n")

            else -> {
                if (insn.opcode in 0x32..0x3d) {
                    emitIf(insn)
                } else {
                    when {
                        insn.opcode in 0x44..0x51 -> emitArrayAccess(insn)
                        insn.opcode in 0x52..0x6d -> emitFieldAccess(insn)
                        insn.opcode in 0x6e..0x72 || insn.opcode in 0x74..0x78 -> emitInvoke(insn)
                        insn.opcode in 0x7b..0x8f -> emitUnary(insn)
                        insn.opcode in 0x90..0xaf -> emitArith(insn)
                        insn.opcode in 0xb0..0xcf -> emitArith2Addr(insn)
                        insn.opcode in 0xd0..0xe2 -> emitArithLit(insn)
                        else -> throw SmaliToCTranslator.TranslationException(
                            "Unsupported opcode 0x" + insn.opcode.toString(16) + " (" + insn.name + ")",
                        )
                    }
                }
            }
        }
    }

    private fun reg(n: Int): String = "v$n"

    private fun returnOf(insn: DexInsn): String {
        val ret = method.proto.returnType.descriptor.value
        return when (ret) {
            "V" -> "return;\n"
            "J" -> "return sb_to_long(" + reg(insn.a) + ");\n"
            "F" -> "return sb_to_float(" + reg(insn.a) + ");\n"
            "D" -> "return sb_to_double(" + reg(insn.a) + ");\n"
            "I" -> "return sb_to_int(" + reg(insn.a) + ");\n"
            "Z" -> "return (jboolean)sb_to_int(" + reg(insn.a) + ");\n"
            "B" -> "return (jbyte)sb_to_int(" + reg(insn.a) + ");\n"
            "C" -> "return (jchar)sb_to_int(" + reg(insn.a) + ");\n"
            "S" -> "return (jshort)sb_to_int(" + reg(insn.a) + ");\n"
            else -> "return sb_to_obj(" + reg(insn.a) + ");\n"
        }
    }

    private fun emitIf(insn: DexInsn) {
        val target = insn.branchTarget!!.index
        emitUnwindForJump(insn.index, target)
        val cond: String = when (insn.opcode) {
            0x32 -> "${reg(insn.a)}.i == ${reg(insn.b)}.i"
            0x33 -> "${reg(insn.a)}.i != ${reg(insn.b)}.i"
            0x34 -> "${reg(insn.a)}.i < ${reg(insn.b)}.i"
            0x35 -> "${reg(insn.a)}.i >= ${reg(insn.b)}.i"
            0x36 -> "${reg(insn.a)}.i > ${reg(insn.b)}.i"
            0x37 -> "${reg(insn.a)}.i <= ${reg(insn.b)}.i"
            0x38 -> "${reg(insn.a)}.i == 0"
            0x39 -> "${reg(insn.a)}.i != 0"
            0x3a -> "${reg(insn.a)}.i < 0"
            0x3b -> "${reg(insn.a)}.i >= 0"
            0x3c -> "${reg(insn.a)}.i > 0"
            else -> "${reg(insn.a)}.i <= 0"
        }
        out.append("if (").append(cond).append(") goto ").append(label(target)).append(";\n")
    }

    private fun arrayKind(descriptor: String): Char = when (descriptor) {
        "[I" -> 'I'
        "[J" -> 'J'
        "[F" -> 'F'
        "[D" -> 'D'
        "[Z" -> 'Z'
        "[B" -> 'B'
        "[C" -> 'C'
        "[S" -> 'S'
        else -> 'L'
    }

    private fun accessKind(descriptor: String): Char = when (descriptor) {
        "I" -> 'I'; "J" -> 'J'; "F" -> 'F'; "D" -> 'D'
        "Z" -> 'Z'; "B" -> 'B'; "C" -> 'C'; "S" -> 'S'; else -> 'L'
    }

    private fun emitArrayAccess(insn: DexInsn) {
        val array = reg(insn.b)
        val index = reg(insn.c.toInt())
        val value = reg(insn.a)
        when (insn.opcode) {
            in 0x44..0x4a -> out.append(value).append(" = SB_").append(suffixOf(arrayChar(insn)))
                .append("(sb_aget(env, ").append(array).append(".o, ").append(index)
                .append(".i, '").append(arrayChar(insn)).append("'));\n")
            else -> out.append("sb_aput(env, ").append(array).append(".o, ").append(index)
                .append(".i, '").append(arrayChar(insn)).append("', ").append(value).append(");\n")
        }
    }

    private fun arrayChar(insn: DexInsn): Char = when (insn.opcode) {
        0x45, 0x4c -> 'J'
        0x46, 0x4d -> 'L'
        else -> 'I'
    }

    private fun emitFieldAccess(insn: DexInsn) {
        val field = insn.ref as DexField
        val className = escape(field.declaringClass.descriptor.value)
        val fieldName = escape(field.name.value)
        val fieldType = escape(field.type.descriptor.value)
        val kind = accessKind(field.type.descriptor.value)
        when (insn.opcode) {
            in 0x52..0x58 -> {
                out.append(reg(insn.a)).append(" = SB_").append(suffixOf(kind))
                    .append("(sb_iget(env, ").append(reg(insn.b)).append(".o, \"").append(className)
                    .append("\", \"").append(fieldName).append("\", \"").append(fieldType)
                    .append("\"));\n")
            }
            in 0x59..0x5f -> {
                out.append("sb_iput(env, ").append(reg(insn.b)).append(".o, \"").append(className)
                    .append("\", \"").append(fieldName).append("\", \"").append(fieldType)
                    .append("\", ").append(reg(insn.a)).append(");\n")
            }
            in 0x60..0x66 -> {
                out.append(reg(insn.a)).append(" = SB_").append(suffixOf(kind))
                    .append("(sb_sget(env, \"").append(className).append("\", \"").append(fieldName)
                    .append("\", \"").append(fieldType).append("\"));\n")
            }
            else -> {
                out.append("sb_sput(env, \"").append(className).append("\", \"").append(fieldName)
                    .append("\", \"").append(fieldType).append("\", ")
                    .append(reg(insn.a)).append(");\n")
            }
        }
    }

    private fun suffixOf(kind: Char): String = when (kind) {
        'J' -> "J"
        'F' -> "F"
        'D' -> "D"
        'L' -> "O"
        else -> "I"
    }

    private fun emitInvoke(insn: DexInsn) {
        val target = insn.ref as DexMethod
        val kind = when (insn.opcode) {
            0x6e, 0x74 -> "SB_INVOKE_VIRTUAL"
            0x6f, 0x75 -> "SB_INVOKE_SUPER"
            0x70, 0x76 -> "SB_INVOKE_DIRECT"
            0x71, 0x77 -> "SB_INVOKE_STATIC"
            else -> "SB_INVOKE_INTERFACE"
        }
        val paramTypes = parseTypes(target.proto.parameterDescriptors)
        val retKind = accessKind(target.proto.returnType.descriptor.value)
        val static = kind == "SB_INVOKE_STATIC"
        val regList = insn.regs ?: IntArray(0)
        val argStart = if (static) 0 else 1

        out.append("        {\n")
        out.append("            jvalue sb_args[").append(maxOf(paramTypes.size, 1)).append("];\n")
        var cursor = argStart
        paramTypes.forEachIndexed { index, type ->
            if (cursor >= regList.size) {
                throw SmaliToCTranslator.TranslationException("Invoke register list too short")
            }
            out.append("            sb_args[").append(index).append("] = sb_arg(")
                .append(reg(regList[cursor])).append(", '")
                .append(accessKind(type))
                .append("');\n")
            cursor += if (type == "J" || type == "D") 2 else 1
        }
        out.append("            sb_ret = sb_invoke(env, ").append(kind).append(", ")
        if (!static) {
            out.append(reg(regList[0])).append(".o, ")
        } else {
            out.append("NULL, ")
        }
        out.append("\"").append(escape(target.declaringClass.descriptor.value)).append("\", \"")
            .append(escape(target.name.value)).append("\", \"")
            .append(escape(target.proto.parameterDescriptors))
            .append(escape(target.proto.returnType.descriptor.value)).append("\", '")
            .append(retKind).append("', sb_args);\n")
        out.append("        }\n")
    }

    private fun emitFilledNewArray(insn: DexInsn) {
        val type = (insn.ref as DexType).descriptor.value
        val kind = accessKind(type.substring(1))
        val regs = insn.regs ?: IntArray(0)
        out.append("        {\n")
        out.append("            SB sb_vals[").append(maxOf(regs.size, 1)).append("];\n")
        regs.forEachIndexed { index, register ->
            out.append("            sb_vals[").append(index).append("] = ").append(reg(register)).append(";\n")
        }
        out.append("            sb_ret = SB_O(sb_filled_new_array(env, \"")
            .append(escape(type)).append("\", sb_vals, ").append(regs.size).append(", '")
            .append(kind).append("'));\n")
        out.append("        }\n")
    }

    private fun emitFillArrayData(insn: DexInsn) {
        val payload = insn.payload ?: throw SmaliToCTranslator.TranslationException("Missing array payload")
        if (payload.kind != PayloadKind.ARRAY_DATA) {
            throw SmaliToCTranslator.TranslationException("Wrong payload for fill-array-data")
        }
        val blobName = "sb_data_${insn.index}"
        dataBlobs.add(blobName to payload.data)
        out.append("sb_fill_array_data(env, ").append(reg(insn.a)).append(".o, ")
            .append(blobName).append(", ").append(payload.data.size).append(", ")
            .append(payload.elementWidth).append(");\n")
    }

    private fun emitSwitch(insn: DexInsn, packed: Boolean) {
        val payload = insn.payload ?: throw SmaliToCTranslator.TranslationException("Missing switch payload")
        out.append("switch (").append(reg(insn.a)).append(".i) {\n")
        if (packed) {
            payload.targets.forEachIndexed { index, target ->
                val targetIndex = addrToIndex[target] ?: target
                emitUnwindForJump(insn.index, targetIndex)
                out.append("case ").append(payload.firstKey + index).append(": goto ")
                    .append(label(targetIndex)).append(";\n")
            }
        } else {
            payload.keys.forEachIndexed { index, key ->
                val target = payload.targets[index]
                val targetIndex = addrToIndex[target] ?: target
                emitUnwindForJump(insn.index, targetIndex)
                out.append("case ").append(key).append(": goto ")
                    .append(label(targetIndex)).append(";\n")
            }
        }
        out.append("default: break;\n")
        out.append("}\n")
    }

    private fun emitUnary(insn: DexInsn) {
        val dst = reg(insn.a)
        val src = reg(insn.b)
        when (insn.opcode) {
            0x7b -> out.append(dst).append(" = SB_I(-").append(src).append(".i);\n")
            0x7c -> out.append(dst).append(" = SB_I(~").append(src).append(".i);\n")
            0x7d -> out.append(dst).append(" = SB_J(-").append(src).append(".j);\n")
            0x7e -> out.append(dst).append(" = SB_J(~").append(src).append(".j);\n")
            0x7f -> out.append(dst).append(" = SB_F(-").append(src).append(".f);\n")
            0x80 -> out.append(dst).append(" = SB_D(-").append(src).append(".d);\n")
            0x81 -> out.append(dst).append(" = SB_J((jlong)").append(src).append(".i);\n")
            0x82 -> out.append(dst).append(" = SB_F((jfloat)").append(src).append(".i);\n")
            0x83 -> out.append(dst).append(" = SB_D((jdouble)").append(src).append(".i);\n")
            0x84 -> out.append(dst).append(" = SB_I((jint)").append(src).append(".j);\n")
            0x85 -> out.append(dst).append(" = SB_F(sb_l2f(").append(src).append(".j));\n")
            0x86 -> out.append(dst).append(" = SB_D((jdouble)").append(src).append(".j);\n")
            0x87 -> out.append(dst).append(" = SB_I(sb_f2i(").append(src).append(".f));\n")
            0x88 -> out.append(dst).append(" = SB_J(sb_f2l(").append(src).append(".f));\n")
            0x89 -> out.append(dst).append(" = SB_D((jdouble)").append(src).append(".f);\n")
            0x8a -> out.append(dst).append(" = SB_I(sb_d2i(").append(src).append(".d));\n")
            0x8b -> out.append(dst).append(" = SB_J(sb_d2l(").append(src).append(".d));\n")
            0x8c -> out.append(dst).append(" = SB_F((jfloat)").append(src).append(".d);\n")
            0x8d -> out.append(dst).append(" = SB_I((jint)(jbyte)").append(src).append(".i);\n")
            0x8e -> out.append(dst).append(" = SB_I((jint)(jchar)").append(src).append(".i);\n")
            0x8f -> out.append(dst).append(" = SB_I((jint)(jshort)").append(src).append(".i);\n")
        }
    }

    private fun emitArith(insn: DexInsn) {
        val dst = reg(insn.a)
        val lhs = reg(insn.b)
        val rhs = reg(insn.c.toInt())
        when {
            insn.opcode == 0x93 || insn.opcode == 0x94 ->
                out.append(dst).append(" = SB_I(").append(intOpName(insn.opcode))
                    .append("(env, ").append(lhs).append(".i, ").append(rhs).append(".i));\n")
            insn.opcode == 0x9e || insn.opcode == 0x9f ->
                out.append(dst).append(" = SB_J(").append(longOpName(insn.opcode))
                    .append("(env, ").append(lhs).append(".j, ").append(rhs).append(".j));\n")
            insn.opcode in 0x90..0x9a ->
                out.append(dst).append(" = SB_I(").append(intOpName(insn.opcode))
                    .append("(").append(lhs).append(".i, ").append(rhs).append(".i));\n")
            insn.opcode in 0x9b..0xa5 ->
                out.append(dst).append(" = SB_J(").append(longOpName(insn.opcode))
                    .append("(").append(lhs).append(".j, ").append(rhs).append(".j));\n")
            insn.opcode in 0xa6..0xaa ->
                out.append(dst).append(" = SB_F(").append(floatOpName(insn.opcode))
                    .append("(").append(lhs).append(".f, ").append(rhs).append(".f));\n")
            else ->
                out.append(dst).append(" = SB_D(").append(doubleOpName(insn.opcode))
                    .append("(").append(lhs).append(".d, ").append(rhs).append(".d));\n")
        }
    }

    private fun emitArith2Addr(insn: DexInsn) {
        // Two address form: vA = vA op vB, translated as the three address
        // equivalent with the left operand duplicated.
        emitArith(
            DexInsn(
                opcode = insn.opcode - 0x20,
                format = com.soulbrou.dex2c.code.InsnFormat.F23X,
                a = insn.a,
                b = insn.a,
                c = insn.b.toLong(),
            ),
        )
    }

    private fun emitArithLit(insn: DexInsn) {
        val dst = reg(insn.b)
        val lhs = reg(insn.a)
        val literal = insn.c.toInt()
        when (insn.opcode) {
            0xd1, 0xd9 -> {
                // rsub-int: literal - register
                out.append(dst).append(" = SB_I(sb_sub_i(")
                    .append(literal).append(", ").append(lhs).append(".i));\n")
            }
            else -> {
                val base = when (insn.opcode) {
                    in 0xd0..0xd7 -> insn.opcode - 0xd0 + 0x90
                    in 0xd8..0xe2 -> insn.opcode - 0xd8 + 0x90
                    else -> throw SmaliToCTranslator.TranslationException("Bad literal opcode")
                }
                out.append(dst).append(" = SB_I(").append(intOpName(base))
                    .append("(").append(lhs).append(".i, ").append(literal).append("));\n")
            }
        }
    }

    private fun intOpName(opcode: Int): String = when (opcode) {
        0x90 -> "sb_add_i"
        0x91 -> "sb_sub_i"
        0x92 -> "sb_mul_i"
        0x93 -> "sb_div_i"
        0x94 -> "sb_rem_i"
        0x95 -> "sb_and_i"
        0x96 -> "sb_or_i"
        0x97 -> "sb_xor_i"
        0x98 -> "sb_shl_i"
        0x99 -> "sb_shr_i"
        0x9a -> "sb_ushr_i"
        else -> throw SmaliToCTranslator.TranslationException("Bad int op")
    }

    private fun longOpName(opcode: Int): String = when (opcode) {
        0x9b -> "sb_add_l"
        0x9c -> "sb_sub_l"
        0x9d -> "sb_mul_l"
        0x9e -> "sb_div_l"
        0x9f -> "sb_rem_l"
        0xa0 -> "sb_and_l"
        0xa1 -> "sb_or_l"
        0xa2 -> "sb_xor_l"
        0xa3 -> "sb_shl_l"
        0xa4 -> "sb_shr_l"
        0xa5 -> "sb_ushr_l"
        else -> throw SmaliToCTranslator.TranslationException("Bad long op")
    }

    private fun floatOpName(opcode: Int): String = when (opcode) {
        0xa6 -> "sb_add_f"
        0xa7 -> "sb_sub_f"
        0xa8 -> "sb_mul_f"
        0xa9 -> "sb_div_f"
        0xaa -> "sb_rem_f"
        else -> throw SmaliToCTranslator.TranslationException("Bad float op")
    }

    private fun doubleOpName(opcode: Int): String = when (opcode) {
        0xab -> "sb_add_d"
        0xac -> "sb_sub_d"
        0xad -> "sb_mul_d"
        0xae -> "sb_div_d"
        0xaf -> "sb_rem_d"
        else -> throw SmaliToCTranslator.TranslationException("Bad double op")
    }

    private fun emitBlobs() {
        for ((name, data) in dataBlobs) {
            out.append("\nstatic const unsigned char ").append(name).append("[").append(data.size)
                .append("] = {")
            for (i in data.indices) {
                if (i % 16 == 0) out.append("\n    ")
                out.append(data[i].toInt() and 0xFF).append(',')
            }
            out.append("\n};\n")
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

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

    private fun cTypeOf(type: String): String = when (type) {
        "V" -> "void"
        "J" -> "jlong"
        "F" -> "jfloat"
        "D" -> "jdouble"
        "I" -> "jint"
        "Z" -> "jboolean"
        "B" -> "jbyte"
        "C" -> "jchar"
        "S" -> "jshort"
        else -> "jobject"
    }

    private fun escape(text: String): String {
        val sb = StringBuilder(text.length + 16)
        for (ch in text) {
            when {
                ch == '"' -> sb.append("\\\"")
                ch == '\\' -> sb.append("\\\\")
                ch == '\n' -> sb.append("\\n")
                ch == '\r' -> sb.append("\\r")
                ch == '\t' -> sb.append("\\t")
                ch.code in 0x20..0x7E -> sb.append(ch)
                else -> sb.append(String.format("\\%03o", ch.code))
            }
        }
        return sb.toString()
    }
}
