package com.soulbrou.dex2c.code

import com.soulbrou.dex2c.model.DexField
import com.soulbrou.dex2c.model.DexMethod
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.model.DexType

/**
 * Renders decoded instructions back to smali syntax, used by the method
 * preview of the selection screen.
 */
class SmaliPrinter(private val code: DexCode) {

    fun print(): String {
        val out = StringBuilder(512)
        out.append(".registers ").append(code.registersSize).append('\n')
        for (insn in code.insns) {
            if (insn.isPayload) continue
            out.append("    ").append(format(insn)).append('\n')
        }
        return out.toString()
    }

    private fun format(insn: DexInsn): String {
        val name = insn.name
        val operands = StringBuilder()
        fun target() = ":L" + (insn.branchTarget?.index ?: insn.branchAddress)

        when (insn.format) {
            InsnFormat.F10X -> Unit
            InsnFormat.F12X -> operands.append("v").append(insn.a).append(", v").append(insn.b)
            InsnFormat.F11N -> operands.append("v").append(insn.a).append(", ").append(insn.b)
            InsnFormat.F11X -> operands.append("v").append(insn.a)
            InsnFormat.F10T -> operands.append(target())
            InsnFormat.F20T -> operands.append(target())
            InsnFormat.F21T -> operands.append("v").append(insn.a).append(", ").append(target())
            InsnFormat.F21S -> operands.append("v").append(insn.a).append(", ").append(insn.b)
            InsnFormat.F21H -> operands.append("v").append(insn.a).append(", 0x")
                .append(insn.c.toString(16))
            InsnFormat.F21C, InsnFormat.F31C -> operands.append("v").append(insn.a).append(", ")
                .append(refText(insn.ref))
            InsnFormat.F22X -> operands.append("v").append(insn.a).append(", v").append(insn.b)
            InsnFormat.F23X -> operands.append("v").append(insn.a).append(", v").append(insn.b)
                .append(", v").append(insn.c.toInt())
            InsnFormat.F22B -> operands.append("v").append(insn.a).append(", v").append(insn.b)
                .append(", ").append(insn.c.toInt())
            InsnFormat.F22T -> operands.append("v").append(insn.a).append(", v").append(insn.b)
                .append(", ").append(target())
            InsnFormat.F22S -> operands.append("v").append(insn.a).append(", v").append(insn.b)
                .append(", ").append(insn.c.toInt())
            InsnFormat.F22C -> operands.append("v").append(insn.a).append(", v").append(insn.b)
                .append(", ").append(refText(insn.ref))
            InsnFormat.F30T -> operands.append(target())
            InsnFormat.F31I -> operands.append("v").append(insn.a).append(", 0x")
                .append(insn.c.toInt().toLong().and(0xFFFFFFFFL).toString(16))
            InsnFormat.F31T -> operands.append("v").append(insn.a).append(", ")
                .append(payloadSummary(insn))
            InsnFormat.F32X -> operands.append("v").append(insn.a).append(", v").append(insn.b)
            InsnFormat.F35C, InsnFormat.F45CC -> {
                val regs = insn.regs ?: IntArray(0)
                operands.append("{")
                regs.forEachIndexed { index, register ->
                    if (index > 0) operands.append(", ")
                    operands.append("v").append(register)
                }
                operands.append("}, ").append(refText(insn.ref))
            }
            InsnFormat.F3RC, InsnFormat.F4RCC -> {
                val regs = insn.regs ?: IntArray(0)
                operands.append("{v").append(regs.firstOrNull() ?: 0).append(" .. v")
                    .append((regs.lastOrNull() ?: 0)).append("}, ").append(refText(insn.ref))
            }
            InsnFormat.F51L -> operands.append("v").append(insn.a).append(", 0x")
                .append(insn.c.toString(16)).append('L')
        }
        return name + (if (operands.isEmpty()) "" else " $operands")
    }

    private fun payloadSummary(insn: DexInsn): String {
        val payload = insn.payload ?: return "payload"
        return when (payload.kind) {
            PayloadKind.PACKED_SWITCH -> "packed-switch:+${payload.targets.size} targets"
            PayloadKind.SPARSE_SWITCH -> "sparse-switch:${payload.keys.size} keys"
            PayloadKind.ARRAY_DATA -> "array-data:${payload.data.size} bytes"
        }
    }

    private fun refText(ref: Any?): String = when (ref) {
        null -> "0"
        is DexString -> "\"" + ref.value.replace("\n", "\\n") + "\""
        is DexType -> ref.descriptor.value
        is DexField -> ref.declaringClass.descriptor.value + "->" + ref.name.value + ":" +
            ref.type.descriptor.value
        is DexMethod -> ref.declaringClass.descriptor.value + "->" + ref.name.value + "(" +
            ref.proto.parameterDescriptors + ")" + ref.proto.returnType.descriptor.value
        else -> ref.toString()
    }
}
