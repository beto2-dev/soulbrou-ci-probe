package com.soulbrou.dex2c.code

/**
 * Instruction formats of the Dalvik bytecode. The numeric value is the
 * encoded size in 16 bit code units.
 */
enum class InsnFormat(val size: Int) {
    F10X(1),
    F12X(1),
    F11N(1),
    F11X(1),
    F10T(1),
    F20T(2),
    F22X(2),
    F21T(2),
    F21S(2),
    F21H(2),
    F21C(2),
    F23X(2),
    F22B(2),
    F22T(2),
    F22S(2),
    F22C(2),
    F30T(3),
    F31I(3),
    F31T(3),
    F31C(3),
    F32X(3),
    F35C(3),
    F3RC(3),
    F45CC(4),
    F4RCC(4),
    F51L(5),
}

/** Formats that behave as goto and can be widened when offsets grow. */
private val GOTO_FORMATS = setOf(InsnFormat.F10T, InsnFormat.F20T, InsnFormat.F30T)

/** Kind of an embedded payload pseudo instruction. */
enum class PayloadKind { PACKED_SWITCH, SPARSE_SWITCH, ARRAY_DATA }

/**
 * Payload data referenced by packed-switch, sparse-switch and
 * fill-array-data instructions. Payloads are kept in the instruction stream
 * (at their original position) so offsets can be recomputed on re-encoding.
 */
class DexPayload(
    val kind: PayloadKind,
    val elementWidth: Int,
    val elementCount: Int,
    val firstKey: Int,
    val targets: IntArray,
    val keys: IntArray,
    val data: ByteArray,
) {
    val unitCount: Int
        get() = when (kind) {
            PayloadKind.PACKED_SWITCH -> 4 + targets.size * 2
            PayloadKind.SPARSE_SWITCH -> 2 + keys.size + targets.size * 2
            PayloadKind.ARRAY_DATA -> 2 + (data.size + 1) / 2
        }

    companion object {
        fun packed(firstKey: Int, targets: IntArray) =
            DexPayload(PayloadKind.PACKED_SWITCH, 0, targets.size, firstKey, targets, IntArray(0), ByteArray(0))

        fun sparse(keys: IntArray, targets: IntArray) =
            DexPayload(PayloadKind.SPARSE_SWITCH, 0, keys.size, 0, targets, keys, ByteArray(0))

        fun array(elementWidth: Int, data: ByteArray) =
            DexPayload(PayloadKind.ARRAY_DATA, elementWidth, data.size / elementWidth, 0, IntArray(0), IntArray(0), data)
    }
}

/**
 * A decoded Dalvik instruction. Operands are stored in generic slots whose
 * meaning depends on the format and the opcode table entry:
 *
 * - [a] holds the first register operand (A, AA) or register count.
 * - [b] holds the second register operand (B, BB) or literal bits.
 * - [c] holds wide literals (64 bit) or 32 bit literal payloads.
 * - [ref] holds the referenced string, type, field, method, proto or
 *   call site depending on the opcode.
 * - [extraProto] holds the second proto of invoke-polymorphic instructions.
 * - [regs] holds the register list of invoke style instructions.
 * - [branchTarget] holds the resolved branch instruction.
 * - [payload] holds the switch or array payload.
 */
class DexInsn(
    var opcode: Int,
    var format: InsnFormat,
    val a: Int = 0,
    val b: Int = 0,
    val c: Long = 0L,
    val ref: Any? = null,
    val regs: IntArray? = null,
) {
    /** Address in 16 bit code units from the start of the method body. */
    var address: Int = 0

    /** Ordinal position within the instruction list. */
    var index: Int = 0

    /** Resolved branch target, set after decoding. */
    var branchTarget: DexInsn? = null

    /** Raw branch target address, used before resolution. */
    var branchAddress: Int = 0

    /** Resolved payload, set after decoding. */
    var payload: DexPayload? = null

    /** Raw payload address, used before resolution. */
    var payloadAddress: Int = 0

    /** Second prototype of invoke-polymorphic instructions. */
    var extraProto: com.soulbrou.dex2c.model.DexProto? = null

    /** Payload pseudo instruction marker. */
    val isPayload: Boolean get() = payload != null

    val name: String get() = OpcodeInfo.name(opcode)
}

/**
 * A try region expressed in code unit addresses.
 */
class DexTry(
    val startAddress: Int,
    val instructionCount: Int,
    val handler: DexCatchHandler,
)

/**
 * One typed entry of a catch handler.
 */
class DexCatchEntry(
    val type: com.soulbrou.dex2c.model.DexType,
    val address: Int,
)

/**
 * A full catch handler: the ordered typed entries plus an optional
 * catch-all address. Models an encoded_catch_handler.
 */
class DexCatchHandler(
    val entries: List<DexCatchEntry>,
    val catchAllAddress: Int?,
)

/**
 * Debug information of one code item, fully decoded so the string and type
 * indices can be remapped when the identifier tables change.
 */
class DexDebugInfo(
    val lineStart: Int,
    val parameterNames: List<com.soulbrou.dex2c.model.DexString?>,
    val ops: List<DebugOp>,
)

/** One decoded entry of the debug information state machine. */
sealed class DebugOp {
    data class AdvancePc(val units: Int) : DebugOp()
    data class AdvanceLine(val line: Int) : DebugOp()
    data class StartLocal(
        val register: Int,
        val name: com.soulbrou.dex2c.model.DexString?,
        val type: com.soulbrou.dex2c.model.DexType?,
    ) : DebugOp()

    data class StartLocalExtended(
        val register: Int,
        val name: com.soulbrou.dex2c.model.DexString?,
        val type: com.soulbrou.dex2c.model.DexType?,
        val signature: com.soulbrou.dex2c.model.DexString?,
    ) : DebugOp()

    data class EndLocal(val register: Int) : DebugOp()
    data class RestartLocal(val register: Int) : DebugOp()
    data object SetPrologueEnd : DebugOp()
    data object SetEpilogueBegin : DebugOp()
    data class SetFile(val name: com.soulbrou.dex2c.model.DexString?) : DebugOp()
}

/**
 * A fully decoded code item.
 */
class DexCode(
    var registersSize: Int,
    var insSize: Int,
    var outsSize: Int,
    var debugInfo: DexDebugInfo?,
    val insns: MutableList<DexInsn>,
    var tries: List<DexTry>,
) {
    /** Total size of the instruction stream in code units. */
    val codeUnits: Int
        get() = insns.sumOf { if (it.isPayload) it.payload!!.unitCount else it.format.size }
}
