package com.soulbrou.dex2c.code

import com.soulbrou.dex2c.model.DexCallSite
import com.soulbrou.dex2c.model.DexField
import com.soulbrou.dex2c.model.DexMethod
import com.soulbrou.dex2c.model.DexMethodHandle
import com.soulbrou.dex2c.model.DexProto
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.model.DexType

/**
 * Decodes and encodes code items. The codec turns the raw instruction stream
 * plus try blocks of a code_item into a symbolic [DexCode] and back, keeping
 * branch targets and payload references resolved as object links so that
 * instruction insertions stay consistent.
 *
 * The codec needs access to the identifier tables of the owning DEX model to
 * intern references while decoding; the [ReferenceResolver] callbacks hide
 * the details of that model.
 */
class DexCodeCodec(private val resolver: ReferenceResolver) {

    /** Bridges the codec to the identifier tables of the model. */
    interface ReferenceResolver {
        fun string(index: Int): DexString
        fun type(index: Int): DexType
        fun proto(index: Int): DexProto
        fun field(index: Int): DexField
        fun method(index: Int): DexMethod
        fun methodHandle(index: Int): DexMethodHandle
        fun callSite(index: Int): DexCallSite
        fun stringIndexOf(value: DexString): Int
        fun typeIndexOf(value: DexType): Int
        fun protoIndexOf(value: DexProto): Int
        fun fieldIndexOf(value: DexField): Int
        fun methodIndexOf(value: DexMethod): Int
        fun methodHandleIndexOf(value: DexMethodHandle): Int
        fun callSiteIndexOf(value: DexCallSite): Int
    }

    /** Thrown when a method body uses bytecode the codec cannot process. */
    class CodeDecodeException(message: String) : Exception(message)

    // ------------------------------------------------------------------
    // Decoding
    // ------------------------------------------------------------------

    fun decode(
        registersSize: Int,
        insSize: Int,
        outsSize: Int,
        debugInfo: DexDebugInfo?,
        units: IntArray,
        triesSpec: List<TrySpec>,
    ): DexCode {
        val payloadAddresses = scanPayloadAddresses(units)

        val insns = ArrayList<DexInsn>(units.size / 2 + 8)
        var address = 0
        while (address < units.size) {
            val insn = if (address in payloadAddresses) {
                decodePayload(units, address)
            } else {
                decodeInsn(units, address)
            }
            insn.address = address
            insn.index = insns.size
            insns.add(insn)
            address += if (insn.isPayload) insn.payload!!.unitCount else insn.format.size
        }

        // Second pass: resolve branch and payload links by address.
        val byAddress = HashMap<Int, DexInsn>()
        for (insn in insns) {
            byAddress[insn.address] = insn
        }
        for (insn in insns) {
            when (insn.format) {
                InsnFormat.F10T, InsnFormat.F20T, InsnFormat.F21T, InsnFormat.F22T, InsnFormat.F30T -> {
                    val target = byAddress[insn.branchAddress]
                        ?: throw CodeDecodeException(
                            "Unresolved branch target ${insn.branchAddress} at ${insn.address}",
                        )
                    insn.branchTarget = target
                }
                else -> Unit
            }
            when (insn.opcode) {
                OpcodeInfo.OP_PACKED_SWITCH, OpcodeInfo.OP_SPARSE_SWITCH, OpcodeInfo.OP_FILL_ARRAY_DATA -> {
                    val payloadInsn = byAddress[insn.payloadAddress]
                        ?: throw CodeDecodeException(
                            "Unresolved payload ${insn.payloadAddress} at ${insn.address}",
                        )
                    val payload = payloadInsn.payload
                        ?: throw CodeDecodeException("Target is not a payload at ${insn.payloadAddress}")
                    insn.payload = payload
                }
                else -> Unit
            }
        }

        val tries = triesSpec.map { raw ->
            DexTry(raw.startAddress, raw.instructionCount, raw.handler)
        }

        return DexCode(registersSize, insSize, outsSize, debugInfo, insns, tries)
    }

    private fun scanPayloadAddresses(units: IntArray): Set<Int> {
        val addresses = HashSet<Int>()
        var address = 0
        while (address < units.size) {
            val opcode = units[address] and 0xFF
            val spec = OpcodeInfo.spec(opcode) ?: break
            if (opcode == OpcodeInfo.OP_PACKED_SWITCH ||
                opcode == OpcodeInfo.OP_SPARSE_SWITCH ||
                opcode == OpcodeInfo.OP_FILL_ARRAY_DATA
            ) {
                val offset = readI32(units, address + 1)
                addresses.add(address + offset)
            }
            address += spec.format.size
        }
        return addresses
    }

    private fun decodePayload(units: IntArray, address: Int): DexInsn {
        val ident = units[address]
        val payload = when (ident) {
            OpcodeInfo.PAYLOAD_PACKED_IDENT -> {
                val size = units[address + 1]
                val firstKey = readI32(units, address + 2)
                val targets = IntArray(size) { i -> readI32(units, address + 4 + i * 2) }
                DexPayload.packed(firstKey, targets)
            }
            OpcodeInfo.PAYLOAD_SPARSE_IDENT -> {
                val size = units[address + 1]
                val keys = IntArray(size) { units[address + 2 + it] }
                val targets = IntArray(size) { i -> readI32(units, address + 2 + size + i * 2) }
                DexPayload.sparse(keys, targets)
            }
            OpcodeInfo.PAYLOAD_ARRAY_IDENT -> {
                val width = units[address + 1]
                val size = readI32(units, address + 2)
                val byteCount = size * width
                val data = ByteArray(byteCount)
                var byteIndex = 0
                var unitIndex = address + 4
                while (byteIndex < byteCount) {
                    val unit = units[unitIndex++]
                    var shift = 0
                    while (shift < 16 && byteIndex < byteCount) {
                        data[byteIndex++] = ((unit shr shift) and 0xFF).toByte()
                        shift += 8
                    }
                }
                DexPayload.array(width, data)
            }
            else -> throw CodeDecodeException("Unknown payload identity 0x" + ident.toString(16))
        }
        return DexInsn(OpcodeInfo.OP_NOP, InsnFormat.F10X).apply { this.payload = payload }
    }

    private fun decodeInsn(units: IntArray, address: Int): DexInsn {
        val u0 = units[address]
        val opcode = u0 and 0xFF
        val spec = OpcodeInfo.spec(opcode)
            ?: throw CodeDecodeException("Unknown opcode 0x" + opcode.toString(16))

        fun u1() = units[address + 1]
        fun u2() = units[address + 2]
        fun u3() = units[address + 3]

        return when (spec.format) {
            InsnFormat.F10X -> DexInsn(opcode, spec.format)
            InsnFormat.F12X -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xF, b = (u0 shr 12) and 0xF)
            InsnFormat.F11N -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xF, b = signed4((u0 shr 12) and 0xF))
            InsnFormat.F11X -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF)
            InsnFormat.F10T -> DexInsn(opcode, spec.format).apply {
                branchAddress = address + signed8((u0 shr 8) and 0xFF)
            }
            InsnFormat.F20T -> DexInsn(opcode, spec.format).apply {
                branchAddress = address + signed16(u1())
            }
            InsnFormat.F21T -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF).apply {
                branchAddress = address + signed16(u1())
            }
            InsnFormat.F21S -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, b = signed16(u1()))
            InsnFormat.F21H -> {
                val raw = signed16(u1()).toLong()
                DexInsn(
                    opcode, spec.format,
                    a = (u0 shr 8) and 0xFF,
                    c = if (opcode == 0x19) raw shl 48 else raw shl 16,
                )
            }
            InsnFormat.F21C -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, ref = resolveRef(spec.ref, u1()))
            InsnFormat.F22X -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, b = u1())
            InsnFormat.F23X -> DexInsn(
                opcode, spec.format,
                a = (u0 shr 8) and 0xFF,
                b = u1() and 0xFF,
                c = ((u1() shr 8) and 0xFF).toLong(),
            )
            InsnFormat.F22B -> DexInsn(
                opcode, spec.format,
                a = (u0 shr 8) and 0xFF,
                b = u1() and 0xFF,
                c = signed8((u1() shr 8) and 0xFF).toLong(),
            )
            InsnFormat.F22T -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xF, b = (u0 shr 12) and 0xF).apply {
                branchAddress = address + signed16(u1())
            }
            InsnFormat.F22S -> DexInsn(
                opcode, spec.format,
                a = (u0 shr 8) and 0xF,
                b = (u0 shr 12) and 0xF,
                c = signed16(u1()).toLong(),
            )
            InsnFormat.F22C -> DexInsn(
                opcode, spec.format,
                a = (u0 shr 8) and 0xF,
                b = (u0 shr 12) and 0xF,
                ref = resolveRef(spec.ref, u1()),
            )
            InsnFormat.F30T -> DexInsn(opcode, spec.format).apply {
                branchAddress = address + readI32(units, address + 1)
            }
            InsnFormat.F31I -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, c = readI32(units, address + 1).toLong())
            InsnFormat.F31T -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF).apply {
                payloadAddress = address + readI32(units, address + 1)
            }
            InsnFormat.F31C -> DexInsn(
                opcode, spec.format,
                a = (u0 shr 8) and 0xFF,
                ref = resolveRef(spec.ref, readI32(units, address + 1)),
            )
            InsnFormat.F32X -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, b = u1())
            InsnFormat.F35C -> {
                val count = (u0 shr 8) and 0xF
                val regG = (u0 shr 12) and 0xF
                val regsWord = u2()
                val regs = IntArray(count) { i -> if (i < 4) (regsWord shr (i * 4)) and 0xF else regG }
                DexInsn(opcode, spec.format, a = count, regs = regs, ref = resolveRef(spec.ref, u1()))
            }
            InsnFormat.F3RC -> {
                val count = (u0 shr 8) and 0xFF
                val first = u2()
                val regs = if (count == 0) IntArray(0) else IntArray(count) { first + it }
                DexInsn(opcode, spec.format, a = count, regs = regs, ref = resolveRef(spec.ref, u1()))
            }
            InsnFormat.F45CC -> {
                val count = (u0 shr 8) and 0xF
                val regG = (u0 shr 12) and 0xF
                val regsWord = u2()
                val regs = IntArray(count) { i -> if (i < 4) (regsWord shr (i * 4)) and 0xF else regG }
                DexInsn(opcode, spec.format, a = count, regs = regs, ref = resolveRef(RefKind.METHOD, u1())).apply {
                    extraProto = resolver.proto(u3())
                }
            }
            InsnFormat.F4RCC -> {
                val count = (u0 shr 8) and 0xFF
                val first = u2()
                val regs = if (count == 0) IntArray(0) else IntArray(count) { first + it }
                DexInsn(opcode, spec.format, a = count, regs = regs, ref = resolveRef(RefKind.METHOD, u1())).apply {
                    extraProto = resolver.proto(u3())
                }
            }
            InsnFormat.F51L -> DexInsn(opcode, spec.format, a = (u0 shr 8) and 0xFF, c = readI64(units, address + 1))
        }
    }

    private fun resolveRef(kind: RefKind, index: Int): Any? = when (kind) {
        RefKind.NONE -> null
        RefKind.STRING -> resolver.string(index)
        RefKind.TYPE -> resolver.type(index)
        RefKind.FIELD -> resolver.field(index)
        RefKind.METHOD -> resolver.method(index)
        RefKind.PROTO -> resolver.proto(index)
        RefKind.CALL_SITE -> resolver.callSite(index)
        RefKind.METHOD_HANDLE -> resolver.methodHandle(index)
    }

    // ------------------------------------------------------------------
    // Encoding
    // ------------------------------------------------------------------

    /** Encodes a symbolic code item back into raw units and try blocks. */
    fun encode(code: DexCode): EncodedCode {
        assignAddresses(code.insns)
        registerPayloadHolders(code.insns)

        val units = ArrayList<Int>(code.insns.size * 2 + 16)
        for (insn in code.insns) {
            if (insn.isPayload) {
                if (units.size % 2 != 0) {
                    units.add(0x0000) // nop alignment unit
                }
                emitPayload(units, insn.payload!!)
            } else {
                encodeInsn(units, insn)
            }
        }
        val direct = units.toIntArray()
        val padded = if (direct.size % 2 == 1) direct + intArrayOf(0) else direct

        return EncodedCode(
            registersSize = code.registersSize,
            insSize = code.insSize,
            outsSize = code.outsSize,
            units = padded,
            tries = code.tries,
            debugInfo = code.debugInfo,
        )
    }

    /**
     * Assigns addresses to instructions, widening goto instructions when an
     * insertion pushed a branch offset beyond its natural range. Payload
     * items are aligned to a 4 byte boundary as required by the format.
     */
    private fun assignAddresses(insns: List<DexInsn>) {
        var changed = true
        while (changed) {
            changed = false
            var address = 0
            for (insn in insns) {
                if (insn.isPayload && address % 2 != 0) {
                    // A nop occupies one unit and realigns the payload.
                    address += 1
                }
                insn.address = address
                address += if (insn.isPayload) insn.payload!!.unitCount else insn.format.size
            }
            // Check goto ranges and widen when needed.
            for (insn in insns) {
                if (insn.isPayload) continue
                val target = insn.branchTarget ?: continue
                val offset = target.address - insn.address
                when (insn.format) {
                    InsnFormat.F10T -> {
                        if (offset < -128 || offset > 127) {
                            widenGoto(insn, 0x29)
                            changed = true
                        }
                    }
                    InsnFormat.F20T -> {
                        if (offset < -32768 || offset > 32767) {
                            widenGoto(insn, 0x2a)
                            changed = true
                        }
                    }
                    else -> Unit
                }
            }
        }
        // Assign ordinals once more after any widening.
        insns.forEachIndexed { index, insn -> insn.index = index }
    }

    private fun widenGoto(insn: DexInsn, newOpcode: Int) {
        val spec = OpcodeInfo.spec(newOpcode) ?: throw CodeDecodeException("Invalid goto opcode")
        insn.opcode = newOpcode
        insn.format = spec.format
    }

    private fun encodeInsn(units: MutableList<Int>, insn: DexInsn) {
        val opcode = insn.opcode
        when (insn.format) {
            InsnFormat.F10X -> units.add(opcode)
            InsnFormat.F12X -> units.add(opcode or (insn.a shl 8) or (insn.b shl 12))
            InsnFormat.F11N -> units.add(opcode or (insn.a shl 8) or ((insn.b and 0xF) shl 12))
            InsnFormat.F11X -> units.add(opcode or (insn.a shl 8))
            InsnFormat.F10T -> units.add(opcode or ((branchOffset(insn, 8) and 0xFF) shl 8))
            InsnFormat.F20T -> {
                units.add(opcode)
                units.add(branchOffset(insn, 16) and 0xFFFF)
            }
            InsnFormat.F21T -> {
                units.add(opcode or (insn.a shl 8))
                units.add(branchOffset(insn, 16) and 0xFFFF)
            }
            InsnFormat.F21S -> {
                units.add(opcode or (insn.a shl 8))
                units.add(insn.b and 0xFFFF)
            }
            InsnFormat.F21H -> {
                units.add(opcode or (insn.a shl 8))
                val shift = if (opcode == 0x19) 48 else 16
                units.add(((insn.c shr shift) and 0xFFFF).toInt())
            }
            InsnFormat.F21C -> {
                units.add(opcode or (insn.a shl 8))
                units.add(refIndex(insn.ref))
            }
            InsnFormat.F22X -> {
                units.add(opcode or (insn.a shl 8))
                units.add(insn.b and 0xFFFF)
            }
            InsnFormat.F23X -> {
                units.add(opcode or (insn.a shl 8))
                units.add((insn.b and 0xFF) or ((insn.c.toInt() and 0xFF) shl 8))
            }
            InsnFormat.F22B -> {
                units.add(opcode or (insn.a shl 8))
                units.add((insn.b and 0xFF) or ((insn.c.toInt() and 0xFF) shl 8))
            }
            InsnFormat.F22T -> {
                units.add(opcode or (insn.a shl 8) or (insn.b shl 12))
                units.add(branchOffset(insn, 16) and 0xFFFF)
            }
            InsnFormat.F22S -> {
                units.add(opcode or (insn.a shl 8) or (insn.b shl 12))
                units.add(insn.c.toInt() and 0xFFFF)
            }
            InsnFormat.F22C -> {
                units.add(opcode or (insn.a shl 8) or (insn.b shl 12))
                units.add(refIndex(insn.ref))
            }
            InsnFormat.F30T -> {
                units.add(opcode)
                writeI32(units, branchOffset(insn, 32))
            }
            InsnFormat.F31I -> {
                units.add(opcode or (insn.a shl 8))
                writeI32(units, insn.c.toInt())
            }
            InsnFormat.F31T -> {
                units.add(opcode or (insn.a shl 8))
                writeI32(units, payloadOffset(insn))
            }
            InsnFormat.F31C -> {
                units.add(opcode or (insn.a shl 8))
                writeI32(units, refIndex(insn.ref))
            }
            InsnFormat.F32X -> {
                units.add(opcode or (insn.a shl 8))
                units.add(insn.b and 0xFFFF)
            }
            InsnFormat.F35C -> {
                val regs = insn.regs ?: IntArray(0)
                val count = regs.size
                val regsWord = buildRegsWord(regs)
                val regG = if (count == 5) regs[4] else 0
                units.add(opcode or (count shl 8) or (regG shl 12))
                units.add(refIndex(insn.ref))
                units.add(regsWord)
            }
            InsnFormat.F3RC -> {
                val regs = insn.regs ?: IntArray(0)
                val count = regs.size
                val first = if (count == 0) 0 else regs[0]
                units.add(opcode or (count shl 8))
                units.add(refIndex(insn.ref))
                units.add(first)
            }
            InsnFormat.F45CC -> {
                val regs = insn.regs ?: IntArray(0)
                val count = regs.size
                val regsWord = buildRegsWord(regs)
                val regG = if (count == 5) regs[4] else 0
                units.add(opcode or (count shl 8) or (regG shl 12))
                units.add(refIndex(insn.ref))
                units.add(regsWord)
                units.add(resolver.protoIndexOf(insn.extraProto!!))
            }
            InsnFormat.F4RCC -> {
                val regs = insn.regs ?: IntArray(0)
                val count = regs.size
                val first = if (count == 0) 0 else regs[0]
                units.add(opcode or (count shl 8))
                units.add(refIndex(insn.ref))
                units.add(first)
                units.add(resolver.protoIndexOf(insn.extraProto!!))
            }
            InsnFormat.F51L -> {
                units.add(opcode or (insn.a shl 8))
                writeI64(units, insn.c)
            }
        }
    }

    private fun buildRegsWord(regs: IntArray): Int {
        var word = 0
        for (i in 0 until minOf(4, regs.size)) {
            word = word or ((regs[i] and 0xF) shl (i * 4))
        }
        return word
    }

    private fun branchOffset(insn: DexInsn, bits: Int): Int {
        val target = insn.branchTarget
            ?: throw CodeDecodeException("Branch without target: ${insn.name}")
        val offset = target.address - insn.address
        if (bits == 8 && (offset < -128 || offset > 127)) {
            throw CodeDecodeException("Branch offset out of 8 bit range")
        }
        if (bits == 16 && (offset < -32768 || offset > 32767)) {
            throw CodeDecodeException("Branch offset out of 16 bit range")
        }
        return offset
    }

    private fun payloadOffset(insn: DexInsn): Int {
        // The payload pseudo instruction carrying our payload is located
        // during address assignment; find it in the owning list.
        val holder = payloadHolders[insn]
            ?: throw CodeDecodeException("Payload holder not registered for ${insn.name}")
        return holder.address - insn.address
    }

    /** Maps switch instructions to the instruction carrying their payload. */
    private val payloadHolders = HashMap<DexInsn, DexInsn>()

    private fun registerPayloadHolders(insns: List<DexInsn>) {
        payloadHolders.clear()
        val byPayload = HashMap<DexPayload, DexInsn>()
        for (insn in insns) {
            if (insn.isPayload) byPayload[insn.payload!!] = insn
        }
        for (insn in insns) {
            val payload = insn.payload ?: continue
            val holder = byPayload[payload]
            if (holder != null && holder !== insn) {
                payloadHolders[insn] = holder
            }
        }
    }

    private fun emitPayload(units: MutableList<Int>, payload: DexPayload) {
        when (payload.kind) {
            PayloadKind.PACKED_SWITCH -> {
                units.add(OpcodeInfo.PAYLOAD_PACKED_IDENT)
                units.add(payload.targets.size)
                writeI32(units, payload.firstKey)
                for (target in payload.targets) writeI32(units, target)
            }
            PayloadKind.SPARSE_SWITCH -> {
                units.add(OpcodeInfo.PAYLOAD_SPARSE_IDENT)
                units.add(payload.keys.size)
                for (key in payload.keys) units.add(key and 0xFFFF)
                for (target in payload.targets) writeI32(units, target)
            }
            PayloadKind.ARRAY_DATA -> {
                units.add(OpcodeInfo.PAYLOAD_ARRAY_IDENT)
                units.add(payload.elementWidth)
                writeI32(units, payload.elementCount)
                var i = 0
                while (i < payload.data.size) {
                    var unit = 0
                    var shift = 0
                    while (shift < 16 && i < payload.data.size) {
                        unit = unit or ((payload.data[i].toInt() and 0xFF) shl shift)
                        i += 1
                        shift += 8
                    }
                    units.add(unit and 0xFFFF)
                }
            }
        }
    }

    private fun refIndex(ref: Any?): Int = when (ref) {
        null -> 0
        is DexString -> resolver.stringIndexOf(ref)
        is DexType -> resolver.typeIndexOf(ref)
        is DexProto -> resolver.protoIndexOf(ref)
        is DexField -> resolver.fieldIndexOf(ref)
        is DexMethod -> resolver.methodIndexOf(ref)
        is DexMethodHandle -> resolver.methodHandleIndexOf(ref)
        is DexCallSite -> resolver.callSiteIndexOf(ref)
        else -> throw IllegalStateException("Unexpected reference ${ref.javaClass}")
    }

    private fun readI32(units: IntArray, index: Int): Int =
        (units[index] and 0xFFFF) or (units[index + 1] shl 16)

    private fun readI64(units: IntArray, index: Int): Long {
        var result = 0L
        for (i in 0 until 4) {
            result = result or ((units[index + i].toLong() and 0xFFFF) shl (i * 16))
        }
        return result
    }

    private fun writeI32(units: MutableList<Int>, value: Int) {
        units.add(value and 0xFFFF)
        units.add((value ushr 16) and 0xFFFF)
    }

    private fun writeI64(units: MutableList<Int>, value: Long) {
        for (i in 0 until 4) {
            units.add(((value ushr (i * 16)) and 0xFFFF).toInt())
        }
    }

    private fun signed4(value: Int): Int = (value shl 28) shr 28
    private fun signed8(value: Int): Int = (value shl 24) shr 24
    private fun signed16(value: Int): Int = (value shl 16) shr 16

    companion object {
        // Intentionally empty: per instance state only.
    }
}

/** A try region specification before decoding. */
class TrySpec(
    val startAddress: Int,
    val instructionCount: Int,
    val handler: DexCatchHandler,
)

/** Result of encoding a code item. */
class EncodedCode(
    val registersSize: Int,
    val insSize: Int,
    val outsSize: Int,
    val units: IntArray,
    val tries: List<DexTry>,
    val debugInfo: DexDebugInfo?,
)
