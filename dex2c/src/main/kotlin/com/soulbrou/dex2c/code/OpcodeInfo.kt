package com.soulbrou.dex2c.code

/**
 * Reference kinds carried in the operand of index bearing instructions.
 */
enum class RefKind { NONE, STRING, TYPE, FIELD, METHOD, PROTO, CALL_SITE, METHOD_HANDLE }

/**
 * Static Dalvik opcode table: canonical name, instruction format and the
 * kind of indexed reference carried in the operand. Opcodes not part of the
 * standard bytecode set are listed as null entries and are treated as
 * untranslatable by the engine.
 */
object OpcodeInfo {

    /** One table entry. */
    data class OpcodeSpec(val name: String, val format: InsnFormat, val ref: RefKind)

    private data class Simple(val name: String, val fmt: String, val ref: String)

    private val raw: Array<Simple?> = arrayOf(
        Simple("nop", "10x", "NONE"),                                    // 0x00
        Simple("move", "12x", "NONE"),
        Simple("move/from16", "22x", "NONE"),
        Simple("move/16", "32x", "NONE"),
        Simple("move-wide", "12x", "NONE"),
        Simple("move-wide/from16", "22x", "NONE"),
        Simple("move-wide/16", "32x", "NONE"),
        Simple("move-object", "12x", "NONE"),
        Simple("move-object/from16", "22x", "NONE"),
        Simple("move-object/16", "32x", "NONE"),
        Simple("move-result", "11x", "NONE"),
        Simple("move-result-wide", "11x", "NONE"),
        Simple("move-result-object", "11x", "NONE"),
        Simple("move-exception", "11x", "NONE"),
        Simple("return-void", "10x", "NONE"),
        Simple("return", "11x", "NONE"),
        Simple("return-wide", "11x", "NONE"),
        Simple("return-object", "11x", "NONE"),
        Simple("const/4", "11n", "NONE"),
        Simple("const/16", "21s", "NONE"),
        Simple("const", "31i", "NONE"),
        Simple("const/high16", "21h", "NONE"),
        Simple("const-wide/16", "21s", "NONE"),
        Simple("const-wide/32", "31i", "NONE"),
        Simple("const-wide", "51l", "NONE"),
        Simple("const-wide/high16", "21h", "NONE"),
        Simple("const-string", "21c", "STRING"),
        Simple("const-string/jumbo", "31c", "STRING"),
        Simple("const-class", "21c", "TYPE"),
        Simple("monitor-enter", "11x", "NONE"),
        Simple("monitor-exit", "11x", "NONE"),
        Simple("check-cast", "21c", "TYPE"),
        Simple("instance-of", "22c", "TYPE"),
        Simple("array-length", "12x", "NONE"),
        Simple("new-instance", "21c", "TYPE"),
        Simple("new-array", "22c", "TYPE"),
        Simple("filled-new-array", "35c", "TYPE"),
        Simple("filled-new-array/range", "3rc", "TYPE"),
        Simple("fill-array-data", "31t", "NONE"),
        Simple("throw", "11x", "NONE"),
        Simple("goto", "10t", "NONE"),
        Simple("goto/16", "20t", "NONE"),
        Simple("goto/32", "30t", "NONE"),
        Simple("packed-switch", "31t", "NONE"),
        Simple("sparse-switch", "31t", "NONE"),
        Simple("cmpl-float", "23x", "NONE"),
        Simple("cmpg-float", "23x", "NONE"),
        Simple("cmpl-double", "23x", "NONE"),
        Simple("cmpg-double", "23x", "NONE"),
        Simple("cmp-long", "23x", "NONE"),
        Simple("if-eq", "22t", "NONE"),
        Simple("if-ne", "22t", "NONE"),
        Simple("if-lt", "22t", "NONE"),
        Simple("if-ge", "22t", "NONE"),
        Simple("if-gt", "22t", "NONE"),
        Simple("if-le", "22t", "NONE"),
        Simple("if-eqz", "21t", "NONE"),
        Simple("if-nez", "21t", "NONE"),
        Simple("if-ltz", "21t", "NONE"),
        Simple("if-gez", "21t", "NONE"),
        Simple("if-gtz", "21t", "NONE"),
        Simple("if-lez", "21t", "NONE"),                                 // 0x3d
        null, null, null, null, null, null,                               // 0x3e-0x43
        Simple("aget", "23x", "NONE"),                                   // 0x44
        Simple("aget-wide", "23x", "NONE"),
        Simple("aget-object", "23x", "NONE"),
        Simple("aget-boolean", "23x", "NONE"),
        Simple("aget-byte", "23x", "NONE"),
        Simple("aget-char", "23x", "NONE"),
        Simple("aget-short", "23x", "NONE"),
        Simple("aput", "23x", "NONE"),
        Simple("aput-wide", "23x", "NONE"),
        Simple("aput-object", "23x", "NONE"),
        Simple("aput-boolean", "23x", "NONE"),
        Simple("aput-byte", "23x", "NONE"),
        Simple("aput-char", "23x", "NONE"),
        Simple("aput-short", "23x", "NONE"),
        Simple("iget", "22c", "FIELD"),
        Simple("iget-wide", "22c", "FIELD"),
        Simple("iget-object", "22c", "FIELD"),
        Simple("iget-boolean", "22c", "FIELD"),
        Simple("iget-byte", "22c", "FIELD"),
        Simple("iget-char", "22c", "FIELD"),
        Simple("iget-short", "22c", "FIELD"),
        Simple("iput", "22c", "FIELD"),
        Simple("iput-wide", "22c", "FIELD"),
        Simple("iput-object", "22c", "FIELD"),
        Simple("iput-boolean", "22c", "FIELD"),
        Simple("iput-byte", "22c", "FIELD"),
        Simple("iput-char", "22c", "FIELD"),
        Simple("iput-short", "22c", "FIELD"),
        Simple("sget", "21c", "FIELD"),
        Simple("sget-wide", "21c", "FIELD"),
        Simple("sget-object", "21c", "FIELD"),
        Simple("sget-boolean", "21c", "FIELD"),
        Simple("sget-byte", "21c", "FIELD"),
        Simple("sget-char", "21c", "FIELD"),
        Simple("sget-short", "21c", "FIELD"),
        Simple("sput", "21c", "FIELD"),
        Simple("sput-wide", "21c", "FIELD"),
        Simple("sput-object", "21c", "FIELD"),
        Simple("sput-boolean", "21c", "FIELD"),
        Simple("sput-byte", "21c", "FIELD"),
        Simple("sput-char", "21c", "FIELD"),
        Simple("sput-short", "21c", "FIELD"),
        Simple("invoke-virtual", "35c", "METHOD"),
        Simple("invoke-super", "35c", "METHOD"),
        Simple("invoke-direct", "35c", "METHOD"),
        Simple("invoke-static", "35c", "METHOD"),
        Simple("invoke-interface", "35c", "METHOD"),
        null,                                                             // 0x73
        Simple("invoke-virtual/range", "3rc", "METHOD"),
        Simple("invoke-super/range", "3rc", "METHOD"),
        Simple("invoke-direct/range", "3rc", "METHOD"),
        Simple("invoke-static/range", "3rc", "METHOD"),
        Simple("invoke-interface/range", "3rc", "METHOD"),
        null, null,                                                       // 0x79-0x7a
        Simple("neg-int", "12x", "NONE"),                                 // 0x7b
        Simple("not-int", "12x", "NONE"),
        Simple("neg-long", "12x", "NONE"),
        Simple("not-long", "12x", "NONE"),
        Simple("neg-float", "12x", "NONE"),
        Simple("neg-double", "12x", "NONE"),
        Simple("int-to-long", "12x", "NONE"),
        Simple("int-to-float", "12x", "NONE"),
        Simple("int-to-double", "12x", "NONE"),
        Simple("long-to-int", "12x", "NONE"),
        Simple("long-to-float", "12x", "NONE"),
        Simple("long-to-double", "12x", "NONE"),
        Simple("float-to-int", "12x", "NONE"),
        Simple("float-to-long", "12x", "NONE"),
        Simple("float-to-double", "12x", "NONE"),
        Simple("double-to-int", "12x", "NONE"),
        Simple("double-to-long", "12x", "NONE"),
        Simple("double-to-float", "12x", "NONE"),
        Simple("int-to-byte", "12x", "NONE"),
        Simple("int-to-char", "12x", "NONE"),
        Simple("int-to-short", "12x", "NONE"),                            // 0x8f
        Simple("add-int", "23x", "NONE"),                                 // 0x90
        Simple("sub-int", "23x", "NONE"),
        Simple("mul-int", "23x", "NONE"),
        Simple("div-int", "23x", "NONE"),
        Simple("rem-int", "23x", "NONE"),
        Simple("and-int", "23x", "NONE"),
        Simple("or-int", "23x", "NONE"),
        Simple("xor-int", "23x", "NONE"),
        Simple("shl-int", "23x", "NONE"),
        Simple("shr-int", "23x", "NONE"),
        Simple("ushr-int", "23x", "NONE"),
        Simple("add-long", "23x", "NONE"),
        Simple("sub-long", "23x", "NONE"),
        Simple("mul-long", "23x", "NONE"),
        Simple("div-long", "23x", "NONE"),
        Simple("rem-long", "23x", "NONE"),
        Simple("and-long", "23x", "NONE"),
        Simple("or-long", "23x", "NONE"),
        Simple("xor-long", "23x", "NONE"),
        Simple("shl-long", "23x", "NONE"),
        Simple("shr-long", "23x", "NONE"),
        Simple("ushr-long", "23x", "NONE"),
        Simple("add-float", "23x", "NONE"),
        Simple("sub-float", "23x", "NONE"),
        Simple("mul-float", "23x", "NONE"),
        Simple("div-float", "23x", "NONE"),
        Simple("rem-float", "23x", "NONE"),
        Simple("add-double", "23x", "NONE"),
        Simple("sub-double", "23x", "NONE"),
        Simple("mul-double", "23x", "NONE"),
        Simple("div-double", "23x", "NONE"),
        Simple("rem-double", "23x", "NONE"),                               // 0xaf
        Simple("add-int/2addr", "12x", "NONE"),                            // 0xb0
        Simple("sub-int/2addr", "12x", "NONE"),
        Simple("mul-int/2addr", "12x", "NONE"),
        Simple("div-int/2addr", "12x", "NONE"),
        Simple("rem-int/2addr", "12x", "NONE"),
        Simple("and-int/2addr", "12x", "NONE"),
        Simple("or-int/2addr", "12x", "NONE"),
        Simple("xor-int/2addr", "12x", "NONE"),
        Simple("shl-int/2addr", "12x", "NONE"),
        Simple("shr-int/2addr", "12x", "NONE"),
        Simple("ushr-int/2addr", "12x", "NONE"),
        Simple("add-long/2addr", "12x", "NONE"),
        Simple("sub-long/2addr", "12x", "NONE"),
        Simple("mul-long/2addr", "12x", "NONE"),
        Simple("div-long/2addr", "12x", "NONE"),
        Simple("rem-long/2addr", "12x", "NONE"),
        Simple("and-long/2addr", "12x", "NONE"),
        Simple("or-long/2addr", "12x", "NONE"),
        Simple("xor-long/2addr", "12x", "NONE"),
        Simple("shl-long/2addr", "12x", "NONE"),
        Simple("shr-long/2addr", "12x", "NONE"),
        Simple("ushr-long/2addr", "12x", "NONE"),
        Simple("add-float/2addr", "12x", "NONE"),
        Simple("sub-float/2addr", "12x", "NONE"),
        Simple("mul-float/2addr", "12x", "NONE"),
        Simple("div-float/2addr", "12x", "NONE"),
        Simple("rem-float/2addr", "12x", "NONE"),
        Simple("add-double/2addr", "12x", "NONE"),
        Simple("sub-double/2addr", "12x", "NONE"),
        Simple("mul-double/2addr", "12x", "NONE"),
        Simple("div-double/2addr", "12x", "NONE"),
        Simple("rem-double/2addr", "12x", "NONE"),                          // 0xcf
        Simple("add-int/lit16", "22s", "NONE"),                             // 0xd0
        Simple("rsub-int", "22s", "NONE"),
        Simple("mul-int/lit16", "22s", "NONE"),
        Simple("div-int/lit16", "22s", "NONE"),
        Simple("rem-int/lit16", "22s", "NONE"),
        Simple("and-int/lit16", "22s", "NONE"),
        Simple("or-int/lit16", "22s", "NONE"),
        Simple("xor-int/lit16", "22s", "NONE"),
        Simple("add-int/lit8", "22b", "NONE"),
        Simple("rsub-int/lit8", "22b", "NONE"),
        Simple("mul-int/lit8", "22b", "NONE"),
        Simple("div-int/lit8", "22b", "NONE"),
        Simple("rem-int/lit8", "22b", "NONE"),
        Simple("and-int/lit8", "22b", "NONE"),
        Simple("or-int/lit8", "22b", "NONE"),
        Simple("xor-int/lit8", "22b", "NONE"),
        Simple("shl-int/lit8", "22b", "NONE"),
        Simple("shr-int/lit8", "22b", "NONE"),
        Simple("ushr-int/lit8", "22b", "NONE"),                            // 0xe2
        null, null, null, null, null, null, null, null, null, null,          // 0xe3-0xec
        null, null, null, null, null, null, null, null, null, null, null,    // 0xed-0xf7
        null, null,                                                          // 0xf8-0xf9
        Simple("invoke-polymorphic", "45cc", "METHOD"),                     // 0xfa
        Simple("invoke-polymorphic/range", "4rcc", "METHOD"),
        Simple("invoke-custom", "35c", "CALL_SITE"),
        Simple("invoke-custom/range", "3rc", "CALL_SITE"),
        Simple("const-method-handle", "21c", "METHOD_HANDLE"),
        Simple("const-method-type", "21c", "PROTO"),                        // 0xff
    )

    val table: Array<OpcodeSpec?> = Array(raw.size) { i ->
        raw[i]?.let {
            OpcodeSpec(
                it.name,
                InsnFormat.valueOf("F" + it.fmt.uppercase()),
                RefKind.valueOf(it.ref),
            )
        }
    }

    init {
        check(table.size == 256) { "Opcode table must cover 256 entries, was ${table.size}" }
    }

    fun spec(opcode: Int): OpcodeSpec? = table[opcode]

    fun name(opcode: Int): String = table[opcode]?.name ?: "unknown-0x%02x".format(opcode)

    fun format(opcode: Int): InsnFormat? = table[opcode]?.format

    fun isKnown(opcode: Int): Boolean = table[opcode] != null

    const val OP_NOP = 0x00
    const val OP_CONST_STRING = 0x1a
    const val OP_FILL_ARRAY_DATA = 0x26
    const val OP_PACKED_SWITCH = 0x2b
    const val OP_SPARSE_SWITCH = 0x2c
    const val OP_CONST_WIDE = 0x18

    /** Payload identity constants (high byte of the first code unit). */
    const val PAYLOAD_PACKED_IDENT = 0x0100
    const val PAYLOAD_SPARSE_IDENT = 0x0200
    const val PAYLOAD_ARRAY_IDENT = 0x0300
}
