package com.soulbrou.dex2c.io

import java.io.EOFException

/**
 * Reader for LEB128 (Little Endian Base 128) variable length integers as
 * used by the DEX format. Supports both unsigned and signed encodings and
 * operates over an in memory buffer with an explicit cursor.
 */
class Leb128Reader(private val data: ByteArray) {

    var offset: Int = 0

    fun readUnsignedLeb128(): Int {
        var result = 0
        var shift = 0
        var byte: Int
        do {
            if (offset >= data.size) throw EOFException("Truncated uleb128")
            byte = data[offset++].toInt() and 0xFF
            result = result or ((byte and 0x7F) shl shift)
            shift += 7
        } while (byte and 0x80 != 0)
        // Values wider than 32 bits are rejected by the DEX specification.
        if (shift >= 35) throw IllegalArgumentException("uleb128 too wide: $result")
        return result
    }

    fun readSignedLeb128(): Int {
        var result = 0
        var shift = 0
        var byte: Int
        do {
            if (offset >= data.size) throw EOFException("Truncated sleb128")
            byte = data[offset++].toInt() and 0xFF
            result = result or ((byte and 0x7F) shl shift)
            shift += 7
        } while (byte and 0x80 != 0)
        if (shift < 32 && byte and 0x40 != 0) {
            result = result or (-1 shl shift)
        }
        return result
    }
}

/**
 * Writer counterpart of [Leb128Reader].
 */
object Leb128Writer {

    fun writeUnsignedLeb128(value: Int): ByteArray {
        require(value >= 0) { "Negative uleb128 value: $value" }
        var remaining = value ushr 7
        var byte = value and 0x7F
        val out = ArrayList<Byte>(5)
        while (remaining != 0) {
            out.add((byte or 0x80).toByte())
            byte = remaining and 0x7F
            remaining = remaining ushr 7
        }
        out.add(byte.toByte())
        return out.toByteArray()
    }

    fun writeSignedLeb128(value: Int): ByteArray {
        var remaining = value
        var hasMore = true
        val out = ArrayList<Byte>(5)
        while (hasMore) {
            var byte = remaining and 0x7F
            remaining = remaining shr 7
            if ((remaining == 0 && byte and 0x40 == 0) || (remaining == -1 && byte and 0x40 != 0)) {
                hasMore = false
            } else {
                byte = byte or 0x80
            }
            out.add(byte.toByte())
        }
        return out.toByteArray()
    }
}
