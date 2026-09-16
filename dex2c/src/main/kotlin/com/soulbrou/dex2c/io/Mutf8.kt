package com.soulbrou.dex2c.io

/**
 * Modified UTF-8 (MUTF-8) codec as required by the DEX string data format.
 *
 * MUTF-8 differs from standard UTF-8 in two ways: the NUL character is
 * encoded as a two byte sequence (0xC0 0x80) and supplementary characters
 * above U+FFFF are encoded as two three byte surrogate halves (CESU-8 style)
 * instead of a single four byte sequence.
 */
object Mutf8 {

    /**
     * Decodes a MUTF-8 byte sequence (without the trailing NUL terminator)
     * into a Kotlin string.
     */
    fun decode(bytes: ByteArray, offset: Int, utf16Length: Int): String {
        val chars = CharArray(utf16Length)
        var charIndex = 0
        var byteIndex = offset
        while (charIndex < utf16Length) {
            val a = bytes[byteIndex++].toInt() and 0xFF
            when {
                a and 0x80 == 0 -> {
                    chars[charIndex++] = a.toChar()
                }
                a and 0xE0 == 0xC0 -> {
                    val b = bytes[byteIndex++].toInt() and 0xFF
                    if (b and 0xC0 != 0x80) throw IllegalArgumentException("Invalid MUTF-8 continuation")
                    chars[charIndex++] = (((a and 0x1F) shl 6) or (b and 0x3F)).toChar()
                }
                a and 0xF0 == 0xE0 -> {
                    val b = bytes[byteIndex++].toInt() and 0xFF
                    val c = bytes[byteIndex++].toInt() and 0xFF
                    if ((b and 0xC0) != 0x80 || (c and 0xC0) != 0x80) {
                        throw IllegalArgumentException("Invalid MUTF-8 continuation")
                    }
                    chars[charIndex++] =
                        (((a and 0x0F) shl 12) or ((b and 0x3F) shl 6) or (c and 0x3F)).toChar()
                }
                else -> throw IllegalArgumentException("Invalid MUTF-8 start byte 0x${a.toString(16)}")
            }
        }
        return String(chars)
    }

    /**
     * Computes the number of UTF-16 code units of a MUTF-8 sequence starting
     * at [offset]. The sequence is terminated by the NUL byte.
     */
    fun utf16Length(bytes: ByteArray, offset: Int): Int {
        var length = 0
        var index = offset
        while (true) {
            val a = bytes[index].toInt() and 0xFF
            if (a == 0x00) break
            index += when {
                a and 0x80 == 0 -> 1
                a and 0xE0 == 0xC0 -> 2
                a and 0xF0 == 0xE0 -> 3
                else -> throw IllegalArgumentException("Invalid MUTF-8 start byte")
            }
            length++
        }
        return length
    }

    /**
     * Encodes a string into MUTF-8 bytes including the trailing NUL.
     */
    fun encode(text: String): ByteArray {
        val out = ArrayList<ByteArray>(text.length + 4)
        var total = 0
        for (ch in text) {
            val encoded = encodeChar(ch)
            out.add(encoded)
            total += encoded.size
        }
        out.add(byteArrayOf(0))
        total += 1
        val result = ByteArray(total)
        var index = 0
        for (chunk in out) {
            chunk.copyInto(result, index)
            index += chunk.size
        }
        return result
    }

    private fun encodeChar(ch: Char): ByteArray = when {
        ch.code == 0 -> byteArrayOf(0xC0.toByte(), 0x80.toByte())
        ch.code < 0x80 -> byteArrayOf(ch.code.toByte())
        ch.code < 0x800 -> byteArrayOf(
            (0xC0 or (ch.code shr 6)).toByte(),
            (0x80 or (ch.code and 0x3F)).toByte(),
        )
        else -> byteArrayOf(
            (0xE0 or (ch.code shr 12)).toByte(),
            (0x80 or ((ch.code shr 6) and 0x3F)).toByte(),
            (0x80 or (ch.code and 0x3F)).toByte(),
        )
    }
}
