package com.soulbrou.core.io

import java.io.File
import java.io.IOException

/**
 * Small binary and text helpers shared across modules.
 */
object IoUtils {

    private val HEX = "0123456789abcdef".toCharArray()

    /** Formats the given bytes as lowercase hexadecimal, two chars per byte. */
    fun toHex(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): String {
        require(offset >= 0 && length >= 0 && offset + length <= bytes.size)
        val out = CharArray(length * 2)
        for (i in 0 until length) {
            val v = bytes[offset + i].toInt() and 0xFF
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0F]
        }
        return String(out)
    }

    /** Parses a hexadecimal string, ignoring whitespace and colons. */
    fun fromHex(hex: String): ByteArray {
        val cleaned = hex.filterNot { it.isWhitespace() || it == ':' }
        require(cleaned.length % 2 == 0) { "Odd hexadecimal length" }
        return ByteArray(cleaned.length / 2) { i ->
            ((Character.digit(cleaned[i * 2], 16) shl 4) or
                Character.digit(cleaned[i * 2 + 1], 16)).toByte()
        }
    }

    /** Reads a little endian u16 value at [offset]. */
    fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    /** Reads a little endian u32 value at [offset], unsigned. */
    fun u32(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toInt() and 0xFF).toLong() or
            ((bytes[offset + 1].toInt() and 0xFF).toLong() shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF).toLong() shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF).toLong() shl 24)

    /** Writes a little endian u16 value at [offset]. */
    fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    /** Writes a little endian u32 value at [offset]. */
    fun putU32(bytes: ByteArray, offset: Int, value: Long) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    /** Copies [length] bytes of [source] into a fresh array starting at [offset]. */
    fun slice(source: ByteArray, offset: Int, length: Int): ByteArray {
        require(offset >= 0 && length >= 0 && offset + length <= source.size)
        return source.copyOfRange(offset, offset + length)
    }

    /** Deletes a directory recursively, tolerating missing files. */
    fun deleteRecursively(file: File) {
        if (file.isDirectory) {
            val children = file.listFiles() ?: return
            for (child in children) {
                deleteRecursively(child)
            }
        }
        if (!file.delete() && file.exists()) {
            throw IOException("Unable to delete ${file.name}")
        }
    }
}
