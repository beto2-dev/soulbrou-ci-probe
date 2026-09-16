package com.soulbrou.core.io

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the low level byte helpers shared by the parsers and writers.
 */
class IoUtilsTest {

    @Test
    fun `hex round trip`() {
        val bytes = byteArrayOf(0, 1, 0x7F, -1, -128)
        val hex = IoUtils.toHex(bytes)
        assertEquals(bytes.size * 2, hex.length)
        assertArrayEquals(bytes, IoUtils.fromHex(hex))
    }

    @Test
    fun `u16 and u32 round trip`() {
        val buffer = ByteArray(8)
        IoUtils.putU16(buffer, 0, 0xBEEF)
        IoUtils.putU32(buffer, 2, 0xDEADBEEFL)
        assertEquals(0xBEEF, IoUtils.u16(buffer, 0))
        assertEquals(0xDEADBEEFL, IoUtils.u32(buffer, 2))
    }

    @Test
    fun `u16 reads little endian`() {
        val buffer = byteArrayOf(0xCD.toByte(), 0xAB.toByte())
        assertEquals(0xABCD, IoUtils.u16(buffer, 0))
    }

    @Test
    fun `u32 reads little endian`() {
        val buffer = byteArrayOf(0x78, 0x56, 0x34, 0x12)
        assertEquals(0x12345678L, IoUtils.u32(buffer, 0))
    }

    @Test
    fun `slice extracts the requested window`() {
        val bytes = byteArrayOf(1, 2, 3, 4, 5)
        val slice = IoUtils.slice(bytes, 1, 3)
        assertEquals(3, slice.size)
        assertEquals(2.toByte(), slice[0])
        assertEquals(4.toByte(), slice[2])
    }
}
