package com.soulbrou.dex2c.blob

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the XXTEA primitive used to encrypt the runtime blob: encrypting
 * and decrypting with the same key must restore the original words.
 */
class XxteaTest {

    @Test
    fun `xxtea round trip restores the original words`() {
        val key = intArrayOf(0x01234567, 0x89ABCDEF.toInt(), 0xFEDCBA98.toInt(), 0x76543210)
        val original = intArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val cipher = original.copyOf()
        Xxtea.encrypt(cipher, key)
        assertTrue("Ciphertext differs from the input", !cipher.contentEquals(original))
        Xxtea.decrypt(cipher, key)
        assertTrue("Round trip restores the input", cipher.contentEquals(original))
    }

    @Test
    fun `same key and input produce the same ciphertext`() {
        val key = intArrayOf(1, 2, 3, 4)
        val first = intArrayOf(42, -7, 100, 3)
        val second = intArrayOf(42, -7, 100, 3)
        Xxtea.encrypt(first, key)
        Xxtea.encrypt(second, key)
        assertTrue(first.contentEquals(second))
    }

    @Test
    fun `different keys produce different ciphertexts`() {
        val first = intArrayOf(9, 9, 9, 9)
        val second = intArrayOf(9, 9, 9, 9)
        Xxtea.encrypt(first, intArrayOf(1, 1, 1, 1))
        Xxtea.encrypt(second, intArrayOf(2, 2, 2, 2))
        assertTrue(!first.contentEquals(second))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `keys must have four words`() {
        Xxtea.encrypt(intArrayOf(1), intArrayOf(1, 2, 3))
    }
}
