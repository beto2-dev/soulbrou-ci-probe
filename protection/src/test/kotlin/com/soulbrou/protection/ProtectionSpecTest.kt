package com.soulbrou.protection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the protection catalogue and of the serializable configuration
 * that drives both the UI and the native mask.
 */
class ProtectionSpecTest {

    @Test
    fun `mask of defaults covers every default flag`() {
        val spec = ProtectionSpec()
        assertEquals(0x3F, spec.mask)
    }

    @Test
    fun `mask round trips through fromMask`() {
        for (type in ProtectionType.entries) {
            val types = ProtectionType.fromMask(type.bit)
            assertEquals(listOf(type), types)
        }
    }

    @Test
    fun `maskOf folds the bits`() {
        val mask = ProtectionType.maskOf(
            listOf(ProtectionType.ANTI_ROOT, ProtectionType.ANTI_EMULATOR),
        )
        assertEquals(0x41, mask)
    }

    @Test
    fun `mask zero when nothing is enabled`() {
        val spec = ProtectionSpec(enabled = emptyMap())
        assertEquals(0, spec.mask)
        assertTrue(spec.activeKeys.isEmpty())
    }

    @Test
    fun `toggling a flag changes the mask`() {
        val base = ProtectionSpec()
        val flags = base.enabled.toMutableMap()
        flags[ProtectionType.ANTI_EMULATOR.key] = true
        val updated = base.copy(enabled = flags)
        assertEquals(base.mask or 0x40, updated.mask)
    }

    @Test
    fun `every type has a unique bit and key`() {
        val bits = ProtectionType.entries.map { it.bit }
        val keys = ProtectionType.entries.map { it.key }
        assertEquals(bits.size, bits.toSet().size)
        assertEquals(keys.size, keys.toSet().size)
    }

    @Test
    fun `fromMask of a zero mask is empty`() {
        assertTrue(ProtectionType.fromMask(0).isEmpty())
    }

    @Test
    fun `unpatchable mode is enabled by default`() {
        assertTrue(ProtectionSpec().markUnpatchable)
        assertFalse(ProtectionSpec(markUnpatchable = false).markUnpatchable)
    }
}
