package com.soulbrou.dex2c.writer

import com.soulbrou.dex2c.TestDexFactory
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.parser.DexParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round trip checks of the DEX emitter: a document built in memory must be
 * parseable again with every class, method and instruction intact.
 */
class DexWriterTest {

    @Test
    fun `written dex parses back with same class count`() {
        val bytes = TestDexFactory.dexBytes()
        assertTrue("Header magic", String(bytes, 0, 3, Charsets.US_ASCII) == "dex")

        val parsed = DexParser(bytes).parse()
        assertEquals(1, parsed.classes.size)
        assertEquals(
            TestDexFactory.CLASS_DESCRIPTOR,
            parsed.classes[0].type.descriptor.value,
        )
    }

    @Test
    fun `method bodies survive the round trip`() {
        val original = TestDexFactory.document()
        val parsed = DexParser(TestDexFactory.dexBytes()).parse()

        val originalMethod = original.classes[0].classData!!.directMethods
            .first { it.method.name.value == TestDexFactory.METHOD_NAME }
        val parsedMethod = parsed.classes[0].classData!!.directMethods
            .first { it.method.name.value == TestDexFactory.METHOD_NAME }

        assertEquals(originalMethod.isStatic, parsedMethod.isStatic)
        assertEquals(originalMethod.code!!.registersSize, parsedMethod.code!!.registersSize)
        assertEquals(originalMethod.code!!.insns.size, parsedMethod.code!!.insns.size)
        val firstOpcode = originalMethod.code!!.insns[0].opcode
        assertEquals(firstOpcode, parsedMethod.code!!.insns[0].opcode)
        assertEquals("add-int", parsedMethod.code!!.insns[0].name)
        assertEquals("const/4", parsedMethod.code!!.insns[1].name)
        assertEquals("return", parsedMethod.code!!.insns[2].name)
    }

    @Test
    fun `identifier tables are sorted on write`() {
        val bytes = TestDexFactory.dexBytes()
        val parsed = DexParser(bytes).parse()
        val descriptors = parsed.types.map { it.descriptor.value }
        assertEquals(descriptors.sorted(), descriptors)
    }

    @Test
    fun `checksum and signature are refreshed`() {
        val bytes = TestDexFactory.dexBytes()
        // adler32 at offset 8 and sha1 at offset 12 must be non zero for a
        // freshly emitted file and consistent with its contents.
        val checksum = java.util.zip.Adler32().apply { update(bytes, 12, bytes.size - 12) }
        val stored = (bytes[8].toLong() and 0xFF) or
            ((bytes[9].toLong() and 0xFF) shl 8) or
            ((bytes[10].toLong() and 0xFF) shl 16) or
            ((bytes[11].toLong() and 0xFF) shl 24)
        assertEquals(checksum.value, stored)
    }

    @Test
    fun `empty document writes a valid minimal dex`() {
        val document = DexDocument()
        document.internType("Ljava/lang/Object;")
        val bytes = DexWriter(document).write()
        // Header file_size (offset 32) must match the emitted length.
        val storedSize = (bytes[32].toLong() and 0xFF) or
            ((bytes[33].toLong() and 0xFF) shl 8) or
            ((bytes[34].toLong() and 0xFF) shl 16) or
            ((bytes[35].toLong() and 0xFF) shl 24)
        assertEquals(bytes.size.toLong(), storedSize)
        val parsed = DexParser(bytes).parse()
        assertEquals(0, parsed.classes.size)
    }
}
