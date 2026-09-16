package com.soulbrou.dex2c.translate

import com.soulbrou.dex2c.TestDexFactory
import com.soulbrou.dex2c.code.SmaliPrinter
import com.soulbrou.dex2c.parser.DexParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the smali printer and of the C generator over the fixture dex.
 */
class SmaliToCTranslatorTest {

    @Test
    fun `smali printer renders the method body`() {
        val document = TestDexFactory.document()
        val method = document.classes[0].classData!!.directMethods
            .first { it.method.name.value == TestDexFactory.METHOD_NAME }
        val smali = SmaliPrinter(method.code!!).print()
        assertTrue(smali.contains("add-int"))
        assertTrue(smali.contains("return"))
    }

    @Test
    fun `smali printer keeps the original instruction count`() {
        val bytes = TestDexFactory.dexBytes()
        val parsed = DexParser(bytes).parse()
        val method = parsed.classes[0].classData!!.directMethods
            .first { it.method.name.value == TestDexFactory.METHOD_NAME }
        val smali = SmaliPrinter(method.code!!).print()
        assertEquals(
            method.code!!.insns.size,
            Regex("\n").findAll(smali).count() - 1,
        )
    }
}
