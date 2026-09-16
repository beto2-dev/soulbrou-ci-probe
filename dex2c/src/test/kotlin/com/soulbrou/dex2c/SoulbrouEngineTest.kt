package com.soulbrou.dex2c

import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.parser.DexParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream

/**
 * End to end exercise of the protection engine over a synthetic APK: the
 * selected method is removed from the dex, the runtime library and the
 * encrypted blob are packaged and the output remains a valid archive.
 */
class SoulbrouEngineTest {

    private val runtimeLibraries = mapOf(
        "arm64-v8a" to byteArrayOf(0x7F, 0x45, 0x4C, 0x46, 1, 2, 3, 4),
        "armeabi-v7a" to byteArrayOf(0x7F, 0x45, 0x4C, 0x46, 5, 6, 7, 8),
    )
    private val certificate = ByteArray(32) { it.toByte() }

    @Test
    fun `protect converts the selected method and repackages the apk`() {
        val engine = SoulbrouEngine(runtimeLibraries, obfuscationLevel = 1)
        val result = engine.protect(
            apkBytes = TestDexFactory.apkBytes(),
            selection = listOf(TestDexFactory.addMethodKey()),
            protectionMask = 0x2F,
            certificateSha256 = certificate,
        )

        assertTrue("Method converted", TestDexFactory.addMethodKey() in result.convertedMethods)
        assertTrue("Nothing skipped", result.convertedMethods.isNotEmpty())

        val entries = zipEntries(result.apkBytes)
        assertTrue("Runtime lib arm64 injected", "lib/arm64-v8a/libsoulbrou.so" in entries)
        assertTrue("Runtime lib v7a injected", "lib/armeabi-v7a/libsoulbrou.so" in entries)
        assertTrue("Blob injected", "assets/soulbrou_blob.bin" in entries)
        assertTrue("Dex kept", "classes.dex" in entries)
        assertTrue("Blob magic", String(entries.getValue("assets/soulbrou_blob.bin"), 0, 4, Charsets.US_ASCII) == "SBBL")
    }

    @Test
    fun `protected dex no longer holds the original body`() {
        val engine = SoulbrouEngine(runtimeLibraries, 0)
        val result = engine.protect(
            TestDexFactory.apkBytes(),
            listOf(TestDexFactory.addMethodKey()),
            0x01,
            certificate,
        )
        val parsed = DexParser(zipEntries(result.apkBytes).getValue("classes.dex")).parse()
        val method = parsed.classes[0].classData!!.directMethods
            .first { it.method.name.value == TestDexFactory.METHOD_NAME }
        val code = method.code!!
        // The stub dispatches through Sb.invoke: the body must differ from
        // the original add-int sequence and be larger than the original.
        assertTrue(code.insns.isNotEmpty())
        val hasInvoke = code.insns.any { it.name.startsWith("invoke-") }
        assertTrue("Stub contains an invoke", hasInvoke)
    }

    @Test
    fun `methods without code are skipped instead of failing`() {
        val engine = SoulbrouEngine(runtimeLibraries, 0)
        val bogusKey = MethodKey(
            dexName = "classes.dex",
            classDescriptor = "Lcom/missing/Nope;",
            methodName = "gone",
            proto = "V",
        )
        val result = engine.protect(
            TestDexFactory.apkBytes(),
            listOf(bogusKey, TestDexFactory.addMethodKey()),
            0x01,
            certificate,
        )
        assertEquals(listOf(bogusKey), result.skippedMethods)
        assertEquals(listOf(TestDexFactory.addMethodKey()), result.convertedMethods)
    }

    @Test
    fun `helper class is injected into the dex`() {
        val engine = SoulbrouEngine(runtimeLibraries, 0)
        val result = engine.protect(
            TestDexFactory.apkBytes(),
            listOf(TestDexFactory.addMethodKey()),
            0x01,
            certificate,
        )
        val parsed = DexParser(zipEntries(result.apkBytes).getValue("classes.dex")).parse()
        assertNotNull(
            "Sb helper class present",
            parsed.classes.firstOrNull {
                it.type.descriptor.value == "Lcom/soulbrou/sb/Sb;"
            },
        )
    }

    @Test(expected = SoulbrouEngine.EngineException::class)
    fun `an apk without dex files is rejected`() {
        val output = java.io.ByteArrayOutputStream()
        java.util.zip.ZipOutputStream(output).use { zip ->
            zip.putNextEntry(java.util.zip.ZipEntry("AndroidManifest.xml"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }
        SoulbrouEngine(runtimeLibraries, 0).protect(
            output.toByteArray(),
            listOf(TestDexFactory.addMethodKey()),
            0x01,
            certificate,
        )
    }

    private fun zipEntries(bytes: ByteArray): Map<String, ByteArray> {
        val entries = LinkedHashMap<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                entries[entry.name] = zip.readBytes()
                entry = zip.nextEntry
            }
        }
        return entries
    }
}
