package com.soulbrou.dex2c.apk

import com.soulbrou.dex2c.TestDexFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Checks of the archive level analyzer over a real temporary file.
 */
class ApkAnalyzerTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun `analyze inventories dex files and method totals`() {
        val apk = folder.newFile("target.apk")
        apk.writeBytes(TestDexFactory.apkBytes())

        val analysis = ApkAnalyzer.analyze(apk.absolutePath)
        assertEquals(listOf("classes.dex"), analysis.dexEntryNames)
        assertEquals(1, analysis.info.dexFiles.size)
        assertTrue(analysis.info.methodCount > 0)
        assertTrue(analysis.info.classCount == 1)
        assertTrue(analysis.info.fileSizeBytes > 0)
    }

    @Test
    fun `manifest facts stay null when the manifest is not parseable`() {
        val apk = folder.newFile("raw.apk")
        apk.writeBytes(TestDexFactory.apkBytes(manifest = byteArrayOf(1, 2, 3)))
        val analysis = ApkAnalyzer.analyze(apk.absolutePath)
        assertNull(analysis.info.packageName)
        assertNull(analysis.info.versionName)
    }

    @Test
    fun `readEntry returns the bytes of a stored entry`() {
        val apk = folder.newFile("entry.apk")
        apk.writeBytes(TestDexFactory.apkBytes())
        val dex = ApkAnalyzer.readEntry(apk.absolutePath, "classes.dex")
        assertNotNull(dex)
        assertTrue(dex!!.size > 112)
        assertEquals("dex", String(dex, 0, 3, Charsets.US_ASCII))
    }

    @Test
    fun `readEntry returns null for a missing entry`() {
        val apk = folder.newFile("missing.apk")
        apk.writeBytes(TestDexFactory.apkBytes())
        assertNull(ApkAnalyzer.readEntry(apk.absolutePath, "not/there.txt"))
    }
}
