package com.soulbrou

import com.soulbrou.dex2c.MethodKey
import com.soulbrou.engine.MethodCatalog
import com.soulbrou.protection.ProtectionSpec
import com.soulbrou.session.BuildSession
import com.soulbrou.session.SelectedApk
import com.soulbrou.core.model.ApkInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * JVM checks of the shared build session and of the method catalog over a
 * synthetic archive. The full engine behaviour is covered by the dex2c
 * module suite; here the wiring of the application layer is exercised.
 */
class BuildSessionTest {

    private fun syntheticApk(): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(ByteArray(8))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(fixtureDex())
            zip.closeEntry()
        }
        return output.toByteArray()
    }

    private fun fixtureDex(): ByteArray {
        val document = com.soulbrou.dex2c.model.DexDocument()
        val owner = document.internType("Ldemo/Sample;")
        val intType = document.internType("I")
        val proto = document.internProto("II", intType, listOf(intType, intType))
        val method = document.internMethod(owner, "compute", proto)
        val code = com.soulbrou.dex2c.code.DexCode(
            registersSize = 4,
            insSize = 2,
            outsSize = 0,
            debugInfo = null,
            insns = mutableListOf(
                com.soulbrou.dex2c.code.DexInsn(
                    opcode = 0x90,
                    format = com.soulbrou.dex2c.code.InsnFormat.F23X,
                    a = 0, b = 2, c = 3,
                ),
                com.soulbrou.dex2c.code.DexInsn(
                    opcode = 0x0f,
                    format = com.soulbrou.dex2c.code.InsnFormat.F11X,
                    a = 0,
                ),
            ),
            tries = emptyList(),
        )
        val classData = com.soulbrou.dex2c.model.DexClassData(
            staticFields = emptyList(),
            instanceFields = emptyList(),
            directMethods = mutableListOf(
                com.soulbrou.dex2c.model.DexEncodedMethod(method, 0x00008, code),
            ),
            virtualMethods = mutableListOf(),
        )
        document.classes.add(
            com.soulbrou.dex2c.model.DexClassDef(
                type = owner,
                accessFlags = 0x00008,
                superclass = document.internType("Ljava/lang/Object;"),
                interfaces = emptyList(),
                sourceFile = null,
                annotationsDirectory = null,
                staticValues = emptyList(),
                classData = classData,
            ),
        )
        return com.soulbrou.dex2c.writer.DexWriter(document).write()
    }

    @Test
    fun `selecting a new apk resets the derived session state`() {
        val session = BuildSession()
        val apk = SelectedApk(
            fileName = "demo.apk",
            cachedPath = "/cache/demo.apk",
            bytes = syntheticApk(),
            info = com.soulbrou.core.model.ApkInfo(fileName = "demo.apk", fileSizeBytes = 100),
        )
        session.setApk(apk)
        session.setSelection(
            setOf(
                MethodKey("classes.dex", "Ldemo/Sample;", "compute", "III"),
            ),
        )
        session.setKeystore(null)

        val second = SelectedApk(
            fileName = "other.apk",
            cachedPath = "/cache/other.apk",
            bytes = apk.bytes,
            info = ApkInfo(fileName = "other.apk", fileSizeBytes = 100),
        )
        session.setApk(second)
        assertTrue(session.selection.value.isEmpty())
        assertNull(session.outcome.value)
        assertEquals("other.apk", session.apk.value?.fileName)
    }

    @Test
    fun `method catalog groups classes by package`() {
        val catalog = MethodCatalog.fromApk(syntheticApk())
        val packages = catalog.packages()
        assertTrue(packages.isNotEmpty())
        val demo = packages.first { it.name == "demo" }
        val sample = demo.classes.first { it.displayName == "Sample" }
        val compute = sample.methods.first { it.key.methodName == "compute" }
        assertTrue(compute.convertible)
        assertEquals("III", compute.key.proto)
        assertNotNull(catalog.smaliOf(compute.key))
    }

    @Test
    fun `smali of a missing method is null`() {
        val catalog = MethodCatalog.fromApk(syntheticApk())
        assertNull(
            catalog.smaliOf(
                MethodKey("classes.dex", "Ldemo/Missing;", "gone", "V"),
            ),
        )
    }

    @Test
    fun `session spec defaults match the protection catalogue`() {
        val session = BuildSession()
        assertEquals(ProtectionSpec(), session.spec.value)
        assertFalse(session.spec.value.enabled[com.soulbrou.protection.ProtectionType.ANTI_EMULATOR.key]!!)
    }
}
