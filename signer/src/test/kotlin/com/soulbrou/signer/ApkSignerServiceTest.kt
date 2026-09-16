package com.soulbrou.signer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Checks of the signing service: signs a minimal archive with every scheme
 * and verifies it end to end, including tamper detection.
 */
class ApkSignerServiceTest {

    private val manager = KeystoreManager
    private val password = "signing-test".toCharArray()

    private fun storeBytes(): ByteArray = manager.generate(
        alias = "soulbrou",
        storePassword = password,
        keyPassword = password,
        commonName = "Signer Test",
    )

    private fun request(keystore: ByteArray): SigningRequest = SigningRequest(
        keystoreBytes = keystore,
        keystorePassword = password,
        keyAlias = "soulbrou",
        keyPassword = password,
        keystoreType = "PKCS12",
        minSdkVersion = 24,
    )

    private fun minimalApk(): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(byteArrayOf(1, 2, 3, 4))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(ByteArray(64) { it.toByte() })
            zip.closeEntry()
        }
        return output.toByteArray()
    }

    @Test
    fun `signed apk verifies`() {
        val keystore = storeBytes()
        val signed = ApkSignerService.sign(minimalApk(), request(keystore))
        assertTrue(signed.apkBytes.size > 0)
        assertEquals(32, signed.certificateSha256.size)
        assertTrue(signed.certificateSubject.isNotBlank())
        ApkSignerService.verify(signed.apkBytes)
    }

    @Test
    fun `tampering breaks the verification`() {
        val keystore = storeBytes()
        val signed = ApkSignerService.sign(minimalApk(), request(keystore))
        val tampered = signed.apkBytes.copyOf()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2] + 1).toByte()
        try {
            ApkSignerService.verify(tampered)
            throw AssertionError("A tampered APK must not verify")
        } catch (expected: Exception) {
            assertTrue(expected is ApkSignerService.SigningException || expected is RuntimeException)
        }
    }

    @Test
    fun `certificate fingerprint matches the signer certificate`() {
        val keystore = storeBytes()
        val signing = request(keystore)
        val fingerprint = ApkSignerService.certificateFingerprint(signing)
        val signed = ApkSignerService.sign(minimalApk(), signing)
        assertTrue(fingerprint.contentEquals(signed.certificateSha256))
    }

    @Test
    fun `signing adds meta inf entries`() {
        val signed = ApkSignerService.sign(minimalApk(), request(storeBytes()))
        val names = ArrayList<String>()
        java.util.zip.ZipInputStream(java.io.ByteArrayInputStream(signed.apkBytes)).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                names.add(entry.name)
                entry = zip.nextEntry
            }
        }
        assertTrue(names.contains("classes.dex"))
        assertTrue(names.any { it.startsWith("META-INF/") })
    }
}
