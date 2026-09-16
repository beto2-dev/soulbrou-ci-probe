package com.soulbrou.signer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the keystore manager: generation, detection, summary and
 * fingerprinting of PKCS12 stores built on the JVM.
 */
class KeystoreManagerTest {

    private val manager = KeystoreManager

    @Test
    fun `generated store loads with the same password`() {
        val password = "unit-test-1".toCharArray()
        val bytes = manager.generate(
            alias = "soulbrou",
            storePassword = password,
            keyPassword = password,
            commonName = "Unit Test",
        )
        val store = manager.detectAndLoad(bytes, password)
        assertTrue(store.aliases().hasMoreElements())
    }

    @Test
    fun `summary reports the alias and the certificate subject`() {
        val password = "unit-test-2".toCharArray()
        val bytes = manager.generate(
            alias = "release",
            storePassword = password,
            keyPassword = password,
            commonName = "Soulbrou Release",
        )
        val summary = manager.summarize(bytes, password)
        assertEquals("PKCS12", summary.type)
        assertTrue(summary.aliases.contains("release"))
        assertTrue(summary.subject.contains("Soulbrou Release"))
        assertTrue(summary.notAfter > summary.notBefore)
    }

    @Test
    fun `fingerprint is a 32 byte sha256`() {
        val password = "unit-test-3".toCharArray()
        val bytes = manager.generate(
            alias = "fp",
            storePassword = password,
            keyPassword = password,
            commonName = "Fingerprint",
        )
        val fingerprint = manager.fingerprint(bytes, password, "fp")
        assertEquals(32, fingerprint.size)
    }

    @Test
    fun `fingerprints of the same certificate are stable`() {
        val password = "unit-test-4".toCharArray()
        val bytes = manager.generate(
            alias = "stable",
            storePassword = password,
            keyPassword = password,
            commonName = "Stable",
        )
        val first = manager.fingerprint(bytes, password, "stable")
        val second = manager.fingerprint(bytes, password, "stable")
        assertTrue(first.contentEquals(second))
    }

    @Test(expected = KeystoreManager.KeystoreException::class)
    fun `wrong password is rejected`() {
        val bytes = manager.generate(
            alias = "guard",
            storePassword = "right".toCharArray(),
            keyPassword = "right".toCharArray(),
            commonName = "Guard",
        )
        manager.detectAndLoad(bytes, "wrong".toCharArray())
    }
}
