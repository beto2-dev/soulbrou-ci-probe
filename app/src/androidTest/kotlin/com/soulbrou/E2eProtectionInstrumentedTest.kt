package com.soulbrou

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.soulbrou.dex2c.MethodKey
import com.soulbrou.dex2c.apk.ApkAnalyzer
import com.soulbrou.engine.MethodCatalog
import com.soulbrou.engine.ProtectionPipeline
import com.soulbrou.engine.RuntimeLibrarySource
import com.soulbrou.protection.ProtectionType
import com.soulbrou.signer.ApkSignerService
import com.soulbrou.signer.KeystoreManager
import com.soulbrou.signer.SigningRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.zip.ZipInputStream

/**
 * End to end protection cycle executed on a device or emulator: reads the
 * bundled test app fixture, converts its engine methods, signs the output
 * and verifies the result. This suite guards the full wiring between the
 * dex2c engine, the signer and the runtime library packaging.
 */
@RunWith(AndroidJUnit4::class)
class E2eProtectionInstrumentedTest {

    private fun readFixtureApk(): ByteArray {
        val context = InstrumentationRegistry.getInstrumentation().context
        return context.assets.open("testapp.apk").use { it.readBytes() }
    }

    private fun methodKeysOf(apkBytes: ByteArray, methodName: String): List<MethodKey> {
        val catalog = MethodCatalog.fromApk(apkBytes)
        return catalog.packages()
            .asSequence()
            .flatMap { it.classes.asSequence() }
            .filter { it.displayName == "Engine" }
            .flatMap { it.methods.asSequence() }
            .filter { it.convertible && it.key.methodName == methodName }
            .map { it.key }
            .toList()
    }

    @Test
    fun fullProtectionCycleProducesSignedValidApk() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val apkBytes = readFixtureApk()
        assertTrue("Fixture loaded", apkBytes.size > 1000)

        // Analyze the input.
        val tempInput = File(context.cacheDir, "e2e-input.apk")
        tempInput.writeBytes(apkBytes)
        val analysis = ApkAnalyzer.analyze(tempInput.absolutePath)
        assertTrue(analysis.info.methodCount > 0)
        assertEquals(1, analysis.dexEntryNames.size)

        // Select every overload of the fibonacci method.
        val selection = methodKeysOf(apkBytes, "fibonacci")
        assertTrue("fibonacci method found", selection.isNotEmpty())

        // Generate a signing keystore on the fly.
        val password = "e2e-signing-1".toCharArray()
        val keystoreBytes = KeystoreManager.generate(
            alias = "e2e",
            storePassword = password,
            keyPassword = password,
            commonName = "Soulbrou E2E",
        )
        val signing = SigningRequest(
            keystoreBytes = keystoreBytes,
            keystorePassword = password,
            keyAlias = "e2e",
            keyPassword = password,
        )

        val runtimeLibraries = RuntimeLibrarySource(context).load()
        assertTrue("Runtime libraries available", runtimeLibraries.isNotEmpty())

        val done = CountDownLatch(1)
        val outcomes = ArrayList<com.soulbrou.core.model.BuildOutcome?>()
        val pipeline = ProtectionPipeline(
            statistics = (context.applicationContext as SoulbrouApplication).container.statistics,
            outputDirectory = File(context.filesDir, "builds"),
            keepSignedCopy = false,
        )
        try {
            val outcome = runBlocking {
                pipeline.run(
                    apkBytes = apkBytes,
                    runtimeLibraries = runtimeLibraries,
                    selection = selection,
                    protectionMask = ProtectionType.maskOf(
                        listOf(
                            ProtectionType.ANTI_DEBUG,
                            ProtectionType.SIGNATURE_CHECK,
                        ),
                    ),
                    signing = signing,
                    obfuscationLevel = 1,
                    onDone = { result ->
                        outcomes.add(result)
                        done.countDown()
                    },
                )
            }
            assertTrue("Build succeeded: ${outcome.errorMessage}", outcome.success)
            val output = outcome.outputApkBytes
            assertNotNull("Signed output available", output)
            assertTrue(output!!.size > apkBytes.size / 2)

            // The output must carry the runtime and the blob.
            val names = zipEntryNames(output)
            assertTrue("Blob present", names.contains("assets/soulbrou_blob.bin"))
            assertTrue("Runtime present", names.any { it.endsWith("libsoulbrou.so") })

            // And the signature must verify.
            ApkSignerService.verify(output)

            val comparison = outcome.comparison
            assertNotNull(comparison)
            assertTrue(comparison!!.nativeMethodCount >= selection.size)
        } finally {
            pipeline.state.value
        }
    }

    @Test
    fun protectedTestAppStillInstallsAsValidArchive() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val apkBytes = readFixtureApk()
        val selection = methodKeysOf(apkBytes, "isEven")
        assertTrue(selection.isNotEmpty())

        val password = "e2e-signing-2".toCharArray()
        val keystoreBytes = KeystoreManager.generate(
            alias = "e2e2",
            storePassword = password,
            keyPassword = password,
            commonName = "Soulbrou E2E 2",
        )
        val pipeline = ProtectionPipeline(
            statistics = (context.applicationContext as SoulbrouApplication).container.statistics,
            outputDirectory = File(context.filesDir, "builds"),
            keepSignedCopy = false,
        )
        val outcome = runBlocking {
            pipeline.run(
                apkBytes = apkBytes,
                runtimeLibraries = RuntimeLibrarySource(context).load(),
                selection = selection,
                protectionMask = 0x00,
                signing = SigningRequest(
                    keystoreBytes = keystoreBytes,
                    keystorePassword = password,
                    keyAlias = "e2e2",
                    keyPassword = password,
                ),
                obfuscationLevel = 0,
                onDone = { },
            )
        }
        assertTrue(outcome.success)
        val output = outcome.outputApkBytes!!
        val names = zipEntryNames(output)
        assertTrue(names.contains("AndroidManifest.xml"))
        assertTrue(names.any { it.startsWith("classes") && it.endsWith(".dex") })
    }

    private fun zipEntryNames(bytes: ByteArray): List<String> {
        val names = ArrayList<String>()
        ZipInputStream(bytes.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                names.add(entry.name)
                entry = zip.nextEntry
            }
        }
        return names
    }
}
