package com.soulbrou.signer

import com.android.apksig.ApkSigner
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/** Parameters of one signing request. */
data class SigningRequest(
    val keystoreBytes: ByteArray,
    val keystorePassword: CharArray,
    val keyAlias: String,
    val keyPassword: CharArray,
    val keystoreType: String = "PKCS12",
    val minSdkVersion: Int = 24,
)

/** Result of a signing operation. */
data class SigningResult(
    val apkBytes: ByteArray,
    val certificateSha256: ByteArray,
    val certificateSubject: String,
)

/**
 * Signs APKs with the apksig library using the v1, v2 and v3 schemes.
 *
 * The certificate fingerprint returned here is the value the runtime binds
 * the encrypted method blob to, so the pipeline must compute the blob with
 * the same key material.
 */
object ApkSignerService {

    class SigningException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Signs the given APK bytes, returning the signed output. */
    fun sign(apkBytes: ByteArray, request: SigningRequest): SigningResult {
        val keyStore = KeyStore.getInstance(request.keystoreType)
        keyStore.load(
            request.keystoreBytes.inputStream(),
            request.keystorePassword,
        )
        val entry = keyStore.getEntry(
            request.keyAlias,
            KeyStore.PasswordProtection(request.keyPassword),
        ) as? KeyStore.PrivateKeyEntry
            ?: throw SigningException("Alias no encontrado o sin clave privada: ${request.keyAlias}")

        val privateKey: PrivateKey = entry.privateKey
        val certificates = entry.certificateChain.filterIsInstance<X509Certificate>()
        if (certificates.isEmpty()) {
            throw SigningException("La keystore no contiene certificados X509")
        }

        val tempInput = File.createTempFile("soulbrou-in", ".apk")
        val tempOutput = File.createTempFile("soulbrou-out", ".apk")
        try {
            tempInput.writeBytes(apkBytes)
            val signer = ApkSigner.Builder(listOf(ApkSigner.SignerConfig.Builder("soulbrou", privateKey, certificates).build()))
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setMinSdkVersion(request.minSdkVersion)
                .setInputApk(tempInput)
                .setOutputApk(tempOutput)
                .build()
            try {
                signer.sign()
            } catch (error: Exception) {
                // Very small keystores can exceed the v1 digest length cap.
                val fallback = ApkSigner.Builder(
                    listOf(ApkSigner.SignerConfig.Builder("soulbrou", privateKey, certificates).build()),
                )
                    .setV1SigningEnabled(false)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setMinSdkVersion(request.minSdkVersion)
                    .setInputApk(tempInput)
                    .setOutputApk(tempOutput)
                    .build()
                fallback.sign()
            }

            val encoded = certificates[0].encoded
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(encoded)
            return SigningResult(
                apkBytes = tempOutput.readBytes(),
                certificateSha256 = digest,
                certificateSubject = certificates[0].subjectX500Principal.name,
            )
        } catch (error: Exception) {
            if (error is SigningException) throw error
            throw SigningException("No se pudo firmar el APK: ${error.message}", error)
        } finally {
            tempInput.delete()
            tempOutput.delete()
        }
    }

    /** Verifies the signature of an APK, throwing when invalid. */
    fun verify(apkBytes: ByteArray, minSdkVersion: Int = 24) {
        val temp = File.createTempFile("soulbrou-verify", ".apk")
        try {
            temp.writeBytes(apkBytes)
            val result = com.android.apksig.ApkVerifier.Builder(temp)
                .setMinCheckedPlatformVersion(minSdkVersion)
                .build()
                .verify()
            if (!result.isVerified) {
                val errors = result.allErrors.joinToString("; ") { it.toString() }
                throw SigningException("La firma del APK no es valida: $errors")
            }
        } finally {
            temp.delete()
        }
    }

    /**
     * Computes the SHA-256 fingerprint of the certificate that would sign
     * with the given keystore entry, without signing anything.
     */
    fun certificateFingerprint(request: SigningRequest): ByteArray {
        val keyStore = KeyStore.getInstance(request.keystoreType)
        keyStore.load(request.keystoreBytes.inputStream(), request.keystorePassword)
        val certificate = keyStore.getCertificate(request.keyAlias) as? X509Certificate
            ?: throw SigningException("Alias no encontrado: ${request.keyAlias}")
        return java.security.MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
    }
}
