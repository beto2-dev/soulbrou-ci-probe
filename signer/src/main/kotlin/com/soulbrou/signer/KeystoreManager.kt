package com.soulbrou.signer

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Manages keystores: validation, alias enumeration and generation of new
 * PKCS12 keystores with a self signed RSA 2048 certificate built with a
 * minimal DER encoder, so the module works on Android without heavyweight
 * dependencies.
 */
object KeystoreManager {

    class KeystoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Summary of a keystore. */
    data class Summary(
        val type: String,
        val aliases: List<String>,
        val subject: String,
        val notBefore: Long,
        val notAfter: Long,
    )

    /** Detects the keystore format and validates the password. */
    fun detectAndLoad(bytes: ByteArray, password: CharArray): KeyStore {
        val candidates = listOf("PKCS12", "JKS", "BKS")
        var lastError: Exception? = null
        for (type in candidates) {
            try {
                val store = KeyStore.getInstance(type)
                store.load(bytes.inputStream(), password)
                return store
            } catch (error: Exception) {
                lastError = error
            }
        }
        throw KeystoreException("Formato de keystore no reconocido o password incorrecto", lastError)
    }

    /** Summarizes the aliases and certificate of a keystore. */
    fun summarize(bytes: ByteArray, password: CharArray): Summary {
        val store = detectAndLoad(bytes, password)
        val aliases = store.aliases().toList()
        var subject = ""
        var notBefore = 0L
        var notAfter = 0L
        for (alias in aliases) {
            val chain = store.getCertificateChain(alias) ?: continue
            val certificate = chain.firstOrNull() as? X509Certificate ?: continue
            subject = certificate.subjectX500Principal.name
            notBefore = certificate.notBefore.time
            notAfter = certificate.notAfter.time
            break
        }
        return Summary(store.type, aliases, subject, notBefore, notAfter)
    }

    /**
     * Generates a new PKCS12 keystore with a self signed RSA 2048 key valid
     * for [validityDays]. Returns the keystore bytes.
     */
    fun generate(
        alias: String,
        storePassword: CharArray,
        keyPassword: CharArray,
        commonName: String,
        validityDays: Int = 10950,
    ): ByteArray {
        require(alias.isNotBlank()) { "Alias requerido" }
        try {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply {
                initialize(2048, SecureRandom())
            }.generateKeyPair()

            val certificate = SelfSignedCertificate.create(keyPair, commonName, validityDays)

            val store = KeyStore.getInstance("PKCS12")
            store.load(null, null)
            store.setKeyEntry(alias, keyPair.private, keyPassword, arrayOf(certificate))

            val output = ByteArrayOutputStream()
            store.store(output, storePassword)
            return output.toByteArray()
        } catch (error: Exception) {
            throw KeystoreException("No se pudo generar la keystore: ${error.message}", error)
        }
    }

    /** Computes the SHA-256 fingerprint of the first certificate of an alias. */
    fun fingerprint(bytes: ByteArray, password: CharArray, alias: String): ByteArray {
        val store = detectAndLoad(bytes, password)
        val certificate = store.getCertificate(alias)
            ?: throw KeystoreException("Alias no encontrado: $alias")
        return MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
    }
}

/**
 * Minimal self signed X.509 certificate builder using a hand written DER
 * encoder. Produces SHA256withRSA certificates compatible with Android.
 */
internal object SelfSignedCertificate {

    fun create(keyPair: KeyPair, commonName: String, validityDays: Int): X509Certificate {
        val now = Date()
        val calendar = Calendar.getInstance()
        calendar.time = now
        calendar.add(Calendar.DAY_OF_YEAR, validityDays)

        val issuer = X500Principal("CN=$commonName, O=Soulbrou")
        val serial = BigInteger(63, SecureRandom())

        val tbs = DerBuilder().apply {
            raw(byteArrayOf(0xA0.toByte(), 0x03, 0x02, 0x01, 0x02)) // version v3
            integer(normalizePositive(serial.toByteArray()))
            raw(algorithmIdentifier())
            raw(issuer.encoded)
            raw(validity(now, calendar.time))
            raw(issuer.encoded) // subject equals issuer (self signed)
            raw(keyPair.public.encoded)
        }.buildSequence()

        val signer = java.security.Signature.getInstance("SHA256withRSA")
        signer.initSign(keyPair.private)
        signer.update(tbs)
        val signature = signer.sign()

        val signedCert = DerBuilder().apply {
            raw(tbs)
            raw(algorithmIdentifier())
            bitString(signature)
        }.buildSequence()

        val factory = java.security.cert.CertificateFactory.getInstance("X.509")
        return factory.generateCertificate(signedCert.inputStream()) as X509Certificate
    }

    /** DER integers must be positive: prepend a zero when the high bit is set. */
    private fun normalizePositive(bytes: ByteArray): ByteArray =
        if (bytes.isNotEmpty() && bytes[0].toInt() and 0x80 != 0) byteArrayOf(0) + bytes else bytes

    private fun validity(notBefore: Date, notAfter: Date): ByteArray {
        val utc = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US)
        utc.timeZone = java.util.TimeZone.getTimeZone("UTC")
        val general = java.text.SimpleDateFormat("yyyyMMddHHmmss'Z'", java.util.Locale.US)
        general.timeZone = java.util.TimeZone.getTimeZone("UTC")

        // Years from 2050 onwards must use GeneralizedTime (tag 0x18) with a
        // four digit year; UTCTime (tag 0x17) only covers 1950 to 2049.
        fun time(date: Date, tag: Int, format: java.text.SimpleDateFormat): ByteArray {
            val text = format.format(date).toByteArray(Charsets.US_ASCII)
            return byteArrayOf(tag.toByte(), text.size.toByte()) + text
        }

        fun encoded(date: Date): ByteArray {
            val calendar = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
            calendar.time = date
            return if (calendar.get(java.util.Calendar.YEAR) >= 2050) {
                time(date, 0x18, general)
            } else {
                time(date, 0x17, utc)
            }
        }

        return DerBuilder().apply {
            raw(encoded(notBefore))
            raw(encoded(notAfter))
        }.buildSequence()
    }

    private fun algorithmIdentifier(): ByteArray =
        // OID 1.2.840.113549.1.1.11 (SHA256withRSA) with NULL parameters.
        byteArrayOf(
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(),
            0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00,
        )
}

/** Minimal DER writer used by the certificate builder. */
internal class DerBuilder {
    private val output = ByteArrayOutputStream()

    fun raw(bytes: ByteArray) {
        output.write(bytes)
    }

    fun integer(bytes: ByteArray) {
        raw(tagged(0x02, bytes))
    }

    fun bitString(bytes: ByteArray) {
        raw(tagged(0x03, byteArrayOf(0) + bytes))
    }

    fun build(): ByteArray = output.toByteArray()

    /** Wraps the accumulated content in a DER SEQUENCE. */
    fun buildSequence(): ByteArray = tagged(0x30, output.toByteArray())

    private fun tagged(tagByte: Int, body: ByteArray): ByteArray {
        val header = ByteArrayOutputStream()
        header.write(tagByte)
        val length = body.size
        when {
            length < 0x80 -> header.write(length)
            length < 0x100 -> {
                header.write(0x81)
                header.write(length)
            }
            length < 0x10000 -> {
                header.write(0x82)
                header.write(length shr 8)
                header.write(length and 0xFF)
            }
            else -> {
                header.write(0x83)
                header.write(length shr 16)
                header.write((length shr 8) and 0xFF)
                header.write(length and 0xFF)
            }
        }
        return header.toByteArray() + body
    }
}
