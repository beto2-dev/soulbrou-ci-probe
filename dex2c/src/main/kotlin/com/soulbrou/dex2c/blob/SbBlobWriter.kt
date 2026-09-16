package com.soulbrou.dex2c.blob

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * XXTEA implementation used to encrypt the runtime method blob. The matching
 * decryptor lives in the native runtime (runtime/crypto.cpp).
 */
object Xxtea {

    private const val DELTA = -0x61C88647L // 0x9E3779B9 as signed 32 bit

    fun encrypt(data: IntArray, key: IntArray) {
        require(key.size == 4) { "XXTEA key must have four words" }
        if (data.size < 2) return
        val n = data.size - 1
        val q = 6 + 52 / data.size
        var sum = 0L
        var z = data[n]
        var y: Int
        repeat(q) { _ ->
            sum = (sum + DELTA) and 0xFFFFFFFFL
            val e = ((sum ushr 2) and 3).toInt()
            for (p in 0 until n) {
                y = data[p + 1]
                z = data[p] + mx(sum, y, z, p, e, key)
                data[p] = z
            }
            y = data[0]
            z = data[n] + mx(sum, y, z, n, e, key)
            data[n] = z
        }
    }

    /** Inverse of [encrypt]; mirrors the native runtime decryptor. */
    fun decrypt(data: IntArray, key: IntArray) {
        require(key.size == 4) { "XXTEA key must have four words" }
        if (data.size < 2) return
        val n = data.size - 1
        val q = 6 + 52 / data.size
        var sum = (q * DELTA) and 0xFFFFFFFFL
        var y = data[0]
        var z: Int
        repeat(q) { _ ->
            val e = ((sum ushr 2) and 3).toInt()
            for (p in n downTo 1) {
                z = data[p - 1]
                y = data[p] - mx(sum, y, z, p, e, key)
                data[p] = y
            }
            z = data[n]
            y = data[0] - mx(sum, y, z, 0, e, key)
            data[0] = y
            sum = (sum - DELTA) and 0xFFFFFFFFL
        }
    }

    private fun mx(sum: Long, y: Int, z: Int, p: Int, e: Int, key: IntArray): Int {
        val mixed = (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor
            (((sum.toInt() xor y) + (key[(p and 3) xor e] xor z)))
        return mixed
    }
}

/**
 * Serializes the protected method bodies into the encrypted runtime blob
 * consumed by the native interpreter. The blob layout mirrors the parser in
 * runtime/dalvik_interp.cpp.
 */
class SbBlobWriter(
    private val certificateSha256: ByteArray,
    private val protectionMask: Int,
    private val expectedDexCrc: Int,
) {

    class MethodBlock(
        val key: String,
        val registersSize: Int,
        val insSize: Int,
        val outsSize: Int,
        val signature: String,
        val isStatic: Boolean,
        val insns: IntArray,
        val tries: List<TryBlock>,
        val strings: List<String>,
        val methodRefs: List<Triple<String, String, String>>,
        val fieldRefs: List<Triple<String, String, String>>,
        val types: List<String>,
        val payloads: List<PayloadBlock>,
    ) {
        class TryBlock(val start: Int, val count: Int, val handler: Int)
        class HandlerBlock(
            val entries: List<Pair<String, Int>>,
            val catchAll: Int?,
        )
        class PayloadBlock(val address: Int, val data: ByteArray)
    }

    private val methods = ArrayList<MethodBlock>()
    private val methodHandlers = HashMap<String, List<MethodBlock.HandlerBlock>>()
    private val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }

    fun add(method: MethodBlock) {
        methods.add(method)
    }

    /** Registers the flattened handler list of a method. */
    fun handlersOf(key: String, handlers: List<MethodBlock.HandlerBlock>) {
        methodHandlers[key] = handlers
    }

    /** Builds the encrypted blob. */
    fun build(): ByteArray {
        val key = deriveKey()

        fun string(target: ByteArrayOutputStream, value: String) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            u16(target, bytes.size)
            target.write(bytes)
        }

        // Serialize every block, padding to a four byte multiple.
        val blocks = ArrayList<Triple<Int, Long, ByteArray>>() // hash, offset, ciphertext
        val assembly = ByteArrayOutputStream()
        // Header: magic, version, mask, salt, crc, count, indexOffset.
        assembly.write("SBBL".toByteArray(Charsets.US_ASCII))
        u32(assembly, 1L)
        u32(assembly, protectionMask.toLong())
        assembly.write(salt)
        u32(assembly, expectedDexCrc.toLong() and 0xFFFFFFFFL)
        u32(assembly, methods.size.toLong())
        u32(assembly, 0L) // index offset, patched after assembly
        val dataStart = assembly.size()

        for (method in methods) {
            val block = ByteArrayOutputStream()
            string(block, method.key)
            u16(block, method.registersSize)
            u16(block, method.insSize)
            u16(block, method.outsSize)
            string(block, method.signature)
            block.write(if (method.isStatic) 1 else 0)
            u32(block, method.insns.size.toLong())
            for (unit in method.insns) {
                u16(block, unit)
            }
            u32(block, method.tries.size.toLong())
            for (tryBlock in method.tries) {
                u32(block, tryBlock.start.toLong() and 0xFFFFFFFFL)
                u16(block, tryBlock.count)
                u16(block, tryBlock.handler)
            }
            val handlers = methodHandlers[method.key] ?: emptyList()
            u32(block, handlers.size.toLong())
            for (handler in handlers) {
                val encoded = handler.entries.size or (if (handler.catchAll != null) 0x80 else 0)
                block.write(encoded)
                for ((type, address) in handler.entries) {
                    string(block, type)
                    u32(block, address.toLong() and 0xFFFFFFFFL)
                }
                if (handler.catchAll != null) {
                    u32(block, handler.catchAll.toLong() and 0xFFFFFFFFL)
                }
            }
            u32(block, method.strings.size.toLong())
            for (value in method.strings) string(block, value)
            u32(block, method.methodRefs.size.toLong())
            for ((className, name, signature) in method.methodRefs) {
                string(block, className)
                string(block, name)
                string(block, signature)
            }
            u32(block, method.fieldRefs.size.toLong())
            for ((className, name, type) in method.fieldRefs) {
                string(block, className)
                string(block, name)
                string(block, type)
            }
            u32(block, method.types.size.toLong())
            for (type in method.types) string(block, type)
            u32(block, method.payloads.size.toLong())
            for (payload in method.payloads) {
                u32(block, payload.address.toLong() and 0xFFFFFFFFL)
                u32(block, payload.data.size.toLong())
                var index = 0
                while (index < payload.data.size) {
                    val first = payload.data[index].toInt() and 0xFF
                    val second = if (index + 1 < payload.data.size) {
                        payload.data[index + 1].toInt() and 0xFF
                    } else {
                        0
                    }
                    u16(block, first or (second shl 8))
                    index += 2
                }
            }

            var plain = block.toByteArray()
            val padding = (4 - plain.size % 4) % 4
            if (padding > 0) {
                plain += ByteArray(padding)
            }
            val words = IntArray(plain.size / 4) { i ->
                (plain[i * 4].toInt() and 0xFF) or
                    ((plain[i * 4 + 1].toInt() and 0xFF) shl 8) or
                    ((plain[i * 4 + 2].toInt() and 0xFF) shl 16) or
                    ((plain[i * 4 + 3].toInt() and 0xFF) shl 24)
            }
            Xxtea.encrypt(words, key)
            val cipher = ByteArray(words.size * 4) { i ->
                ((words[i / 4] ushr ((i % 4) * 8)) and 0xFF).toByte()
            }
            blocks.add(Triple(fnvHash(method.key), (assembly.size() - dataStart).toLong(), cipher))
            assembly.write(cipher)
        }

        val indexOffset = assembly.size() - dataStart
        for ((hash, offset, cipher) in blocks) {
            u32(assembly, hash.toLong() and 0xFFFFFFFFL)
            u32(assembly, offset)
            u32(assembly, cipher.size.toLong())
        }

        val result = assembly.toByteArray()
        // Patch the index offset field, located right after the header
        // constant part: 4 (magic) + 4 + 4 + 16 + 4 + 4 = 36.
        writeU32At(result, 36, indexOffset.toLong())
        return result
    }

    private fun deriveKey(): IntArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(certificateSha256 + salt, "HmacSHA256"))
        val digest = mac.doFinal("soulbrou-blob-v1".toByteArray(Charsets.UTF_8))
        return intArrayOf(
            readU32(digest, 0),
            readU32(digest, 4),
            readU32(digest, 8),
            readU32(digest, 12),
        )
    }

    private fun readU32(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)

    private fun u16(target: ByteArrayOutputStream, value: Int) {
        target.write(value and 0xFF)
        target.write((value shr 8) and 0xFF)
    }

    private fun u32(target: ByteArrayOutputStream, value: Long) {
        target.write((value and 0xFF).toInt())
        target.write(((value shr 8) and 0xFF).toInt())
        target.write(((value shr 16) and 0xFF).toInt())
        target.write(((value shr 24) and 0xFF).toInt())
    }

    private fun writeU32At(target: ByteArray, offset: Int, value: Long) {
        target[offset] = (value and 0xFF).toByte()
        target[offset + 1] = ((value shr 8) and 0xFF).toByte()
        target[offset + 2] = ((value shr 16) and 0xFF).toByte()
        target[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

    companion object {
        /** FNV-1a hash used as the method index key. */
        fun fnvHash(key: String): Int {
            var hash = -2128831035 // 2166136261 as signed 32 bit
            for (ch in key) {
                hash = hash xor (ch.code and 0xFF)
                hash *= 16777619
            }
            return hash
        }
    }
}
