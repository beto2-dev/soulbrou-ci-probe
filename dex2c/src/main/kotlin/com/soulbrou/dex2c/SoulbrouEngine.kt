package com.soulbrou.dex2c

import com.soulbrou.core.logging.SoulLog
import com.soulbrou.dex2c.blob.SbBlobWriter
import com.soulbrou.dex2c.code.DexCodeCodec
import com.soulbrou.dex2c.code.PayloadKind
import com.soulbrou.dex2c.mutate.StubInjector
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedMethod
import com.soulbrou.dex2c.model.DexField
import com.soulbrou.dex2c.model.DexMethod
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.model.DexType
import com.soulbrou.dex2c.parser.DexParser
import com.soulbrou.dex2c.translate.SmaliToCTranslator
import com.soulbrou.dex2c.writer.DexWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/** Stable identifier of a method selected for conversion. */
data class MethodKey(
    val dexName: String,
    val classDescriptor: String,
    val methodName: String,
    val proto: String,
) {
    /** Full signature including return type, used by the runtime blob. */
    val fullSignature: String get() = "($proto)"
}

/** Result of a protection run. */
data class ProtectionResult(
    val apkBytes: ByteArray,
    val convertedMethods: List<MethodKey>,
    val skippedMethods: List<MethodKey>,
    val generatedC: Map<MethodKey, String>,
    val dexMethodCountBefore: Int,
    val dexMethodCountAfter: Int,
    val classesDexCrc: Int,
)

/**
 * Core protection engine. Given an APK, the selected methods, the protection
 * configuration and the expected signer certificate, produces a new
 * unsigned APK whose selected method bodies live encrypted inside the native
 * runtime blob.
 *
 * The engine is a pure JVM component: it runs identically on the device,
 * in the JVM unit tests and in the continuous integration pipeline.
 */
class SoulbrouEngine(
    private val runtimeLibraries: Map<String, ByteArray>,
    private val obfuscationLevel: Int = 0,
) {

    class EngineException(message: String) : Exception(message)

    fun protect(
        apkBytes: ByteArray,
        selection: List<MethodKey>,
        protectionMask: Int,
        certificateSha256: ByteArray,
    ): ProtectionResult {
        val entries = readZip(apkBytes)

        val dexNames = entries.keys.filter { it.endsWith(".dex") && it.startsWith("classes") }.sorted()
        if (dexNames.isEmpty()) {
            throw EngineException("El APK no contiene archivos dex")
        }

        val documents = LinkedHashMap<String, DexDocument>()
        val methodIndex = HashMap<MethodKey, Pair<DexDocument, DexEncodedMethod>>()
        var methodCountBefore = 0

        for (dexName in dexNames) {
            val document = try {
                DexParser(entries[dexName]!!.second).parse()
            } catch (error: Exception) {
                SoulLog.w("soulbrou", "Dex no procesable $dexName: ${error.message}")
                continue
            }
            documents[dexName] = document
            document.unseal()
            document.strings.seal()
            document.types.seal()
            document.protos.seal()
            document.fields.seal()
            document.methods.seal()
            document.classes.seal()
            for (classDef in document.classes) {
                val classData = classDef.classData ?: continue
                for (method in classData.directMethods + classData.virtualMethods) {
                    if (method.code != null) {
                        methodCountBefore++
                    }
                    val key = MethodKey(
                        dexName = dexName,
                        classDescriptor = classDef.type.descriptor.value,
                        methodName = method.method.name.value,
                        proto = method.method.proto.parameterDescriptors +
                            method.method.proto.returnType.descriptor.value,
                    )
                    methodIndex[key] = document to method
                }
            }
        }

        // ---- Phase 1: extract the original bodies and validate ------------
        val translatorResults = HashMap<MethodKey, String>()
        val skipped = ArrayList<MethodKey>()
        val selected = ArrayList<MethodKey>()
        val extractedBlocks = LinkedHashMap<MethodKey, Pair<SbBlobWriter.MethodBlock, List<SbBlobWriter.MethodBlock.HandlerBlock>>>()

        for (key in selection) {
            val found = methodIndex[key]
            if (found == null) {
                skipped.add(key)
                continue
            }
            val (document, method) = found
            val classDef = document.classes.firstOrNull {
                it.type.descriptor.value == key.classDescriptor
            } ?: continue
            val translator = SmaliToCTranslator(document, obfuscationLevel)
            try {
                val generated = translator.translate(classDef, method)
                translatorResults[key] = generated.source
                extractedBlocks[key] = extractBlock(document, method, key)
                selected.add(key)
            } catch (error: Exception) {
                SoulLog.i(
                    "soulbrou",
                    "Metodo no convertible, se mantiene en dex: ${key.classDescriptor}->${key.methodName}",
                )
                skipped.add(key)
            }
        }

        // ---- Phase 2: replace the bodies with dispatch stubs --------------
        val injectors = documents.mapValues { (_, document) -> StubInjector(document) }
        injectors.values.firstOrNull()?.injectHelperClass()
        for (key in selected) {
            val (document, method) = methodIndex.getValue(key)
            val injector = injectors.values.first { it.documentOf() === document }
            injector.replaceMethodWithStub(
                document.classes.firstOrNull { it.type.descriptor.value == key.classDescriptor }!!,
                method,
                "(" + key.proto + ")",
            )
        }

        // ---- Phase 3: rewrite the dex files ------------------------------
        val newDexes = LinkedHashMap<String, ByteArray>()
        for ((dexName, document) in documents) {
            newDexes[dexName] = DexWriter(document).write()
        }

        var dexCrc = 0
        if (newDexes.containsKey("classes.dex")) {
            val crc = CRC32()
            crc.update(newDexes.getValue("classes.dex"))
            dexCrc = crc.value.toInt()
        }

        // ---- Phase 4: build the encrypted blob ----------------------------
        val blobWriter = SbBlobWriter(certificateSha256, protectionMask, dexCrc)
        for (key in selected) {
            val (block, handlers) = extractedBlocks.getValue(key)
            blobWriter.handlersOf(block.key, handlers)
            blobWriter.add(block)
        }
        val blob = blobWriter.build()

        // ---- Phase 5: assemble the output APK ----------------------------
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            for ((name, original) in entries) {
                if (name in newDexes) continue
                if (name.startsWith("META-INF/") &&
                    (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA"))
                ) {
                    continue // old signatures are dropped
                }
                val copy = ZipEntry(name)
                copy.time = 0
                zip.putNextEntry(copy)
                zip.write(original.second)
                zip.closeEntry()
            }
            for ((dexName, bytes) in newDexes) {
                val copy = ZipEntry(dexName)
                copy.time = 0
                zip.putNextEntry(copy)
                zip.write(bytes)
                zip.closeEntry()
            }
            for ((abi, library) in runtimeLibraries) {
                val copy = ZipEntry("lib/$abi/libsoulbrou.so")
                copy.time = 0
                copy.method = ZipEntry.STORED
                copy.size = library.size.toLong()
                copy.compressedSize = library.size.toLong()
                val crc = CRC32()
                crc.update(library)
                copy.crc = crc.value
                zip.putNextEntry(copy)
                zip.write(library)
                zip.closeEntry()
            }
            val blobEntry = ZipEntry("assets/soulbrou_blob.bin")
            blobEntry.time = 0
            blobEntry.method = ZipEntry.STORED
            blobEntry.size = blob.size.toLong()
            blobEntry.compressedSize = blob.size.toLong()
            val blobCrc = CRC32()
            blobCrc.update(blob)
            blobEntry.crc = blobCrc.value
            zip.putNextEntry(blobEntry)
            zip.write(blob)
            zip.closeEntry()
        }

        return ProtectionResult(
            apkBytes = output.toByteArray(),
            convertedMethods = selected,
            skippedMethods = skipped,
            generatedC = translatorResults,
            dexMethodCountBefore = methodCountBefore,
            dexMethodCountAfter = methodCountBefore,
            classesDexCrc = dexCrc,
        )
    }

    private fun readZip(bytes: ByteArray): LinkedHashMap<String, Pair<ZipEntry, ByteArray>> {
        val entries = LinkedHashMap<String, Pair<ZipEntry, ByteArray>>()
        val stream = ZipInputStream(ByteArrayInputStream(bytes))
        var entry: ZipEntry? = stream.nextEntry
        while (entry != null) {
            if (!entry.isDirectory) {
                entries[entry.name] = entry to stream.readBytes()
            }
            stream.closeEntry()
            entry = stream.nextEntry
        }
        stream.close()
        return entries
    }

    /** Serializes the original body of a method for the runtime blob. */
    private fun extractBlock(
        document: DexDocument,
        method: DexEncodedMethod,
        key: MethodKey,
    ): Pair<SbBlobWriter.MethodBlock, List<SbBlobWriter.MethodBlock.HandlerBlock>> {
        val code = method.code ?: throw EngineException("Metodo sin cuerpo")
        val codec = DexCodeCodec(document)
        val encoded = codec.encode(code)

        // Collect the referenced strings, methods, fields and types with
        // their original indices, which the instruction operands use.
        val strings = HashMap<Int, String>()
        val methodRefs = HashMap<Int, Triple<String, String, String>>()
        val fieldRefs = HashMap<Int, Triple<String, String, String>>()
        val types = HashMap<Int, String>()

        fun indexString(value: DexString): Int = document.strings.indexOfItem(value)
        fun indexType(value: DexType): Int = document.types.indexOfItem(value)
        fun indexMethod(value: DexMethod): Int = document.methods.indexOfItem(value)
        fun indexField(value: DexField): Int = document.fields.indexOfItem(value)

        for (insn in code.insns) {
            when (val ref = insn.ref) {
                is DexString -> strings[indexString(ref)] = ref.value
                is DexType -> types[indexType(ref)] = ref.descriptor.value
                is DexMethod -> methodRefs[indexMethod(ref)] = Triple(
                    ref.declaringClass.descriptor.value,
                    ref.name.value,
                    "(" + ref.proto.parameterDescriptors + ")" + ref.proto.returnType.descriptor.value,
                )
                is DexField -> fieldRefs[indexField(ref)] = Triple(
                    ref.declaringClass.descriptor.value,
                    ref.name.value,
                    ref.type.descriptor.value,
                )
            }
        }

        fun <V> sparse(maxIndex: Int, source: Map<Int, V>, placeholder: V): List<V> =
            if (maxIndex < 0) emptyList() else (0 until maxIndex + 1).map { source[it] ?: placeholder }

        val stringsMax = strings.keys.maxOrNull() ?: -1
        val typesMax = types.keys.maxOrNull() ?: -1
        val methodMax = methodRefs.keys.maxOrNull() ?: -1
        val fieldMax = fieldRefs.keys.maxOrNull() ?: -1

        // Handlers: flatten unique handlers and index them.
        val handlerList = ArrayList<SbBlobWriter.MethodBlock.HandlerBlock>()
        val handlerIndex = HashMap<Any, Int>()
        for (tryItem in encoded.tries) {
            val handler = tryItem.handler
            val existing = handlerIndex[handler]
            if (existing == null) {
                handlerList.add(
                    SbBlobWriter.MethodBlock.HandlerBlock(
                        entries = handler.entries.map { it.type.descriptor.value to it.address },
                        catchAll = handler.catchAllAddress,
                    ),
                )
                handlerIndex[handler] = handlerList.size - 1
            }
        }

        val tryBlocks = encoded.tries.map {
            SbBlobWriter.MethodBlock.TryBlock(it.startAddress, it.instructionCount, handlerIndex.getValue(it.handler))
        }

        // Payloads re-encoded from the decoded payload objects.
        val payloads = ArrayList<SbBlobWriter.MethodBlock.PayloadBlock>()
        for (insn in code.insns) {
            val payload = insn.payload ?: continue
            val stream = ByteArrayOutputStream()
            when (payload.kind) {
                PayloadKind.PACKED_SWITCH -> {
                    stream.write(le16(0x0100))
                    stream.write(le16(payload.targets.size))
                    stream.write(le32(payload.firstKey))
                    for (target in payload.targets) stream.write(le32(target))
                }
                PayloadKind.SPARSE_SWITCH -> {
                    stream.write(le16(0x0200))
                    stream.write(le16(payload.keys.size))
                    for (k in payload.keys) stream.write(le16(k))
                    for (target in payload.targets) stream.write(le32(target))
                }
                else -> {
                    stream.write(le16(0x0300))
                    stream.write(le16(payload.elementWidth))
                    stream.write(le32(payload.data.size / payload.elementWidth))
                    stream.write(payload.data)
                    if (payload.data.size % 2 == 1) stream.write(0)
                }
            }
            payloads.add(SbBlobWriter.MethodBlock.PayloadBlock(insn.address, stream.toByteArray()))
        }

        val block = SbBlobWriter.MethodBlock(
            key = "(" + key.proto + ")",
            registersSize = encoded.registersSize,
            insSize = encoded.insSize,
            outsSize = encoded.outsSize,
            signature = "(" + method.method.proto.parameterDescriptors + ")" +
                method.method.proto.returnType.descriptor.value,
            isStatic = method.isStatic,
            insns = encoded.units,
            tries = tryBlocks,
            strings = sparse(stringsMax, strings, ""),
            methodRefs = sparse(methodMax, methodRefs, Triple("", "", "")),
            fieldRefs = sparse(fieldMax, fieldRefs, Triple("", "", "")),
            types = sparse(typesMax, types, ""),
            payloads = payloads,
        )
        return block to handlerList
    }

    private fun le16(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
    )

    private fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
        ((value shr 16) and 0xFF).toByte(),
        ((value shr 24) and 0xFF).toByte(),
    )
}
