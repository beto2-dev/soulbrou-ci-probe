package com.soulbrou.dex2c.apk

import com.soulbrou.core.io.IoUtils
import com.soulbrou.core.model.ApkInfo
import java.io.ByteArrayInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Lightweight reader for the compiled binary XML (AXML) resources used
 * inside APK files. Only the subset required to inspect the manifest is
 * implemented: chunk walking, string pools and start element attributes.
 */
class BinaryXmlParser {

    class XmlParseException(message: String) : Exception(message)

    /** One parsed start element with its attributes. */
    data class Element(
        val name: String,
        val attributes: Map<String, String>,
    )

    /** Parses the AXML document and returns every start element found. */
    fun parseStartElements(bytes: ByteArray): List<Element> {
        if (bytes.size < 8) throw XmlParseException("Truncated AXML header")
        if (IoUtils.u16(bytes, 0) != 0x0003) throw XmlParseException("Not a binary XML resource")

        var offset = IoUtils.u16(bytes, 2).toInt() // header size
        val strings = ArrayList<String>()
        val elements = ArrayList<Element>(32)

        while (offset + 8 <= bytes.size) {
            val type = IoUtils.u16(bytes, offset)
            val headerSize = IoUtils.u16(bytes, offset + 2).toInt()
            val size = IoUtils.u32(bytes, offset + 4).toInt()
            if (size <= 0 || offset + size > bytes.size) break

            when (type) {
                0x0001 -> parseStringPool(bytes, offset, size, strings)
                0x0102 -> parseStartElement(bytes, offset + headerSize, strings, elements)
                else -> Unit
            }
            offset += size
        }
        return elements
    }

    private fun parseStringPool(bytes: ByteArray, offset: Int, size: Int, out: MutableList<String>) {
        val stringCount = IoUtils.u32(bytes, offset + 8).toInt()
        val flags = IoUtils.u32(bytes, offset + 16).toInt()
        val stringsStart = IoUtils.u32(bytes, offset + 20).toInt()
        val isUtf8 = flags and 0x100 != 0
        for (i in 0 until stringCount) {
            val stringOffset = offset + stringsStart + IoUtils.u32(bytes, offset + 28 + i * 4).toInt()
            if (stringOffset >= bytes.size) {
                out.add("")
                continue
            }
            out.add(readPoolString(bytes, stringOffset, isUtf8))
        }
    }

    private fun readPoolString(bytes: ByteArray, offset: Int, utf8: Boolean): String {
        if (utf8) {
            var cursor = offset
            cursor += skipLength8(bytes, cursor) // character count
            val byteCount = readLength8(bytes, cursor)
            cursor += length8Size(bytes, cursor)
            val end = cursor + byteCount
            return String(bytes, cursor, (end - cursor).coerceAtMost(bytes.size - cursor), Charsets.UTF_8)
        }
        val charCount = readLength16(bytes, offset)
        var cursor = offset + length16Size(bytes, offset) * 2 - 2
        // Cursor now points at the first character (after the length units).
        val end = cursor + charCount * 2
        if (end > bytes.size) return ""
        val chars = CharArray(charCount)
        for (i in 0 until charCount) {
            chars[i] = ((bytes[cursor + i * 2].toInt() and 0xFF) or
                ((bytes[cursor + i * 2 + 1].toInt() and 0xFF) shl 8)).toChar()
        }
        return String(chars)
    }

    /** Reads an encoded UTF-16 length, returning the character count. */
    private fun readLength16(bytes: ByteArray, offset: Int): Int {
        val first = IoUtils.u16(bytes, offset)
        return if (first and 0x8000 != 0) {
            ((first and 0x7FFF) shl 16) or IoUtils.u16(bytes, offset + 2)
        } else {
            first
        }
    }

    /** Number of length units in an encoded UTF-16 length. */
    private fun length16Size(bytes: ByteArray, offset: Int): Int {
        val first = IoUtils.u16(bytes, offset)
        return if (first and 0x8000 != 0) 2 else 1
    }

    private fun readLength8(bytes: ByteArray, offset: Int): Int {
        val first = bytes[offset].toInt() and 0xFF
        return if (first and 0x80 != 0) {
            ((first and 0x7F) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        } else {
            first
        }
    }

    private fun skipLength8(bytes: ByteArray, offset: Int): Int =
        if (bytes[offset].toInt() and 0x80 != 0) 2 else 1

    private fun length8Size(bytes: ByteArray, offset: Int): Int =
        skipLength8(bytes, offset)

    private fun parseStartElement(
        bytes: ByteArray,
        bodyOffset: Int,
        strings: List<String>,
        out: MutableList<Element>,
    ) {
        if (bodyOffset + 36 > bytes.size) return
        val nameIdx = IoUtils.u32(bytes, bodyOffset + 20).toInt()
        val attributeStart = IoUtils.u16(bytes, bodyOffset + 24)
        val attributeCount = IoUtils.u16(bytes, bodyOffset + 28)
        val name = strings.getOrNull(nameIdx) ?: return

        val attributes = HashMap<String, String>(attributeCount)
        for (i in 0 until attributeCount) {
            val base = bodyOffset + attributeStart + i * 20
            if (base + 20 > bytes.size) break
            val attrNameIdx = IoUtils.u32(bytes, base + 4).toInt()
            val rawValueIdx = IoUtils.u32(bytes, base + 8).toInt()
            val attrName = strings.getOrNull(attrNameIdx) ?: continue

            if (rawValueIdx != 0xFFFFFFFF.toInt()) {
                attributes[attrName] = strings.getOrNull(rawValueIdx) ?: ""
                continue
            }
            // Typed value: size u16, res0 u8, dataType u8, data u32.
            val dataType = bytes[base + 15].toInt() and 0xFF
            val data = IoUtils.u32(bytes, base + 16).toInt()
            attributes[attrName] = when (dataType) {
                0x03 -> strings.getOrNull(data) ?: ""
                0x10, 0x12 -> data.toString()
                0x01 -> "@0x" + Integer.toHexString(data)
                else -> data.toString()
            }
        }
        out.add(Element(name, attributes))
    }
}

/**
 * Extracts the manifest level facts of an APK required by the analyzer UI.
 */
object ManifestReader {

    class ManifestInfo {
        var packageName: String? = null
        var versionName: String? = null
        var versionCode: Long? = null
        var minSdk: Int? = null
        var targetSdk: Int? = null
        val permissions = ArrayList<String>()
    }

    fun read(bytes: ByteArray): ManifestInfo {
        val info = ManifestInfo()
        val elements = BinaryXmlParser().parseStartElements(bytes)
        for (element in elements) {
            when (element.name) {
                "manifest" -> {
                    info.packageName = element.attributes["package"]
                    info.versionName = element.attributes["versionName"]
                    info.versionCode = element.attributes["versionCode"]?.toLongOrNull()
                }
                "uses-sdk" -> {
                    info.minSdk = element.attributes["minSdkVersion"]?.toIntOrNull()
                        ?: element.attributes["minSdkVersion"]?.let { versionShorthand(it) }
                    info.targetSdk = element.attributes["targetSdkVersion"]?.toIntOrNull()
                        ?: element.attributes["targetSdkVersion"]?.let { versionShorthand(it) }
                }
                "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m" -> {
                    element.attributes["name"]?.let { info.permissions.add(it) }
                }
            }
        }
        return info
    }

    /** Resolves codename shorthands such as "M" or "T". */
    private fun versionShorthand(text: String): Int? = when (text.uppercase()) {
        "M" -> 23
        "N" -> 24
        "O" -> 26
        "P" -> 28
        "Q" -> 29
        "R" -> 30
        "S", "SV2" -> 31
        "T" -> 33
        else -> null
    }
}

/**
 * High level analysis of an APK: manifest facts, dex inventory, native
 * libraries and archive statistics.
 */
object ApkAnalyzer {

    class Analysis(
        val info: ApkInfo,
        val dexEntryNames: List<String>,
    )

    fun analyze(path: String): Analysis {
        ZipFile(path).use { zip ->
            val entries = zip.entries()
            var dexCount = 0
            var classes = 0
            var methods = 0
            val dexNames = ArrayList<String>()
            val abis = HashSet<String>()

            while (entries.hasMoreElements()) {
                val entry: ZipEntry = entries.nextElement()
                val name = entry.name
                if (name.endsWith(".dex") && name.startsWith("classes")) {
                    dexNames.add(name)
                    dexCount++
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    val parts = name.split('/')
                    if (parts.size == 3) abis.add(parts[1])
                }
            }

            var manifest: ManifestReader.ManifestInfo? = null
            zip.getEntry("AndroidManifest.xml")?.let { entry ->
                try {
                    manifest = ManifestReader.read(zip.getInputStream(entry).readBytes())
                } catch (error: Exception) {
                    // Unreadable manifests degrade to null facts instead of
                    // aborting the whole analysis.
                    manifest = null
                }
            }

            // Method and class totals across dex files.
            for (dexName in dexNames) {
                val bytes = zip.getInputStream(zip.getEntry(dexName)).readBytes()
                if (bytes.size >= 0x70 && bytes[0] == 'd'.code.toByte()) {
                    val classDefs = IoUtils.u32(bytes, 96).toInt()
                    val methodIds = IoUtils.u32(bytes, 88).toInt()
                    classes += classDefs
                    methods += methodIds
                }
            }

            val info = ApkInfo(
                fileName = path.substringAfterLast('/'),
                fileSizeBytes = java.io.File(path).length(),
                packageName = manifest?.packageName,
                versionName = manifest?.versionName,
                versionCode = manifest?.versionCode,
                minSdk = manifest?.minSdk,
                targetSdk = manifest?.targetSdk,
                permissions = manifest?.permissions ?: emptyList(),
                nativeAbis = abis.toList(),
                dexFiles = dexNames,
                classCount = classes,
                methodCount = methods,
            )
            return Analysis(info, dexNames)
        }
    }

    /** Convenience for opening a stream over an APK entry. */
    fun readEntry(path: String, entryName: String): ByteArray? {
        ZipFile(path).use { zip ->
            val entry = zip.getEntry(entryName) ?: return null
            return zip.getInputStream(entry).readBytes()
        }
    }
}
