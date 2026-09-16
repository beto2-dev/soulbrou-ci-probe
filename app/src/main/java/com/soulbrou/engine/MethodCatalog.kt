package com.soulbrou.engine

import com.soulbrou.dex2c.MethodKey
import com.soulbrou.dex2c.code.SmaliPrinter
import com.soulbrou.dex2c.model.DexEncodedMethod
import com.soulbrou.dex2c.parser.DexParser
import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream

/**
 * Browsable inventory of the convertible methods of an APK, grouped by
 * package and class. The catalog also produces the smali preview and the
 * translatability verdict shown by the method selection screen.
 */
class MethodCatalog private constructor(
    private val dexBodies: Map<String, ByteArray>,
    private val packages: List<PackageEntry>,
) {

    /** A method entry of the tree. */
    class MethodEntry(
        val key: MethodKey,
        val displayName: String,
        val dexName: String,
        val convertible: Boolean,
    )

    /** A class entry of the tree. */
    class ClassEntry(
        val descriptor: String,
        val displayName: String,
        val methods: List<MethodEntry>,
    ) {
        val convertibleCount: Int get() = methods.count { it.convertible }
    }

    /** A package entry of the tree. */
    class PackageEntry(
        val name: String,
        val classes: List<ClassEntry>,
    )

    fun packages(): List<PackageEntry> = packages

    /** Number of convertible methods found in the APK. */
    fun convertibleMethodCount(): Int =
        packages.sumOf { pkg -> pkg.classes.sumOf { it.convertibleCount } }

    /** Renders the smali of the selected method, or null when unavailable. */
    fun smaliOf(key: MethodKey): String? {
        val body = dexBodies[key.dexName] ?: return null
        val document = DexParser(body).parse()
        val target = document.classes.firstOrNull { it.type.descriptor.value == key.classDescriptor }
            ?: return null
        val methods = target.classData?.let { it.directMethods + it.virtualMethods } ?: return null
        val method: DexEncodedMethod = methods.firstOrNull {
            it.method.name.value == key.methodName &&
                (it.method.proto.parameterDescriptors +
                    it.method.proto.returnType.descriptor.value) == key.proto &&
                it.code != null
        } ?: return null
        return SmaliPrinter(method.code!!).print()
    }

    companion object {

        /** Builds the catalog of every dex of the APK. */
        fun fromApk(apkBytes: ByteArray): MethodCatalog {
            val bodies = LinkedHashMap<String, ByteArray>()
            ZipInputStream(ByteArrayInputStream(apkBytes)).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (name.startsWith("classes") && name.endsWith(".dex")) {
                        bodies[name] = zip.readBytes()
                    }
                    entry = zip.nextEntry
                }
            }

            val grouped = LinkedHashMap<String, MutableList<ClassEntry>>()
            for ((dexName, body) in bodies) {
                val document = DexParser(body).parse()
                for (classDef in document.classes) {
                    val descriptor = classDef.type.descriptor.value
                    val classData = classDef.classData ?: continue
                    val methodEntries = (classData.directMethods + classData.virtualMethods)
                        .map { method ->
                            val key = MethodKey(
                                dexName = dexName,
                                classDescriptor = descriptor,
                                methodName = method.method.name.value,
                                proto = method.method.proto.parameterDescriptors +
                                    method.method.proto.returnType.descriptor.value,
                            )
                            MethodEntry(
                                key = key,
                                displayName = method.method.name.value +
                                    "(" + method.method.proto.parameterDescriptors + ")" +
                                    method.method.proto.returnType.descriptor.value,
                                dexName = dexName,
                                convertible = method.code != null &&
                                    document.isCodeSupported(method.code),
                            )
                        }
                    if (methodEntries.isEmpty()) continue
                    val packageName = descriptor
                        .removePrefix("L")
                        .removeSuffix(";")
                        .let { full -> full.substringBeforeLast('/', "") }
                        .replace('/', '.')
                    val label = if (packageName.isEmpty()) "<default>" else packageName
                    val classEntry = ClassEntry(
                        descriptor = descriptor,
                        displayName = descriptor
                            .removePrefix("L")
                            .removeSuffix(";")
                            .substringAfterLast('/'),
                        methods = methodEntries,
                    )
                    grouped.getOrPut(label) { ArrayList() }.add(classEntry)
                }
            }

            val packages = grouped.entries
                .map { (name, classes) ->
                    PackageEntry(
                        name = name,
                        classes = classes.sortedBy { it.displayName },
                    )
                }
                .sortedBy { it.name }
            return MethodCatalog(bodies, packages)
        }
    }
}
