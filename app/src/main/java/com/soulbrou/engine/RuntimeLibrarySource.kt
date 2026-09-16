package com.soulbrou.engine

import android.content.Context
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Reads the runtime libraries bundled inside the Soulbrou APK so the
 * pipeline can inject them into the protected targets. All ABIs shipped
 * with Soulbrou are available regardless of the CPU of the device running
 * the protection.
 */
class RuntimeLibrarySource(context: Context) {

    private val apkPath: String = context.applicationInfo.sourceDir

    /** Returns an ABI to library bytes map of the injectable runtime. */
    fun load(): Map<String, ByteArray> {
        val result = LinkedHashMap<String, ByteArray>()
        ZipFile(apkPath).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry: ZipEntry = entries.nextElement()
                val name = entry.name
                if (!name.startsWith("lib/") || !name.endsWith("libsoulbrou-runtime.so")) {
                    continue
                }
                val parts = name.split('/')
                if (parts.size != 3) continue
                val abi = parts[1]
                val output = ByteArrayOutputStream(entry.size.toInt().coerceAtLeast(1024))
                zip.getInputStream(entry).use { input ->
                    input.copyTo(output)
                }
                result[abi] = output.toByteArray()
            }
        }
        return result
    }
}
