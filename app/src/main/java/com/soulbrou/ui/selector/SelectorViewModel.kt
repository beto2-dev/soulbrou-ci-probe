package com.soulbrou.ui.selector

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.dex2c.apk.ApkAnalyzer
import com.soulbrou.session.SelectedApk
import com.soulbrou.ui.components.formatBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/** States of the APK intake flow. */
enum class SelectorPhase { IDLE, READING, ANALYZING, READY, ERROR }

/** Rendered state of the selector screen. */
data class SelectorUiState(
    val phase: SelectorPhase = SelectorPhase.IDLE,
    val errorMessage: String? = null,
    val fileName: String? = null,
)

/**
 * Reads the APK chosen through the system document picker, caches a copy in
 * application storage, runs the automatic analysis and publishes the result
 * to the shared build session.
 */
class SelectorViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container
    private val cacheDir: File = app.cacheDir

    private val _state = MutableStateFlow(SelectorUiState())
    val state: StateFlow<SelectorUiState> = _state

    fun onApkPicked(uri: Uri) {
        if (_state.value.phase == SelectorPhase.READING || _state.value.phase == SelectorPhase.ANALYZING) return
        _state.value = SelectorUiState(phase = SelectorPhase.READING)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resolver = getApplication<Application>().contentResolver
                val fileName = queryDisplayName(getApplication(), uri) ?: "input.apk"
                val cached = File(cacheDir, "session_input.apk")
                resolver.openInputStream(uri)?.use { input ->
                    cached.outputStream().use { output -> input.copyTo(output) }
                } ?: error("Empty stream")

                if (!isZipHeader(cached)) {
                    _state.value = SelectorUiState(
                        phase = SelectorPhase.ERROR,
                        errorMessage = "invalid",
                    )
                    return@launch
                }

                _state.value = SelectorUiState(phase = SelectorPhase.ANALYZING, fileName = fileName)
                val analysis = ApkAnalyzer.analyze(cached.absolutePath)
                val info = analysis.info.copy(fileName = fileName)
                container.session.setApk(
                    SelectedApk(
                        fileName = fileName,
                        cachedPath = cached.absolutePath,
                        bytes = cached.readBytes(),
                        info = info,
                    ),
                )
                _state.value = SelectorUiState(phase = SelectorPhase.READY, fileName = fileName)
                SoulLog.i("selector", "APK listo: $fileName, ${info.methodCount} metodos")
            } catch (error: Exception) {
                SoulLog.w("selector", "No se pudo procesar el APK: ${error.message}")
                _state.value = SelectorUiState(
                    phase = SelectorPhase.ERROR,
                    errorMessage = error.message ?: "unknown",
                )
            }
        }
    }

    fun clearSession() {
        container.session.clearApk()
        _state.value = SelectorUiState()
    }

    private fun isZipHeader(file: File): Boolean {
        val header = ByteArray(4)
        file.inputStream().use { it.read(header) }
        return header[0] == 'P'.code.toByte() && header[1] == 'K'.code.toByte()
    }

    private fun queryDisplayName(context: Context, uri: Uri): String? = try {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
    } catch (error: Exception) {
        null
    }
}

/** Formats the permissions preview of the analyzed APK. */
fun permissionsPreview(permissions: List<String>): String =
    permissions.joinToString(separator = ", ") { it.substringAfterLast('.') }

/** Size caption of an APK in bytes units. */
fun sizeCaption(bytes: Long): String = formatBytes(bytes)
