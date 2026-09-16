package com.soulbrou.ui.result

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.core.model.BuildOutcome
import com.soulbrou.signer.ApkSignerService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/** Rendered state of the result screen. */
data class ResultUiState(
    val outcome: BuildOutcome? = null,
    val verified: Boolean = false,
    val verificationDone: Boolean = false,
    val savedMessage: String? = null,
    val saveError: Boolean = false,
)

/**
 * Presents the comparison between original and protected APK, verifies the
 * signature of the output once more and offers saving or sharing it.
 */
class ResultViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    private val _state = MutableStateFlow(ResultUiState())
    val state: StateFlow<ResultUiState> = _state

    init {
        refresh()
    }

    fun refresh() {
        val outcome = container.session.outcome.value
        val bytes = outcome?.outputApkBytes
        if (outcome != null && bytes != null && outcome.success) {
            _state.value = _state.value.copy(outcome = outcome)
            viewModelScope.launch(Dispatchers.Default) {
                val verified = try {
                    ApkSignerService.verify(bytes)
                    true
                } catch (error: Exception) {
                    SoulLog.w("result", "Verificacion fallo: ${error.message}")
                    false
                }
                _state.value = _state.value.copy(
                    outcome = container.session.outcome.value,
                    verified = verified,
                    verificationDone = true,
                )
            }
        } else {
            _state.value = _state.value.copy(outcome = outcome)
        }
    }

    /** Writes the protected APK to the public Downloads directory. */
    fun saveOutput() {
        val outcome = container.session.outcome.value ?: return
        val bytes = outcome.outputApkBytes ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val context = getApplication<Application>()
                val collection = android.provider.MediaStore.Downloads.getContentUri("external_primary")
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, "soulbrou-protected-${System.currentTimeMillis()}.apk")
                    put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/vnd.android.package-archive")
                }
                val uri = context.contentResolver.insert(collection, values)
                if (uri == null) {
                    val fallback = File(
                        File(context.filesDir, "builds").apply { mkdirs() },
                        "soulbrou-protected.apk",
                    )
                    fallback.writeBytes(bytes)
                    _state.value = _state.value.copy(savedMessage = fallback.absolutePath)
                } else {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        output.write(bytes)
                    } ?: error("Stream unavailable")
                    _state.value = _state.value.copy(savedMessage = uri.toString())
                }
            } catch (error: Exception) {
                SoulLog.w("result", "Guardado fallo: ${error.message}")
                _state.value = _state.value.copy(saveError = true)
            }
        }
    }

    fun consumeSavedMessage() {
        _state.value = _state.value.copy(savedMessage = null, saveError = false)
    }
}
