package com.soulbrou.ui.methods

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.dex2c.MethodKey
import com.soulbrou.engine.MethodCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Rendered state of the method selection screen. */
data class MethodsUiState(
    val loading: Boolean = false,
    val catalog: MethodCatalog? = null,
    val selection: Set<MethodKey> = emptySet(),
    val filter: String = "",
    val previewKey: MethodKey? = null,
    val previewSmali: String? = null,
    val previewLoading: Boolean = false,
    val errorMessage: String? = null,
)

/**
 * Builds the method catalog of the selected APK and manages the multi
 * selection plus the smali preview of the chosen method.
 */
class MethodsViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    private val _state = MutableStateFlow(MethodsUiState())
    val state: StateFlow<MethodsUiState> = _state

    init {
        val apk = container.session.apk.value
        if (apk != null) {
            _state.value = _state.value.copy(loading = true)
            viewModelScope.launch(Dispatchers.Default) {
                try {
                    val catalog = MethodCatalog.fromApk(apk.bytes)
                    _state.value = _state.value.copy(
                        loading = false,
                        catalog = catalog,
                        selection = container.session.selection.value,
                    )
                } catch (error: Exception) {
                    SoulLog.w("methods", "Fallo el catalogo: ${error.message}")
                    _state.value = _state.value.copy(loading = false, errorMessage = error.message)
                }
            }
        }
    }

    fun setFilter(text: String) {
        _state.value = _state.value.copy(filter = text)
    }

    fun toggleMethod(key: MethodKey) {
        val current = _state.value.selection
        val updated = if (key in current) current - key else current + key
        _state.value = _state.value.copy(selection = updated)
        container.session.setSelection(updated)
    }

    fun toggleClass(keys: List<MethodKey>) {
        val current = _state.value.selection
        val allSelected = keys.all { it in current }
        val updated = if (allSelected) current - keys.toSet() else current + keys
        _state.value = _state.value.copy(selection = updated)
        container.session.setSelection(updated)
    }

    fun selectPackage(keys: List<MethodKey>) {
        val updated = _state.value.selection + keys
        _state.value = _state.value.copy(selection = updated)
        container.session.setSelection(updated)
    }

    fun requestPreview(key: MethodKey) {
        if (_state.value.previewKey == key) {
            _state.value = _state.value.copy(previewKey = null, previewSmali = null)
            return
        }
        _state.value = _state.value.copy(previewKey = key, previewSmali = null, previewLoading = true)
        viewModelScope.launch(Dispatchers.Default) {
            val smali = try {
                _state.value.catalog?.smaliOf(key)
            } catch (error: Exception) {
                SoulLog.w("methods", "Vista previa fallo: ${error.message}")
                null
            }
            if (_state.value.previewKey == key) {
                _state.value = _state.value.copy(previewSmali = smali, previewLoading = false)
            }
        }
    }
}
