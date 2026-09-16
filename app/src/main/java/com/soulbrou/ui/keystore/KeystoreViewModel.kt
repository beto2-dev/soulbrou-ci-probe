package com.soulbrou.ui.keystore

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.signer.KeystoreManager
import com.soulbrou.session.KeystoreSelection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.io.File

/** One stored keystore entry in the list. */
data class StoredKeystore(
    val file: File,
    val selected: Boolean,
    val inUseAlias: String?,
    val inUseType: String?,
)

/** States of the keystore intake flow. */
enum class KeystorePhase { IDLE, IMPORTING, GENERATING, ERROR }

/** Rendered state of the keystore screen. */
data class KeystoreUiState(
    val stores: List<StoredKeystore> = emptyList(),
    val phase: KeystorePhase = KeystorePhase.IDLE,
    val errorMessage: String? = null,
    val generatedPassword: String? = null,
)

/**
 * Lists, imports and generates signing keystores. Validated credentials are
 * kept in the build session so the build screen can sign without asking
 * again. Passwords of imported stores are kept only in memory.
 */
class KeystoreViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    private val _state = MutableStateFlow(KeystoreUiState())
    val state: StateFlow<KeystoreUiState> = _state

    init {
        refresh()
    }

    fun refresh() {
        val selection = container.session.keystore.value
        val stores = container.keystores.list().map { file ->
            val selected = selection != null && selection.displayName == displayNameOf(file)
            StoredKeystore(
                file = file,
                selected = selected,
                inUseAlias = if (selected) selection?.alias else null,
                inUseType = if (selected) selection?.keystoreType else null,
            )
        }
        _state.value = KeystoreUiState(
            stores = stores,
            generatedPassword = _state.value.generatedPassword.takeIf { it != null },
        )
    }

    fun importStore(uri: Uri, displayName: String, password: CharArray, alias: String) {
        if (password.isEmpty()) {
            _state.value = _state.value.copy(phase = KeystorePhase.ERROR, errorMessage = "mismatch")
            return
        }
        _state.value = _state.value.copy(phase = KeystorePhase.IMPORTING, errorMessage = null)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bytes = readUri(uri)
                val type = detectType(bytes)
                val loaded = KeystoreManager.detectAndLoad(bytes, password)
                val effectiveAlias = if (alias.isBlank()) loaded.aliases().nextElement() else alias
                val name = if (displayName.isBlank()) "imported" else displayName
                container.keystores.save(name, bytes)
                container.session.setKeystore(
                    KeystoreSelection(
                        displayName = name,
                        bytes = bytes,
                        password = password,
                        alias = effectiveAlias,
                        keyPassword = password,
                        keystoreType = type,
                    ),
                )
                SoulLog.i("keystore", "Almac importado: $name")
                refresh()
            } catch (error: Exception) {
                SoulLog.w("keystore", "Import fallo: ${error.message}")
                _state.value = _state.value.copy(
                    phase = KeystorePhase.ERROR,
                    errorMessage = "invalid",
                )
            }
        }
    }

    fun generateStore(displayName: String, alias: String, commonName: String, password: CharArray) {
        if (displayName.isBlank() || alias.isBlank() || password.isEmpty()) {
            _state.value = _state.value.copy(phase = KeystorePhase.ERROR, errorMessage = "mismatch")
            return
        }
        _state.value = _state.value.copy(phase = KeystorePhase.GENERATING, errorMessage = null)
        viewModelScope.launch(Dispatchers.Default) {
            try {
                val bytes = KeystoreManager.generate(
                    alias = alias,
                    storePassword = password,
                    keyPassword = password,
                    commonName = commonName.ifBlank { alias },
                )
                container.keystores.save(displayName, bytes)
                container.session.setKeystore(
                    KeystoreSelection(
                        displayName = displayName,
                        bytes = bytes,
                        password = password,
                        alias = alias,
                        keyPassword = password,
                        keystoreType = "PKCS12",
                    ),
                )
                SoulLog.i("keystore", "Almac generado: $displayName")
                _state.value = KeystoreUiState(generatedPassword = String(password))
                refresh()
            } catch (error: Exception) {
                SoulLog.w("keystore", "Generacion fallo: ${error.message}")
                _state.value = _state.value.copy(
                    phase = KeystorePhase.ERROR,
                    errorMessage = error.message ?: "unknown",
                )
            }
        }
    }

    fun useStore(store: StoredKeystore, password: CharArray) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bytes = container.keystores.read(store.file)
                val type = detectType(bytes)
                val loaded = KeystoreManager.detectAndLoad(bytes, password)
                val alias = loaded.aliases().nextElement()
                container.session.setKeystore(
                    KeystoreSelection(
                        displayName = displayNameOf(store.file),
                        bytes = bytes,
                        password = password,
                        alias = alias,
                        keyPassword = password,
                        keystoreType = type,
                    ),
                )
                refresh()
            } catch (error: Exception) {
                SoulLog.w("keystore", "Credenciales rechazadas: ${error.message}")
                _state.value = _state.value.copy(
                    phase = KeystorePhase.ERROR,
                    errorMessage = "invalid",
                )
            }
        }
    }

    fun clearSelection() {
        container.session.setKeystore(null)
        refresh()
    }

    fun deleteStore(store: StoredKeystore) {
        if (store.selected) clearSelection()
        container.keystores.delete(store.file)
        refresh()
    }

    fun randomPassword(): String = KeystoreRepositoryPasswords.next()

    fun consumeError() {
        _state.value = _state.value.copy(phase = KeystorePhase.IDLE, errorMessage = null)
    }

    fun consumeGeneratedPassword() {
        _state.value = _state.value.copy(generatedPassword = null)
    }

    private fun displayNameOf(file: File): String =
        file.name.removeSuffix(".p12").replace(Regex("_\\d+$"), "")

    private fun readUri(uri: Uri): ByteArray =
        getApplication<Application>().contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: error("Empty stream")

    private fun detectType(bytes: ByteArray): String = try {
        val magic = bytes.copyOfRange(0, 4.coerceAtMost(bytes.size))
        if (magic.size >= 2 && magic[0] == 0xFE.toByte() && magic[1] == 0xED.toByte()) "JKS" else "PKCS12"
    } catch (error: Exception) {
        "PKCS12"
    }
}

/** Delegates password generation to the repository helper. */
private object KeystoreRepositoryPasswords {
    fun next(): String = com.soulbrou.data.KeystoreRepository.randomPassword()
}
