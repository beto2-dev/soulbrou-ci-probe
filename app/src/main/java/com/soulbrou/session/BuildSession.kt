package com.soulbrou.session

import com.soulbrou.core.model.ApkInfo
import com.soulbrou.core.model.BuildOutcome
import com.soulbrou.dex2c.MethodKey
import com.soulbrou.protection.ProtectionSpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Keystore selected for the current build along with its credentials. */
class KeystoreSelection(
    val displayName: String,
    val bytes: ByteArray,
    val password: CharArray,
    val alias: String,
    val keyPassword: CharArray,
    val keystoreType: String,
)

/** APK selected for the current build: cached file plus its analysis. */
class SelectedApk(
    val fileName: String,
    val cachedPath: String,
    val bytes: ByteArray,
    val info: ApkInfo,
)

/**
 * Holds the state shared across the workflow screens: the chosen APK, the
 * method selection, the protection configuration, the signing keystore and
 * the outcome of the last build. The session is cleared explicitly when a
 * new APK is chosen so stale data never leaks between builds.
 */
class BuildSession {

    private val _apk = MutableStateFlow<SelectedApk?>(null)
    val apk: StateFlow<SelectedApk?> = _apk

    private val _selection = MutableStateFlow<Set<MethodKey>>(emptySet())
    val selection: StateFlow<Set<MethodKey>> = _selection

    private val _spec = MutableStateFlow(ProtectionSpec())
    val spec: StateFlow<ProtectionSpec> = _spec

    private val _keystore = MutableStateFlow<KeystoreSelection?>(null)
    val keystore: StateFlow<KeystoreSelection?> = _keystore

    private val _outcome = MutableStateFlow<BuildOutcome?>(null)
    val outcome: StateFlow<BuildOutcome?> = _outcome

    private val _outputBytes = MutableStateFlow<ByteArray?>(null)
    val outputBytes: StateFlow<ByteArray?> = _outputBytes

    fun setApk(apk: SelectedApk) {
        _apk.value = apk
        resetDerived()
    }

    fun clearApk() {
        _apk.value = null
        resetDerived()
    }

    fun setSelection(keys: Set<MethodKey>) {
        _selection.value = keys
    }

    fun setSpec(spec: ProtectionSpec) {
        _spec.value = spec
    }

    fun setKeystore(selection: KeystoreSelection?) {
        _keystore.value = selection
    }

    fun setOutcome(outcome: BuildOutcome?, outputBytes: ByteArray?) {
        _outcome.value = outcome
        _outputBytes.value = outputBytes
    }

    private fun resetDerived() {
        _selection.value = emptySet()
        _keystore.value = null
        _outcome.value = null
        _outputBytes.value = null
    }
}
