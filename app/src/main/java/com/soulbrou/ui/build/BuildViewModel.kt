package com.soulbrou.ui.build

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.model.BuildOutcome
import com.soulbrou.data.Settings
import com.soulbrou.engine.BuildState
import com.soulbrou.engine.ProtectionPipeline
import com.soulbrou.signer.SigningRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.File

/** Validation problems reported before a build starts. */
enum class BuildValidation { NO_APK, NO_METHODS, NO_KEYSTORE }

/**
 * Drives the protection pipeline with the data gathered by the other
 * screens: the APK, the method selection, the protection configuration and
 * the signing keystore, all taken from the shared build session.
 */
class BuildViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    val session = container.session

    private val _pipelineState = MutableStateFlow(BuildState())
    val pipelineState: StateFlow<BuildState> = _pipelineState

    private val _validation = MutableStateFlow<BuildValidation?>(null)
    val validation: StateFlow<BuildValidation?> = _validation

    private val _startedAt = MutableStateFlow(0L)
    val startedAt: StateFlow<Long> = _startedAt

    private var buildJob: Job? = null
    private var mirrorJob: Job? = null

    /** Starts the protection build using the current session data. */
    fun start() {
        if (buildJob?.isActive == true) return
        val apk = session.apk.value
        if (apk == null) {
            _validation.value = BuildValidation.NO_APK
            return
        }
        if (session.selection.value.isEmpty()) {
            _validation.value = BuildValidation.NO_METHODS
            return
        }
        val keystore = session.keystore.value
        if (keystore == null) {
            _validation.value = BuildValidation.NO_KEYSTORE
            return
        }
        _validation.value = null
        _startedAt.value = System.currentTimeMillis()

        val spec = session.spec.value
        val selection = session.selection.value.toList()
        val signing = SigningRequest(
            keystoreBytes = keystore.bytes,
            keystorePassword = keystore.password,
            keyAlias = keystore.alias,
            keyPassword = keystore.keyPassword,
            keystoreType = keystore.keystoreType,
        )
        val outputDirectory = File(getApplication<Application>().filesDir, "builds")
        val context = getApplication<Application>()

        buildJob = viewModelScope.launch(Dispatchers.Main) {
            val settings: Settings = container.settings.settings.first()
            val runtime = container.runtimeLibraries.load()
            val pipeline = ProtectionPipeline(
                statistics = container.statistics,
                defaultDispatcher = Dispatchers.Default,
                outputDirectory = outputDirectory,
                keepSignedCopy = settings.keepSignedCopies,
            )
            mirrorJob?.cancel()
            mirrorJob = launch {
                pipeline.state.collect { _pipelineState.value = it }
            }
            try {
                val outcome = pipeline.run(
                    apkBytes = apk.bytes,
                    runtimeLibraries = runtime,
                    selection = selection,
                    protectionMask = spec.mask,
                    signing = signing,
                    obfuscationLevel = settings.obfuscationLevel,
                    onDone = { result ->
                        session.setOutcome(result, result.outputApkBytes)
                    },
                )
                session.setOutcome(outcome, outcome.outputApkBytes)
            } catch (error: kotlinx.coroutines.CancellationException) {
                session.setOutcome(
                    BuildOutcome(
                        success = false,
                        outputApkPath = null,
                        comparison = null,
                        errorMessage = "cancelado",
                    ),
                    outputBytes = null,
                )
            }
        }
    }

    /** Cancels the running build, keeping the collected log. */
    fun cancel() {
        buildJob?.cancel()
        buildJob = null
        mirrorJob?.cancel()
        mirrorJob = null
    }

    fun isRunning(): Boolean = buildJob?.isActive == true

    fun consumeValidation() {
        _validation.value = null
    }

    override fun onCleared() {
        cancel()
        super.onCleared()
    }
}
