package com.soulbrou.engine

import com.soulbrou.core.logging.LogEntry
import com.soulbrou.core.logging.LogLevel
import com.soulbrou.core.logging.LogPlant
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.core.model.BuildComparison
import com.soulbrou.core.model.BuildStage
import com.soulbrou.core.model.BuildOutcome
import com.soulbrou.core.model.BuildRecord
import com.soulbrou.core.model.LogLine
import com.soulbrou.core.model.LogLineLevel
import com.soulbrou.core.model.StageState
import com.soulbrou.data.StatisticsRepository
import com.soulbrou.dex2c.MethodKey
import com.soulbrou.dex2c.SoulbrouEngine
import com.soulbrou.signer.ApkSignerService
import com.soulbrou.signer.SigningRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/** Progress of one pipeline stage. */
data class StageProgress(
    val stage: BuildStage,
    val state: StageState = StageState.PENDING,
)

/** Live state of the protection build. */
data class BuildState(
    val running: Boolean = false,
    val stages: Map<BuildStage, StageState> = BuildStage.entries.associateWith { StageState.PENDING },
    val currentStage: BuildStage? = null,
    val logs: List<LogLine> = emptyList(),
    val outcome: BuildOutcome? = null,
)

/**
 * Orchestrates the full protection pipeline: analysis, method conversion,
 * native injection, packaging and signing. Every stage reports progress and
 * log lines through [state] so the build screen can render them live.
 */
class ProtectionPipeline(
    private val statistics: StatisticsRepository,
    private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val outputDirectory: File,
    private val keepSignedCopy: Boolean = true,
) {

    private val _state = MutableStateFlow(BuildState())
    val state: StateFlow<BuildState> = _state

    private val unusedJob: Job? = null
    private val recordId = AtomicLong(System.currentTimeMillis())
    private val pipelineActive = java.util.concurrent.atomic.AtomicBoolean(false)

    private val logPlant = LogPlant { entry: LogEntry ->
        val line = LogLine(
            timestamp = entry.timestamp,
            level = when (entry.level) {
                LogLevel.VERBOSE, LogLevel.DEBUG -> LogLineLevel.DEBUG
                LogLevel.INFO -> LogLineLevel.INFO
                LogLevel.WARN -> LogLineLevel.WARN
                LogLevel.ERROR -> LogLineLevel.ERROR
            },
            message = "[${entry.tag}] ${entry.message}",
        )
        _state.value = _state.value.copy(logs = (_state.value.logs + line).takeLast(600))
    }

    /**
     * Runs the pipeline. [runtimeLibraries] maps ABI to the runtime .so bytes,
     * [selection] lists the methods to convert and [signing] the keystore
     * request. Returns the final outcome.
     */
    suspend fun run(
        apkBytes: ByteArray,
        runtimeLibraries: Map<String, ByteArray>,
        selection: List<MethodKey>,
        protectionMask: Int,
        signing: SigningRequest,
        obfuscationLevel: Int,
        onDone: (BuildOutcome) -> Unit,
    ): BuildOutcome {
        check(!pipelineActive.getAndSet(true)) { "Pipeline already running" }
        SoulLog.plant(logPlant)
        _state.value = BuildState(running = true)
        val startedAt = System.currentTimeMillis()

        var outcome: BuildOutcome? = null
        try {
            markStage(BuildStage.ANALYZE)
            log("Analizando APK de entrada (${apkBytes.size / 1024} KB)")
            val fingerprint = withContext(defaultDispatcher) {
                ApkSignerService.certificateFingerprint(signing)
            }
            completeStage(BuildStage.ANALYZE)

            markStage(BuildStage.PARSE_DEX)
            log("Preparando documentos dex y seleccion de ${selection.size} metodos")
            val engine = SoulbrouEngineFactory.create(runtimeLibraries, obfuscationLevel)
            completeStage(BuildStage.PARSE_DEX)

            markStage(BuildStage.PLAN_SELECTION)
            markStage(BuildStage.GENERATE_NATIVE)

            val result = withContext(defaultDispatcher) {
                engine.protect(apkBytes, selection, protectionMask, fingerprint)
            }
            completeStage(BuildStage.PLAN_SELECTION)
            completeStage(BuildStage.GENERATE_NATIVE)

            markStage(BuildStage.COMPILE_NATIVE)
            log("Codigo nativo generado para ${result.convertedMethods.size} metodos")
            if (result.skippedMethods.isNotEmpty()) {
                log("Metodos omitidos (bytecode no soportado): ${result.skippedMethods.size}", LogLineLevel.WARN)
            }
            completeStage(BuildStage.COMPILE_NATIVE)

            markStage(BuildStage.INJECT_PROTECTIONS)
            log("Inyectando runtime y protecciones (mask=$protectionMask)")
            completeStage(BuildStage.INJECT_PROTECTIONS)

            markStage(BuildStage.PACKAGE)
            completeStage(BuildStage.PACKAGE)

            markStage(BuildStage.ALIGN_SIGN)
            val signed = withContext(defaultDispatcher) {
                ApkSignerService.sign(result.apkBytes, signing)
            }
            log("APK firmado con ${signed.certificateSubject}")
            completeStage(BuildStage.ALIGN_SIGN)

            markStage(BuildStage.VERIFY)
            withContext(defaultDispatcher) {
                ApkSignerService.verify(signed.apkBytes)
            }
            log("Firma verificada correctamente")
            completeStage(BuildStage.VERIFY)

            val comparison = BuildComparison(
                inputSizeBytes = apkBytes.size.toLong(),
                outputSizeBytes = signed.apkBytes.size.toLong(),
                inputDexMethodCount = result.dexMethodCountBefore,
                outputDexMethodCount = result.dexMethodCountAfter,
                nativeMethodCount = result.convertedMethods.size,
                appliedProtections = protectionMaskNames(protectionMask),
            )
            val savedPath = if (keepSignedCopy) {
                saveSignedCopy(signed.apkBytes, apkBytes.size)
            } else {
                null
            }
            outcome = BuildOutcome(
                success = true,
                outputApkPath = savedPath,
                comparison = comparison,
                outputApkBytes = signed.apkBytes,
            )
            log("Proceso completado")

            statistics.append(
                BuildRecord(
                    id = recordId.incrementAndGet(),
                    startedAtEpochMs = startedAt,
                    durationMs = System.currentTimeMillis() - startedAt,
                    apkName = "target.apk",
                    success = true,
                    nativeMethodCount = result.convertedMethods.size,
                    protectionNames = protectionMaskNames(protectionMask),
                    inputSizeBytes = apkBytes.size.toLong(),
                    outputSizeBytes = signed.apkBytes.size.toLong(),
                ),
            )
        } catch (error: CancellationException) {
            log("Proceso cancelado", LogLineLevel.WARN)
            outcome = BuildOutcome(success = false, outputApkPath = null, comparison = null, errorMessage = "cancelado")
            pipelineActive.set(false)
            throw error
        } catch (error: Exception) {
            log("Error: ${error.message}", LogLineLevel.ERROR)
            _state.value.stages.forEach { (stage, stageState) ->
                if (stageState == StageState.RUNNING) {
                    markStageFailed(stage)
                }
            }
            outcome = BuildOutcome(success = false, outputApkPath = null, comparison = null, errorMessage = error.message)
        } finally {
            SoulLog.uproot(logPlant)
            pipelineActive.set(false)
            _state.value = _state.value.copy(running = false, outcome = outcome)
            onDone(outcome ?: BuildOutcome(false, null, null, "sin resultado"))
        }
        return outcome
    }

    private fun saveSignedCopy(bytes: ByteArray, sourceSize: Int): String? = try {
        val directory = File(outputDirectory, "signed")
        directory.mkdirs()
        val target = File(directory, "soulbrou-out-${System.currentTimeMillis()}.apk")
        target.writeBytes(bytes)
        target.absolutePath
    } catch (error: Exception) {
        SoulLog.w("pipeline", "No se pudo guardar la copia firmada: ${error.message}")
        null
    }

    private fun markStage(stage: BuildStage) {
        val stages = _state.value.stages.toMutableMap()
        stages[stage] = StageState.RUNNING
        _state.value = _state.value.copy(stages = stages, currentStage = stage)
    }

    private fun markStageFailed(stage: BuildStage) {
        val stages = _state.value.stages.toMutableMap()
        stages[stage] = StageState.FAILED
        _state.value = _state.value.copy(stages = stages)
    }

    private fun completeStage(stage: BuildStage) {
        val stages = _state.value.stages.toMutableMap()
        stages[stage] = StageState.COMPLETED
        _state.value = _state.value.copy(stages = stages)
    }

    private fun log(message: String, level: LogLineLevel = LogLineLevel.INFO) {
        _state.value = _state.value.copy(
            logs = (_state.value.logs + LogLine(System.currentTimeMillis(), level, message)).takeLast(600),
        )
    }

    private fun protectionMaskNames(mask: Int): List<String> =
        com.soulbrou.protection.ProtectionType.fromMask(mask).map { it.key }

    companion object {
        fun logFileName(): String = "soulbrou-${SecureRandom().nextInt(0xFFFF)}.log"
    }
}

/** Factory used by the pipeline to build the engine on demand. */
private object SoulbrouEngineFactory {
    fun create(runtimeLibraries: Map<String, ByteArray>, obfuscationLevel: Int): SoulbrouEngine =
        SoulbrouEngine(runtimeLibraries, obfuscationLevel)
}
