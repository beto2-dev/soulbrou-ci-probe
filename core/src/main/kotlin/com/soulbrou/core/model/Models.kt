package com.soulbrou.core.model

import kotlinx.serialization.Serializable

/**
 * High level description of an APK under analysis.
 */
@Serializable
data class ApkInfo(
    val fileName: String,
    val fileSizeBytes: Long,
    val packageName: String? = null,
    val versionName: String? = null,
    val versionCode: Long? = null,
    val minSdk: Int? = null,
    val targetSdk: Int? = null,
    val permissions: List<String> = emptyList(),
    val nativeAbis: List<String> = emptyList(),
    val dexFiles: List<String> = emptyList(),
    val classCount: Int = 0,
    val methodCount: Int = 0,
)

/**
 * Stages of the protection pipeline, in execution order.
 */
enum class BuildStage {
    ANALYZE,
    PARSE_DEX,
    PLAN_SELECTION,
    GENERATE_NATIVE,
    COMPILE_NATIVE,
    INJECT_PROTECTIONS,
    PACKAGE,
    ALIGN_SIGN,
    VERIFY,
}

/**
 * Severity of a line shown in the build log viewer.
 */
enum class LogLineLevel { DEBUG, INFO, WARN, ERROR }

/**
 * One rendered line of the live build log.
 */
data class LogLine(
    val timestamp: Long,
    val level: LogLineLevel,
    val message: String,
)

/**
 * State of a single pipeline stage for the progress stepper UI.
 */
enum class StageState { PENDING, RUNNING, COMPLETED, FAILED, SKIPPED }

/**
 * Comparison snapshot taken before and after a protection build.
 */
@Serializable
data class BuildComparison(
    val inputSizeBytes: Long,
    val outputSizeBytes: Long,
    val inputDexMethodCount: Int,
    val outputDexMethodCount: Int,
    val nativeMethodCount: Int,
    val appliedProtections: List<String>,
)

/**
 * Persistent record of a finished build, used by the dashboard statistics.
 */
@Serializable
data class BuildRecord(
    val id: Long,
    val startedAtEpochMs: Long,
    val durationMs: Long,
    val apkName: String,
    val success: Boolean,
    val nativeMethodCount: Int = 0,
    val protectionNames: List<String> = emptyList(),
    val inputSizeBytes: Long = 0,
    val outputSizeBytes: Long = 0,
    val mode: String = "runtime",
)

/**
 * Summary of a keystore managed by the tool.
 */
@Serializable
data class KeystoreSummary(
    val id: Long,
    val displayName: String,
    val type: String,
    val aliases: List<String>,
    val certificateSubject: String,
    val createdAtEpochMs: Long = 0,
)

/**
 * Outcome of a full protection build. The signed APK bytes are carried
 * transiently for the result screen and are never serialized.
 */
data class BuildOutcome(
    val success: Boolean,
    val outputApkPath: String?,
    val comparison: BuildComparison?,
    val errorMessage: String? = null,
    val outputApkBytes: ByteArray? = null,
)
