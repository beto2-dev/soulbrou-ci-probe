package com.soulbrou.ui.home

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.core.model.BuildRecord
import com.soulbrou.engine.NativeEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** Rendered state of the dashboard screen. */
data class HomeUiState(
    val totalBuilds: Int = 0,
    val successRate: Int = 0,
    val nativeMethods: Int = 0,
    val lastBuild: BuildRecord? = null,
    val runtimeVersion: String = "",
    val selfTest: Int = 0,
    val apkFileName: String? = null,
)

/**
 * Powers the dashboard: aggregates the build history, reports the version
 * of the bundled native runtime and runs its integrity self test once.
 */
class HomeViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    private val selfTest = MutableStateFlow(0)
    private val runtimeVersion = MutableStateFlow("")

    val state: StateFlow<HomeUiState> = combine(
        container.statistics.history,
        container.session.apk,
        selfTest,
        runtimeVersion,
    ) { history, apk, test, version ->
        HomeUiState(
            totalBuilds = history.size,
            successRate = if (history.isEmpty()) 0 else (history.count { it.success } * 100 / history.size),
            nativeMethods = history.sumOf { it.nativeMethodCount },
            lastBuild = history.maxByOrNull { it.startedAtEpochMs },
            runtimeVersion = version,
            selfTest = test,
            apkFileName = apk?.fileName,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(3000), HomeUiState())

    init {
        viewModelScope.launch(Dispatchers.IO) {
            runtimeVersion.value = try {
                NativeEngine.nativeVersion()
            } catch (error: UnsatisfiedLinkError) {
                "n/a"
            }
            selfTest.value = try {
                if (NativeEngine.nativeSelfTest()) 1 else 2
            } catch (error: UnsatisfiedLinkError) {
                2
            }
        }
    }
}
