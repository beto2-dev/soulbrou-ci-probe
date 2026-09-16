package com.soulbrou.ui.settings

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.soulbrou.SoulbrouApplication
import com.soulbrou.data.Settings
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Reads and updates the persisted settings: theme, language, obfuscation
 * level, external toolchain path and signed copy retention.
 */
class SettingsViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    val settings: StateFlow<Settings?> = container.settings.settings
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(3000), null)

    fun updateTheme(mode: String) {
        viewModelScope.launch {
            container.settings.update { it.copy(themeMode = mode) }
        }
    }

    fun updateLanguage(language: String) {
        viewModelScope.launch {
            container.settings.update { it.copy(language = language) }
        }
        val locales = androidx.core.os.LocaleListCompat.forLanguageTags(language)
        androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(locales)
    }

    fun updateObfuscation(level: Int) {
        viewModelScope.launch {
            container.settings.update { it.copy(obfuscationLevel = level.coerceIn(0, 3)) }
        }
    }

    fun updateToolchain(path: String) {
        viewModelScope.launch {
            container.settings.update { it.copy(toolchainPath = path) }
        }
    }

    fun updateKeepSigned(keep: Boolean) {
        viewModelScope.launch {
            container.settings.update { it.copy(keepSignedCopies = keep) }
        }
    }
}
