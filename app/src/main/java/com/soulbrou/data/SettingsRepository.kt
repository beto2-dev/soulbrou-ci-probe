package com.soulbrou.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** User configuration of the application. */
data class Settings(
    val themeMode: String = "dark",
    val language: String = "es",
    val obfuscationLevel: Int = 1,
    val toolchainPath: String = "",
    val keepSignedCopies: Boolean = true,
)

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "soulbrou_settings")

/**
 * Persists the application settings through DataStore preferences.
 */
class SettingsRepository(private val context: Context) {

    private object Keys {
        val THEME = stringPreferencesKey("theme_mode")
        val LANGUAGE = stringPreferencesKey("language")
        val OBFUSCATION = intPreferencesKey("obfuscation_level")
        val TOOLCHAIN = stringPreferencesKey("toolchain_path")
        val KEEP_SIGNED = booleanPreferencesKey("keep_signed_copies")
    }

    val settings: Flow<Settings> = context.dataStore.data.map { prefs ->
        Settings(
            themeMode = prefs[Keys.THEME] ?: "dark",
            language = prefs[Keys.LANGUAGE] ?: "es",
            obfuscationLevel = prefs[Keys.OBFUSCATION] ?: 1,
            toolchainPath = prefs[Keys.TOOLCHAIN] ?: "",
            keepSignedCopies = prefs[Keys.KEEP_SIGNED] ?: true,
        )
    }

    suspend fun update(transform: (Settings) -> Settings) {
        context.dataStore.edit { prefs ->
            val current = Settings(
                themeMode = prefs[Keys.THEME] ?: "dark",
                language = prefs[Keys.LANGUAGE] ?: "es",
                obfuscationLevel = prefs[Keys.OBFUSCATION] ?: 1,
                toolchainPath = prefs[Keys.TOOLCHAIN] ?: "",
                keepSignedCopies = prefs[Keys.KEEP_SIGNED] ?: true,
            )
            val updated = transform(current)
            prefs[Keys.THEME] = updated.themeMode
            prefs[Keys.LANGUAGE] = updated.language
            prefs[Keys.OBFUSCATION] = updated.obfuscationLevel
            prefs[Keys.TOOLCHAIN] = updated.toolchainPath
            prefs[Keys.KEEP_SIGNED] = updated.keepSignedCopies
        }
    }
}
