package com.soulbrou

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.lifecycleScope
import com.soulbrou.ui.navigation.SoulbrouApp
import com.soulbrou.ui.theme.SoulbrouTheme
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * Main launcher activity. Hosts the Compose UI tree of the application and
 * applies the persisted theme and locale preferences.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val container = (application as SoulbrouApplication).container

        lifecycleScope.launch {
            container.settings.settings.collect { settings ->
                val current = androidx.appcompat.app.AppCompatDelegate.getApplicationLocales()
                if (current.toLanguageTags() != settings.language) {
                    androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(
                        androidx.core.os.LocaleListCompat.forLanguageTags(settings.language),
                    )
                }
            }
        }

        setContent {
            val settings by container.settings.settings.collectAsState(initial = null)
            SoulbrouTheme(themeMode = settings?.themeMode ?: "dark") {
                SoulbrouApp()
            }
        }
    }
}
