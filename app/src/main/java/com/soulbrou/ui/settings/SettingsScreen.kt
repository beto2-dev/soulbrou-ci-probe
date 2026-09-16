package com.soulbrou.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.soulbrou.R
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel

/**
 * Settings screen: theme mode, language, obfuscation level, external NDK
 * path and retention of signed copies.
 */
@Composable
fun SettingsScreen() {
    val viewModel: SettingsViewModel = viewModel()
    val settings by viewModel.settings.collectAsState()

    LaunchedEffect(settings?.language) {
        val lang = settings?.language ?: return@LaunchedEffect
        val current = androidx.appcompat.app.AppCompatDelegate.getApplicationLocales()
        if (current.toLanguageTags() != lang) {
            androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(
                androidx.core.os.LocaleListCompat.forLanguageTags(lang),
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(title = stringResource(R.string.settings_title))
        Spacer(modifier = Modifier.height(16.dp))

        SectionLabel(text = stringResource(R.string.settings_section_general))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = stringResource(R.string.settings_theme),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.height(8.dp))
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    val modes = listOf(
                        "dark" to R.string.settings_theme_dark,
                        "light" to R.string.settings_theme_light,
                        "system" to R.string.settings_theme_system,
                    )
                    modes.forEachIndexed { index, (mode, label) ->
                        SegmentedButton(
                            selected = (settings?.themeMode ?: "dark") == mode,
                            onClick = { viewModel.updateTheme(mode) },
                            shape = SegmentedButtonDefaults.itemShape(index, modes.size),
                        ) {
                            Text(stringResource(label))
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.settings_language),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.height(8.dp))
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    val languages = listOf(
                        "es" to R.string.settings_language_es,
                        "en" to R.string.settings_language_en,
                    )
                    languages.forEachIndexed { index, (tag, label) ->
                        SegmentedButton(
                            selected = (settings?.language ?: "es") == tag,
                            onClick = { viewModel.updateLanguage(tag) },
                            shape = SegmentedButtonDefaults.itemShape(index, languages.size),
                        ) {
                            Text(stringResource(label))
                        }
                    }
                }
            }
        }

        SectionLabel(text = stringResource(R.string.settings_section_build))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = stringResource(R.string.settings_obfuscation),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(R.string.settings_obfuscation_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(text = (settings?.obfuscationLevel ?: 1).toString())
                    Slider(
                        value = (settings?.obfuscationLevel ?: 1).toFloat(),
                        onValueChange = { viewModel.updateObfuscation(it.toInt()) },
                        valueRange = 0f..3f,
                        steps = 2,
                        modifier = Modifier.weight(1f),
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.settings_toolchain),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(R.string.settings_toolchain_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(8.dp))
                var toolchain by remember(settings?.toolchainPath) {
                    mutableStateOf(settings?.toolchainPath ?: "")
                }
                androidx.compose.material3.OutlinedTextField(
                    value = toolchain,
                    onValueChange = { toolchain = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text(stringResource(R.string.settings_toolchain_hint)) },
                    singleLine = true,
                    trailingIcon = {
                        androidx.compose.material3.TextButton(
                            onClick = { viewModel.updateToolchain(toolchain) },
                        ) { Text(stringResource(R.string.action_save)) }
                    },
                )

                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.settings_keep_signed),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = stringResource(R.string.settings_keep_signed_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = settings?.keepSignedCopies ?: true,
                        onCheckedChange = viewModel::updateKeepSigned,
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}
