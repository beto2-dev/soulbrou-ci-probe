package com.soulbrou.ui.selector

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.soulbrou.R
import com.soulbrou.ui.components.InfoRow
import com.soulbrou.ui.components.LoadingRow
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel

/**
 * APK intake screen: opens the system document picker, accepts drops on
 * capable form factors and shows the automatic analysis of the chosen file.
 */
@Composable
fun SelectorScreen() {
    val viewModel: SelectorViewModel = viewModel()
    val state by viewModel.state.collectAsState()
    val sessionApk = com.soulbrou.ui.currentSessionApk()

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) viewModel.onApkPicked(uri)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.selector_title),
            subtitle = stringResource(R.string.selector_subtitle),
        )
        Spacer(modifier = Modifier.height(18.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Android,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.height(48.dp),
                )
                when (state.phase) {
                    SelectorPhase.READING, SelectorPhase.ANALYZING ->
                        LoadingRow(caption = stringResource(R.string.selector_analyzing))
                    SelectorPhase.ERROR -> Text(
                        text = when (state.errorMessage) {
                            "invalid" -> stringResource(R.string.selector_invalid_apk)
                            else -> stringResource(R.string.selector_analysis_error)
                        },
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    else -> Text(
                        text = stringResource(R.string.selector_drop_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Button(
                    onClick = { picker.launch(arrayOf("application/vnd.android.package-archive")) },
                    enabled = state.phase != SelectorPhase.READING && state.phase != SelectorPhase.ANALYZING,
                ) {
                    Icon(imageVector = Icons.Outlined.FolderOpen, contentDescription = null)
                    Spacer(modifier = Modifier.padding(4.dp))
                    Text(
                        text = if (sessionApk == null) stringResource(R.string.selector_pick)
                        else stringResource(R.string.selector_change),
                    )
                }
                if (sessionApk != null) {
                    OutlinedButton(onClick = { viewModel.clearSession() }) {
                        Text(text = stringResource(R.string.selector_clear))
                    }
                }
            }
        }

        if (sessionApk != null) {
            val info = sessionApk.info
            SectionLabel(text = info.fileName)
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    info.packageName?.let {
                        InfoRow(label = stringResource(R.string.selector_info_package), value = it)
                    }
                    val version = listOfNotNull(
                        info.versionName,
                        info.versionCode?.toString(),
                    ).joinToString(" / ")
                    if (version.isNotEmpty()) {
                        InfoRow(label = stringResource(R.string.selector_info_version), value = version)
                    }
                    info.minSdk?.let {
                        InfoRow(label = stringResource(R.string.selector_info_min_sdk), value = it.toString())
                    }
                    info.targetSdk?.let {
                        InfoRow(label = stringResource(R.string.selector_info_target_sdk), value = it.toString())
                    }
                    InfoRow(
                        label = stringResource(R.string.selector_info_size),
                        value = sizeCaption(info.fileSizeBytes),
                    )
                    InfoRow(
                        label = stringResource(R.string.selector_info_classes),
                        value = info.classCount.toString(),
                    )
                    InfoRow(
                        label = stringResource(R.string.selector_info_methods),
                        value = info.methodCount.toString(),
                    )
                    InfoRow(
                        label = stringResource(R.string.selector_info_dex),
                        value = info.dexFiles.joinToString(", "),
                    )
                    InfoRow(
                        label = stringResource(R.string.selector_info_abis),
                        value = if (info.nativeAbis.isEmpty()) {
                            stringResource(R.string.selector_info_abis_none)
                        } else {
                            info.nativeAbis.joinToString(", ")
                        },
                    )
                }
            }

            if (info.permissions.isNotEmpty()) {
                SectionLabel(
                    text = stringResource(R.string.selector_info_permissions, info.permissions.size),
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        info.permissions.take(12).forEach { permission ->
                            Text(
                                text = permission.substringAfterLast('.'),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (info.permissions.size > 12) {
                            Text(
                                text = "+" + (info.permissions.size - 12),
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.selector_ready),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}
