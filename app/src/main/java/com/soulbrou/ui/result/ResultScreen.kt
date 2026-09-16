package com.soulbrou.ui.result

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.CompareArrows
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material.icons.outlined.Save
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.soulbrou.R
import com.soulbrou.ui.components.InfoRow
import com.soulbrou.ui.components.LoadingRow
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel
import com.soulbrou.ui.components.StatCard
import com.soulbrou.ui.components.formatBytes
import java.io.File

/**
 * Result screen: before and after comparison of the protected build, the
 * signature verification verdict and save or share actions.
 */
@Composable
fun ResultScreen() {
    val viewModel: ResultViewModel = viewModel()
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val savedText = stringResource(R.string.result_saved, state.savedMessage ?: "")
    val errorText = stringResource(R.string.result_save_error)

    LaunchedEffect(state.savedMessage, state.saveError) {
        when {
            state.savedMessage != null -> snackbar.showSnackbar(savedText)
            state.saveError -> snackbar.showSnackbar(errorText)
        }
        if (state.savedMessage != null || state.saveError) viewModel.consumeSavedMessage()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.result_title),
            subtitle = stringResource(R.string.result_subtitle),
        )
        Spacer(modifier = Modifier.height(16.dp))

        val outcome = state.outcome
        val comparison = outcome?.comparison
        if (outcome == null || comparison == null || !outcome.success) {
            Text(
                text = stringResource(R.string.result_not_available),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCard(
                    label = stringResource(R.string.result_input),
                    value = formatBytes(comparison.inputSizeBytes),
                    icon = Icons.Outlined.CompareArrows,
                    modifier = Modifier.weight(1f),
                )
                StatCard(
                    label = stringResource(R.string.result_output),
                    value = formatBytes(comparison.outputSizeBytes),
                    icon = Icons.Outlined.Save,
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(modifier = Modifier.height(12.dp))

            SectionLabel(text = stringResource(R.string.result_title))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    InfoRow(
                        label = stringResource(R.string.result_size),
                        value = "${formatBytes(comparison.inputSizeBytes)} -> ${formatBytes(comparison.outputSizeBytes)}",
                    )
                    InfoRow(
                        label = stringResource(R.string.result_dex_methods),
                        value = "${comparison.inputDexMethodCount} -> ${comparison.outputDexMethodCount}",
                    )
                    InfoRow(
                        label = stringResource(R.string.result_native_methods),
                        value = comparison.nativeMethodCount.toString(),
                    )
                    InfoRow(
                        label = stringResource(R.string.result_protections),
                        value = if (comparison.appliedProtections.isEmpty()) {
                            stringResource(R.string.result_protections_none)
                        } else {
                            comparison.appliedProtections.joinToString(", ")
                        },
                    )
                }
            }

            SectionLabel(text = stringResource(R.string.result_verify_title))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    if (!state.verificationDone) {
                        LoadingRow(caption = stringResource(R.string.home_selftest_running))
                    } else {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Icon(
                                imageVector = if (state.verified) Icons.Outlined.CheckCircle else Icons.Outlined.Error,
                                contentDescription = null,
                                tint = if (state.verified) {
                                    MaterialTheme.colorScheme.tertiary
                                } else {
                                    MaterialTheme.colorScheme.error
                                },
                            )
                            Spacer(modifier = Modifier.size(8.dp))
                            Text(
                                text = if (state.verified) {
                                    stringResource(R.string.result_verified)
                                } else {
                                    stringResource(R.string.result_verify_failed)
                                },
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = viewModel::saveOutput,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(imageVector = Icons.Outlined.Save, contentDescription = null)
                    Spacer(modifier = Modifier.size(4.dp))
                    Text(text = stringResource(R.string.action_save))
                }
                OutlinedButton(
                    onClick = { shareProtectedApk(context, state.savedMessage) },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(imageVector = Icons.Outlined.Share, contentDescription = null)
                    Spacer(modifier = Modifier.size(4.dp))
                    Text(text = stringResource(R.string.action_share))
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }

    SnackbarHost(
        hostState = snackbar,
        modifier = Modifier.padding(12.dp),
    )
}

private fun shareProtectedApk(context: android.content.Context, savedPath: String?) {
    val container = (context.applicationContext as com.soulbrou.SoulbrouApplication).container
    val bytes = container.session.outcome.value?.outputApkBytes ?: return
    try {
        val shareDir = File(context.cacheDir, "share").apply { mkdirs() }
        val file = File(shareDir, "soulbrou-protected.apk")
        file.writeBytes(bytes)
        val uri = FileProvider.getUriForFile(
            context,
            context.packageName + ".fileprovider",
            file,
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, context.getString(R.string.result_share_via)))
    } catch (error: Exception) {
        android.widget.Toast.makeText(context, R.string.result_save_error, android.widget.Toast.LENGTH_SHORT).show()
    }
}
