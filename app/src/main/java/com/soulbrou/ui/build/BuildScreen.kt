package com.soulbrou.ui.build

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.soulbrou.R
import com.soulbrou.core.model.BuildStage
import com.soulbrou.core.model.StageState
import com.soulbrou.ui.components.InfoRow
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel

/**
 * Build screen: visualizes the nine pipeline stages with live progress,
 * streams the build log and allows cancelling a running build.
 */
@Composable
fun BuildScreen(
    onNavigateToResult: () -> Unit,
) {
    val viewModel: BuildViewModel = viewModel()
    val pipelineState by viewModel.pipelineState.collectAsState()
    val validation by viewModel.validation.collectAsState()
    val session = viewModel.session
    val apk by session.apk.collectAsState()
    val selection by session.selection.collectAsState()
    val keystore by session.keystore.collectAsState()
    val spec by session.spec.collectAsState()

    var confirmCancel by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.build_title),
            subtitle = stringResource(R.string.build_subtitle),
        )
        Spacer(modifier = Modifier.height(12.dp))

        validation?.let { problem ->
            Text(
                text = when (problem) {
                    BuildValidation.NO_APK -> stringResource(R.string.build_validation_no_apk)
                    BuildValidation.NO_METHODS -> stringResource(R.string.build_validation_no_methods)
                    BuildValidation.NO_KEYSTORE -> stringResource(R.string.build_validation_no_keystore)
                },
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        SummaryCard(
            apkName = apk?.fileName,
            methodCount = selection.size,
            protectionCount = spec.activeKeys.size,
            keystoreName = keystore?.displayName,
        )
        Spacer(modifier = Modifier.height(12.dp))

        StageList(stages = pipelineState.stages)

        Spacer(modifier = Modifier.height(8.dp))
        when {
            pipelineState.running -> OutlinedButton(
                onClick = { confirmCancel = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(imageVector = Icons.Outlined.Cancel, contentDescription = null)
                Spacer(modifier = Modifier.size(4.dp))
                Text(text = stringResource(R.string.build_cancel))
            }
            pipelineState.outcome?.success == true -> Button(
                onClick = onNavigateToResult,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(text = stringResource(R.string.action_view_result))
            }
            else -> Button(
                onClick = viewModel::start,
                modifier = Modifier.fillMaxWidth(),
                enabled = apk != null,
            ) {
                Text(text = stringResource(R.string.build_start))
            }
        }

        if (pipelineState.outcome != null && pipelineState.outcome?.success == false) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.build_failed) +
                    (pipelineState.outcome?.errorMessage?.let { ": $it" } ?: ""),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        SectionLabel(text = stringResource(R.string.build_logs))
        LogPanel(
            logs = pipelineState.logs,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
        )
    }

    if (confirmCancel) {
        AlertDialog(
            onDismissRequest = { confirmCancel = false },
            title = { Text(stringResource(R.string.build_cancel)) },
            text = { Text(stringResource(R.string.build_confirm_cancel)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmCancel = false
                    viewModel.cancel()
                }) { Text(stringResource(R.string.action_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmCancel = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun SummaryCard(
    apkName: String?,
    methodCount: Int,
    protectionCount: Int,
    keystoreName: String?,
) {
    SectionLabel(text = stringResource(R.string.build_summary_selection, methodCount, protectionCount))
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            InfoRow(
                label = stringResource(R.string.tab_selector),
                value = apkName ?: "-",
            )
            InfoRow(
                label = stringResource(R.string.tab_methods),
                value = methodCount.toString(),
            )
            InfoRow(
                label = stringResource(R.string.tab_protection),
                value = protectionCount.toString(),
            )
            InfoRow(
                label = stringResource(R.string.tab_keystore),
                value = keystoreName ?: "-",
            )
        }
    }
}

@Composable
private fun StageList(stages: Map<BuildStage, StageState>) {
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .height(300.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        items(BuildStage.entries.toList()) { stage ->
            StageRow(stage = stage, state = stages[stage] ?: StageState.PENDING)
        }
    }
}

@Composable
private fun StageRow(stage: BuildStage, state: StageState) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        when (state) {
            StageState.COMPLETED -> Icon(
                imageVector = Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.tertiary,
            )
            StageState.RUNNING -> Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.secondary,
                modifier = Modifier.size(16.dp),
            ) {}
            StageState.FAILED -> Icon(
                imageVector = Icons.Outlined.Error,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
            )
            else -> Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                modifier = Modifier.size(20.dp),
            ) {}
        }
        Text(
            text = stageLabel(stage),
            style = MaterialTheme.typography.bodyMedium,
            color = when (state) {
                StageState.COMPLETED -> MaterialTheme.colorScheme.onSurface
                StageState.RUNNING -> MaterialTheme.colorScheme.secondary
                StageState.FAILED -> MaterialTheme.colorScheme.error
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
            fontWeight = if (state == StageState.RUNNING) FontWeight.Bold else FontWeight.Normal,
        )
    }
}

@Composable
private fun stageLabel(stage: BuildStage): String = when (stage) {
    BuildStage.ANALYZE -> stringResource(R.string.build_stage_analyze)
    BuildStage.PARSE_DEX -> stringResource(R.string.build_stage_parse_dex)
    BuildStage.PLAN_SELECTION -> stringResource(R.string.build_stage_plan_selection)
    BuildStage.GENERATE_NATIVE -> stringResource(R.string.build_stage_generate_native)
    BuildStage.COMPILE_NATIVE -> stringResource(R.string.build_stage_compile_native)
    BuildStage.INJECT_PROTECTIONS -> stringResource(R.string.build_stage_inject_protections)
    BuildStage.PACKAGE -> stringResource(R.string.build_stage_package)
    BuildStage.ALIGN_SIGN -> stringResource(R.string.build_stage_align_sign)
    BuildStage.VERIFY -> stringResource(R.string.build_stage_verify)
}

@Composable
private fun LogPanel(
    logs: List<com.soulbrou.core.model.LogLine>,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.background,
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            if (logs.isEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.build_logs),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(logs) { line ->
                Text(
                    text = line.message,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = when (line.level) {
                        com.soulbrou.core.model.LogLineLevel.ERROR -> MaterialTheme.colorScheme.error
                        com.soulbrou.core.model.LogLineLevel.WARN -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
    }
}
