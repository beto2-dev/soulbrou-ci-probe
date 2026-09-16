package com.soulbrou.ui.home

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import com.soulbrou.core.model.BuildRecord
import com.soulbrou.ui.components.InfoRow
import com.soulbrou.ui.components.LoadingRow
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel
import com.soulbrou.ui.components.StatCard
import com.soulbrou.ui.components.formatBytes
import java.text.DateFormat
import java.util.Date

/**
 * Dashboard: build statistics, native engine status, workflow guidance and
 * the APK currently loaded in the session.
 */
@Composable
fun HomeScreen() {
    val viewModel: HomeViewModel = viewModel()
    val state by viewModel.state.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.home_title),
            subtitle = stringResource(R.string.home_subtitle),
        )
        Spacer(modifier = Modifier.height(18.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(
                label = stringResource(R.string.home_stat_builds),
                value = state.totalBuilds.toString(),
                icon = Icons.Outlined.Build,
                modifier = Modifier.weight(1f),
            )
            StatCard(
                label = stringResource(R.string.home_stat_success),
                value = "${state.successRate}%",
                icon = Icons.Outlined.Verified,
                modifier = Modifier.weight(1f),
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(
                label = stringResource(R.string.home_stat_native_methods),
                value = state.nativeMethods.toString(),
                icon = Icons.Outlined.Memory,
                modifier = Modifier.weight(1f),
            )
            StatCard(
                label = stringResource(R.string.home_stat_last),
                value = state.lastBuild?.let { formatRelative(it) } ?: "-",
                icon = Icons.Outlined.Schedule,
                modifier = Modifier.weight(1f),
            )
        }

        SectionLabel(text = stringResource(R.string.home_runtime_version))
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Outlined.Memory,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.secondary,
                    )
                    Spacer(modifier = Modifier.padding(4.dp))
                    Text(
                        text = if (state.runtimeVersion.isEmpty()) "" else state.runtimeVersion,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                when (state.selfTest) {
                    0 -> LoadingRow(caption = stringResource(R.string.home_selftest_running))
                    1 -> StatusLine(
                        icon = Icons.Outlined.CheckCircle,
                        text = stringResource(R.string.home_selftest_ok),
                        positive = true,
                    )
                    else -> StatusLine(
                        icon = Icons.Outlined.Schedule,
                        text = stringResource(R.string.home_selftest_failed),
                        positive = false,
                    )
                }
            }
        }

        SectionLabel(text = stringResource(R.string.home_workflow_title))
        WorkflowCard()

        SectionLabel(text = stringResource(R.string.tab_selector))
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                val name = state.apkFileName
                if (name != null) {
                    InfoRow(
                        label = stringResource(R.string.home_apk_selected),
                        value = name,
                    )
                } else {
                    Text(
                        text = stringResource(R.string.home_apk_none),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        if (state.totalBuilds == 0) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.home_get_started),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun WorkflowCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            WorkflowStep(
                icon = Icons.Outlined.FolderOpen,
                text = stringResource(R.string.home_workflow_step_1),
            )
            WorkflowStep(
                icon = Icons.Outlined.Memory,
                text = stringResource(R.string.home_workflow_step_2),
            )
            WorkflowStep(
                icon = Icons.Outlined.Verified,
                text = stringResource(R.string.home_workflow_step_3),
            )
            WorkflowStep(
                icon = Icons.Outlined.Build,
                text = stringResource(R.string.home_workflow_step_4),
            )
        }
    }
}

@Composable
private fun WorkflowStep(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(
        modifier = Modifier.padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.secondary,
        )
        Text(text = text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun StatusLine(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, positive: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (positive) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.error,
        )
        Spacer(modifier = Modifier.padding(4.dp))
        Text(text = text, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun formatRelative(record: BuildRecord): String {
    val format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
    return format.format(Date(record.startedAtEpochMs)) + " (" + formatBytes(record.outputSizeBytes) + ")"
}
