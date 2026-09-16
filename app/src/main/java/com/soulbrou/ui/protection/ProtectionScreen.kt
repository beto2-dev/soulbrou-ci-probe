package com.soulbrou.ui.protection

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
import androidx.compose.material3.Switch
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
import com.soulbrou.protection.ProtectionType
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel

/**
 * Protection configuration screen: one switch per countermeasure plus the
 * unpatchable mode that locks the configuration inside the native blob.
 */
@Composable
fun ProtectionScreen() {
    val viewModel: ProtectionViewModel = viewModel()
    val spec by viewModel.spec.collectAsState()
    val activeCount = spec.activeKeys.size

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.protection_title),
            subtitle = stringResource(R.string.protection_subtitle),
        )
        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = if (activeCount == 0) {
                stringResource(R.string.protection_none_active)
            } else {
                stringResource(
                    R.string.protection_active_count,
                    activeCount,
                    ProtectionType.entries.size,
                )
            },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = if (activeCount == 0) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.secondary
            },
        )
        Spacer(modifier = Modifier.height(12.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            ToggleRow(
                title = stringResource(R.string.protection_unpatchable),
                description = stringResource(R.string.protection_unpatchable_desc),
                checked = spec.markUnpatchable,
                onChecked = viewModel::setUnpatchable,
                emphasized = true,
            )
        }
        Spacer(modifier = Modifier.height(12.dp))

        ProtectionType.entries.forEach { type ->
            val (titleRes, descRes) = type.labels()
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                ToggleRow(
                    title = stringResource(titleRes),
                    description = stringResource(descRes),
                    checked = spec.enabled[type.key] ?: false,
                    onChecked = { viewModel.toggle(type) },
                )
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun ToggleRow(
    title: String,
    description: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
    emphasized: Boolean = false,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = if (emphasized) MaterialTheme.typography.titleMedium else MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = if (checked || emphasized) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onChecked)
    }
}

private fun ProtectionType.labels(): Pair<Int, Int> = when (this) {
    ProtectionType.ANTI_ROOT -> R.string.protection_type_anti_root to R.string.protection_type_anti_root_desc
    ProtectionType.ANTI_FRIDA -> R.string.protection_type_anti_frida to R.string.protection_type_anti_frida_desc
    ProtectionType.ANTI_DEXDUMP -> R.string.protection_type_anti_dexdump to R.string.protection_type_anti_dexdump_desc
    ProtectionType.ANTI_TAMPERING -> R.string.protection_type_anti_tampering to R.string.protection_type_anti_tampering_desc
    ProtectionType.SIGNATURE_CHECK -> R.string.protection_type_signature_check to R.string.protection_type_signature_check_desc
    ProtectionType.ANTI_DEBUG -> R.string.protection_type_anti_debug to R.string.protection_type_anti_debug_desc
    ProtectionType.ANTI_EMULATOR -> R.string.protection_type_anti_emulator to R.string.protection_type_anti_emulator_desc
}
