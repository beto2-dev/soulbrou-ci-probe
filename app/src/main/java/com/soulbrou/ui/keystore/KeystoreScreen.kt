package com.soulbrou.ui.keystore

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.soulbrou.R
import com.soulbrou.ui.components.InfoRow
import com.soulbrou.ui.components.ScreenHeader
import java.text.DateFormat
import java.util.Date

/**
 * Keystore manager screen: lists stored keystores, imports JKS/PKCS12
 * files through the system picker and generates new PKCS12 stores.
 */
@Composable
fun KeystoreScreen() {
    val viewModel: KeystoreViewModel = viewModel()
    val state by viewModel.state.collectAsState()

    var showGenerate by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<StoredKeystore?>(null) }
    var useTarget by remember { mutableStateOf<StoredKeystore?>(null) }
    var pendingUri by remember { mutableStateOf<android.net.Uri?>(null) }

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        pendingUri = uri
        if (uri != null) showImport = true
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.keystore_title),
            subtitle = stringResource(R.string.keystore_subtitle),
        )
        Spacer(modifier = Modifier.height(16.dp))

        if (state.errorMessage != null) {
            Text(
                text = when (state.errorMessage) {
                    "mismatch" -> stringResource(R.string.keystore_passwords_mismatch)
                    "invalid" -> stringResource(R.string.keystore_invalid)
                    else -> state.errorMessage ?: ""
                },
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { picker.launch(arrayOf("*/*")) },
                enabled = state.phase == KeystorePhase.IDLE,
                modifier = Modifier.weight(1f),
            ) {
                Icon(imageVector = Icons.Outlined.Add, contentDescription = null)
                Spacer(modifier = Modifier.size(4.dp))
                Text(text = stringResource(R.string.keystore_import))
            }
            Button(
                onClick = { showGenerate = true },
                enabled = state.phase == KeystorePhase.IDLE,
                modifier = Modifier.weight(1f),
            ) {
                Icon(imageVector = Icons.Outlined.Key, contentDescription = null)
                Spacer(modifier = Modifier.size(4.dp))
                Text(text = stringResource(R.string.keystore_generate))
            }
        }

        if (state.phase != KeystorePhase.IDLE) {
            LoadingBlock(state.phase)
        }

        Spacer(modifier = Modifier.height(16.dp))
        if (state.stores.isEmpty()) {
            Text(
                text = stringResource(R.string.keystore_none),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            state.stores.forEach { store ->
                StoreCard(
                    store = store,
                    onUse = { useTarget = store },
                    onClear = viewModel::clearSelection,
                    onDelete = { pendingDelete = store },
                )
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }

    if (showGenerate) {
        GenerateDialog(
            onDismiss = {
                showGenerate = false
                viewModel.consumeError()
            },
            onGenerate = { name, alias, cn, password ->
                showGenerate = false
                viewModel.generateStore(name, alias, cn, password)
            },
            onRandomPassword = viewModel::randomPassword,
        )
    }

    if (showImport && pendingUri != null) {
        val uri = pendingUri
        ImportDialog(
            onDismiss = {
                showImport = false
                pendingUri = null
                viewModel.consumeError()
            },
            onImport = { name, password, alias ->
                showImport = false
                if (uri != null) viewModel.importStore(uri, name, password, alias)
                pendingUri = null
            },
        )
    }

    useTarget?.let { target ->
        UseDialog(
            store = target,
            onDismiss = { useTarget = null },
            onConfirm = { password ->
                viewModel.useStore(target, password)
                useTarget = null
            },
        )
    }

    pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.action_delete)) },
            text = { Text(stringResource(R.string.keystore_confirm_delete)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteStore(target)
                    pendingDelete = null
                }) { Text(stringResource(R.string.action_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    state.generatedPassword?.let { password ->
        AlertDialog(
            onDismissRequest = viewModel::consumeGeneratedPassword,
            title = { Text(stringResource(R.string.keystore_generated)) },
            text = {
                Column {
                    Text(stringResource(R.string.keystore_generated_password_note))
                    Spacer(modifier = Modifier.height(12.dp))
                    Card(colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    )) {
                        Text(
                            text = password,
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = viewModel::consumeGeneratedPassword) {
                    Text(stringResource(R.string.action_close))
                }
            },
        )
    }
}

@Composable
private fun LoadingBlock(phase: KeystorePhase) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
        Text(
            text = stringResource(if (phase == KeystorePhase.GENERATING) R.string.keystore_generate else R.string.keystore_import),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun StoreCard(
    store: StoredKeystore,
    onUse: () -> Unit,
    onClear: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (store.selected) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (store.selected) Icons.Outlined.Verified else Icons.Outlined.Key,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary,
                )
                Spacer(modifier = Modifier.size(8.dp))
                Text(
                    text = store.file.name.removeSuffix(".p12"),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onDelete) {
                    Icon(
                        imageVector = Icons.Outlined.Delete,
                        contentDescription = stringResource(R.string.action_delete),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
            InfoRow(
                label = stringResource(R.string.keystore_type),
                value = store.inUseType ?: "PKCS12/JKS",
            )
            if (store.inUseAlias != null) {
                InfoRow(
                    label = stringResource(R.string.keystore_alias),
                    value = store.inUseAlias,
                )
            }
            InfoRow(
                label = stringResource(R.string.keystore_created),
                value = DateFormat.getDateInstance(DateFormat.MEDIUM)
                    .format(Date(store.file.lastModified())),
            )
            if (store.selected) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.keystore_in_use),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                TextButton(onClick = onClear) { Text(stringResource(R.string.action_clear)) }
            } else {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(onClick = onUse) {
                    Text(stringResource(R.string.keystore_use))
                }
            }
        }
    }
}

@Composable
private fun GenerateDialog(
    onDismiss: () -> Unit,
    onGenerate: (String, String, String, CharArray) -> Unit,
    onRandomPassword: () -> String,
) {
    var name by remember { mutableStateOf("") }
    var alias by remember { mutableStateOf("soulbrou") }
    var commonName by remember { mutableStateOf("Soulbrou") }
    var password by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.keystore_generate_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.keystore_name)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = alias,
                    onValueChange = { alias = it },
                    label = { Text(stringResource(R.string.keystore_alias)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = commonName,
                    onValueChange = { commonName = it },
                    label = { Text(stringResource(R.string.keystore_common_name)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.keystore_password)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    trailingIcon = {
                        TextButton(onClick = { password = onRandomPassword() }) {
                            Text(stringResource(R.string.action_generate))
                        }
                    },
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onGenerate(name, alias, commonName, password.toCharArray()) },
                enabled = name.isNotBlank() && alias.isNotBlank() && password.isNotEmpty(),
            ) { Text(stringResource(R.string.action_generate)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

@Composable
private fun ImportDialog(
    onDismiss: () -> Unit,
    onImport: (String, CharArray, String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var alias by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.keystore_import_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.keystore_name)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.keystore_password)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                )
                OutlinedTextField(
                    value = alias,
                    onValueChange = { alias = it },
                    label = { Text(stringResource(R.string.keystore_alias)) },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onImport(name, password.toCharArray(), alias) },
                enabled = password.isNotEmpty(),
            ) { Text(stringResource(R.string.action_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

@Composable
private fun UseDialog(
    store: StoredKeystore,
    onDismiss: () -> Unit,
    onConfirm: (CharArray) -> Unit,
) {
    var password by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.keystore_use)) },
        text = {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.keystore_password)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(password.toCharArray()) },
                enabled = password.isNotEmpty(),
            ) { Text(stringResource(R.string.action_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}
