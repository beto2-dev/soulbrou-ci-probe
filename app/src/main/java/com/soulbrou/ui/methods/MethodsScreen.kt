package com.soulbrou.ui.methods

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import com.soulbrou.dex2c.MethodKey
import com.soulbrou.engine.MethodCatalog
import com.soulbrou.ui.components.LoadingRow
import com.soulbrou.ui.components.MonoPanel
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.currentSessionApk

/**
 * Method selection screen: a filterable package tree with multi selection
 * of convertible methods and an inline smali preview.
 */
@Composable
fun MethodsScreen() {
    val viewModel: MethodsViewModel = viewModel()
    val state by viewModel.state.collectAsState()
    val sessionApk = currentSessionApk()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(
            title = stringResource(R.string.methods_title),
            subtitle = stringResource(R.string.methods_subtitle),
        )
        Spacer(modifier = Modifier.height(12.dp))

        when {
            sessionApk == null -> EmptyHint(text = stringResource(R.string.methods_no_apk))
            state.loading -> LoadingRow(caption = stringResource(R.string.selector_analyzing))
            else -> {
                Text(
                    text = stringResource(R.string.methods_selected_count, state.selection.size),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.secondary,
                )
                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = state.filter,
                    onValueChange = viewModel::setFilter,
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text(stringResource(R.string.methods_search_hint)) },
                    singleLine = true,
                )
                Spacer(modifier = Modifier.height(12.dp))

                val catalog = state.catalog
                when {
                    catalog == null || catalog.packages().isEmpty() ->
                        EmptyHint(text = stringResource(R.string.methods_empty))
                    else -> PackageTree(
                        catalog = catalog,
                        state = state,
                        onToggleMethod = viewModel::toggleMethod,
                        onToggleClass = viewModel::toggleClass,
                        onSelectPackage = viewModel::selectPackage,
                        onPreview = viewModel::requestPreview,
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }
        }
    }
}

@Composable
private fun PackageTree(
    catalog: MethodCatalog,
    state: MethodsUiState,
    onToggleMethod: (MethodKey) -> Unit,
    onToggleClass: (List<MethodKey>) -> Unit,
    onSelectPackage: (List<MethodKey>) -> Unit,
    onPreview: (MethodKey) -> Unit,
    modifier: Modifier = Modifier,
) {
    val filter = state.filter.trim().lowercase()
    val packages = remember(catalog, filter) {
        if (filter.isEmpty()) {
            catalog.packages()
        } else {
            catalog.packages().mapNotNull { pkg ->
                val nameHit = pkg.name.lowercase().contains(filter)
                val classes = pkg.classes.filter { cls ->
                    nameHit ||
                        cls.displayName.lowercase().contains(filter) ||
                        cls.methods.any { it.displayName.lowercase().contains(filter) }
                }
                if (classes.isEmpty()) null else MethodCatalog.PackageEntry(pkg.name, classes)
            }
        }
    }

    if (packages.isEmpty()) {
        EmptyHint(text = stringResource(R.string.methods_filter_no_results))
        return
    }

    LazyColumn(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(packages, key = { it.name }) { pkg ->
            PackageCard(pkg, state, onToggleMethod, onToggleClass, onSelectPackage, onPreview)
        }
        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
private fun PackageCard(
    pkg: MethodCatalog.PackageEntry,
    state: MethodsUiState,
    onToggleMethod: (MethodKey) -> Unit,
    onToggleClass: (List<MethodKey>) -> Unit,
    onSelectPackage: (List<MethodKey>) -> Unit,
    onPreview: (MethodKey) -> Unit,
) {
    var expanded by remember(pkg.name) { mutableStateOf(false) }
    val packageKeys = remember(pkg) { pkg.classes.flatMap { it.methods.map { m -> m.key } } }
    val selectedInPackage = packageKeys.count { it in state.selection }
    val packageFullySelected = selectedInPackage == packageKeys.size

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                        contentDescription = stringResource(R.string.methods_expand_package),
                    )
                }
                Text(
                    text = stringResource(R.string.methods_package_label, pkg.name),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier
                        .weight(1f)
                        .clickable { expanded = !expanded },
                )
                Text(
                    text = stringResource(R.string.methods_class_count, pkg.classes.size),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(end = 8.dp),
                )
                MethodCheckbox(
                    checked = packageFullySelected,
                    onChecked = { onSelectPackage(packageKeys) },
                )
            }
            if (selectedInPackage > 0 && !packageFullySelected) {
                Text(
                    text = stringResource(R.string.methods_selected_count, selectedInPackage),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.padding(start = 48.dp),
                )
            }
            AnimatedVisibility(visible = expanded) {
                Column {
                    pkg.classes.forEach { cls ->
                        ClassRow(cls, state, onToggleMethod, onToggleClass, onPreview)
                    }
                }
            }
        }
    }
}

@Composable
private fun ClassRow(
    cls: MethodCatalog.ClassEntry,
    state: MethodsUiState,
    onToggleMethod: (MethodKey) -> Unit,
    onToggleClass: (List<MethodKey>) -> Unit,
    onPreview: (MethodKey) -> Unit,
) {
    var expanded by remember(cls.descriptor) { mutableStateOf(false) }
    val classKeys = remember(cls) { cls.methods.map { it.key } }
    val classSelected = classKeys.count { it in state.selection }

    Column(modifier = Modifier.padding(start = 24.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Outlined.AccountTree,
                contentDescription = stringResource(R.string.methods_expand_class),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(end = 8.dp),
            )
            Text(
                text = cls.displayName,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.weight(1f),
            )
            MethodCheckbox(
                checked = classSelected == classKeys.size && classKeys.isNotEmpty(),
                onChecked = { onToggleClass(classKeys) },
            )
        }
        if (expanded) {
            cls.methods.forEach { method ->
                MethodRow(method, state, onToggleMethod, onPreview)
            }
        }
    }
}

@Composable
private fun MethodRow(
    method: MethodCatalog.MethodEntry,
    state: MethodsUiState,
    onToggleMethod: (MethodKey) -> Unit,
    onPreview: (MethodKey) -> Unit,
) {
    val selected = method.key in state.selection
    Column(modifier = Modifier.padding(start = 40.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onToggleMethod(method.key) }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MethodCheckbox(checked = selected, onChecked = { onToggleMethod(method.key) })
            Text(
                text = method.displayName,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = if (method.convertible) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.outline
                },
                modifier = Modifier.weight(1f),
            )
            if (method.convertible) {
                IconButton(onClick = { onPreview(method.key) }) {
                    Icon(
                        imageVector = Icons.Outlined.Code,
                        contentDescription = stringResource(R.string.methods_preview_title),
                        tint = if (state.previewKey == method.key) {
                            MaterialTheme.colorScheme.secondary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
            }
        }
        if (state.previewKey == method.key) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                shape = MaterialTheme.shapes.small,
                color = MaterialTheme.colorScheme.background,
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Text(
                        text = stringResource(R.string.methods_preview_title),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    when {
                        state.previewLoading -> LoadingRow(caption = stringResource(R.string.selector_analyzing))
                        state.previewSmali != null -> Text(
                            text = state.previewSmali,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                        else -> Text(
                            text = stringResource(R.string.methods_preview_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        text = stringResource(R.string.methods_preview_note),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun MethodCheckbox(checked: Boolean, onChecked: () -> Unit) {
    IconButton(onClick = onChecked) {
        Icon(
            imageVector = if (checked) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (checked) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.outline,
        )
    }
}

@Composable
private fun EmptyHint(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 32.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
