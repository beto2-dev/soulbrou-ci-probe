package com.soulbrou.ui.about

import android.content.Intent
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
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Source
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.soulbrou.BuildConfig
import com.soulbrou.R
import com.soulbrou.ui.components.ScreenHeader
import com.soulbrou.ui.components.SectionLabel

private const val REPOSITORY_URL = "https://github.com/beto2-dev/soulbrou"
private const val CHANGELOG_URL = "$REPOSITORY_URL/blob/main/CHANGELOG.md"

/**
 * About screen: application description, author, license, changelog link
 * and version information.
 */
@Composable
fun AboutScreen() {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        ScreenHeader(title = stringResource(R.string.about_title))
        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = stringResource(R.string.about_description),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        SectionLabel(text = stringResource(R.string.about_version))
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Text(
                text = BuildConfig.VERSION_NAME,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(16.dp),
            )
        }

        SectionLabel(text = stringResource(R.string.about_author))
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Person,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary,
                )
                Spacer(modifier = Modifier.size(12.dp))
                Text(
                    text = "beto2-dev",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }

        SectionLabel(text = stringResource(R.string.about_license))
        AboutRow(
            icon = Icons.Outlined.Description,
            title = stringResource(R.string.about_license_desc),
            subtitle = "Copyright 2025 beto2-dev",
            onClick = { open(context, "$REPOSITORY_URL/blob/main/LICENSE") },
        )

        SectionLabel(text = stringResource(R.string.about_changelog))
        AboutRow(
            icon = Icons.Outlined.History,
            title = stringResource(R.string.about_changelog),
            subtitle = stringResource(R.string.about_changelog_desc),
            onClick = { open(context, CHANGELOG_URL) },
        )

        SectionLabel(text = stringResource(R.string.about_source))
        AboutRow(
            icon = Icons.Outlined.Source,
            title = "github.com/beto2-dev/soulbrou",
            subtitle = stringResource(R.string.about_source),
            onClick = { open(context, REPOSITORY_URL) },
        )
        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun AboutRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        onClick = onClick,
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.secondary,
            )
            Spacer(modifier = Modifier.size(12.dp))
            Column {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun open(context: android.content.Context, url: String) {
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
    } catch (error: Exception) {
        android.widget.Toast.makeText(context, url, android.widget.Toast.LENGTH_LONG).show()
    }
}
