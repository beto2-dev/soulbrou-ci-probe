package com.soulbrou.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Brand palette: deep indigo with violet accents. */
private val IndigoPrimary = Color(0xFF7C6BF2)
private val IndigoOnPrimary = Color(0xFF130B47)
private val IndigoPrimaryContainer = Color(0xFF322E68)
private val IndigoOnPrimaryContainer = Color(0xFFE3DEFF)
private val VioletSecondary = Color(0xFFB9A7FF)
private val TealTertiary = Color(0xFF7FDAC4)

private val DarkColors = darkColorScheme(
    primary = IndigoPrimary,
    onPrimary = IndigoOnPrimary,
    primaryContainer = IndigoPrimaryContainer,
    onPrimaryContainer = IndigoOnPrimaryContainer,
    secondary = VioletSecondary,
    onSecondary = Color(0xFF221B57),
    secondaryContainer = Color(0xFF3A316D),
    onSecondaryContainer = Color(0xFFE5DEFF),
    tertiary = TealTertiary,
    onTertiary = Color(0xFF00382B),
    tertiaryContainer = Color(0xFF00513F),
    onTertiaryContainer = Color(0xFF9DF6DD),
    background = Color(0xFF121021),
    onBackground = Color(0xFFE4E1F3),
    surface = Color(0xFF121021),
    onSurface = Color(0xFFE4E1F3),
    surfaceVariant = Color(0xFF282345),
    onSurfaceVariant = Color(0xFFC9C4DF),
    outline = Color(0xFF938EA8),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF4B3AD1),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE3DEFF),
    onPrimaryContainer = Color(0xFF150069),
    secondary = Color(0xFF5A4BC0),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE5DEFF),
    onSecondaryContainer = Color(0xFF1B1259),
    tertiary = Color(0xFF006B54),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFF9DF6DD),
    onTertiaryContainer = Color(0xFF002017),
    background = Color(0xFFFDF7FF),
    onBackground = Color(0xFF1C1B26),
    surface = Color(0xFFFDF7FF),
    onSurface = Color(0xFF1C1B26),
    surfaceVariant = Color(0xFFE6E0F0),
    onSurfaceVariant = Color(0xFF484554),
    outline = Color(0xFF787487),
    error = Color(0xFFBA1A1A),
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
)

/**
 * Applies the visual theme of the application. The dark indigo palette is
 * the default; light and system modes follow the user preference stored in
 * the settings screen.
 */
@Composable
fun SoulbrouTheme(
    themeMode: String = "dark",
    content: @Composable () -> Unit,
) {
    val useDark = when (themeMode) {
        "light" -> false
        "system" -> isSystemInDarkTheme()
        else -> true
    }
    MaterialTheme(
        colorScheme = if (useDark) DarkColors else LightColors,
        content = content,
    )
}
