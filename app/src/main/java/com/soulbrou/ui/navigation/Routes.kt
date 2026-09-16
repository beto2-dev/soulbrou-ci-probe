package com.soulbrou.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Security
import androidx.compose.ui.graphics.vector.ImageVector

/** Route identifiers of the application. */
object Routes {
    const val HOME = "home"
    const val SELECTOR = "selector"
    const val METHODS = "methods"
    const val PROTECTION = "protection"
    const val KEYSTORE = "keystore"
    const val BUILD = "build"
    const val RESULT = "result"
    const val SETTINGS = "settings"
    const val ABOUT = "about"
}

/** Bottom navigation tab in workflow order. */
data class TabItem(
    val route: String,
    val labelRes: Int,
    val icon: ImageVector,
)

val workflowTabs: List<TabItem> = listOf(
    TabItem(
        route = Routes.HOME,
        labelRes = com.soulbrou.R.string.tab_home,
        icon = Icons.Outlined.Dashboard,
    ),
    TabItem(
        route = Routes.SELECTOR,
        labelRes = com.soulbrou.R.string.tab_selector,
        icon = Icons.Outlined.FolderOpen,
    ),
    TabItem(
        route = Routes.METHODS,
        labelRes = com.soulbrou.R.string.tab_methods,
        icon = Icons.Outlined.AccountTree,
    ),
    TabItem(
        route = Routes.PROTECTION,
        labelRes = com.soulbrou.R.string.tab_protection,
        icon = Icons.Outlined.Security,
    ),
    TabItem(
        route = Routes.KEYSTORE,
        labelRes = com.soulbrou.R.string.tab_keystore,
        icon = Icons.Outlined.Key,
    ),
    TabItem(
        route = Routes.BUILD,
        labelRes = com.soulbrou.R.string.tab_build,
        icon = Icons.Outlined.Build,
    ),
)
