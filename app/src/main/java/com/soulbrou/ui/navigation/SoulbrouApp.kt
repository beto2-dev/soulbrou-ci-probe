package com.soulbrou.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.soulbrou.R
import com.soulbrou.ui.about.AboutScreen
import com.soulbrou.ui.build.BuildScreen
import com.soulbrou.ui.home.HomeScreen
import com.soulbrou.ui.keystore.KeystoreScreen
import com.soulbrou.ui.methods.MethodsScreen
import com.soulbrou.ui.protection.ProtectionScreen
import com.soulbrou.ui.result.ResultScreen
import com.soulbrou.ui.selector.SelectorScreen
import com.soulbrou.ui.settings.SettingsScreen

/**
 * Root composable of the application: top bar with secondary destinations,
 * bottom navigation with the workflow tabs and the nav host itself.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SoulbrouApp() {
    val navController: NavHostController = rememberNavController()
    val backStack by navController.currentBackStackEntryAsState()
    val currentRoute = backStack?.destination?.route

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(text = stringResource(R.string.app_name)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = androidx.compose.material3.MaterialTheme.colorScheme.surface,
                ),
                actions = {
                    IconButton(onClick = { navController.navigate(Routes.SETTINGS) }) {
                        Icon(
                            imageVector = Icons.Outlined.Settings,
                            contentDescription = stringResource(R.string.settings_title),
                        )
                    }
                    IconButton(onClick = { navController.navigate(Routes.ABOUT) }) {
                        Icon(
                            imageVector = Icons.Outlined.Info,
                            contentDescription = stringResource(R.string.about_title),
                        )
                    }
                },
            )
        },
        bottomBar = {
            if (currentRoute in workflowRoutes) {
                NavigationBar {
                    workflowTabs.forEach { tab ->
                        NavigationBarItem(
                            selected = currentRoute == tab.route,
                            onClick = {
                                navController.navigate(tab.route) {
                                    popUpTo(Routes.HOME) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = tab.icon,
                                    contentDescription = stringResource(tab.labelRes),
                                )
                            },
                            label = { Text(text = stringResource(tab.labelRes)) },
                        )
                    }
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Routes.HOME,
            modifier = Modifier.padding(padding),
        ) {
            composable(Routes.HOME) { HomeScreen() }
            composable(Routes.SELECTOR) { SelectorScreen() }
            composable(Routes.METHODS) { MethodsScreen() }
            composable(Routes.PROTECTION) { ProtectionScreen() }
            composable(Routes.KEYSTORE) { KeystoreScreen() }
            composable(Routes.BUILD) {
                BuildScreen(onNavigateToResult = { navController.navigate(Routes.RESULT) })
            }
            composable(Routes.RESULT) { ResultScreen() }
            composable(Routes.SETTINGS) { SettingsScreen() }
            composable(Routes.ABOUT) { AboutScreen() }
        }
    }
}

private val workflowRoutes = setOf(
    Routes.HOME,
    Routes.SELECTOR,
    Routes.METHODS,
    Routes.PROTECTION,
    Routes.KEYSTORE,
    Routes.BUILD,
)
