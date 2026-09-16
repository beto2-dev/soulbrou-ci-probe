package com.soulbrou.di

import android.content.Context
import com.soulbrou.data.KeystoreRepository
import com.soulbrou.data.SettingsRepository
import com.soulbrou.data.StatisticsRepository
import com.soulbrou.engine.RuntimeLibrarySource
import com.soulbrou.session.BuildSession

/**
 * Application level dependency container. Created once by the application
 * and shared by every view model; keeps construction explicit and testable
 * without pulling a DI framework into the project.
 */
class AppContainer(context: Context) {

    val settings: SettingsRepository = SettingsRepository(context.applicationContext)

    val statistics: StatisticsRepository = StatisticsRepository(context.applicationContext)

    val keystores: KeystoreRepository = KeystoreRepository(context.applicationContext)

    val runtimeLibraries: RuntimeLibrarySource = RuntimeLibrarySource(context.applicationContext)

    val session: BuildSession = BuildSession()
}
