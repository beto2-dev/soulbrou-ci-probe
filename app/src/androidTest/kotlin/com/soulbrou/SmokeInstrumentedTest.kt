package com.soulbrou

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Smoke checks on the instrumented environment: the application context is
 * reachable and the launcher activity renders.
 */
@RunWith(AndroidJUnit4::class)
class SmokeInstrumentedTest {

    @Test
    fun applicationContextExposesContainer() {
        val app = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationContext as SoulbrouApplication
        assertTrue(app.container.settings != null)
        assertTrue(app.container.statistics != null)
        assertTrue(app.container.keystores != null)
    }

    @Test
    fun mainActivityLaunches() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals("com.soulbrou", activity.packageName)
                assertTrue(activity.hasWindowFocus() || !activity.isFinishing)
            }
        }
    }
}
