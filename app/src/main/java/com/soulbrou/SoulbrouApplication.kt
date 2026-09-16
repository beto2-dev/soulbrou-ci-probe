package com.soulbrou

import android.app.Application
import com.soulbrou.core.logging.LogEntry
import com.soulbrou.core.logging.LogLevel
import com.soulbrou.core.logging.SoulLog
import com.soulbrou.core.logging.LogPlant

/**
 * Plant that forwards facade entries to the platform logcat output.
 */
class LogcatPlant : LogPlant {
    override fun onLog(entry: LogEntry) {
        when (entry.level) {
            LogLevel.VERBOSE -> android.util.Log.v(entry.tag, entry.message)
            LogLevel.DEBUG -> android.util.Log.d(entry.tag, entry.message)
            LogLevel.INFO -> android.util.Log.i(entry.tag, entry.message)
            LogLevel.WARN -> android.util.Log.w(entry.tag, entry.message)
            LogLevel.ERROR -> android.util.Log.e(entry.tag, entry.message)
        }
    }
}

/**
 * Application entry point. Initializes the central logging facade used by
 * every module of the tool.
 */
class SoulbrouApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        SoulLog.plant(LogcatPlant())
        SoulLog.i("soulbrou", "Application started, version ${BuildConfig.VERSION_NAME}")
    }
}
