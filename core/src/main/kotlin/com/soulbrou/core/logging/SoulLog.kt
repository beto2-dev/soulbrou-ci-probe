package com.soulbrou.core.logging

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Severity levels understood by the centralized logging facade.
 */
enum class LogLevel(val priority: Int) {
    VERBOSE(2),
    DEBUG(3),
    INFO(4),
    WARN(5),
    ERROR(6),
}

/**
 * A single structured log entry.
 */
data class LogEntry(
    val timestamp: Long,
    val level: LogLevel,
    val tag: String,
    val message: String,
    val sequence: Long = SEQUENCE.getAndIncrement(),
) {
    companion object {
        private val SEQUENCE = AtomicLong(0)
    }
}

/**
 * A sink that receives log entries produced anywhere in the application.
 */
fun interface LogPlant {
    fun onLog(entry: LogEntry)
}

/**
 * Centralized logging facade used by every Soulbrou module. All modules must
 * log through this class instead of direct android.util.Log or println calls,
 * so the build log viewer, the platform log and the JVM unit tests observe a
 * single consistent stream.
 *
 * The facade is safe to use from any thread. Plants can be attached and
 * detached at runtime; when no plant is installed the entries fall back to
 * the standard output, which keeps JVM unit tests usable. The facade is a
 * pure JVM component so it can be exercised by plain unit tests.
 */
object SoulLog {

    private val plants = CopyOnWriteArrayList<LogPlant>()

    private const val MAX_TAG_LENGTH = 23

    /** Installs a plant, ignoring duplicates. */
    fun plant(plant: LogPlant) {
        if (plant !in plants) {
            plants.add(plant)
        }
    }

    /** Removes a previously installed plant. */
    fun uproot(plant: LogPlant) {
        plants.remove(plant)
    }

    fun v(tag: String, message: String) = dispatch(LogLevel.VERBOSE, tag, message)
    fun d(tag: String, message: String) = dispatch(LogLevel.DEBUG, tag, message)
    fun i(tag: String, message: String) = dispatch(LogLevel.INFO, tag, message)
    fun w(tag: String, message: String) = dispatch(LogLevel.WARN, tag, message)
    fun e(tag: String, message: String, error: Throwable? = null) {
        val composed = if (error != null) {
            "$message: ${error.javaClass.simpleName}: ${error.message}"
        } else {
            message
        }
        dispatch(LogLevel.ERROR, tag, composed)
    }

    private fun dispatch(level: LogLevel, rawTag: String, message: String) {
        val tag = if (rawTag.length > MAX_TAG_LENGTH) rawTag.take(MAX_TAG_LENGTH) else rawTag
        val entry = LogEntry(
            timestamp = System.currentTimeMillis(),
            level = level,
            tag = tag,
            message = message,
        )
        val installed = plants.toList()
        if (installed.isEmpty()) {
            println("[${level}] $tag: $message")
            return
        }
        for (plant in installed) {
            try {
                plant.onLog(entry)
            } catch (_: Exception) {
                // A broken plant must never break the caller.
            }
        }
    }

    /** Plant that keeps the last [capacity] entries in memory. */
    class InMemoryPlant(private val capacity: Int = 4096) : LogPlant {
        private val buffer = ArrayDeque<LogEntry>(capacity)

        val snapshot: List<LogEntry>
            get() = synchronized(this) { buffer.toList() }

        override fun onLog(entry: LogEntry) {
            synchronized(this) {
                if (buffer.size >= capacity) {
                    buffer.removeFirst()
                }
                buffer.addLast(entry)
            }
        }
    }
}
