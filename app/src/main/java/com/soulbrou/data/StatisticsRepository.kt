package com.soulbrou.data

import android.content.Context
import com.soulbrou.core.model.BuildRecord
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Persists the history of protection builds as JSON in the application
 * private storage, powering the dashboard statistics.
 */
class StatisticsRepository(context: Context) {

    private val json = Json { prettyPrint = false; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "build_history.json")
    private val records = MutableStateFlow<List<BuildRecord>>(emptyList())

    val history: StateFlow<List<BuildRecord>> get() = records

    init {
        records.value = load()
    }

    fun load(): List<BuildRecord> {
        if (!file.exists()) return emptyList()
        return try {
            json.decodeFromString<List<BuildRecord>>(file.readText())
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun append(record: BuildRecord) {
        val updated = (records.value + record).takeLast(200)
        records.value = updated
        try {
            file.writeText(json.encodeToString(updated))
        } catch (_: Exception) {
            // History persistence is best effort.
        }
    }

    fun clear() {
        records.value = emptyList()
        file.delete()
    }
}
