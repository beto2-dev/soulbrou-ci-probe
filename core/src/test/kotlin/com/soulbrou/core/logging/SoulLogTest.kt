package com.soulbrou.core.logging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks of the centralized logging facade used by every module.
 */
class SoulLogTest {

    @Test
    fun `planted sinks receive the entries`() {
        val sink = RecordingPlant()
        SoulLog.plant(sink)
        try {
            SoulLog.i("test", "hello")
        } finally {
            SoulLog.uproot(sink)
        }
        assertEquals(1, sink.entries.size)
        assertEquals("hello", sink.entries[0].message)
        assertEquals(LogLevel.INFO, sink.entries[0].level)
        assertEquals("test", sink.entries[0].tag)
    }

    @Test
    fun `uprooted sinks stop receiving entries`() {
        val sink = RecordingPlant()
        SoulLog.plant(sink)
        SoulLog.uproot(sink)
        SoulLog.w("test", "after")
        assertEquals(0, sink.entries.size)
    }

    @Test
    fun `duplicate plants are installed once`() {
        val sink = RecordingPlant()
        SoulLog.plant(sink)
        SoulLog.plant(sink)
        try {
            SoulLog.d("test", "once")
        } finally {
            SoulLog.uproot(sink)
        }
        assertEquals(1, sink.entries.size)
    }

    @Test
    fun `sequence numbers grow monotonically`() {
        val sink = RecordingPlant()
        SoulLog.plant(sink)
        try {
            SoulLog.v("t", "1")
            SoulLog.v("t", "2")
            SoulLog.v("t", "3")
        } finally {
            SoulLog.uproot(sink)
        }
        assertTrue(sink.entries[0].sequence < sink.entries[1].sequence)
        assertTrue(sink.entries[1].sequence < sink.entries[2].sequence)
    }

    private class RecordingPlant : LogPlant {
        val entries = ArrayList<LogEntry>()
        override fun onLog(entry: LogEntry) {
            entries.add(entry)
        }
    }
}
