package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test
import java.util.TimeZone

class LogFilterTest {
    private val zone = TimeZone.getTimeZone("Africa/Johannesburg")

    @Test fun dateIncludesBothEndsOfSelectedDayOnly() {
        val day = LogDay(2026, 8, 7)
        val bounds = day.bounds(zone)
        val filter = LogFilter(day = day, zone = zone)
        assertFalse(filter.matches(bounds.first - 1, null, "event"))
        assertTrue(filter.matches(bounds.first, null, "event"))
        assertTrue(filter.matches(bounds.last, null, "event"))
        assertFalse(filter.matches(bounds.last + 1, null, "event"))
    }

    @Test fun dateUsesLocalMidnightRatherThanUtc() {
        val bounds = LogDay(2026, 8, 7).bounds(zone)
        assertEquals(1788732000000L, bounds.first) // 2026-09-06 22:00 UTC
    }

    @Test fun allFiltersMustMatchAndSearchIsCaseInsensitive() {
        val day = LogDay(2026, 8, 7)
        val time = day.bounds(zone).first
        val filter = LogFilter("car", day, "  write  ", zone)
        assertTrue(filter.matches(time, "car", "Car: Write status=0"))
        assertFalse(filter.matches(time, "gate", "Gate: Write status=0"))
        assertFalse(filter.matches(time, null, "Write status=0"))
        assertFalse(filter.matches(time, "car", "Read status=0"))
        assertFalse(filter.matches(time - 1, "car", "Write status=0"))
    }

    @Test fun clearingDatePreservesDeviceAndSearchFilters() {
        val filter = LogFilter("car", LogDay(2026, 8, 7), "press", zone).copy(day = null)
        assertTrue(filter.matches(0, "car", "Pressed"))
        assertFalse(filter.matches(0, "gate", "Pressed"))
        assertFalse(filter.matches(0, "car", "Connected"))
        assertTrue(LogFilter().matches(0, null, "anything"))
    }

    @Test fun daylightSavingDaysFollowCalendarNotFixed24Hours() {
        val dst = TimeZone.getTimeZone("America/New_York")
        val spring = LogDay(2026, 2, 8).bounds(dst)
        val autumn = LogDay(2026, 10, 1).bounds(dst)
        assertEquals(23 * 60 * 60 * 1000L, spring.last + 1 - spring.first)
        assertEquals(25 * 60 * 60 * 1000L, autumn.last + 1 - autumn.first)
    }
}
