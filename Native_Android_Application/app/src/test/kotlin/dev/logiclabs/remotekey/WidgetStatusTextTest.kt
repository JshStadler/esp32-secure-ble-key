package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class WidgetStatusTextTest {
    @Test fun aConnectionOrUncertainReceiptMustNeverLookLikeAConfirmedPress() {
        assertEquals(WidgetStatusText.Tone.CONNECTING, WidgetStatusText.tone("Connecting…"))
        assertEquals(WidgetStatusText.Tone.SENDING, WidgetStatusText.tone("Sending…"))
        assertEquals(WidgetStatusText.Tone.CONFIRMED, WidgetStatusText.tone("Pressed • disconnected"))
        assertEquals("Pressed ✓", WidgetStatusText.label("Pressed • ready for 2 minutes"))
        assertEquals(WidgetStatusText.Tone.ERROR, WidgetStatusText.tone("Unable to confirm — check the device"))
        assertEquals(WidgetStatusText.Tone.ERROR, WidgetStatusText.tone("Not sent — connection timed out"))
        assertEquals(WidgetStatusText.Tone.IDLE, WidgetStatusText.tone("Ready • 2 minutes"))
        assertFalse(WidgetStatusText.replacesCompactName("Ready • 2 minutes"))
    }
}
