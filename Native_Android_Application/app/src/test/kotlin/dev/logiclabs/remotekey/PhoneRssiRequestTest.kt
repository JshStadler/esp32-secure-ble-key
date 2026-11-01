package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class PhoneRssiRequestTest {
    @Test fun timeoutQuarantinesLateCallbackAndAllowsRetryAfterDrain() {
        val request = PhoneRssiRequest()
        var expiry: (() -> Unit)? = null
        val results = mutableListOf<Int?>()
        var starts = 0
        fun read() = request.request({ starts++; true }, { expiry = it }, { results += it })
        read(); expiry!!(); read()
        assertEquals(listOf(null, null), results)
        assertEquals(1, starts)
        request.complete(-98)
        assertEquals(2, results.size)
        read(); request.complete(-60); expiry!!()
        assertEquals(listOf(null, null, -60), results)
        assertEquals(2, starts)
    }

    @Test fun cancelDoesNotReleaseControllerRequestButReconnectDoes() {
        val request = PhoneRssiRequest()
        var oldTimeout: (() -> Unit)? = null
        val results = mutableListOf<Int?>()
        request.request({ true }, { oldTimeout = it }, { fail("Canceled callback") })
        request.cancel()
        request.request({ fail("Overlapping HCI request"); false }, {}, { results += it })
        request.reset()
        request.request({ true }, {}, { results += it })
        oldTimeout!!()
        request.complete(-50)
        assertEquals(listOf(null, -50), results)
    }

    @Test fun rejectedRequestAndInvalidRssiDoNotPoisonLaterRequests() {
        val request = PhoneRssiRequest()
        val results = mutableListOf<Int?>()
        request.request({ false }, { fail("No timeout required") }, { results += it })
        request.complete(-1) // Unsolicited callback ignored.
        request.request({ true }, {}, { results += it })
        request.complete(127)
        request.request({ request.complete(-70); true }, { it() }, { results += it })
        assertEquals(listOf(null, null, -70), results)
    }
}
