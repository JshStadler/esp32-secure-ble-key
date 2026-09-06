package dev.jshstadler.carkey

object AppPolicies {
    enum class AuthenticationRoute { COMBINED, BIOMETRIC, CREDENTIAL, UNAVAILABLE }
    fun authenticationRoute(api: Int, available: Boolean, deviceSecure: Boolean): AuthenticationRoute = when {
        available && api >= 30 -> AuthenticationRoute.COMBINED
        available -> AuthenticationRoute.BIOMETRIC
        deviceSecure -> AuthenticationRoute.CREDENTIAL
        else -> AuthenticationRoute.UNAVAILABLE
    }
    const val DIAGNOSTIC_RETENTION_MS = 24L * 60 * 60 * 1000
    const val OPERATION_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    const val CACHED_FAILURES_BEFORE_FALLBACK = 3

    fun retentionCutoff(now: Long, diagnostic: Boolean): Long =
        now - if (diagnostic) DIAGNOSTIC_RETENTION_MS else OPERATION_RETENTION_MS

    fun <T> replaceSession(items: List<T>, session: String, sessionOf: (T) -> String?, replacement: T): List<T> =
        items.filterNot { sessionOf(it) == session } + replacement

    fun shouldOfferScanFallback(directFailures: Int, preferDirect: Boolean): Boolean =
        preferDirect && directFailures >= CACHED_FAILURES_BEFORE_FALLBACK
}
