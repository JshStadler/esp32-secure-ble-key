package dev.logiclabs.remotekey

/** Retry stages stay in Diagnostics; the device card presents one continuous attempt. */
internal object ConnectionStatusText {
    fun label(state: BleCarKeyClient.State, message: String, hasConnected: Boolean): String = when (state) {
        BleCarKeyClient.State.SCANNING, BleCarKeyClient.State.CONNECTING, BleCarKeyClient.State.RETRYING ->
            if (hasConnected) "Reconnecting…" else "Connecting…"
        BleCarKeyClient.State.DISCONNECTED -> if (message == "Disconnected") "Idle" else message
        BleCarKeyClient.State.CONNECTED -> "Connected"
    }
}
