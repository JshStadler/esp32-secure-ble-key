package dev.logiclabs.remotekey

internal enum class PressWidgetIcon(val label: String, val drawable: Int) {
    CAR("Car", R.drawable.ic_car),
    GATE("Gate", R.drawable.ic_gate),
    DOOR("Door", R.drawable.ic_widget_door),
    GARAGE("Garage", R.drawable.ic_widget_garage),
    KEY("Key", R.drawable.ic_key_notification);

    companion object {
        fun saved(value: String?, type: BleDeviceType?) = entries.firstOrNull { it.name == value }
            ?: if (type == BleDeviceType.ESPHOME_ACCESS) GATE else CAR
    }
}
