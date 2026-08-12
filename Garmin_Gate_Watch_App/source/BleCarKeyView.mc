using Toybox.WatchUi;
using Toybox.Graphics;
using Toybox.System;

class BleCarKeyView extends WatchUi.View {

    var _bleHandler;

    function initialize(bleHandler) {
        View.initialize();
        _bleHandler = bleHandler;
    }

    function onLayout(dc) {
    }

    function onUpdate(dc) {
        // Clear screen
        dc.setColor(Graphics.COLOR_BLACK, Graphics.COLOR_BLACK);
        dc.clear();

        var w = dc.getWidth();
        var h = dc.getHeight();
        var centerX = w / 2;

        // Title stays within the full-width portion of round displays.
        dc.setColor(Graphics.COLOR_WHITE, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, h * 0.13, Graphics.FONT_SMALL, "BLE Gate Key",
                    Graphics.TEXT_JUSTIFY_CENTER);

        // 2. Connection status indicator (The Dot)
        var connected = _bleHandler.isConnected();
        var queued = _bleHandler.hasPendingPress();
        var state = _bleHandler.getState();

        if (queued) {
            dc.setColor(Graphics.COLOR_YELLOW, Graphics.COLOR_TRANSPARENT);
        } else if (connected) {
            dc.setColor(Graphics.COLOR_GREEN, Graphics.COLOR_TRANSPARENT);
        } else if (state == 1 /* STATE_SCANNING */ || state == 2 /* STATE_CONNECTING */) {
            dc.setColor(Graphics.COLOR_YELLOW, Graphics.COLOR_TRANSPARENT);
        } else {
            dc.setColor(Graphics.COLOR_RED, Graphics.COLOR_TRANSPARENT);
        }
        dc.fillCircle(centerX, h * 0.25, 5);

        // Present only concise operational states. Detailed scan and GATT
        // diagnostics remain in the app log instead of spilling off-screen.
        var statusText = _bleHandler.getStatusText();
        if (state == 1 /* STATE_SCANNING */) {
            statusText = "Scanning";
        } else if (state == 2 /* STATE_CONNECTING */) {
            statusText = "Connecting";
        } else if (statusText.find("Connection slow") != null) {
            statusText = "Connecting";
        } else if (statusText.find("Retrying") != null) {
            statusText = "Retrying";
        } else if (statusText.find("Set PSK") != null) {
            statusText = "PSK not set";
        } else if (statusText.find("Press to reconnect") != null) {
            statusText = "Press to connect";
        }
        dc.setColor(Graphics.COLOR_LT_GRAY, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, h * 0.29, Graphics.FONT_TINY, statusText,
                    Graphics.TEXT_JUSTIFY_CENTER);

        // 3. Press button (Centered more vertically)
        var btnY = h * 0.55;
        var btnRadius = h * 0.18; // Slightly bigger for easier tapping

        if (queued) {
            dc.setColor(Graphics.COLOR_YELLOW, Graphics.COLOR_TRANSPARENT);
        } else {
            dc.setColor(connected ? Graphics.COLOR_GREEN : Graphics.COLOR_DK_GRAY, Graphics.COLOR_TRANSPARENT);
        }
        dc.fillCircle(centerX, btnY, btnRadius);

        if (queued) {
            dc.setColor(Graphics.COLOR_WHITE, Graphics.COLOR_TRANSPARENT);
            dc.setPenWidth(3);
            dc.drawCircle(centerX, btnY, btnRadius + 7);
        }

        // Button label
        dc.setColor(Graphics.COLOR_BLACK, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, btnY, Graphics.FONT_SMALL, queued ? "Queued" : "Press",
                    Graphics.TEXT_JUSTIFY_CENTER | Graphics.TEXT_JUSTIFY_VCENTER);

        dc.setColor(Graphics.COLOR_DK_GRAY, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, h * 0.81, Graphics.FONT_TINY, "SELECT to press",
                    Graphics.TEXT_JUSTIFY_CENTER);
    }
}
