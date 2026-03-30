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

        // 1. Title (Slightly lower to avoid top curve clipping)
        dc.setColor(Graphics.COLOR_WHITE, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, h * 0.15, Graphics.FONT_SMALL, "BLE Car Key",
                    Graphics.TEXT_JUSTIFY_CENTER);

        // 2. Connection status indicator (The Dot)
        var connected = _bleHandler.isConnected();
        var state = _bleHandler.getState();

        if (connected) {
            dc.setColor(Graphics.COLOR_GREEN, Graphics.COLOR_TRANSPARENT);
        } else if (state == 1 /* STATE_SCANNING */ || state == 2 /* STATE_CONNECTING */) {
            dc.setColor(Graphics.COLOR_YELLOW, Graphics.COLOR_TRANSPARENT);
        } else {
            dc.setColor(Graphics.COLOR_RED, Graphics.COLOR_TRANSPARENT);
        }
        dc.fillCircle(centerX, h * 0.28, 6); // Slightly smaller dot

        // 3. Press button (Centered more vertically)
        var btnY = h * 0.52; 
        var btnRadius = h * 0.18; // Slightly bigger for easier tapping

        dc.setColor(connected ? Graphics.COLOR_GREEN : Graphics.COLOR_DK_GRAY, Graphics.COLOR_TRANSPARENT);
        dc.fillCircle(centerX, btnY, btnRadius);

        // Button label
        dc.setColor(Graphics.COLOR_BLACK, Graphics.COLOR_TRANSPARENT);
        dc.drawText(centerX, btnY, Graphics.FONT_SMALL, "Press",
                    Graphics.TEXT_JUSTIFY_CENTER | Graphics.TEXT_JUSTIFY_VCENTER);

        // 4. Status text (MOVED TO BOTTOM)
        dc.setColor(Graphics.COLOR_LT_GRAY, Graphics.COLOR_TRANSPARENT);
        // Using 0.85 keeps it visible on round screens without getting cut off
        dc.drawText(centerX, h * 0.85, Graphics.FONT_TINY, _bleHandler.getStatusText(),
                    Graphics.TEXT_JUSTIFY_CENTER);
    }
}
