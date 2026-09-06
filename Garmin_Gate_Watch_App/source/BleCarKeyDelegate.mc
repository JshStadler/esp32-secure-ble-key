using Toybox.WatchUi;
using Toybox.System;

class BleCarKeyDelegate extends WatchUi.BehaviorDelegate {

    var _bleHandler;

    function initialize(bleHandler) {
        BehaviorDelegate.initialize();
        _bleHandler = bleHandler;
    }

    // SELECT button = press the remote button
    function onKey(event) {
        _bleHandler.recordInteraction();
        return BehaviorDelegate.onKey(event);
    }

    function onTap(event) {
        _bleHandler.recordInteraction();
        return BehaviorDelegate.onTap(event);
    }

    function onSwipe(event) {
        _bleHandler.recordInteraction();
        return BehaviorDelegate.onSwipe(event);
    }

    function onSelect() {
        _bleHandler.sendPress();
        return true;
    }

    // MENU button (long-press UP) = force unpair + reconnect fresh
    function onMenu() {
        _bleHandler.forceUnpair();
        return true;
    }

    // BACK button = exit app (preserves pairing for fast reconnect)
    function onBack() {
        _bleHandler.cleanup();
        System.exit();
    }
}
