using Toybox.WatchUi;
using Toybox.System;

class BleCarKeyDelegate extends WatchUi.BehaviorDelegate {

    var _bleHandler;

    function initialize(bleHandler) {
        BehaviorDelegate.initialize();
        _bleHandler = bleHandler;
    }

    // SELECT button = unlock
    function onSelect() {
        _bleHandler.sendUnlock();
        return true;
    }

    // BACK button = exit app
    function onBack() {
        _bleHandler.disconnect();
        System.exit();
    }
}
