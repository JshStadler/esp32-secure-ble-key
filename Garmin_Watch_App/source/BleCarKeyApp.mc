using Toybox.Application;
using Toybox.WatchUi;
using Toybox.System;

class BleCarKeyApp extends Application.AppBase {

    var _bleHandler = null;

    function initialize() {
        AppBase.initialize();
    }

    function onStart(state) {
        _bleHandler = new BleHandler();
        _bleHandler.startScan();
    }

    function onStop(state) {
        if (_bleHandler != null) {
            _bleHandler.cleanup();
        }
    }

    function getInitialView() {
        var view = new BleCarKeyView(_bleHandler);
        var delegate = new BleCarKeyDelegate(_bleHandler);
        return [view, delegate];
    }

    function getBleHandler() {
        return _bleHandler;
    }
}