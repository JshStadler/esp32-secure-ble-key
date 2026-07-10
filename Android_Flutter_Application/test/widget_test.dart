// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';

import 'package:car_unlock/main.dart';

void main() {
  test('BLE connection states expose stable user labels', () {
    expect(BleConnectionState.disconnected.label, 'Disconnected');
    expect(BleConnectionState.scanning.label, 'Scanning...');
    expect(BleConnectionState.connecting.label, 'Connecting...');
    expect(BleConnectionState.connected.label, 'Connected');
  });
}
