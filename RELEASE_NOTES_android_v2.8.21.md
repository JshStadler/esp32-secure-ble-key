# Remote Key Android 2.8.21 (build 47)

- Follow the phone's light/dark theme by default, or choose Light or Dark in **App settings → Theme and accent colour**.
- Choose Blue, Teal, Green, Purple, Orange or Rose as the app accent. Dashboard actions, native controls, dialogs and logs use matching colours with readable text.
- Light and dark palettes cover setup, authentication, device/radio settings, device health, firmware updates, logs, privacy and widget configuration.
- Set an inactive background colour independently for each widget. Choose a preset or enter a six-digit RGB hex colour, with a live preview. Black remains the default for existing and new widgets.
- Edit a placed widget through the launcher's widget settings/Edit action. Its device, icon and current colour are preselected; Save commits changes and Cancel preserves the existing configuration.
- Widget labels and icons adapt their contrast to the selected inactive colour. Connected widgets stay blue, and progress/success/error colours continue to indicate status.
- Widgets retain their existing tap-to-press and tap-to-cancel behaviour, including 1×1 layouts and independent requests for different devices. No connect-only or custom long-press action was added.

No ESPHome, standalone ESP or Garmin update is required. No new permissions or scheduled/background work are introduced.

## Manual checks

1. Leave Theme on Follow system and switch the phone between light and dark. Check the dashboard, app/device settings and logs. Then select a manual theme and accent, close/reopen the app and verify they persist.
2. Edit a placed 1×1 widget, select a light or custom inactive colour and save. Verify its selected device/icon remain correct, idle content stays legible, and connected/progress/result colours still work. Cancel an edit and confirm it preserves the previous colour.
3. With a safe device in range, verify one ordinary press and one canceled out-of-range request using the existing widget behaviour.
