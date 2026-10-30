# Remote Key Android 2.8.19 (build 45)

The press widget requests one launcher cell by one cell and can shrink to 48×48 dp.
Its smallest layout shows the selected device icon with a clock, success or error
badge during an action. Connection and result colors, cancellation and the full
accessibility description are preserved without squeezing text into an icon.

Responsive layouts let the launcher select an icon, compact label or full status
card as space changes, including screen rotation. Larger sizes are still available
by dragging the existing widget's resize handles. Existing widget configurations
and independent per-device press behavior are preserved.

Manual check: after updating, resize an existing widget down to 1×1 in the phone's
launcher. If that launcher has cached the old minimum, remove and re-add only the
widget. Verify Wait/cancel and result badges, the disconnected/connected colors,
rotation, and expanding back to a larger widget. No ESP or watch update is needed.
