"""Extract the production timer/host callbacks for deterministic interleavings."""
from pathlib import Path

source = Path("ESP32-C3_Firmware/main/main.c").read_text()

def function(name):
    start = source.index(name + "(")
    # The completion callback also has a forward declaration.
    while source.find(";", start) < source.find("{", start):
        start = source.index(name + "(", start + len(name))
    start = source.rfind("static ", 0, start)
    body = source.index("{", start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]

Path("button_under_test.inc").write_text("\n\n".join(function(name) for name in (
    "button_timer_callback", "receipt_button_complete", "press_remote_button")))
