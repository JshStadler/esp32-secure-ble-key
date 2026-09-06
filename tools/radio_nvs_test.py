"""Extract production radio NVS functions for host-side storage fault tests."""
from pathlib import Path
source = Path("ESP32-C3_Firmware/main/main.c").read_text()
def function(signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start:end + 1] + "\n"
    raise ValueError(f"Unterminated function: {signature}")

Path("radio_nvs_under_test.inc").write_text(
    function("static void load_radio_config(void)") +
    function("static bool save_radio_config(const radio_config_t *config)")
)
