"""Extract production radio NVS functions for host-side storage fault tests."""
from pathlib import Path
source = Path("ESP32-C3_Firmware/main/main.c").read_text()
start = source.index("static void load_radio_config(void)")
end = source.index("/* ============================================================", start)
Path("radio_nvs_under_test.inc").write_text(source[start:end])
