"""Compile the real firmware load/save functions against an error-injecting NVS fake."""
from pathlib import Path
source = Path("ESP32-C3_Firmware/main/main.c").read_text()
start = source.index("static bool save_psk(const char *new_psk);")
end = source.index("static void configure_power_management", start)
Path("nvs_under_test.inc").write_text(source[start:end])
