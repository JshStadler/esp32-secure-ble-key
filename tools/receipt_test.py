"""Extract the actual GATT handler for host-side transport/fault tests."""
from pathlib import Path
source = Path("ESP32-C3_Firmware/main/main.c").read_text()
start = source.index("static int chr_access_receipt(")
end = source.index("static int chr_access_ota_control", start)
Path("receipt_under_test.inc").write_text(source[start:end])
