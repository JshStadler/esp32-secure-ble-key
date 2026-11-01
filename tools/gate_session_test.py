"""Exercise the actual YAML session guards without gate hardware or credentials."""
from pathlib import Path
import textwrap

source = Path("ESPHome_Gate_Firmware/centurion-d5-evo-ble-v2.yaml").read_text()
handlers = []
for name in ("gate_ble_command", "gate_ble_command_part1", "gate_ble_command_part2"):
    start = source.index("        - id: " + name + "\n")
    start = source.index("              - lambda: |-\n", start) + len("              - lambda: |-\n")
    end = source.index("\n                  const auto rotate_challenge", start) if name == "gate_ble_command" else source.index("\n                  if (x.size()", start)
    guard = textwrap.dedent(source[start:end])
    handlers.append(f"static void {name}(uint16_t id) {{\n{guard}\n    accepted++;\n}}\n")
Path("gate_session_under_test.inc").write_text("\n".join(handlers))
