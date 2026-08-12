"""Replace PlatformIO's unsigned export with ESP-IDF's signed app image.

ESP-IDF creates the ``gen_signed_<project>_binary`` CMake target when signed
updates are enabled. PlatformIO's ESP-IDF builder exports ``firmware.bin``
directly from the ELF and otherwise bypasses that target. This post action
builds the official signed target and copies its result to the filename users
and the Android OTA picker expect.
"""

from pathlib import Path
import os
import re
import shutil
import subprocess

Import("env")  # type: ignore[name-defined]  # supplied by PlatformIO/SCons


def sign_exported_firmware(source, target, env):
    build_dir = Path(env.subst("$BUILD_DIR"))
    exported_image = build_dir / "firmware.bin"
    signed_image = build_dir / "firmware-signed.bin"
    project_dir = Path(env.subst("$PROJECT_DIR"))
    signing_key = project_dir / "secure_boot_signing_key.pem"
    esptool_dir = Path(env.PioPlatform().get_package_dir("tool-esptoolpy"))

    # Use the exact Python interpreter CMake selected for ESP-IDF. Its native
    # crypto wheels match espsecure; PlatformIO's main environment supplies
    # the pure-Python serial package imported by esptool.
    cache = (build_dir / "CMakeCache.txt").read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^PYTHON:UNINITIALIZED=(.+)$", cache, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find ESP-IDF Python in CMakeCache.txt")
    idf_python = Path(match.group(1).strip())
    core_dir = Path(env.subst("$PROJECT_CORE_DIR"))
    process_env = os.environ.copy()
    process_env["PYTHONPATH"] = os.pathsep.join(
        [str(esptool_dir), str(esptool_dir / "_contrib"), str(core_dir / "penv" / "Lib" / "site-packages")]
    )

    subprocess.run(
        [
            str(idf_python), "-m", "espsecure", "sign_data",
            "--version", "2", "--keyfile", str(signing_key),
            "-o", str(signed_image), str(exported_image),
        ],
        check=True,
        env=process_env,
    )
    if not signed_image.is_file():
        raise RuntimeError(f"ESP-IDF signed image was not created: {signed_image}")
    if signed_image.stat().st_size > 0x1E0000:
        raise RuntimeError("Signed image exceeds the 0x1e0000-byte OTA slot")
    shutil.copy2(signed_image, exported_image)
    signed_image.unlink()
    print(f"Exported signed OTA image: {exported_image}")


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", sign_exported_firmware)
