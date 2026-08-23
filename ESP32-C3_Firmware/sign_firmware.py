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
import site
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
    # espsecure imports pyserial from PlatformIO's main environment. Its site
    # directory is ``Lib`` on Windows and ``lib/pythonX.Y`` on Linux/macOS.
    # Discover both layouts instead of embedding one host-specific path.
    core_penv = core_dir / "penv"
    platformio_sites = [core_penv / "Lib" / "site-packages"]
    platformio_sites.extend((core_penv / "lib").glob("python*/site-packages"))
    python_paths = [esptool_dir, esptool_dir / "_contrib"]
    python_paths.extend(path for path in platformio_sites if path.is_dir())
    # A pip-installed PlatformIO (as used by GitHub Actions) keeps pyserial in
    # the Python environment running SCons rather than under PROJECT_CORE_DIR.
    # Include those site directories as well so the isolated ESP-IDF Python can
    # import all of esptool's runtime dependencies on either installation type.
    python_paths.extend(Path(path) for path in site.getsitepackages())
    user_site = site.getusersitepackages()
    if user_site:
        python_paths.append(Path(user_site))
    if process_env.get("PYTHONPATH"):
        python_paths.extend(Path(path) for path in process_env["PYTHONPATH"].split(os.pathsep) if path)
    process_env["PYTHONPATH"] = os.pathsep.join(str(path) for path in python_paths)

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
