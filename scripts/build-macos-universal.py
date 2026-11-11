"""Build and audit Universal macOS bundles using a prepared Universal2 Python venv."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TARGET = "universal-apple-darwin"
ARCHITECTURES = ("aarch64-apple-darwin", "x86_64-apple-darwin")
SERVICES = ("clash-verge-service", "clash-verge-service-install", "clash-verge-service-uninstall")
CORES = ("verge-mihomo", "verge-mihomo-alpha")


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def require_universal(path):
    architectures = subprocess.check_output(["lipo", "-archs", str(path)], text=True).split()
    if not {"arm64", "x86_64"}.issubset(architectures):
        raise SystemExit(f"Not Universal2: {path}: {' '.join(architectures)}")


def main():
    if platform.system() != "Darwin":
        raise SystemExit("Run this script on macOS with a Universal2 Python environment.")
    require_universal(Path(sys.executable).resolve())
    environment = dict(os.environ, CARGO_BUILD_TARGET=TARGET)
    # PyInstaller validates every bundled native extension; do not resync thin wheels afterward.
    run(sys.executable, "scripts/package-companion.py", env=environment)

    staging = ROOT / "target/universal-resources"
    resources = ROOT / "src-tauri/resources"
    sidecars = ROOT / "src-tauri/sidecar"
    for architecture in ARCHITECTURES:
        run("pnpm", "prebuild", architecture)
        destination = staging / architecture
        destination.mkdir(parents=True, exist_ok=True)
        for name in SERVICES:
            shutil.copy2(resources / name, destination / name)

    for name in SERVICES:
        run("lipo", "-create", *(str(staging / arch / name) for arch in ARCHITECTURES),
            "-output", str(resources / name))
    for name in CORES:
        run("lipo", "-create", *(str(sidecars / f"{name}-{arch}") for arch in ARCHITECTURES),
            "-output", str(sidecars / f"{name}-{TARGET}"))

    config = json.dumps({"build": {"beforeBuildCommand": "pnpm run web:build"}})
    run("pnpm", "exec", "tauri", "build", "--target", TARGET,
        "--bundles", "app,dmg", "--config", config)

    bundle = ROOT / "target" / TARGET / "release/bundle/macos/Pilgrim Workspace.app"
    if os.environ.get("CARGO_TARGET_DIR"):
        bundle = ROOT / os.environ["CARGO_TARGET_DIR"] / TARGET / "release/bundle/macos/Pilgrim Workspace.app"
    count = 0
    for path in bundle.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        description = subprocess.check_output(["file", "-b", str(path)], text=True)
        if "Mach-O" in description:
            require_universal(path)
            count += 1
    if count == 0:
        raise SystemExit(f"No native binaries found in {bundle}")
    run("codesign", "--verify", "--deep", "--strict", str(bundle))
    print(f"Verified {count} Universal2 Mach-O files and bundle signature: {bundle}")


if __name__ == "__main__":
    main()
