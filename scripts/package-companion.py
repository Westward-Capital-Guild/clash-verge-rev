"""Build the native companion and its Python runtime into Tauri resources."""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
if os.environ.get("PILGRIM_WORKSPACE_BOOTSTRAP_URL"):
    sys.path.insert(0, str(ROOT / "companion"))
    from workspace_access import AccessError, WorkspaceAccess
    try:
        WorkspaceAccess(os.environ["PILGRIM_WORKSPACE_BOOTSTRAP_URL"])
    except AccessError as error:
        raise SystemExit(str(error)) from None
target = os.environ.get("CARGO_BUILD_TARGET") or os.environ.get("TAURI_ENV_TARGET_TRIPLE", "")
machine = platform.machine()
if target and (("x86_64" in target and machine not in ("x86_64", "AMD64")) or
               ("aarch64" in target and machine not in ("arm64", "aarch64"))):
    raise SystemExit("Build the companion on the target architecture; cross-runtime bundling is unsupported.")

cache = ROOT / "target/companion"
cache.mkdir(parents=True, exist_ok=True)
subprocess.run([
    sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir",
    "--name", "pilgrim-workspace-agent", "--paths", str(ROOT / "companion"),
    "--collect-submodules", "keyring.backends", "--copy-metadata", "keyring",
    "--copy-metadata", "authlib", "--collect-data", "certifi",
    "--distpath", str(cache / "dist"), "--workpath", str(cache / "build"),
    "--specpath", str(cache), str(ROOT / "companion/workspace_agent.py"),
], check=True)

resources = ROOT / "src-tauri/resources"
resources.mkdir(parents=True, exist_ok=True)
staging = resources / "companion.pending"
destination = resources / "companion"
backup = resources / "companion.previous"
if any(path.is_symlink() for path in (staging, destination, backup)):
    raise SystemExit("Refusing a symlink in companion bundle resources.")
if staging.exists():
    shutil.rmtree(staging)
shutil.copytree(cache / "dist/pilgrim-workspace-agent", staging, symlinks=True)
if backup.exists():
    shutil.rmtree(backup)
if destination.exists():
    destination.rename(backup)
try:
    staging.rename(destination)
except OSError:
    if backup.exists():
        backup.rename(destination)
    raise
if backup.exists():
    shutil.rmtree(backup)
