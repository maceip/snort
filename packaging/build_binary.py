#!/usr/bin/env python3
"""Cross-platform standalone binary builder for snort CLI."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def get_target_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine

    if system == "darwin":
        return f"snort-macos-{arch}"
    elif system == "windows":
        return f"snort-windows-{arch}.exe"
    elif system == "linux":
        # Check if Android
        if "ANDROID_ROOT" in os.environ or "termux" in sys.prefix.lower():
            return f"snort-android-{arch}"
        return f"snort-linux-{arch}"
    return f"snort-{system}-{arch}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build standalone binary for snort")
    parser.add_argument("--output-name", default=None, help="Custom output binary name")
    parser.add_argument("--output-dir", default="dist", help="Output directory")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    target_name = args.output_name or get_target_name()
    print(f"[*] Building standalone binary for target: {target_name}...")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        "snort_bin",
        "--clean",
        "--noconfirm",
        "--collect-all",
        "lance",
        "--collect-all",
        "duckdb",
        "--collect-all",
        "pyarrow",
        "--collect-all",
        "blake3",
        str(root / "snort" / "cli.py"),
    ]

    print(f"+ {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=root)

    ext = ".exe" if sys.platform == "win32" else ""
    built_path = root / "dist" / f"snort_bin{ext}"
    final_path = out_dir / target_name

    if not built_path.exists():
        raise FileNotFoundError(f"PyInstaller output not found at {built_path}")

    shutil.move(str(built_path), str(final_path))
    if sys.platform != "win32":
        final_path.chmod(0o755)

    print(f"[*] Successfully built: {final_path} ({final_path.stat().st_size / (1024*1024):.1f} MB)")

    # Smoke test the built binary
    print(f"[*] Running smoke test: {final_path} --help...")
    test_proc = subprocess.run([str(final_path), "--help"], capture_output=True, text=True)
    if test_proc.returncode != 0:
        print(f"Smoke test failed:\n{test_proc.stderr}", file=sys.stderr)
        return test_proc.returncode
    print("[*] Smoke test passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
