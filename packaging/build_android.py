#!/usr/bin/env python3
"""Build standalone Android ARM64 binary/bundle for snort."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Android ARM64 standalone executable for snort")
    parser.add_argument("--output-dir", default="dist", help="Output directory")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "snort-android-arm64"

    print(f"[*] Packaging standalone Android ARM64 executable: {target}...")

    # Staging directory for zipapp
    staging = Path(tempfile.mkdtemp(prefix="snort_android_"))
    try:
        # Copy snort package
        shutil.copytree(root / "snort", staging / "snort")
        shutil.copytree(root / "third_party", staging / "third_party")
        shutil.copytree(root / "lab", staging / "lab")

        # Create __main__.py
        main_py = staging / "__main__.py"
        main_py.write_text(
            'import sys\nfrom snort.cli import main\nif __name__ == "__main__":\n    sys.exit(main())\n',
            encoding="utf-8",
        )

        # Build zipapp archive in memory or temp
        archive_path = staging / "archive.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in staging.rglob("*"):
                if item == archive_path or "__pycache__" in str(item):
                    continue
                if item.is_file():
                    arcname = item.relative_to(staging)
                    zf.write(item, arcname)

        # Android universal shebang trampoline: works in Termux, Android shell, ADB, or Linux
        shebang = (
            b'#!/bin/sh\n'
            b'# Universal Android ARM64 / Termux launcher for snort\n'
            b'if [ -x "/data/data/com.termux/files/usr/bin/python3" ]; then\n'
            b'    exec /data/data/com.termux/files/usr/bin/python3 "$0" "$@"\n'
            b'elif command -v python3 >/dev/null 2>&1; then\n'
            b'    exec python3 "$0" "$@"\n'
            b'elif command -v python >/dev/null 2>&1; then\n'
            b'    exec python "$0" "$@"\n'
            b'else\n'
            b'    echo "Error: python3 not found on Android environment (install via \'pkg install python\' in Termux)" >&2\n'
            b'    exit 127\n'
            b'fi\n'
        )

        # Write executable
        with open(target, "wb") as out_f:
            out_f.write(shebang)
            with open(archive_path, "rb") as in_f:
                out_f.write(in_f.read())

        # Set executable permissions
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        size_mb = target.stat().st_size / (1024 * 1024)
        print(f"[*] Successfully built standalone Android binary: {target} ({size_mb:.2f} MB)")

        # Verify it runs locally on host
        print(f"[*] Testing {target} --help...")
        res = os.system(f"{target} --help > /dev/null")
        if res == 0:
            print("[*] Local execution test: OK")
        else:
            print("[!] Warning: Local execution test exited with code", res)

    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
