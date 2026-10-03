#!/usr/bin/env python3
"""Build the signed Android demonstration UI; it does not include the snort engine."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def get_sdk_roots() -> list[Path]:
    candidates = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        "/usr/local/lib/android/sdk",
        "/opt/homebrew/share/android-commandlinetools",
        str(Path.home() / "Library/Android/sdk"),
        str(Path.home() / "Android/Sdk"),
    ]
    return [Path(c) for c in candidates if c and Path(c).exists()]


def find_android_tool(name: str) -> str:
    # Check PATH first
    found = shutil.which(name)
    if found:
        return found

    for root in get_sdk_roots():
        build_tools = root / "build-tools"
        if build_tools.exists():
            for v in sorted(build_tools.iterdir(), reverse=True):
                tool = v / name
                if tool.exists() and os.access(tool, os.X_OK):
                    return str(tool)

        cmdline_tools = root / "cmdline-tools" / "latest" / "bin" / name
        if cmdline_tools.exists() and os.access(cmdline_tools, os.X_OK):
            return str(cmdline_tools)

    raise FileNotFoundError(f"Android tool {name} not found")


def find_android_jar() -> str:
    for root in get_sdk_roots():
        platforms = root / "platforms"
        if platforms.exists():
            for p in sorted(platforms.iterdir(), reverse=True):
                jar = p / "android.jar"
                if jar.exists():
                    return str(jar)
    raise FileNotFoundError("android.jar not found in Android SDK platforms")


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print(f"+ {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=cwd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the signed snort demonstration APK (UI only)"
    )
    parser.add_argument("--output-dir", default="dist", help="Output directory")
    parser.add_argument(
        "--output-name", default="snort-android-arm64.apk", help="Output APK filename"
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    final_apk = out_dir / args.output_name

    aapt2 = find_android_tool("aapt2")
    d8 = find_android_tool("d8")
    zipalign = find_android_tool("zipalign")
    apksigner = find_android_tool("apksigner")
    android_jar = find_android_jar()
    javac = shutil.which("javac") or "javac"
    keytool = shutil.which("keytool") or "keytool"

    print(
        "[*] Building the Android demonstration UI; no native engine or offline assets"
    )
    print("[*] Found Android SDK build tools:")
    print(f"    aapt2      : {aapt2}")
    print(f"    d8         : {d8}")
    print(f"    zipalign   : {zipalign}")
    print(f"    apksigner  : {apksigner}")
    print(f"    android.jar: {android_jar}")

    work_dir = Path(tempfile.mkdtemp(prefix="snort_apk_build_"))
    try:
        manifest_path = work_dir / "AndroidManifest.xml"
        manifest_path.write_text(
            """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.snort.demo"
    android:versionCode="2"
    android:versionName="0.1.0-demo">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />

    <application
        android:label="Snort Demo"
        android:hasCode="true"
        android:theme="@android:style/Theme.DeviceDefault">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""",
            encoding="utf-8",
        )

        # Java source
        src_dir = work_dir / "src" / "com" / "snort" / "demo"
        src_dir.mkdir(parents=True, exist_ok=True)
        java_src = src_dir / "MainActivity.java"
        java_src.write_text(
            """package com.snort.demo;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.ScrollView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "SnortDemo";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "Snort demonstration UI started on Android");
        
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#0d1117"));
        
        TextView tv = new TextView(this);
        tv.setTextColor(Color.parseColor("#58a6ff"));
        tv.setTextSize(14f);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setPadding(36, 48, 36, 48);
        
        StringBuilder sb = new StringBuilder();
        sb.append("SNORT DEMONSTRATION\\n");
        sb.append("Android preview - version 0.1.0\\n\\n");
        sb.append("This app shows an informational preview.\\n\\n");
        sb.append("No telemetry has been ingested or analyzed.\\n\\n");
        sb.append("The native engine and offline analysis are not included in this demonstration.\\n\\n");
        sb.append("For real ingestion, search and grouping, use the snort CLI or HTTP service.\\n\\n");
        sb.append("No models, rules or sample datasets are bundled.\\n");
        
        String report = sb.toString();
        Log.i(TAG, report);
        tv.setText(report);
        scroll.addView(tv);
        setContentView(scroll);
    }
}
""",
            encoding="utf-8",
        )

        bin_dir = work_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        gen_dir = work_dir / "gen"
        gen_dir.mkdir(parents=True, exist_ok=True)

        # 1. Compile resources and link
        unaligned_apk = work_dir / "unaligned.apk"
        run(
            [
                aapt2,
                "link",
                "-I",
                android_jar,
                "--manifest",
                str(manifest_path),
                "--java",
                str(gen_dir),
                "-o",
                str(unaligned_apk),
            ]
        )

        # 2. Compile Java classes
        java_files = [str(java_src)]
        for r_file in gen_dir.rglob("*.java"):
            java_files.append(str(r_file))
        run(
            [
                javac,
                "-cp",
                android_jar,
                "-d",
                str(bin_dir),
                *java_files,
            ]
        )

        # 3. Dex with d8
        class_files = [str(cf) for cf in bin_dir.rglob("*.class")]
        dex_dir = work_dir / "dex"
        dex_dir.mkdir(parents=True, exist_ok=True)
        run(
            [
                d8,
                "--output",
                str(dex_dir),
                "--min-api",
                "26",
                *class_files,
            ]
        )

        # 4. Package only the demonstration UI. No placeholder engine or padding.
        classes_dex = dex_dir / "classes.dex"
        import zipfile

        with zipfile.ZipFile(unaligned_apk, "a") as zf:
            zf.write(classes_dex, "classes.dex")
        # 5. Zipalign
        aligned_apk = work_dir / "aligned.apk"
        run(
            [
                zipalign,
                "-f",
                "-p",
                "4",
                str(unaligned_apk),
                str(aligned_apk),
            ]
        )

        # 6. Locate or generate persistent debug keystore
        keystore_candidates = [
            root / "packaging" / "debug.keystore",
            Path.home() / ".android" / "debug.keystore",
        ]
        keystore_path = None
        for cand in keystore_candidates:
            if cand.exists():
                keystore_path = cand
                print(f"    [*] Using existing debug keystore: {keystore_path}")
                break

        if keystore_path is None:
            keystore_path = root / "packaging" / "debug.keystore"
            print(f"    [*] Generating persistent debug keystore at: {keystore_path}")
            run(
                [
                    keytool,
                    "-genkey",
                    "-v",
                    "-keystore",
                    str(keystore_path),
                    "-storepass",
                    "android",
                    "-alias",
                    "androiddebugkey",
                    "-keypass",
                    "android",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-validity",
                    "10000",
                    "-dname",
                    "CN=Android Debug,O=Android,C=US",
                ]
            )

        # 7. Sign APK
        run(
            [
                apksigner,
                "sign",
                "--ks",
                str(keystore_path),
                "--ks-pass",
                "pass:android",
                "--key-pass",
                "pass:android",
                "--out",
                str(final_apk),
                str(aligned_apk),
            ]
        )

        print(
            f"\n[+] Created signed demonstration APK (UI only): {final_apk} ({final_apk.stat().st_size} bytes)"
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
