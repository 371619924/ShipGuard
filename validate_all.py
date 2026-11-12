"""Run the complete ShipGuard suite with explicit UTF-8 subprocess logging."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
COMMANDS = [
    ["-m", "unittest", "discover", "-s", "tests", "-v"],
    ["integration.py"],
    ["evaluate.py"],
    ["check_workflow.py"],
    [
        "run.py",
        "--repo",
        "repository",
        "--out",
        "evidence/repository",
        "--as-of",
        "2026-10-30",
    ],
    ["-m", "edge_update.run_validation"],
]


def output_text(value):
    """Timeout output may be bytes; missing captured output may be None."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return value


def validate(root):
    out = root / "evidence"
    out.mkdir(parents=True, exist_ok=True)
    records = []
    env = os.environ.copy()
    env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")

    for i, args in enumerate(COMMANDS, start=1):
        log_path = out / f"Stage_{i}_Log.txt"
        print(f"[{i}/{len(COMMANDS)}] Running: {' '.join(args)}", flush=True)
        try:
            result = subprocess.run(
                [sys.executable, *args],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="backslashreplace",
                env=env,
                timeout=45,
            )
        except subprocess.TimeoutExpired as error:
            log_path.write_text(
                output_text(error.stdout)
                + output_text(error.stderr)
                + "\nStage timed out after 45 seconds.\n",
                encoding="utf-8",
            )
            raise RuntimeError(
                f"Stage {i} timed out. See log: {log_path}"
            ) from error

        log = output_text(result.stdout) + output_text(result.stderr)
        log_path.write_text(log, encoding="utf-8")
        records.append({"arguments": args, "exit_code": result.returncode})
        if result.returncode:
            tail = "\n".join(log.splitlines()[-20:])
            raise RuntimeError(
                f"Stage {i} failed with exit code {result.returncode}.\n"
                f"Log: {log_path}\n{tail}"
            )
    return records


def main():
    # The update suite uses Unix fcntl locks and POSIX directory fsync.
    if os.name == "nt":
        print(
            "The complete ShipGuard suite requires Linux/WSL.\n"
            "Open Ubuntu/WSL and run this file with its Linux Python.\n"
            f"Current interpreter: {sys.executable}",
            file=sys.stderr,
        )
        return 2

    required = ["tests", "edge_update/guard.py", "repository/manifest.json"]
    missing = [name for name in required if not (ROOT / name).exists()]