"""Run the complete ShipGuard suite with UTF-8 logging."""

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
    """Convert captured output safely, including timeout output."""
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
    env.update(
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
    )

    for i, args in enumerate(COMMANDS, start=1):
        log_path = out / f"Stage_{i}_Log.txt"

        print(
            f"[{i}/{len(COMMANDS)}] Running: {' '.join(args)}",
            flush=True,
        )

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
            raise RuntimeError(f"Stage {i} timed out. See log: {log_path}") from error

        log = output_text(result.stdout) + output_text(result.stderr)
        log_path.write_text(log, encoding="utf-8")

        records.append(
            {
                "arguments": args,
                "exit_code": result.returncode,
            }
        )

        if result.returncode:
            tail = "\n".join(log.splitlines()[-20:])
            raise RuntimeError(
                f"Stage {i} failed with exit code {result.returncode}.\n"
                f"Log: {log_path}\n{tail}"
            )

    return records


def main():
    if os.name == "nt":
        print(
            "The complete ShipGuard suite requires Linux/WSL.\n"
            "Open Ubuntu/WSL and run this file with its Linux Python.\n"
            f"Current interpreter: {sys.executable}",
            file=sys.stderr,
        )
        return 2

    required = [
        "tests",
        "edge_update/guard.py",
        "repository/manifest.json",
    ]
    missing = [name for name in required if not (ROOT / name).exists()]

    if missing:
        print(
            "Place this file in the ShipGuard project root.\n"
            f"Missing project paths: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 2

    out = ROOT / "evidence"
    out.mkdir(exist_ok=True)

    report_path = out / "Reproduction_Results.json"
    report_path.unlink(missing_ok=True)

    try:
        print("=== Original source validation ===", flush=True)
        records = validate(ROOT)

        with tempfile.TemporaryDirectory(prefix="shipguard_clean_") as directory:
            fresh = Path(directory) / "ShipGuard"

            shutil.copytree(
                ROOT,
                fresh,
                ignore=shutil.ignore_patterns(
                    "evidence",
                    "__pycache__",
                    "*.pyc",
                    ".git",
                    ".venv",
                    "venv",
                    ".pytest_cache",
                    ".mypy_cache",
                ),
            )

            print(
                "=== Fresh source reproduction ===",
                flush=True,
            )
            clean = validate(fresh)

            before = json.loads(
                (ROOT / "evidence/edge_update/Results.json").read_text(encoding="utf-8")
            )
            after = json.loads(
                (fresh / "evidence/edge_update/Results.json").read_text(
                    encoding="utf-8"
                )
            )

            if before != after:
                raise RuntimeError("Fresh-source edge-update results do not match.")

            summary = {
                "stages": len(records),
                "fresh_source_stages": len(clean),
                "edge_cases": before["tests"],
                "passed": True,
            }

            result = {
                "passed": True,
                "stages": records,
                "fresh_source_stages": clean,
                "source_only_reproduction": True,
                "edge_results_match": True,
            }

        report_path.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

    except Exception as error:
        report_path.write_text(
            json.dumps(
                {
                    "passed": False,
                    "error": str(error),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(json.dumps(summary), flush=True)
    print(f"Report: {report_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
