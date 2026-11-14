import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory() as td:
        clean = Path(td) / "ShipGuard"
        shutil.copytree(
            ROOT,
            clean,
            ignore=shutil.ignore_patterns("evidence", "__pycache__", "*.pyc"),
        )
        records = []
        logs = []
        for command in [
            ["make", "test"],
            ["make", "evaluate"],
            [
                "python3",
                "run.py",
                "--repo",
                "repository",
                "--out",
                "evidence/repository",
                "--as-of",
                "2026-10-30",
            ],
        ]:
            p = subprocess.run(
                command, cwd=clean, text=True, capture_output=True, timeout=40
            )
            records.append({"command": command, "exit_code": p.returncode})
            logs.append("$ " + " ".join(command) + "\n" + p.stdout + p.stderr)
        evidence = ROOT / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "Reproduction_Log.txt").write_text("\n\n".join(logs))
        (evidence / "Reproduction_Results.json").write_text(
            json.dumps(
                {
                    "source_only_copy": True,
                    "commands": records,
                    "passed": all(x["exit_code"] == 0 for x in records),
                },
                indent=2,
            )
        )
        assert all(x["exit_code"] == 0 for x in records), records
        print("Source-only reproduction passed")


if __name__ == "__main__":
    main()
