"""Local structural checks, not a GitHub-hosted execution."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
w = json.loads((ROOT / ".github/workflows/Security_Checks.yml").read_text())
job = w["jobs"]["check"]
steps = job["steps"]
check = []


def verify(name, condition):
    check.append({"name": name, "passed": bool(condition)})
    assert condition, name


verify(
    "Only ordinary PR push and manual triggers",
    set(w["on"]) == {"pull_request", "push", "workflow_dispatch"},
)
verify("No privileged pull request trigger", "pull_request_target" not in w["on"])
verify(
    "Default contents permission is read only", w["permissions"] == {"contents": "read"}
)
verify("No job permission escalation", "permissions" not in job)
verify(
    "Every external action has a complete SHA",
    all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", s["uses"]) for s in steps if "uses" in s),
)
verify(
    "Checkout credentials are not persisted",
    steps[0]["with"]["persist-credentials"] is False,
)
verify("Job has a finite timeout", 0 < job["timeout-minutes"] <= 5)
verify("Tests are included", any(s.get("run") == "make test" for s in steps))
verify(
    "Labeled evaluation is included",
    any(s.get("run") == "make evaluate" for s in steps),
)
verify(
    "Repository gate command is included",
    steps[-1]["run"] == "python3 run.py --repo repository --out evidence/repository",
)
verify(
    "No ignored step failures",
    all(not s.get("continue-on-error", False) for s in steps),
)
verify(
    "No external expressions or configured secrets",
    "${{" not in json.dumps(w) and "secrets" not in w,
)
out = ROOT / "evidence"
out.mkdir(exist_ok=True)
(out / "Workflow_Checks.json").write_text(
    json.dumps(
        {
            "scope": "Local JSON-compatible YAML structure checks only; no GitHub runner execution",
            "checks": check,
        },
        indent=2,
    )
)
print(json.dumps({"checks": len(check), "passed": sum(x["passed"] for x in check)}))
