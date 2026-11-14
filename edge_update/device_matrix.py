"""Plan physical/VM provisioning targets; execute only an explicitly matched local host."""

import argparse, json, platform, subprocess, sys
from pathlib import Path

PROFILES = [
    {"architecture": a, "distribution": d, "runtime_status": "planned; not executed"}
    for a in ["x86_64", "aarch64"]
    for d in ["debian", "ubuntu", "fedora"]
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--expect-arch")
    ap.add_argument("--expect-distro")
    ap.add_argument("--out", default="evidence/edge_update")
    a = ap.parse_args()
    if not a.local:
        print(json.dumps(PROFILES, indent=2))
        return 0
    distro = platform.freedesktop_os_release()["ID"]
    arch = platform.machine()
    if not a.expect_arch or not a.expect_distro:
        ap.error("local execution requires both expected architecture and distro")
    if (arch, distro) != (a.expect_arch, a.expect_distro):
        ap.error(f"host mismatch: actual {arch}/{distro}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "Host.json").write_text(
        json.dumps(
            {
                "architecture": arch,
                "os": platform.freedesktop_os_release(),
                "python": platform.python_version(),
            },
            indent=2,
        )
    )
    return subprocess.run(
        [sys.executable, "-m", "edge_update.run_validation", str(out)], check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
