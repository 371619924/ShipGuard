import io, json, platform, sys, unittest, xml.etree.ElementTree as ET
from pathlib import Path
from edge_update.test_update import UpdateTests


class Results(unittest.TextTestResult):

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.rows = []

    def addSuccess(self, t):
        super().addSuccess(t)
        self.rows.append({"case": t._testMethodName, "status": "passed"})

    def addFailure(self, t, e):
        super().addFailure(t, e)
        self.rows.append({"case": t._testMethodName, "status": "failed"})

    def addError(self, t, e):
        super().addError(t, e)
        self.rows.append({"case": t._testMethodName, "status": "error"})


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence/edge_update")
    out.mkdir(parents=True, exist_ok=True)
    stream = io.StringIO()
    r = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Results).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(UpdateTests)
    )
    (out / "Test_Log.txt").write_text(stream.getvalue())
    report = {
        "runtime": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "tests": r.testsRun,
        "passed": len(r.rows) - len(r.errors) - len(r.failures),
        "cases": r.rows,
        "limitations": [
            "No physical power-cycle or hardware durability proof",
            "No arm64, VM, container or multi-distribution runtime executed",
            "Clock rollback accepted without trusted time; explicit expected limitation",
            "No tc/netem execution; loopback HTTP fixtures only",
            "No Razor, Sigstore or SBOM integration",
        ],
    }
    (out / "Results.json").write_text(json.dumps(report, indent=2))
    suite = ET.Element(
        "testsuite",
        name="EdgeUpdate",
        tests=str(r.testsRun),
        failures=str(len(r.failures)),
        errors=str(len(r.errors)),
    )
    for row in r.rows:
        c = ET.SubElement(suite, "testcase", name=row["case"])
        if row["status"] != "passed":
            ET.SubElement(c, "failure", message=row["status"])
    ET.ElementTree(suite).write(
        out / "JUnit.xml", encoding="utf-8", xml_declaration=True
    )
    print(
        json.dumps(
            {
                "tests": r.testsRun,
                "successful": r.wasSuccessful(),
                "machine": platform.machine(),
            }
        )
    )
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
