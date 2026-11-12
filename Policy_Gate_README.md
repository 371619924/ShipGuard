# ShipGuard

A local security gate work sample for declared Kubernetes JSON, a supported Terraform plan JSON subset, Python AST calls and selected credential-shaped patterns. All examples, plan values and token strings are synthetic. This project is separate from historical internships.

## Run

Python 3.10+ is sufficient. The scanner and its tests use only the standard library. No cloud credentials, Docker, Terraform, Kubernetes cluster or third-party security scanner are required.

```bash
python3 -m unittest discover -s tests -v
python3 integration.py
python3 evaluate.py
python3 check_workflow.py
python3 run.py --repo repository --out evidence/repository --as-of 2026-10-30
python3 reproduce.py
```

Make targets: `test`, `evaluate`, `check`, `reproduce`. The clean reproduction copies source and fixtures without old evidence or bytecode, then runs tests, labeled evaluation and a repository scan. The workflow structure check is a separate local command.

Expected evidence: 36 unit tests, 16 CLI checks, 24 labeled cases (17 positive and seven clean), 12 workflow structure checks. Corpus rule-set comparison yields 17 expected rule hits, zero extra hits and zero missed hits. This is a small self-authored corpus, not a production accuracy benchmark. Unit tests and corpus cases may exercise the same behavior.

## Gate states

- Zero: no active findings in the declared supported scope.
- One: blocking findings exist.
- Two: complete analysis failed; fix scope, types, syntax or exceptions before proceeding.

```bash
python3 run.py --repo fixtures/unsafe --out evidence/unsafe --as-of 2026-10-30
python3 run.py --repo fixtures/safe --out evidence/safe --as-of 2026-10-30
```

The first returns one with 17 findings; the second returns zero. Integration checks verify a reviewed file replacement in a temporary copy turns the unsafe sample clean. The tool never applies infrastructure changes or rotates credentials. fixtures/Reviewed_Changes.patch is a review aid, not an automatic repair.

## Declared scope

manifest.json lists one Kubernetes input, one Terraform input and source/config files. Only listed files are checked. Paths cannot escape the selected root or traverse symlinks. Duplicate paths, invalid UTF-8, malformed JSON, unsupported kinds/types and oversized inputs fail analysis. Maximums: 32 listed files, 256 KiB each, 1 MiB total. These limits do not provide process isolation or protection against concurrent file replacement.

Kubernetes supports JSON arrays of Linux v1 Pods and apps/v1 Deployments, including ordinary, init and ephemeral containers. Terraform supports resource_changes for aws_security_group, aws_vpc_security_group_ingress_rule, aws_ebs_volume, aws_s3_bucket_public_access_block and aws_iam_policy. It checks after for create/update/no-op/replacement and skips delete-only targets. Security-critical after_unknown blocks; an unknown computed ID alone does not. Inputs simulate Terraform plan structure; no real plan was generated here.

## Findings and exceptions

JSON and SARIF 2.1.0 structures retain rule IDs, messages and fingerprints. Python/config line numbers refer to their files. JSON findings use document line one plus an exact JSON Pointer. Full official SARIF Schema validation and GitHub import have not been performed.

Fingerprints hash rule, path, pointer and line. Unchanged input is deterministic; location changes can invalidate exceptions. Optional repository-local exceptions require an exact current fingerprint, owner, reason and expiry. Duplicate, stale and expired entries fail. Expiry is inclusive. TF-UNKNOWN cannot be waived. Use `--exceptions exceptions.json`; production needs real approval and trusted current time, because metadata alone does not authenticate an owner.

Reports do not echo matched credential lines. Known patterns are also redacted during serialization. The detector covers a narrow AKIA-shaped pattern and selected gh-prefixed shapes; it neither validates credentials nor guarantees universal secret detection. Synthetic detector tokens are intentionally present in fixtures.

## CI and limitations

The provided Security_Checks.yml uses JSON-compatible YAML, ordinary PR/push/manual triggers, contents:read, a pinned checkout commit and disabled persisted checkout credentials. It runs tests, evaluation and the declared repository gate. Twelve local structure checks pass; GitHub-hosted CI was not run. Protect scanner, manifest, workflow and exception changes before relying on enforcement.

This is not complete Kubernetes Restricted compliance, IAM effective-permission evaluation, HCL parsing, cloud audit, mature SAST/taint analysis, dependency vulnerability scanning, image scanning/signature verification, SBOM generation or AI runtime defense. OPA, Conftest, Kyverno, Trivy and Semgrep were not executed. Digest checking is syntax only; example images are not pulled. The companion design, threat model, runbook and validation report explain these boundaries.

## Project files

shipguard/engine.py contains typed input handling, policies, findings, exceptions and SARIF conversion. run.py is the CLI. Generate_Fixtures.py defines data and labels before scanning and overwrites fixture/repository files when rerun. tests, integration.py, evaluate.py, check_workflow.py and reproduce.py provide the separate evidence layers. evidence retains logs, raw reports, corpus results and reproduction results.

Reference documents: Kubernetes Pod Security Standards and Security Context; HashiCorp Terraform JSON Output Format; GitHub Actions Secure Use Reference; OASIS SARIF 2.1.0 specification. Exact links are in the companion design document.
