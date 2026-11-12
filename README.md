# ShipGuard: Edge Update Validation

Linux/Python test automation for a small signed application-update protocol, extending the existing ShipGuard policy gate. Completed October-November 2026. The edge extension is a local work sample, not an implementation of Razor or a certified updater.

## Reproduce

Python 3.12, Linux, `make`, and `cryptography==50.0.0` are used. No production credentials or test devices are required for the local suite.

```bash
python -m pip install -r requirements.txt
python validate_all.py
python -m edge_update.device_matrix
python -m edge_update.device_matrix --local --expect-arch x86_64 --expect-distro debian
```

`validate_all.py` runs six stages, then repeats them in a clean source-only copy and compares edge case results. `evidence` retains individual command logs, policy findings, labeled policy cases, and edge JSON/JUnit reports. The edge suite has 24 tests; one deliberately demonstrates the clock-rollback limitation below. These are authored protocol/fault tests, not independent certification or real device availability measurements.

## State and failure model

A generated Ed25519 key signs canonical metadata containing version, SHA-256, size, expiry, and a fixed application target. The installer trusts only its configured public key; test private keys are ephemeral fixtures. It verifies metadata, version, target and bytes before staging a content-addressed image. Under a per-device file lock, a complete image is flushed before atomically replacing a state record containing both active digest and minimum accepted version. Directory fsync follows replacement. Recovery verifies the committed image; abandoned staging files do not become active.

Real child processes terminate during a partial write, after staging, and after state commit. Restart checks distinguish the old complete image from the new complete image. Loopback HTTP fixtures truncate responses, return an initial 503, and delay chunks. The harness retries explicitly and verifies the committed image remains available without a server. A regression test exposed bounded HTTP reads returning a short body without an exception; explicit Content-Length validation now rejects that truncation.

Tests also cover payload/metadata tampering, a different signing key, downgrade/replay, oversize inputs, traversal, concurrent writers, corruption, reset, and injected time. Factory reset intentionally reinitializes the version floor; it is a trusted provisioning operation, not an unprivileged recovery command.

## Devices and containers

Actual execution: Debian 13, x86_64, Python 3.12, local filesystem and loopback networking. Each test provisions its own temporary device root; these are isolated directories, not VMs or physical boards.

`edge_update/device_matrix.py` emits six **planned** x86_64/aarch64 × Debian/Ubuntu/Fedora profiles and refuses a mismatched local host. Capture device OS/architecture before executing the same suite on provided hosts. `edge_update/Dockerfile` is an authored non-root test image configuration; it has not been built or run here. Example future builds:

```bash
docker build --platform linux/amd64 -f edge_update/Dockerfile -t edge-tests .
docker build --platform linux/arm64 -f edge_update/Dockerfile -t edge-tests-arm .
```

The GitHub Actions workflow includes dependency installation and the edge suite. Only local workflow structure checks ran; no hosted CI execution is claimed.

## Limits and next experiments

Process termination is not physical power loss: no flash controller, filesystem crash consistency, bootloader, A/B partition, electrical power cycle, or actual reboot was tested. POSIX fsync/rename is a design assumption, not hardware durability evidence. Local trusted key/state files must resist modification; there is no TPM monotonic counter or key rotation. Only one application object is managed; orphan cleanup/storage exhaustion recovery is not implemented. Download and decoded payload caps are both 256 KiB, so base64 envelope overhead reduces the practical transport payload size.

Forward clock skew rejects expired metadata. **Backward clock skew can accept expired signed metadata**; its expected-limit test passes by observing this weakness. A trusted time source/persisted monotonic time policy is needed before deployment. No `tc/netem`, Sigstore, SBOM, VM, arm64 runtime, or multi-distribution runtime was executed. Next device work would add trusted time, network namespaces/netem, host image provisioning and instrumented power-cycle tests.

`Policy_Gate_README.md` documents the retained narrow Kubernetes/Terraform/credential-pattern scanner, its independent limits and original commands. Its 36 unit tests are distinct from the 24 edge tests; additional CLI/corpus/workflow checks have separate counts.

References used for threat categories and design: https://uptane.org/docs/latest/standard/uptane-standard ; https://theupdateframework.io/ ; https://docs.python.org/3/library/os.html#os.replace . No full TUF/Uptane conformance is claimed.
