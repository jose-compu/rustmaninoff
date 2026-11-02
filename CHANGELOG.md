# Changelog

## 0.4.1 — 2026-11-02

### Security

- GitHub Action (`action.yml`): pass all inputs via environment variables (no `${{ inputs.* }}` interpolation into the shell script body), validate `version` / `path` / `fail-on` / `output` / `sarif-file` / `args`, and verify the downloaded archive against the published `.sha256` before install.

### Changed

- Workspace crates are **0.4.1**.
- Action default `version` pin is `0.4.1`.

## 0.4.0 — 2026-11-02

### Added

- Catalog depth: **536** built-in checks. Docker **100%** and Kubernetes **93.8%** of pinned Checkov ids ([docs/fidelity.md](docs/fidelity.md)).
- `CKV_DOCKER_11` (unique multistage `FROM` aliases) via parser `_from_aliases` + engine `unique` operator.
- Additional Kubernetes PSP/RBAC/control-plane and Terraform AWS / `CKV2_AWS_*` attribute checks.
- Reproducible benches: `benchmarks/corpus/`, `scripts/bench.sh`, `benchmarks/history.json` (#41).
- Checkov comparison CI: `testdata/checkov-compare/`, `scripts/compare_checkov.py`, `.github/workflows/checkov-compare.yml` (#43).

### Changed

- Workspace crates are **0.4.0**.
- README timing claims refreshed against the published synthetic corpus (medians of three runs).

### Still out of scope / follow-ups

- Helm, Kustomize, Terraform plan JSON, local modules (v0.5).
- Baseline/suppressions and Marketplace listing (v0.6).
- Remaining K8s nginx/cipher gaps and TF IAM semantic checks (documented in fidelity).

## 0.3.0 — 2026-11-02

### Added

- Resource graph IR (`Edge`, `EdgeKind`, `ResourceRef`) on `ParseOutput`.
- Static edge emission from Terraform (`depends_on`, traversals), CloudFormation (`Ref` / `GetAtt` / `DependsOn`), and Kubernetes (`ownerReferences`, PVC mounts).
- Graph policy dialect `cond_type: connection` (plus `filter` alias) and `evaluate_graph` second pass.
- First-wave Terraform `CKV2_AWS_*` checks (S3 logging, S3 public access block, IAM role attachment, open SG ingress companion) — **185** built-in policies total.
- Terraform variable / local evaluation: defaults, `TF_VAR_*`, repeatable `--var-file`, same-file `locals`, simple `${var.x}` / `${local.x}` templates.
- OpenTofu `.tofu` / `.tofu.json` treated as Terraform HCL.

### Changed

- Workspace crates are **0.3.0**.
- Attribute fast path unchanged; graph checks run as a separate pass.

### Still out of scope / follow-ups

- Local module expansion, registry modules, plan JSON (`#17`, `#18`).
- Graph edge enrichment from resolved interpolations (`#19`).
- Helm, Kustomize, secrets, Azure/GCP catalog depth.

## 0.2.0 — 2026-10-15

### Added

- Terraform `data` sources in the HCL/JSON parsers. Data sources are IR resources with kind `data` and type `data.TYPE`.
- Dockerfile parser crate `rustmaninoff-parser-docker` and `--framework docker`.
- Docker checks `CKV_DOCKER_1`–`CKV_DOCKER_4` (pinned FROM tag, non-root USER, COPY vs ADD, HEALTHCHECK).
- Additional Terraform, CloudFormation, and Kubernetes attribute checks (181 built-in total).
- LinkedIn release banner template (`img/linkedin-release-banner.jpg`, `scripts/render-linkedin-banner.py`).

### Changed

- Workspace crates are **0.2.0**.
- Interpolations remain unknown. Graph checks, plan JSON, Helm, and Kustomize are still out of scope.
