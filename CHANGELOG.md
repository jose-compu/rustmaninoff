# Changelog

## 0.6.9 — 2026-11-27

- `CKV_K8S_32` fails a `PodSecurityPolicy` when annotation `seccomp.security.alpha.kubernetes.io/defaultProfileName` is missing or does not contain `docker/default` or `runtime/default`. A policy annotated `docker/default` passes. Other Kubernetes kinds are unchanged.
- Milestone **0.7.0** stays open (**8 of 12**). Built-in catalog is **547** checks. Kubernetes coverage is **112/113 (99.1%)**. `CKV_K8S_147` is next.

## 0.6.8 — 2026-11-26

- Re-ran `scripts/bench.sh` and appended `benchmarks/history.json` with the **0.6.8** release binary on a Linux x86_64 runner (2026-11-26). Updated the README and the GitHub Pages site to cite the latest row instead of stale **0.4.0** figures. Added `scripts/workspace_version.py` for history labels.
- No policy or engine changes. Milestone **0.7.0** stays open (7 of 12 boxes). Built-in catalog is **546** checks. `CKV_K8S_32` is next.

## 0.6.7 — 2026-11-26

- `CKV_K8S_151` fails a `kubelet` command when a token after `--tls-cipher-suites=` is not on Checkov's strong-cipher list. An unset flag still passes. Other workloads still pass. The check reads `command`, not `args`.
- Milestone **0.7.0** stays open (7 of 12 boxes). Built-in catalog is **546** checks. `CKV_K8S_32` is next.

## 0.6.6 — 2026-11-26

- `CKV_K8S_105` fails a `kube-apiserver` command when a token after `--tls-cipher-suites=` is not on Checkov's strong-cipher list. An unset flag still passes. Other workloads still pass. The check reads `command`, not `args`.
- Engine operator `csv_within` validates comma-separated tokens after `=` on command items matching a prefix.
- Milestone **0.7.0** stays open (6 of 12 boxes). Built-in catalog is **545** checks. `CKV_K8S_151` is next.

## 0.6.5 — 2026-11-25

- `starting_with`, `ending_with`, and `contains` (and their negations) match any item of a command or args array. A prefix or a substring inside a longer argument matches. Scalar strings are unchanged.
- Milestone **0.7.0** stays open (5 of 12 boxes). Built-in catalog is **544** checks. `CKV_K8S_105` is next.

## 0.6.4 — 2026-11-24

- `CKV_K8S_154` fails an Ingress when the same annotation name contains `snippet` and the value contains `alias`. Both substrings must be on the same annotation.
- Milestone **0.7.0** stays open. Built-in catalog is **544** checks.

## 0.6.3 — 2026-11-24

- `CKV_K8S_153` fails an Ingress when any annotation name contains `snippet`. The value is ignored, so a snippet that does not run Lua still fails.
- Milestone **0.7.0** stays open. Built-in catalog is **543** checks.

## 0.6.2 — 2026-11-23

- `CKV_K8S_152` fails an Ingress when an annotation name contains `snippet` and the value matches Checkov's Lua pattern for CVE-2021-25742. Snippet keys are matched by substring, not a fixed name list.
- On a map of scalar annotation values, `no_element` exposes each entry's `key` and `value` to the `where` clause. Object-valued map entries are unchanged.
- Milestone **0.7.0** stays open. Built-in catalog is **542** checks.

## 0.6.1 — 2026-11-22

- An attribute path may wrap one key in double quotes so dots and slashes stay part of the name (Kubernetes annotation keys). Unquoted paths are unchanged.
- Milestone **0.7.0** stays open. Built-in catalog remains **541** checks.

## 0.6.0 — 2026-11-21

- The README Action section and [ACTION.md](ACTION.md) now show how to scan a saved Terraform plan JSON (`terraform show -json`, then `--framework terraform_plan`). A default directory scan does not select `terraform_plan`, so plan files in the tree are not scanned.
- Milestone **0.6.0** is closed ([#83](https://github.com/jose-compu/rustmaninoff/issues/83)). Scanner and parser behavior unchanged. Built-in catalog remains **541** checks. Workspace crates and Action default `version` are **0.6.0**.

## 0.5.6 — 2026-11-20

- `docs/fidelity.md` documents what an opt-in Terraform plan scan covers; `scripts/coverage_inventory.py` keeps that section on refresh.
- Committed plan JSON fixtures back each claim; parser tests load those files. Parser behavior unchanged.
- Built-in catalog remains **541** checks. Workspace crates and Action default `version` are **0.5.6**.

## 0.5.5 — 2026-11-19

### Added

- Terraform plan scans follow explicit `depends_on` links and attribute or configuration references whose value is another resource address in the plan (including `configuration` references after Terraform resolves a value to a name). Companion `CKV2_*` checks run on those edges ([#81](https://github.com/jose-compu/rustmaninoff/issues/81)).
- A string that only matches another resource's name is not treated as a graph edge. Resources this apply does not create or update stay out of the default scan; `--plan-scope all` still includes them.

### Changed

- Unknown plan leaves still do not fail the process. Sensitive values stay redacted as `(sensitive value)`. The built-in catalog remains **541** checks.
- Workspace crates and the Action default `version` pin are 0.5.5.

## 0.5.4 — 2026-11-19

### Fixed

- Default `terraform_plan` scans report only resources this apply creates or updates (including replace). Attributes come from `resource_changes[].change.after`. Unchanged, read-only, and delete-only resources are skipped ([#80](https://github.com/jose-compu/rustmaninoff/issues/80)).
- `--plan-scope all` keeps the previous whole-state plan scan (0.5.0 through 0.5.3 behavior).

### Changed

- Unknown plan leaves still do not fail the process. Sensitive values stay redacted as `(sensitive value)`.
- Workspace `homepage` is the project site; unused workspace `readme` is removed so `cargo test` and publish no longer warn ([#85](https://github.com/jose-compu/rustmaninoff/issues/85)).
- Workspace crates and the Action default `version` pin are 0.5.4.

## 0.5.3 — 2026-11-18

### Fixed

- SARIF `artifactLocation.uri` values are relative to the scan root with forward slashes, `uriBaseId` `%SRCROOT%`, and `originalUriBaseIds` for GitHub code scanning preview ([#84](https://github.com/jose-compu/rustmaninoff/issues/84)).
- SARIF result messages use the check name only; resource addresses move to result properties when they add context. Redundant Docker file labels are no longer duplicated in the message.
- Each SARIF rule carries an `informationUri` (Checkov or project docs link); the tool driver `informationUri` is `https://github.com/jose-compu/rustmaninoff`.

### Changed

- Workspace crates and the Action default `version` pin are 0.5.3.

## 0.5.2 — 2026-11-18

### Added

- CI benchmark regression gate on every pull request and on pushes to `main`: compares release binaries on fixed corpora (pinned Terraform module, Kubernetes, CloudFormation, Dockerfiles, Terraform plan JSON), writes the table to the job summary and one sticky PR comment, warns above 5% slower, fails above 15% (configurable in `benchmarks/regression_thresholds.json`). Main-branch medians are stored as workflow artifacts ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)).
- Five Terraform AWS resource checks from the 0.8.0 queue: `CKV_AWS_61`, `CKV_AWS_93`, `CKV_AWS_112`, `CKV_AWS_113`, `CKV_AWS_213` (IAM assume-role scope, S3 policy lockout guard, Session Manager encryption and logging, ELB TLS policy hardening).

### Changed

- Built-in catalog: **541** checks (was 536). Terraform AWS exact overlap: **341 / 928** (`docs/fidelity.md`).
- Workspace crates and the Action default `version` pin are 0.5.2.

## 0.5.1 — 2026-11-17

### Added

- Terraform plan scanning redacts attributes Terraform marks sensitive (`sensitive_values`, `before_sensitive`, and `after_sensitive` in `resource_changes`, and `sensitive_values` on planned resources). Redacted values become the fixed placeholder `(sensitive value)` in the scan IR before checks run, so they cannot surface in CLI, JSON, SARIF, or JUnit output.

### Changed

- Workspace crates and the Action default `version` pin are 0.5.1.

### Notes

- This is not a secrets scanner: only provider-schema–marked sensitive values are redacted. Keep plan artifacts out of logs and CI output; unmarked values remain your pipeline’s responsibility.
## 0.5.0 — 2026-11-17

### Added

- Opt-in Terraform plan scanning: `rustmaninoff scan --framework terraform_plan` on a `terraform show -json` file.
- Planned resources and child-module resources use the existing Terraform checks. Data sources use the same `data.<type>` type as HCL.
- Values marked unknown in the plan do not fail the process.
- Tag `v*` pushes publish workspace crates to crates.io via `.github/workflows/publish.yml` (dependency order, skip already-published versions).

### Changed

- Workspace crates and the Action default `version` pin are 0.5.0.

### Unchanged

- 536 built-in checks. Docker 100%, Kubernetes 93.8%, Terraform AWS resource ids 36.2% (`docs/fidelity.md`).
- Default scan frameworks are still Terraform, CloudFormation, Kubernetes, and Docker.

## 0.4.4 — 2026-11-03

### Fixed

- GitHub Action input validation: bash `=~` patterns no longer embed a literal space (word-split broke path/sarif/args checks with exit 2).

### Changed

- Workspace crates are **0.4.4**.
- Action default `version` pin is **0.4.4**.

## 0.4.3 — 2026-11-03

### Changed

- Action Marketplace `description` shortened to ≤125 characters.
- Workspace crates are **0.4.3**; Action default `version` pin is **0.4.3**.

## 0.4.2 — 2026-11-03

### Changed

- Workspace crates are **0.4.2**.
- Action default `version` pin is `0.4.2`.
- Marketplace/docs refresh: Action install guidance, SEO, and [ACTION.md](ACTION.md) on the published listing README path.

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
