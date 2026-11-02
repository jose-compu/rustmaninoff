# Rustmaninoff roadmap

**Now:** v0.3.0 — attribute + graph scanner (463 checks), Terraform vars/locals/`--var-file`, OpenTofu `.tofu`.

**Position:** complementary — *run it next to Trivy, in place of Checkov*. Teams already use Trivy for CVEs. Rustmaninoff’s claim is narrow and provable: **Checkov-compatible CKV policies, single Rust binary, fast**. Broad “scanner platform” scope dilutes that. Do not take on CVE / image layer / vuln-DB work.

**Order of work** (stay on IaC):

1. Raise Checkov check **coverage and fidelity** for Terraform, Kubernetes, and Dockerfile (the common CI surface). Publish a coverage table with percentages.
2. Add **Helm rendering** and **Terraform plan JSON** — what real pipelines scan.
3. Finish **adoption**: SARIF (done), GitHub Action, pre-commit, baseline/ignore so existing repos can onboard without a flood of findings.
4. Only then: adjacent features that reuse the same engine (e.g. simple secret **patterns in IaC files**). Never CVE scanning.

Site: [jose-compu.github.io/rustmaninoff](https://jose-compu.github.io/rustmaninoff/). Tracking: [#11](https://github.com/jose-compu/rustmaninoff/issues/11) · [epics](https://github.com/jose-compu/rustmaninoff/issues?q=is%3Aissue+label%3Aepic) · labels `epic`, `checkov-parity`.

## Now — fix the basics ([#47](https://github.com/jose-compu/rustmaninoff/issues/47))

Launch hygiene (hours, not weeks). README **and** the project site should match.

| Deliverable | Issue | Status |
| --- | ---: | --- |
| Cut / keep v0.3.0 GitHub Release with downloadable binaries | [#48](https://github.com/jose-compu/rustmaninoff/issues/48) | release assets live; spot-check |
| Confirm `cargo install rustmaninoff` via crates.io | [#49](https://github.com/jose-compu/rustmaninoff/issues/49) | 0.3.0 on crates.io; spot-check |
| Badges (crates.io, CI, license) + ~20s terminal demo GIF | [#50](https://github.com/jose-compu/rustmaninoff/issues/50) | README + SVG demo; GIF optional |
| One-line pitch + one comparison (CKV hook) on README + site | [#52](https://github.com/jose-compu/rustmaninoff/issues/52) | README pitch; site mirror on `docs` |
| Label open issues `good first issue` / `help wanted` | [#51](https://github.com/jose-compu/rustmaninoff/issues/51) | seed labels applied |

## v0.2 (shipped)

- Terraform `.tf` / `.tf.json` resources and data sources
- CloudFormation YAML/JSON
- Kubernetes manifests
- Dockerfiles
- 181 attribute checks with pass/fail fixtures
- CLI / JSON / SARIF / JUnit

## v0.3 (shipped core; follow-ups open)

| Epic | Issue | Status |
| --- | ---: | --- |
| Resource graph and `CKV2_*` composite checks | [#1](https://github.com/jose-compu/rustmaninoff/issues/1) | **shipped** in 0.3.0 (first-wave AWS) |
| Terraform variables, locals, OpenTofu | [#16](https://github.com/jose-compu/rustmaninoff/issues/16) | **shipped** in 0.3.0 |
| Local modules / count / for_each | [#17](https://github.com/jose-compu/rustmaninoff/issues/17) | open (feeds plan fidelity) |
| Graph bridge from resolved interpolations | [#19](https://github.com/jose-compu/rustmaninoff/issues/19) | open |

Parent epic [#2](https://github.com/jose-compu/rustmaninoff/issues/2): vars shipped; modules remain; **plan JSON moves to v0.5** with Helm (pipeline scan path).

## v0.4 — coverage credibility (TF / K8s / Dockerfile first)

Coverage is credibility. Each accurate CKV ID makes a Checkov swap easier. Publish the percentage.

| Epic / work | Issue |
| --- | ---: |
| Checkov catalog depth — prioritize Terraform, Kubernetes, Dockerfile fidelity | [#4](https://github.com/jose-compu/rustmaninoff/issues/4) |
| Credibility — reproducible benches, Checkov fidelity table, CI comparison | [#40](https://github.com/jose-compu/rustmaninoff/issues/40) |
| Launch distribution — Show HN, Reddit, TWiR, blog, awesome lists | [#34](https://github.com/jose-compu/rustmaninoff/issues/34) |
| Small-repo tactics — friendly CI offers + disclosed Checkov threads | [#44](https://github.com/jose-compu/rustmaninoff/issues/44) |

### Catalog depth (#4) — v0.4 focus

- Remaining high-severity **Terraform** AWS attribute + graph checks teams hit in CI
- Grow **Kubernetes** (`CKV_K8S_*`) and **Dockerfile** (`CKV_DOCKER_*`) packs
- CloudFormation continues where it shares AWS CKV ids; Azure/GCP packs only after TF/K8s/Docker coverage is visibly strong
- Every new check: pass + fail fixture
- Published coverage table (% of Checkov CKV ids for claimed frameworks) — see [#42](https://github.com/jose-compu/rustmaninoff/issues/42)

### Credibility (#40)

| Deliverable | Issue | Status |
| --- | ---: | --- |
| Reproducible benchmarks: corpus + script; real-world repo | [#41](https://github.com/jose-compu/rustmaninoff/issues/41) | open |
| Fidelity / coverage table: CKV share and intentional gaps | [#42](https://github.com/jose-compu/rustmaninoff/issues/42) | `docs/fidelity.md` + pinned Checkov IDs |
| CI badge + suite comparing output to Checkov on shared fixtures | [#43](https://github.com/jose-compu/rustmaninoff/issues/43) | open |

### Launch (#34) and small-repo tactics (#44)

Lead with: *next to Trivy, in place of Checkov* — speed + CKV compatibility. Honest about catalog % from [#42](https://github.com/jose-compu/rustmaninoff/issues/42).

| Deliverable | Issue |
| --- | ---: |
| Show HN with benchmark story + caveats | [#35](https://github.com/jose-compu/rustmaninoff/issues/35) |
| Reddit: r/rust, r/devops, r/netsec, r/kubernetes | [#36](https://github.com/jose-compu/rustmaninoff/issues/36) |
| This Week in Rust + Rust Users Forum | [#37](https://github.com/jose-compu/rustmaninoff/issues/37) |
| Technical blog: why rewrite policies in Rust | [#38](https://github.com/jose-compu/rustmaninoff/issues/38) |
| Awesome lists | [#39](https://github.com/jose-compu/rustmaninoff/issues/39) |
| Friendly projects: optional CI step | [#45](https://github.com/jose-compu/rustmaninoff/issues/45) |
| Disclosed answers on “Checkov is slow” threads | [#46](https://github.com/jose-compu/rustmaninoff/issues/46) |

## v0.5 — real pipeline inputs (Helm + plan JSON)

| Epic / work | Issue |
| --- | ---: |
| Helm chart rendering → Kubernetes IR | [#3](https://github.com/jose-compu/rustmaninoff/issues/3) (Helm first; Kustomize secondary) |
| `terraform_plan` JSON | [#18](https://github.com/jose-compu/rustmaninoff/issues/18) |
| Local modules / count / for_each (needed for faithful plan/module scans) | [#17](https://github.com/jose-compu/rustmaninoff/issues/17) |

Checkov and Trivy both template Helm and scan plan/rendered surfaces. This release makes Rustmaninoff usable on those CI artifacts without widening into other product lines.

## v0.6 — adoption polish (swap Checkov in CI without a findings flood)

| Epic / work | Issue |
| --- | ---: |
| CI adoption — Action, pre-commit, Homebrew, Docker, Marketplace | [#28](https://github.com/jose-compu/rustmaninoff/issues/28) |
| Baseline / suppressions for brownfield repos | [#58](https://github.com/jose-compu/rustmaninoff/issues/58) |

### CI adoption (#28)

| Deliverable | Issue | Status |
| --- | ---: | --- |
| Reusable Action + SARIF upload | [#29](https://github.com/jose-compu/rustmaninoff/issues/29) | **shipped** |
| Pre-commit hook | [#30](https://github.com/jose-compu/rustmaninoff/issues/30) | **shipped** |
| Homebrew tap | [#31](https://github.com/jose-compu/rustmaninoff/issues/31) | **shipped** (`jose-compu/homebrew-tap`) |
| Official Docker image | [#32](https://github.com/jose-compu/rustmaninoff/issues/32) | **shipped** (`ghcr.io/jose-compu/rustmaninoff`) |
| GitHub Marketplace listing | [#33](https://github.com/jose-compu/rustmaninoff/issues/33) | open |
| Baseline files (adopt without drowning in legacy findings) | [#58](https://github.com/jose-compu/rustmaninoff/issues/58) | open |

## Later — adjacent, same engine only

Only after coverage, pipeline inputs, and adoption are solid.

| Work | Issue | Notes |
| --- | ---: | --- |
| Simple secret **patterns in IaC files** (not a Trivy secrets product) | [#7](https://github.com/jose-compu/rustmaninoff/issues/7) | Narrowed: known patterns on TF/K8s/Docker/CFN content; no entropy product race |
| Compliance pack filters (CIS map over existing CKV ids) | [#10](https://github.com/jose-compu/rustmaninoff/issues/10) | Filter/docs; optional Rego only if demanded |
| Extra IaC formats (ARM, Bicep, Ansible, …) | [#6](https://github.com/jose-compu/rustmaninoff/issues/6) | **Deferred** — dilutes TF/K8s/Docker focus |
| CI/CD-as-code frameworks (Actions/GitLab YAML checks) | [#5](https://github.com/jose-compu/rustmaninoff/issues/5) | **Deferred** — not the Checkov-swap path |
| Live Kubernetes cluster scan | [#9](https://github.com/jose-compu/rustmaninoff/issues/9) | **Deferred** — Trivy/`kubectl` territory |

## Out of scope — do not build

| Work | Issue | Why |
| --- | ---: | --- |
| Image/FS CVE scanning, vuln DB, SBOM-as-product | [#8](https://github.com/jose-compu/rustmaninoff/issues/8) | **Won’t**: Trivy’s business (funded CVE DBs, layer analysis). Stay complementary. |

## Mapping

| Capability | Checkov | Trivy | Rustmaninoff |
| --- | --- | --- | --- |
| TF / CFN / K8s / Dockerfile attributes | yes | misconfig | **v0.2+**; deepen in **v0.4** |
| Graph / `CKV2_*` | yes | some | **v0.3** ([#1](https://github.com/jose-compu/rustmaninoff/issues/1)) |
| Coverage % / fidelity table | — | — | **v0.4** ([#42](https://github.com/jose-compu/rustmaninoff/issues/42)) |
| Terraform plan / modules | yes | misconfig | modules [#17](https://github.com/jose-compu/rustmaninoff/issues/17); plan **v0.5** [#18](https://github.com/jose-compu/rustmaninoff/issues/18) |
| Helm (then Kustomize) | yes | yes | **v0.5** [#3](https://github.com/jose-compu/rustmaninoff/issues/3) |
| Action / pre-commit / brew / Docker / baseline | yes | yes | **v0.6** [#28](https://github.com/jose-compu/rustmaninoff/issues/28), [#58](https://github.com/jose-compu/rustmaninoff/issues/58) |
| Secrets in IaC (narrow patterns) | yes | yes | **Later** [#7](https://github.com/jose-compu/rustmaninoff/issues/7) |
| ARM / Bicep / Ansible / Serverless / OpenAPI | yes | some | Deferred [#6](https://github.com/jose-compu/rustmaninoff/issues/6) |
| GHA / GitLab CI as scanned frameworks | yes | some | Deferred [#5](https://github.com/jose-compu/rustmaninoff/issues/5) |
| Live cluster | limited | `k8s` | Deferred [#9](https://github.com/jose-compu/rustmaninoff/issues/9) |
| Image/FS CVEs, SBOM product | SCA | **core** | **Out of scope** [#8](https://github.com/jose-compu/rustmaninoff/issues/8) |

## Constraint

Do not regress the attribute path. New frameworks are `--framework` flags. Network (module registry, Helm repos) is never implicit in CI. **No vulnerability database on any default or optional path** — point users at Trivy for that.
