# Rustmaninoff roadmap

**Now:** v0.3.0 — attribute + graph scanner (185 checks), Terraform vars/locals/`--var-file`, OpenTofu `.tofu`.

**Aim:** cover the same *job* as Checkov (IaC misconfig, including graph and packaging) and the misconfig/secrets slice of Trivy, without becoming a Python Checkov port or downloading a CVE database on the default scan path.

Speed stays the constraint. Attribute scans should remain milliseconds. Graph, Helm, and plan JSON are extra passes. Image/FS vulnerability scanning is optional and off by default ([#8](https://github.com/jose-compu/rustmaninoff/issues/8)).

Site: [jose-compu.github.io/rustmaninoff](https://jose-compu.github.io/rustmaninoff/). Issues: tracking [#11](https://github.com/jose-compu/rustmaninoff/issues/11) · [epics](https://github.com/jose-compu/rustmaninoff/issues?q=is%3Aissue+label%3Aepic) · labels `epic`, `checkov-parity`, `trivy-parity`.

## Now — fix the basics ([#47](https://github.com/jose-compu/rustmaninoff/issues/47))

Launch hygiene (hours, not weeks). README **and** the project site should match.

| Deliverable | Issue | Status |
| --- | ---: | --- |
| Cut / keep v0.3.0 GitHub Release with downloadable binaries | [#48](https://github.com/jose-compu/rustmaninoff/issues/48) | release assets live; spot-check |
| Confirm `cargo install rustmaninoff` via crates.io | [#49](https://github.com/jose-compu/rustmaninoff/issues/49) | 0.3.0 on crates.io; spot-check |
| Badges (crates.io, CI, license) + ~20s terminal demo GIF | [#50](https://github.com/jose-compu/rustmaninoff/issues/50) | README + SVG demo (this PR); GIF optional follow-up |
| One-line pitch + one comparison (CKV hook) on README + site | [#52](https://github.com/jose-compu/rustmaninoff/issues/52) | README pitch (this PR); site mirror on `docs` |
| Label open issues `good first issue` / `help wanted` | [#51](https://github.com/jose-compu/rustmaninoff/issues/51) | seed labels applied |

## v0.2 (shipped)

- Terraform `.tf` / `.tf.json` resources and data sources
- CloudFormation YAML/JSON
- Kubernetes manifests
- Dockerfiles
- 181 attribute checks with pass/fail fixtures
- CLI / JSON / SARIF / JUnit

Not in 0.2: `CKV2_*`, plan JSON, modules, Helm, Kustomize, secrets, vulns, Azure/GCP catalog depth.

## v0.3 (shipped core; follow-ups open)

| Epic | Issue | Status |
| --- | ---: | --- |
| Resource graph and `CKV2_*` composite checks | [#1](https://github.com/jose-compu/rustmaninoff/issues/1) | **shipped** in 0.3.0 (first-wave AWS) |
| Terraform variables, locals, OpenTofu | [#16](https://github.com/jose-compu/rustmaninoff/issues/16) | **shipped** in 0.3.0 |
| Local modules / count / for_each | [#17](https://github.com/jose-compu/rustmaninoff/issues/17) | open (0.3.x) |
| `terraform_plan` JSON | [#18](https://github.com/jose-compu/rustmaninoff/issues/18) | open (0.3.x) |
| Graph bridge from resolved interpolations | [#19](https://github.com/jose-compu/rustmaninoff/issues/19) | open (0.3.x) |

Parent epic [#2](https://github.com/jose-compu/rustmaninoff/issues/2) remains open until modules + plan JSON land.

## v0.4 — packaging, more IaC, and CI adoption

| Epic | Issue |
| --- | ---: |
| Helm charts and Kustomize overlays | [#3](https://github.com/jose-compu/rustmaninoff/issues/3) |
| ARM, Bicep, Ansible, Serverless, OpenAPI, SAM | [#6](https://github.com/jose-compu/rustmaninoff/issues/6) |
| CI adoption — Action, pre-commit, Homebrew, Docker, Marketplace | [#28](https://github.com/jose-compu/rustmaninoff/issues/28) |
| Launch distribution — Show HN, Reddit, TWiR, blog, awesome lists | [#34](https://github.com/jose-compu/rustmaninoff/issues/34) |
| Credibility — reproducible benches, Checkov fidelity, CI comparison | [#40](https://github.com/jose-compu/rustmaninoff/issues/40) |
| Small-repo tactics — friendly CI offers + disclosed Checkov threads | [#44](https://github.com/jose-compu/rustmaninoff/issues/44) |

Checkov/Trivy gap: they template Helm and walk Kustomize; Checkov also scans ARM/Bicep/Ansible/Serverless/OpenAPI.

### CI adoption (#28)

Make Rustmaninoff easy to adopt before teams invent install scripts. Distinct from [#5](https://github.com/jose-compu/rustmaninoff/issues/5) (scanning CI-as-code).

| Deliverable | Issue |
| --- | ---: |
| Reusable composite Action (`jose-compu/rustmaninoff-action`): download release binary, scan, upload SARIF | [#29](https://github.com/jose-compu/rustmaninoff/issues/29) |
| Pre-commit hook | [#30](https://github.com/jose-compu/rustmaninoff/issues/30) |
| Homebrew tap | [#31](https://github.com/jose-compu/rustmaninoff/issues/31) |
| Official Docker image | [#32](https://github.com/jose-compu/rustmaninoff/issues/32) |
| List the Action on GitHub Marketplace | [#33](https://github.com/jose-compu/rustmaninoff/issues/33) |

Each path is another install surface and another place to be found. Marketplace is itself a discovery channel.

### Launch distribution (#34)

Outreach that brings users. Distinct from [#28](https://github.com/jose-compu/rustmaninoff/issues/28) (install binaries). Lead with the problem and numbers; stay honest that benchmarks are self-reported and from one corpus.

| Deliverable | Issue |
| --- | ---: |
| Show HN with benchmark story + caveats | [#35](https://github.com/jose-compu/rustmaninoff/issues/35) |
| Reddit: r/rust, r/devops, r/netsec, r/kubernetes | [#36](https://github.com/jose-compu/rustmaninoff/issues/36) |
| This Week in Rust (PR) + Rust Users Forum | [#37](https://github.com/jose-compu/rustmaninoff/issues/37) |
| Technical blog: why rewrite policies in Rust (own site + dev.to, cross-link) | [#38](https://github.com/jose-compu/rustmaninoff/issues/38) |
| Awesome lists: awesome-rust, awesome-static-analysis, awesome-devsecops, awesome-terraform | [#39](https://github.com/jose-compu/rustmaninoff/issues/39) |

### Credibility (#40)

Trust for security adopters: numbers others can rerun, an honest Checkov fidelity table, and CI that catches parity drift. Complements [#34](https://github.com/jose-compu/rustmaninoff/issues/34) (telling the story) with evidence.

| Deliverable | Issue |
| --- | ---: |
| Reproducible benchmarks: publish corpus + script; include a real-world repo | [#41](https://github.com/jose-compu/rustmaninoff/issues/41) |
| Fidelity table: Checkov CKV coverage share and where results differ | [#42](https://github.com/jose-compu/rustmaninoff/issues/42) |
| CI badge + test suite comparing output to Checkov on shared fixtures | [#43](https://github.com/jose-compu/rustmaninoff/issues/43) |

### Small-repo tactics (#44)

Outbound, opt-in growth for a small project. Distinct from [#28](https://github.com/jose-compu/rustmaninoff/issues/28) (build install paths) and [#34](https://github.com/jose-compu/rustmaninoff/issues/34) (launch posts). Quality over volume; **no abuse**.

| Deliverable | Issue |
| --- | ---: |
| Open issues/PRs in friendly projects offering the scanner as an optional CI step | [#45](https://github.com/jose-compu/rustmaninoff/issues/45) |
| Answer “Checkov is slow” / “alternatives to Checkov” threads (Reddit, Stack Overflow, GitHub) with author disclosure | [#46](https://github.com/jose-compu/rustmaninoff/issues/46) |

## v0.5 — catalog, pipelines, secrets

| Epic | Issue |
| --- | ---: |
| Checkov catalog depth (AWS, Azure, GCP) | [#4](https://github.com/jose-compu/rustmaninoff/issues/4) |
| CI/CD as code (Actions, GitLab, Azure Pipelines, Argo, …) | [#5](https://github.com/jose-compu/rustmaninoff/issues/5) |
| Secrets scanning | [#7](https://github.com/jose-compu/rustmaninoff/issues/7) |

181 checks is not Checkov’s 1000+. Pipelines and secrets are both Checkov frameworks and Trivy scanners.

## v1.0 — compliance and optional Trivy-class SCA

| Epic | Issue |
| --- | ---: |
| Compliance packs (CIS/NSA) and Rego/custom graph YAML | [#10](https://github.com/jose-compu/rustmaninoff/issues/10) |
| Live Kubernetes cluster scanning | [#9](https://github.com/jose-compu/rustmaninoff/issues/9) |
| Optional image/filesystem vulns, licenses, SBOM | [#8](https://github.com/jose-compu/rustmaninoff/issues/8) |

Default `rustmaninoff scan` remains IaC misconfig. `--scanners vuln` is how Trivy-like coverage is opted in, so CI does not pay for a vulnerability DB unless it asked.

## Mapping

| Capability | Checkov | Trivy | Rustmaninoff |
| --- | --- | --- | --- |
| TF / CFN / K8s / Dockerfile attributes | yes | misconfig | **v0.2** |
| Graph / `CKV2_*` | yes | some | [#1](https://github.com/jose-compu/rustmaninoff/issues/1) |
| Terraform plan / modules / vars | yes | misconfig | [#2](https://github.com/jose-compu/rustmaninoff/issues/2) |
| Helm / Kustomize | yes | yes | [#3](https://github.com/jose-compu/rustmaninoff/issues/3) |
| ARM / Bicep / Ansible / Serverless / OpenAPI | yes | some | [#6](https://github.com/jose-compu/rustmaninoff/issues/6) |
| GHA / GitLab CI / Azure Pipelines / Argo (scan those files) | yes | some | [#5](https://github.com/jose-compu/rustmaninoff/issues/5) |
| Action / brew / Docker / pre-commit (run this scanner) | yes | yes | [#28](https://github.com/jose-compu/rustmaninoff/issues/28) |
| Launch posts / TWiR / awesome lists (discovery) | — | — | [#34](https://github.com/jose-compu/rustmaninoff/issues/34) |
| Reproducible benches / fidelity table / Checkov CI compare | — | — | [#40](https://github.com/jose-compu/rustmaninoff/issues/40) |
| Friendly CI offers + disclosed Checkov-thread answers | — | — | [#44](https://github.com/jose-compu/rustmaninoff/issues/44) |
| Fix the basics (release, crates, README/site pitch) | — | — | [#47](https://github.com/jose-compu/rustmaninoff/issues/47) |
| Azure / GCP catalog | yes | misconfig | [#4](https://github.com/jose-compu/rustmaninoff/issues/4) |
| Secrets | yes | yes | [#7](https://github.com/jose-compu/rustmaninoff/issues/7) |
| Image/FS CVEs, SBOM, licenses | SCA | **core** | [#8](https://github.com/jose-compu/rustmaninoff/issues/8) (opt-in) |
| Live cluster | limited | `k8s` | [#9](https://github.com/jose-compu/rustmaninoff/issues/9) |
| CIS packs / Rego | Prisma / YAML | Rego | [#10](https://github.com/jose-compu/rustmaninoff/issues/10) |

## Constraint

Do not regress the 0.2 attribute path. New frameworks are `--framework` flags. Network (module registry, Helm repos, vuln DB) is never implicit in CI.
