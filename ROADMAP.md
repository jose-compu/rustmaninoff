# Rustmaninoff roadmap

**Now:** v0.2.0 — attribute scanner for Terraform, CloudFormation, Kubernetes, and Dockerfiles (181 CKV-style checks).

**Aim:** cover the same *job* as Checkov (IaC misconfig, including graph and packaging) and the misconfig/secrets slice of Trivy, without becoming a Python Checkov port or downloading a CVE database on the default scan path.

Speed stays the constraint. Attribute scans should remain milliseconds. Graph, Helm, and plan JSON are extra passes. Image/FS vulnerability scanning is optional and off by default ([#8](https://github.com/jose-compu/rustmaninoff/issues/8)).

Issues: tracking [#11](https://github.com/jose-compu/rustmaninoff/issues/11) · [epics](https://github.com/jose-compu/rustmaninoff/issues?q=is%3Aissue+label%3Aepic) · labels `epic`, `checkov-parity`, `trivy-parity`.

## v0.2 (shipped)

- Terraform `.tf` / `.tf.json` resources and data sources
- CloudFormation YAML/JSON
- Kubernetes manifests
- Dockerfiles
- 181 attribute checks with pass/fail fixtures
- CLI / JSON / SARIF / JUnit

Not in 0.2: `CKV2_*`, plan JSON, modules, Helm, Kustomize, secrets, vulns, Azure/GCP catalog depth.

## v0.3 — graph and Terraform evaluation

| Epic | Issue |
| --- | ---: |
| Resource graph and `CKV2_*` composite checks | [#1](https://github.com/jose-compu/rustmaninoff/issues/1) |
| Terraform variables, locals, modules, OpenTofu, plan JSON | [#2](https://github.com/jose-compu/rustmaninoff/issues/2) |

Checkov gap this closes: context-aware policies and the usual `terraform` / `terraform_plan` CI path.

## v0.4 — packaging and more IaC

| Epic | Issue |
| --- | ---: |
| Helm charts and Kustomize overlays | [#3](https://github.com/jose-compu/rustmaninoff/issues/3) |
| ARM, Bicep, Ansible, Serverless, OpenAPI, SAM | [#6](https://github.com/jose-compu/rustmaninoff/issues/6) |

Checkov/Trivy gap: they template Helm and walk Kustomize; Checkov also scans ARM/Bicep/Ansible/Serverless/OpenAPI.

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
| GHA / GitLab CI / Azure Pipelines / Argo | yes | some | [#5](https://github.com/jose-compu/rustmaninoff/issues/5) |
| Azure / GCP catalog | yes | misconfig | [#4](https://github.com/jose-compu/rustmaninoff/issues/4) |
| Secrets | yes | yes | [#7](https://github.com/jose-compu/rustmaninoff/issues/7) |
| Image/FS CVEs, SBOM, licenses | SCA | **core** | [#8](https://github.com/jose-compu/rustmaninoff/issues/8) (opt-in) |
| Live cluster | limited | `k8s` | [#9](https://github.com/jose-compu/rustmaninoff/issues/9) |
| CIS packs / Rego | Prisma / YAML | Rego | [#10](https://github.com/jose-compu/rustmaninoff/issues/10) |

## Constraint

Do not regress the 0.2 attribute path. New frameworks are `--framework` flags. Network (module registry, Helm repos, vuln DB) is never implicit in CI.
