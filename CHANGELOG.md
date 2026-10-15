# Changelog

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
