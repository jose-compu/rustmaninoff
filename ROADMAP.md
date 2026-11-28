# Rustmaninoff roadmap

Current release: **0.6.10**. This file is the queue for daily releases. Tick a box in the same commit that ships the work.

Position, unchanged: Checkov-compatible CKV policies, one Rust binary, fast. Run it next to Trivy. Trivy keeps CVEs, image layers, and SBOMs. Rustmaninoff does not grow a vulnerability database ([#8](https://github.com/jose-compu/rustmaninoff/issues/8) is closed as out of scope).

## How a day ships

1. If [Next patch](#next-patch) has an open box, take that box. Otherwise take the first unchecked box under the earliest open milestone.
2. Ship it as the next **patch** (`0.5.2`, `0.5.3`, …). One box, one release.
3. Tick the box in this file in that same release.
4. When every box in a milestone is ticked, the next release is the **minor** that closes it (`0.6.0`, then `0.7.0`, …). The minor is the close, not a second copy of the work.
5. A patch may also take the first item in [Patch-level backlog](#patch-level-backlog) when the next milestone box is blocked on a missing fact (for example a Checkov id whose operator does not exist yet). Record the block in [docs/fidelity.md](docs/fidelity.md) and move on. Do not skip ahead to a later milestone.
6. Do not tag `1.0.0` until every line in [1.0.0 exit criteria](#100-exit-criteria) is checked.
7. A new framework, output format, or scan mode waits for its minor. Individual checks, fixes, false positives, speed, docs, and hardening stay on the patch train.

### Version scheme

| Bump | When | Example |
| --- | --- | --- |
| Patch `0.x.Y` | A fix, a false positive, a speed or docs change, hardening, or one new check inside the open milestone. This is the default daily release. | `0.5.2` ships the CI benchmark |
| Minor `0.X.0` | The open milestone's boxes are all ticked, or the release adds a framework, an output format, or a scan mode | `0.6.0` closes plan-scan hardening; `0.10.0` adds Helm |
| `1.0.0` | The exit criteria below are all true | Stable CLI, stable library API, parity thresholds |

Before 1.0, a minor may change library crate APIs. A patch may not. After 1.0, library breaks wait for `2.0.0`. CLI flags and the JSON, SARIF, and JUnit schemas follow the same rule once 1.0 ships.

## Where 0.5.1 actually is

Do not re-schedule this work.

| Already shipped | Where |
| --- | --- |
| Terraform (`.tf`, `.tf.json`, OpenTofu `.tofu`), CloudFormation, Kubernetes, Dockerfiles | 0.2 |
| CLI text, JSON, SARIF 2.1.0, JUnit; exit codes `0` / `1` / `2`; `--fail-on`, `--soft-fail` | 0.2, still the only output formats |
| Inline skips: `# checkov:skip=` and `checkov.io/skip` | 0.2 |
| `.rustmaninoff.yaml` (frameworks, `skip_checks`, `fail_on`, `excluded_paths`, `external_checks_dirs`, `show_unknown`, `compact`) and `--config` | 0.3 era CLI |
| `--external-checks-dir` for extra YAML policies | CLI today |
| Resource graph, `cond_type: connection`, first-wave `CKV2_AWS_*` | 0.3.0 ([#1](https://github.com/jose-compu/rustmaninoff/issues/1)) |
| Variables, locals, `TF_VAR_*`, `--var-file`, simple `${var.x}` / `${local.x}` | 0.3.0 ([#16](https://github.com/jose-compu/rustmaninoff/issues/16)) |
| 536 built-in checks, each with a pass and a fail fixture (`crates/cli/src/pack_tests.rs`) | 0.4.0 |
| CI benchmark regression gate + Docker/plan bench corpora | 0.5.2 ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)) |
| Terraform AWS `CKV_AWS_61`, `CKV_AWS_93`, `CKV_AWS_112`, `CKV_AWS_113`, `CKV_AWS_213` | 0.5.2 (toward 0.8.0) |
| Benches (`benchmarks/`, `scripts/bench.sh`), fidelity table, Checkov-compare CI | 0.4.0 ([#41](https://github.com/jose-compu/rustmaninoff/issues/41), [#42](https://github.com/jose-compu/rustmaninoff/issues/42), [#43](https://github.com/jose-compu/rustmaninoff/issues/43)) |
| GitHub Action, pre-commit hook, Homebrew tap `jose-compu/tap`, GHCR image, crates.io publish on `v*` | 0.4.x–0.5.0 ([#28](https://github.com/jose-compu/rustmaninoff/issues/28)) |
| Release archives: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` | `.github/workflows/release.yml` |
| Opt-in `terraform_plan` on `terraform show -json` (planned values, child modules, data sources, `after_unknown` does not fail the process) | 0.5.0 ([#18](https://github.com/jose-compu/rustmaninoff/issues/18)) |
| Terraform-marked sensitive plan values redacted to `(sensitive value)` before checks and reports | 0.5.1 |

547 checks break down as Terraform 373, CloudFormation 51, Kubernetes 112, Docker 11. Families: `CKV_AWS` 404 (Terraform and CloudFormation files together), `CKV_K8S` 112, `CKV_DOCKER` 11, `CKV2_AWS` 20.

The pinned catalog is `tools/checkov-ids/snapshot.json`, scraped from `bridgecrewio/checkov` by `scripts/fetch_checkov_ids.py`. It has three buckets only: Dockerfile attribute checks, Kubernetes attribute checks, and every Terraform **resource** check (the file is named `terraform_aws`, the directory scraped is `checkov/terraform/checks/resource/`). Graph checks are not in the scrape. CloudFormation is not in the scrape.

| Surface in that snapshot | Checkov ids | Exact id in Rustmaninoff | Coverage |
| --- | ---: | ---: | ---: |
| Docker attribute | 11 | 11 | 100% |
| Kubernetes attribute | 113 | 112 | 99.1% |
| Whole Terraform resource directory | 928 | 341 | 36.7% |
| `CKV_AWS_*` inside that directory | 361 | 341 | 94.5% (20 missing) |
| `CKV_AZURE_*` | 242 | 0 | none |
| `CKV_GCP_*` | 123 | 0 | none |
| Other clouds in the same directory | 202 | 0 | none (see below) |

The 36.2% row in [docs/fidelity.md](docs/fidelity.md) is labeled "terraform AWS resource checks". The denominator is all 928 Terraform resource ids. The AWS slice is 336 of 361. The other 202 ids with zero coverage are `CKV_ALI` 40, `CKV_YC` 24, `CKV_OCI` 22, `CKV_NCP` 22, `CKV_PAN` 14, `CKV_TC` 14, `CKV_GIT` 6, `CKV_LIN` 5, `CKV_GLB` 4, `CKV_OPENSTACK` 4, `CKV_DIO` 4, `CKV_OKTA` 1, plus 41 `CKV_K8S_*` ids that also appear in the Terraform resource tree (40 of those 41 already exist on the Kubernetes side). Those smaller clouds are not scheduled below.

Kubernetes ids still missing: `CKV_K8S_147`.

Terraform AWS resource ids still missing: `CKV_AWS_45`, `CKV_AWS_70`, `CKV_AWS_121`, `CKV_AWS_165`, `CKV_AWS_192`, `CKV_AWS_208`, `CKV_AWS_250`, `CKV_AWS_256`, `CKV_AWS_274`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_342`, `CKV_AWS_355`, `CKV_AWS_375`, `CKV_AWS_379`, `CKV_AWS_385`, `CKV_AWS_387`, `CKV_AWS_393`.

`CKV_AWS_45` and `CKV_AWS_287`–`CKV_AWS_290` are the IAM policy-document checks called out in fidelity.md. They need more than the current attribute dialect.

Four of the 20 `CKV2_AWS_*` policies use local names rather than a published id: `CKV2_AWS_IAM_POLICY_ATTACHMENT`, `CKV2_AWS_S3_BUCKET_LOGGING`, `CKV2_AWS_S3_BUCKET_PUBLIC_ACCESS`, `CKV2_AWS_SECURITY_GROUP_INGRESS`.

CloudFormation's 51 policies are mostly `CKV_AWS_*_2` files. That suffix is local. `CKV_AWS_34` is the one id that also appears in the Terraform resource snapshot. The other 50 are absent from the snapshot because CloudFormation was never scraped.

Known engine limits that later boxes depend on:

- Quoted attribute paths can match dotted annotation names (shipped in 0.6.1). Map annotation walks for scalar entries shipped in 0.6.2 (`CKV_K8S_152`). `CKV_K8S_153` shipped in 0.6.3; `CKV_K8S_154` shipped in 0.6.4. Array `starting_with` and substring `contains` across command or args items shipped in 0.6.5. `csv_within` shipped in 0.6.6 for `CKV_K8S_105`; `CKV_K8S_151` shipped in 0.6.7 on `csv_within` (kubelet, same cipher list as `CKV_K8S_105`).
- `CKV_K8S_95` is an approximation (a few exact `--request-timeout=` strings), not Checkov's duration grammar.
- `CKV_K8S_34` does not mean what Checkov means (theirs is "Tiller is absent"; ours is secrets via `envFrom`).
- Default plan scans report resources the plan creates or updates (attributes from `change.after`); `--plan-scope all` keeps the whole `planned_values` walk ([#80](https://github.com/jose-compu/rustmaninoff/issues/80) shipped in 0.5.4).
- Plan graph edges follow `depends_on` and address references, not resolved names that merely match ([#81](https://github.com/jose-compu/rustmaninoff/issues/81) shipped in 0.5.5).
- SARIF relative paths and rule help links ship in 0.5.3 ([#84](https://github.com/jose-compu/rustmaninoff/issues/84)); GitHub Code Scanning can open matched files.
- Local modules, `count`, and `for_each` are not expanded ([#17](https://github.com/jose-compu/rustmaninoff/issues/17)). Resolved interpolations do not become graph edges ([#19](https://github.com/jose-compu/rustmaninoff/issues/19)).
- There is no Helm or Kustomize framework ([#3](https://github.com/jose-compu/rustmaninoff/issues/3)). `Framework::parse("helm")` is `None`.
- There is no baseline file ([#58](https://github.com/jose-compu/rustmaninoff/issues/58)).
- There is no `SECURITY.md`, no `rust-version` field, and no Windows target. CI uses `dtolnay/rust-toolchain@stable`. The README build line says Rust 1.95 or newer.

## Next patch

Ship this before every milestone box, including the SARIF path fix in 0.6.0 ([#84](https://github.com/jose-compu/rustmaninoff/issues/84)). One patch. It does not close 0.17.0.

- [x] Benchmark in CI with regression reporting ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)). On every pull request and on pushes to `main`, build this commit and `main` on the same runner and scan fixed corpora: a large Terraform tree, Kubernetes, CloudFormation, Dockerfiles, and a Terraform plan JSON. Several iterations; report the median and the spread. Write the table (baseline, pull request, absolute delta, percent delta, peak memory when available) to the job summary and to one sticky pull request comment. Warn above 5% slower. Fail above 15% slower. Both limits are configuration. Keep `main`'s medians as a workflow artifact or on a data branch. An unexplained fail stays red.

## Milestones

Each box is one patch unless the text says it is the minor closer. The [next patch](#next-patch) is ahead of this list.

### 0.6.0 — Plan scans and SARIF that match the CI artifact

Goal: a plan scan reports resources that the plan is creating or updating, graph checks run when the plan still shows the relationship, and GitHub code scanning can open the file. Sensitive redaction stays as 0.5.1 left it. Required for 1.0.

- [x] SARIF locations are relative to the scan root, with forward slashes and `uriBaseId` `%SRCROOT%`. The message stays the check name. Set `informationUri` to `https://github.com/jose-compu/rustmaninoff`. Fixture: an absolute path under the scan root ([#84](https://github.com/jose-compu/rustmaninoff/issues/84)). Shipped in 0.5.3.
- [x] `terraform_plan` reads attributes from `resource_changes[].change.after`. Default actions are `create` and `update` (including replace). Skip `no-op`, `read`, and pure `delete`. `--plan-scope all` keeps today's whole-state behavior. Unknown leaves stay unknown ([#80](https://github.com/jose-compu/rustmaninoff/issues/80)). Shipped in 0.5.4.
- [x] Emit plan edges for `depends_on` and for planned values that are another resource address. Run the existing `CKV2_*` pass on those resources. Do not invent an edge from a name that merely matches ([#81](https://github.com/jose-compu/rustmaninoff/issues/81)). Shipped in 0.5.5.
- [x] Add the plan fixtures from [#82](https://github.com/jose-compu/rustmaninoff/issues/82) (managed resource, data source, child-module address, `after_unknown`, delete versus create, sensitive redaction) and a plan section in `docs/fidelity.md`. Shipped in 0.5.6.
- [x] Copy the plan workflow from [ACTION.md](ACTION.md) into the README Action section. State that a default directory scan does not pick up plan files. Close [#83](https://github.com/jose-compu/rustmaninoff/issues/83) when both docs and the dogfood workflow agree. Shipped in 0.6.0.
- [x] Minor closer: the five boxes above are ticked, `cargo test --workspace` is green, and a plan with one new public bucket and one unchanged public bucket fails only the new bucket. Shipped in 0.6.0.

### 0.7.0 — Finish the pinned Kubernetes attribute pack

Goal: every id in the Kubernetes snapshot is implemented, or fidelity.md records it as an intentional divergence and the coverage denominator drops that id. Docker stays at 11/11; do not add Docker checks that are not in the snapshot. Required for 1.0.

- [x] Attribute lookup accepts keys that contain dots, so annotation names can match. Shipped in 0.6.1.
- [x] `CKV_K8S_152` with pass and fail fixtures. Shipped in 0.6.2.
- [x] `CKV_K8S_153` with pass and fail fixtures. Shipped in 0.6.3.
- [x] `CKV_K8S_154` with pass and fail fixtures. Shipped in 0.6.4.
- [x] Match `starting_with` (and the substring form the check needs) across items of a command or args array. Shipped in 0.6.5.
- [x] `CKV_K8S_105` with pass and fail fixtures. Shipped in 0.6.6.
- [x] `CKV_K8S_151` with pass and fail fixtures. Shipped in 0.6.7.
- [x] `CKV_K8S_32` with pass and fail fixtures. Shipped in 0.6.9.
- [ ] `CKV_K8S_147` with pass and fail fixtures.
- [ ] `CKV_K8S_34`: either match Checkov's Tiller check, or keep the current meaning, give it the id Checkov uses for that meaning, and write the divergence into fidelity.md so the old id is not counted as coverage.
- [ ] Regenerate `docs/fidelity.md`. Kubernetes shows 100%, or 100% of the ids that remain after documented divergences. Checkov-compare stays green.
- [ ] Minor closer: the Kubernetes row meets that bar and Docker is still 11/11.

### 0.8.0 — Close the 25 missing Terraform AWS resource ids

Goal: each missing `CKV_AWS_*` resource id is either a real check with fixtures, or a row in fidelity.md that names the engine limit. Required for 1.0. The 36.2% label gets corrected first so later patches are aimed at the 25, not at Azure.

- [ ] Split the fidelity table: one row for the 928-id Terraform resource directory, one row for `CKV_AWS_*` (336/361). Same change in the README sentence that says "~36%".
- [x] `CKV_AWS_61`
- [ ] `CKV_AWS_70`
- [x] `CKV_AWS_93`
- [x] `CKV_AWS_112`
- [x] `CKV_AWS_113`
- [ ] `CKV_AWS_121`
- [ ] `CKV_AWS_165`
- [ ] `CKV_AWS_192`
- [ ] `CKV_AWS_208`
- [x] `CKV_AWS_213`
- [ ] `CKV_AWS_250`
- [ ] `CKV_AWS_256`
- [ ] `CKV_AWS_274`
- [ ] `CKV_AWS_342`
- [ ] `CKV_AWS_355`
- [ ] `CKV_AWS_375`
- [ ] `CKV_AWS_379`
- [ ] `CKV_AWS_385`
- [ ] `CKV_AWS_387`
- [ ] `CKV_AWS_393`
- [ ] Policy-document walk for IAM JSON (the operator or helper the next five checks share). One release, no new check id yet.
- [ ] `CKV_AWS_45`
- [ ] `CKV_AWS_287`
- [ ] `CKV_AWS_288`
- [ ] `CKV_AWS_289`
- [ ] `CKV_AWS_290`
- [ ] Minor closer: fidelity.md shows 361/361, or each leftover id has an explicit exclusion and the percentage is computed without it.

If a listed id cannot be expressed, document the missing operator in fidelity.md, tick that id's box with the exclusion, and do not invent a check that fails the wrong resources. The policy-document box is the intended home for the five IAM ids; only exclude one of them if that walker still cannot express it.

### 0.9.0 — Local modules, count, and for_each

Goal: a child module and a static `count` / `for_each` fail the same CKV id as the expanded resource. No network on the default path. Required for 1.0.

- [ ] Expand local module sources (`./` and `../`) into resources. Registry and git sources stay unloaded and produce a diagnostic ([#17](https://github.com/jose-compu/rustmaninoff/issues/17)).
- [ ] Expand a static `count` into distinct resource addresses.
- [ ] Expand a static `for_each` (list or map of literals) into distinct resource addresses.
- [ ] When `count` or `for_each` is unknown, keep a single unknown resource and do not fail the process.
- [ ] Build graph edges from resolved interpolations that point at another resource in the same scan ([#19](https://github.com/jose-compu/rustmaninoff/issues/19)).
- [ ] Fixture: a child module with an unencrypted volume fails `CKV_AWS_3` (or whichever id the in-tree check is), and the same file with the module directory missing is a diagnostic, not a crash.
- [ ] Minor closer: those fixtures pass and a scan still does not contact the Terraform registry.

### 0.10.0 — Helm, then Kustomize

Goal: `--framework helm` renders a chart to Kubernetes resources and reuses `CKV_K8S_*`. `--framework kustomize` builds a local overlay the same way. Both are required for 1.0. The minor closes when both are done.

- [ ] `Framework::Helm` and `--framework helm`. `Chart.yaml` selects the chart. Missing `helm` on `PATH` is a diagnostic, not a crash ([#3](https://github.com/jose-compu/rustmaninoff/issues/3)).
- [ ] `--helm-values` (repeatable) passed through to `helm template`. Default values file is used when present.
- [ ] Refuse a chart install or repo update. Remote charts render only when the caller passes an explicit flag, and that flag stays off in CI examples.
- [ ] Skip `CKV_K8S_21` (default namespace) on Helm-rendered resources, matching Checkov.
- [ ] Fixture chart: rendered manifests and `helm template` output fail the same `CKV_K8S_*` ids.
- [ ] `--framework kustomize`. `kustomization.yaml` is built with `kustomize` on `PATH`. Missing binary is a diagnostic. No remote base fetch unless a flag asks for it.
- [ ] Fixture: a local kustomize overlay fails the same ids as the built YAML.
- [ ] Minor closer: both frameworks are accepted by the CLI and the Action `args` allowlist, and the default framework list is still Terraform, CloudFormation, Kubernetes, and Docker.

### 0.11.0 — Baselines and the rest of the config file

Goal: an existing repo can adopt the scanner without failing on a recorded set of legacy findings. Inline skips and `--skip-check` stay as they are. Required for 1.0.

- [ ] Baseline file format (YAML): one entry is check id plus resource address, plus the file path when the address is not unique ([#58](https://github.com/jose-compu/rustmaninoff/issues/58)).
- [ ] `--baseline PATH` suppresses matching failures from the exit code.
- [ ] `rustmaninoff baseline create` (or `scan --create-baseline`) writes that file from the current failures.
- [ ] `.rustmaninoff.yaml` accepts `baseline`.
- [ ] `--show-suppressed` prints suppressed failures. Default output omits them from the failure count and still returns exit 0 when nothing unsuppressed fails.
- [ ] Fixture: exit 0 with the baseline, exit 1 after one entry is removed.
- [ ] Config keys for the flags that are CLI-only today: `checks`, `soft_fail`, `output`, `var_files`, `show_passed`. Document them next to the existing keys.
- [ ] README section: generate a baseline, land the Action, delete entries over time.
- [ ] Minor closer: the fixture is in CI and the README section matches the flags.

### 0.12.0 — CloudFormation, with a denominator

Goal: publish how many Checkov CloudFormation attribute ids exist, then add or realign one id per patch until coverage of the ones the dialect can express is at least 80%. The 51 current policies stay. The `_2` suffix gets a written explanation. Does not block 1.0 beyond the first two boxes (the denominator and the id-scheme note), which are also listed in the exit criteria as docs.

- [ ] Teach `scripts/fetch_checkov_ids.py` to scrape `checkov/cloudformation/checks/` (attribute checks, not graph). Refresh the snapshot.
- [ ] Add a CloudFormation row to `docs/fidelity.md` with the scraped count, the exact overlap, and a sentence on why current files use a `_2` suffix.
- [ ] Reach 80% of scraped CloudFormation attribute ids that the current dialect can express. Each patch adds or realigns one id and its fixtures. Leave this box unchecked until the percentage is true. Ids that need a missing operator are exclusions in fidelity.md and do not count against the 80%.
- [ ] Minor closer: the row shows at least 80% and `pack_tests` still requires fixtures on every built-in policy.

### 0.13.0 — Graph checks with a published count

Goal: the snapshot includes Terraform graph checks, the four local `CKV2` names are aligned or documented, and exact `CKV2_AWS_*` coverage grows by one id per patch until 40 published ids exist or the scraped AWS graph set runs out. The 20 policies already in tree count toward 40 once their ids are published Checkov ids. Does not block 1.0 except where 0.6 already runs today's `CKV2` set on plans.

- [ ] Scrape `checkov/terraform/checks/graph_checks/` (and the Kubernetes graph directory if it has ids) into the snapshot. Publish the count in fidelity.md.
- [ ] Map `CKV2_AWS_IAM_POLICY_ATTACHMENT`, `CKV2_AWS_S3_BUCKET_LOGGING`, `CKV2_AWS_S3_BUCKET_PUBLIC_ACCESS`, and `CKV2_AWS_SECURITY_GROUP_INGRESS` onto published ids, or document them as local aliases and stop counting them in the overlap.
- [ ] Reach 40 exact `CKV2_AWS_*` ids, one new id per patch, each with fixtures. Leave this box unchecked until the count is 40 or the scraped set is exhausted.
- [ ] Minor closer: fidelity.md shows that count and the plan-scan path from 0.6 still runs the graph pass.

### 0.14.0 — Output schemas, plus two more formats

Goal: JSON, SARIF, and JUnit have golden files so a patch cannot change them quietly. Markdown and GitLab SAST are new formats (their arrival is this minor). CycloneDX stays out; see [Out of scope](#out-of-scope). Golden files for the three existing formats are required for 1.0. Markdown and GitLab SAST do not block 1.0.

- [ ] Check in golden JSON, SARIF 2.1.0, and JUnit for one fixed fixture scan. CI fails on a diff.
- [ ] Write the field list for those three formats in `docs/fidelity.md` or a short `docs/outputs.md` (schema versions, exit codes, which severities appear).
- [ ] `--output markdown`: one human-readable file, failed checks grouped by file.
- [ ] `--output gitlab-sast`: GitLab's SAST report schema, enough for a GitLab MR widget. Map severity and file/line. Do not invent a CVE field.
- [ ] Document both new formats next to the golden files.
- [ ] Minor closer: `cli,json,sarif,junit,markdown,gitlab-sast` all run in one scan and the goldens match.

### 0.15.0 — Terraform Azure starter pack

Goal: the HCL parser already accepts any resource type. Add the first 20 `CKV_AZURE_*` ids from the snapshot, one per patch. Further Azure ids continue as patches after this minor and do not block 1.0. Does not block 1.0.

- [ ] `CKV_AZURE_1`
- [ ] `CKV_AZURE_2`
- [ ] `CKV_AZURE_3`
- [ ] `CKV_AZURE_4`
- [ ] `CKV_AZURE_5`
- [ ] `CKV_AZURE_6`
- [ ] `CKV_AZURE_7`
- [ ] `CKV_AZURE_8`
- [ ] `CKV_AZURE_9`
- [ ] `CKV_AZURE_10`
- [ ] `CKV_AZURE_11`
- [ ] `CKV_AZURE_12`
- [ ] `CKV_AZURE_13`
- [ ] `CKV_AZURE_14`
- [ ] `CKV_AZURE_15`
- [ ] `CKV_AZURE_16`
- [ ] `CKV_AZURE_17`
- [ ] `CKV_AZURE_18`
- [ ] `CKV_AZURE_19`
- [ ] `CKV_AZURE_20`
- [ ] Fidelity row for `CKV_AZURE_*` (20 / 242 at the close, unless an id was excluded with a reason).
- [ ] Minor closer: those 20 exist with fixtures, or excluded ids are named and replaced by the next snapshot id so the pack still holds 20 checks.

### 0.16.0 — Terraform GCP starter pack

Same rule as Azure. The snapshot has no `CKV_GCP_5` or `CKV_GCP_19`; the list below is the first 20 ids that do exist. Does not block 1.0. Further GCP ids stay on the patch train after the minor.

- [ ] `CKV_GCP_1`
- [ ] `CKV_GCP_2`
- [ ] `CKV_GCP_3`
- [ ] `CKV_GCP_4`
- [ ] `CKV_GCP_6`
- [ ] `CKV_GCP_7`
- [ ] `CKV_GCP_8`
- [ ] `CKV_GCP_9`
- [ ] `CKV_GCP_10`
- [ ] `CKV_GCP_11`
- [ ] `CKV_GCP_12`
- [ ] `CKV_GCP_13`
- [ ] `CKV_GCP_14`
- [ ] `CKV_GCP_15`
- [ ] `CKV_GCP_16`
- [ ] `CKV_GCP_17`
- [ ] `CKV_GCP_18`
- [ ] `CKV_GCP_20`
- [ ] `CKV_GCP_21`
- [ ] `CKV_GCP_22`
- [ ] Fidelity row for `CKV_GCP_*`.
- [ ] Minor closer: 20 GCP checks with fixtures, exclusions replaced from the snapshot so the pack still holds 20.

### 0.17.0 — Speed on a large repository

Goal: widen the corpus after the CI regression job in [Next patch](#next-patch) ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)) is already required. The README and the site cite the latest row in `benchmarks/history.json` (0.6.8 release binary, 43 ms median on 1,540 resources, 2026-11-26, Linux x86_64 runner). Older rows stay; new runs append and do not rewrite old rows. The CI gate itself is not this milestone. Does not block 1.0 beyond the exit-criteria line for that gate.

- [ ] Pin a second public repository (larger than `terraform-aws-modules/terraform-aws-s3-bucket@v4.1.2`) in `scripts/bench.sh`, with a commit SHA. The CI job may keep using the smaller pinned sample until this lands.
- [ ] Record wall time and peak RSS for the synthetic corpus and that repository in `benchmarks/history.json`.
- [ ] Minor closer: `./scripts/bench.sh` fills both rows. Do not add a second CI budget. The 5% / 15% job from [#89](https://github.com/jose-compu/rustmaninoff/issues/89) is the gate.

### 0.18.0 — Library API and MSRV

Goal: the crates people can depend on have a written compatibility rule, and CI compiles with the stated minimum compiler. Required for 1.0.

Public crates today, all versioned together at the workspace version: `rustmaninoff-ir`, `rustmaninoff-engine`, `rustmaninoff-parser-terraform`, `rustmaninoff-parser-cfn`, `rustmaninoff-parser-k8s`, `rustmaninoff-parser-docker`, `rustmaninoff-report`, and the `rustmaninoff` CLI library (`scan`, `execute`, `builtin_policies`).

- [ ] Set `rust-version` in the workspace to the README floor (1.95 today, or a lower version if CI proves one). Add a CI job that uses that toolchain, not only `@stable`.
- [ ] Write `docs/msrv.md`: patch releases keep the MSRV, a minor may raise it, 1.0 holds it until 1.x minors.
- [ ] Write `docs/semver.md`: before 1.0, minors may break those crates; patches may not. From 1.0, breaks wait for 2.0. CLI flags and the three original output schemas follow the same split. New formats added at a minor are stable at the next minor.
- [ ] List the supported public functions (parse, evaluate, evaluate_graph, render_text / render_json / render_sarif / render_junit, scan) in `docs/semver.md`. Anything else public is unsupported until it is added to that list.
- [ ] CI check that fails when a supported signature changes on a pull request that does not bump the minor (a committed rustdoc dump or `cargo public-api` diff is enough).
- [ ] Minor closer: both docs exist, `rust-version` matches CI, and the signature check runs.

### 0.19.0 — Docs, security policy, and the project site

Goal: a new user can install, scan, suppress, and report a vulnerability without reading the crate source. Required for 1.0.

- [ ] `SECURITY.md`: where to report, which versions receive fixes (the latest 0.x minor, and 1.x once it exists), and a statement that the scanner does not phone home.
- [ ] `CONTRIBUTING.md`: how to add one check (YAML, pass and fail fixtures, `python3 scripts/coverage_inventory.py`, `cargo test -p rustmaninoff`).
- [ ] Remove the duplicated `## Refresh` heading in `docs/fidelity.md`.
- [ ] Example directory of one external policy under `examples/`, matching the dialect already listed in the README (operators, `missing: pass|fail|unknown`, `connection`). A file that does not parse fails the process with exit code 2 and the file path in the error.
- [ ] Project site (`docs` branch) roadmap page matches this file's milestone list and does not list CVE scanning as a 1.0 goal.
- [ ] Minor closer: those pages are linked from the README and from the site footer nav.

### 0.20.0 — Windows and extra packages

Goal: the release workflow, the Action, and the README name the same operating systems. Adding Windows is this milestone. Scoop and a `.deb` are the extra packages. An apt repository (a signed feed, not a single `.deb` attached to the GitHub Release) stays out until a user asks. Does not block 1.0 if ACTION.md already says Windows runners are unsupported; the exit criteria only require that the document and the workflow agree. This milestone is still the work that adds Windows.

- [ ] `release.yml`: `x86_64-pc-windows-msvc` archive and checksum, same as the Unix tarballs (zip if tar is a poor fit for that target).
- [ ] Action: select that archive on Windows. `uname` is not how Windows runners identify themselves today (`action.yml` only matches `Linux` and `Darwin`).
- [ ] README and ACTION.md list the runner OS/arch pairs the Action accepts.
- [ ] Scoop manifest in `jose-compu/homebrew-tap` or a scoop bucket the README links, updated from the release workflow the way Homebrew already is.
- [ ] Attach a `.deb` built from the Linux gnu binary to the GitHub Release. Document `dpkg -i`. Do not stand up an apt repository in this milestone.
- [ ] Minor closer: a Windows runner completes the Action on a fixture repo, and the Linux `.deb` installs the same version as the tarball.

### 0.21.0 — Narrow secret patterns in IaC files

Goal: opt-in detection of a fixed set of token shapes inside files the scanner already parses. This is [#7](https://github.com/jose-compu/rustmaninoff/issues/7). It is not a secrets product: no entropy scoring, no git history, no Trivy rule parity. Does not block 1.0. Schedule it only after 0.11 baselines exist, so a brownfield run can suppress the new findings.

- [ ] `--framework secrets` off by default. Patterns: AWS access key id (`AKIA`), GitHub tokens, GitLab tokens, Slack tokens, PEM private keys, JWT shape, and `user:password@` URLs.
- [ ] Findings go through the existing reporters. The matched secret is redacted in CLI, JSON, SARIF, and JUnit.
- [ ] Honor inline skips and the baseline file.
- [ ] Fixtures with planted tokens fail; a scan of the same fixture with the framework omitted does not report them.
- [ ] Minor closer: the redaction fixture proves the raw token is absent from every output format.

### 0.22.0 — Compliance filters over checks we already have

Goal: `--compliance` selects a named subset of implemented CKV ids. This is [#10](https://github.com/jose-compu/rustmaninoff/issues/10). Built-ins stay YAML. Rego is not part of this milestone. Does not block 1.0.

- [ ] One map, CIS AWS foundations, from control id to CKV ids that exist in tree. Controls whose checks are missing are listed as unsupported in the command output, not silently passed.
- [ ] `--compliance cis-aws` (name to be the map's id) intersects with `--check` / `--skip-check`.
- [ ] Document the map and the unsupported controls.
- [ ] Minor closer: a fixture that fails only the checks in the map, and passes a resource that would fail a CKV id outside the map.

## 1.0.0 exit criteria

Tag `1.0.0` when every line below is true. Milestones marked as not blocking 1.0 may still be open.

- [ ] CLI: `rustmaninoff scan` flags that exist in 0.5.1 are unchanged in name and meaning: `path`, `--framework`, `--check`, `--skip-check`, `--config`, `--output`, `--json-file`, `--sarif-file`, `--junit-file`, `--fail-on`, `--external-checks-dir`, `--var-file`, `--show-unknown`, `--compact`, `--soft-fail`, `--show-passed`. Exit codes remain 0 (below the threshold), 1 (finding at or above `--fail-on`, or a file failed to parse), 2 (usage or a policy file that did not parse).
- [ ] Flags added on the way (baseline, plan scope, Helm values, compliance, secrets, new output names) are in the README and stay stable across 1.x patches.
- [ ] JSON, SARIF 2.1.0, and JUnit goldens from 0.14 match on the 1.0 commit. SARIF locations are repo-relative (0.6).
- [ ] `docs/semver.md` and `docs/msrv.md` exist. `rust-version` is set. CI compiles with that toolchain. The supported public function list is enforced.
- [ ] Parity, measured by `scripts/coverage_inventory.py` against the snapshot committed on the 1.0 tag: Docker attribute ids 100%; Kubernetes attribute ids 100% after documented divergences are removed from the denominator; every `CKV_AWS_*` Terraform resource id from the 0.5.1 missing list is implemented or named as an exclusion; the fidelity table no longer calls the 928-id directory "AWS".
- [ ] Plan scan: create/update scope is the default, `--plan-scope all` remains, sensitive values stay redacted, and fidelity.md has the plan section from 0.6.
- [ ] Local module expansion works with no network (0.9). Helm and Kustomize rendering work with no implicit remote fetch (0.10).
- [ ] `--baseline` can hold a fixture repo at exit 0, and deleting an entry brings that finding back (0.11).
- [ ] CloudFormation and graph sections of fidelity.md publish a scraped denominator (the first boxes of 0.12 and 0.13), even if the 80% and 40-id targets are still open.
- [ ] `SECURITY.md` and `CONTRIBUTING.md` exist. The project site roadmap describes these milestones and does not offer CVE scanning.
- [ ] `cargo test --workspace` is green, including `builtin_pack_covers_at_least_160_policies_with_fixtures` (every built-in policy still has pass and fail fixtures). `cargo fmt` and `cargo clippy --workspace --all-targets -- -D warnings` are green, with no unused-readme or redundant-homepage warning ([#85](https://github.com/jose-compu/rustmaninoff/issues/85)).
- [ ] The CI benchmark ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)) runs on the 1.0 commit. No scenario is more than 15% slower than the `main` baseline from the same runner unless that pull request explains the regression and changes the threshold in the same change. A result more than 5% slower is visible as a warning. `./scripts/bench.sh` still runs on the synthetic corpus.
- [ ] ACTION.md and `release.yml` list the same OS/arch pairs. Each listed pair has a release archive. Pairs the Action refuses are named in ACTION.md.
- [ ] Latest minor and the 1.0 tag itself are the only versions `SECURITY.md` promises to fix.

## Patch-level backlog

Any of these can ship on a day when the next milestone box is a one-check port that turns out to be blocked, or alongside a patch if it is a single-file fix. Do not let the backlog jump the queue when the next milestone box is ready.

- [x] On the next version bump, clear the Cargo warnings in [#85](https://github.com/jose-compu/rustmaninoff/issues/85): drop unused workspace `readme` (keep the CLI readme), point workspace `homepage` at `https://jose-compu.github.io/rustmaninoff/`. Shipped in 0.5.4.
- [ ] `CKV_K8S_95`: match Checkov's duration grammar, or narrow the fidelity note if the approximation is the intended behavior. One patch.
- [ ] Each Checkov-compare disagreement: fix the check, or add one row to the divergence table. One disagreement per patch.
- [ ] False positives reported against a published CKV id: one id per patch, with a fixture that used to fail and now passes.
- [ ] Speed: a CI benchmark failure (median more than 15% slower, [#89](https://github.com/jose-compu/rustmaninoff/issues/89)) is fixed in the next patch, or that same patch explains the regression and updates the threshold. Do not merge an unexplained fail.
- [ ] Confirm the GitHub Marketplace listing still resolves for `jose-compu/rustmaninoff` and close [#33](https://github.com/jose-compu/rustmaninoff/issues/33) if the page is the current Action. The README already links it.
- [ ] Launch notes ([#34](https://github.com/jose-compu/rustmaninoff/issues/34) and children [#35](https://github.com/jose-compu/rustmaninoff/issues/35)–[#39](https://github.com/jose-compu/rustmaninoff/issues/39), [#44](https://github.com/jose-compu/rustmaninoff/issues/44)–[#46](https://github.com/jose-compu/rustmaninoff/issues/46)) are writing and outreach. They are not version bumps. Do not cut a release only to post them.

## Parked frameworks

Checkov has these runners. They are not milestones. Issues [#5](https://github.com/jose-compu/rustmaninoff/issues/5) and [#6](https://github.com/jose-compu/rustmaninoff/issues/6) already defer them. Reopen a milestone only after 1.0, and only if a user asks: Ansible, ARM, Bicep, Serverless, OpenAPI, SAM, CDK, GitHub Actions workflows, GitLab CI, Azure Pipelines, CircleCI, Bitbucket Pipelines, Argo Workflows, and the smaller clouds listed in the coverage table (Alibaba, Yandex, OCI, NCP, Palo Alto, Tencent, Linode, DigitalOcean, OpenStack, Okta).

Live Kubernetes cluster scanning stays deferred ([#9](https://github.com/jose-compu/rustmaninoff/issues/9)). Point cluster users at Trivy or kubectl.

## Out of scope

- Image and filesystem CVE scanning, vulnerability databases, license feeds, and SBOM output, including CycloneDX ([#8](https://github.com/jose-compu/rustmaninoff/issues/8)).
- A general secrets product: entropy, git history, or parity with Trivy's secret catalog. The narrow opt-in patterns in 0.21 are the whole of that idea.
- Implicit network during a scan: Terraform module registry, Helm repos, and Kustomize remote bases stay off unless a flag is set, and the flag stays out of the default CI examples.
- Phone-home, policy downloads, and a hosted backend.

## Tracking

- This file is the daily queue. GitHub epics: [#1](https://github.com/jose-compu/rustmaninoff/issues/1), [#2](https://github.com/jose-compu/rustmaninoff/issues/2), [#3](https://github.com/jose-compu/rustmaninoff/issues/3), [#11](https://github.com/jose-compu/rustmaninoff/issues/11).
- Fidelity numbers: [docs/fidelity.md](docs/fidelity.md). Regenerate with `python3 scripts/coverage_inventory.py -o docs/fidelity.md` after a snapshot refresh.
- Site copy of the milestone list: [roadmap.html](https://jose-compu.github.io/rustmaninoff/roadmap.html) on the `docs` branch.
