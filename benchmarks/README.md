# Benchmarks

Synthetic corpus under `corpus/` (deterministic):

| Framework | Files | Resources |
| --- | ---: | ---: |
| Terraform | 40 | 1,080 |
| CloudFormation | 20 | 300 |
| Kubernetes | 20 | 160 |
| Dockerfiles | 4 | 4 |
| **Total** | **84** | **1,544** |

## Run

```sh
cargo build --release -p rustmaninoff
./scripts/bench.sh
```

Optional: install Checkov and/or Trivy on `PATH` for comparison columns. The script also clones a small real-world public repo (pinned commit) into `benchmarks/.cache/` when network is available.

## CI regression gate

Pull requests and pushes to `main` run `scripts/bench_ci_compare.py` in the `benchmark` job (see `.github/workflows/ci.yml`). The job builds the release binary for `main` and for the pull request head on the same runner, benches fixed corpora (pinned Terraform module, synthetic Kubernetes/CloudFormation/Docker, and a plan JSON file), and writes a Markdown table to the job summary. On pull requests, one sticky comment is updated with the same table. Warn when the median is more than **5%** slower than `main`; fail above **15%**. Thresholds live in `benchmarks/regression_thresholds.json` and may be overridden with `BENCH_WARN_PCT` / `BENCH_FAIL_PCT`.

Main-branch medians are uploaded as workflow artifacts for trend tracking.

Caveats: catalogs differ; machine and binary build affect timings. The README and the site cite the **latest** row in `history.json`. After a run, append a row (do not rewrite older rows). Label the binary with the workspace version from `python3 scripts/workspace_version.py`. Timings are medians of three runs after warmup on the machine noted in that row.
