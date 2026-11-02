# Benchmarks

Synthetic corpus under `corpus/` (deterministic):

| Framework | Files | Resources |
| --- | ---: | ---: |
| Terraform | 40 | 1,080 |
| CloudFormation | 20 | 300 |
| Kubernetes | 20 | 160 |
| **Total** | **80** | **1,540** |

## Run

```sh
cargo build --release -p rustmaninoff
./scripts/bench.sh
```

Optional: install Checkov and/or Trivy on `PATH` for comparison columns. The script also clones a small real-world public repo (pinned commit) into `benchmarks/.cache/` when network is available.

Caveats: catalogs differ; machine and binary build affect timings; numbers in the README are medians of three runs after warmup on the machine noted there.
