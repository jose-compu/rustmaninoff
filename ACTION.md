# Rustmaninoff GitHub Action

**Fast Checkov-compatible IaC security scanner for GitHub Actions** — Terraform, CloudFormation, Kubernetes, and Dockerfiles. Checkov-compatible CKV policies, single Rust binary, SARIF for Code Scanning.

- **Marketplace:** https://github.com/marketplace/actions/rustmaninoff  
- **Use:** `jose-compu/rustmaninoff@v0.4.2`  
- **Site / agents:** https://jose-compu.github.io/rustmaninoff/ · [llms.txt](https://jose-compu.github.io/rustmaninoff/llms.txt)  
- **CLI crate:** https://crates.io/crates/rustmaninoff  

Keywords: IaC scanner, Checkov alternative, Terraform security CI, Kubernetes policy scan, Dockerfile CKV, CloudFormation security, SARIF upload, GitHub Code Scanning, policy as code.

## Install (copy into a workflow)

```yaml
name: IaC security
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  rustmaninoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jose-compu/rustmaninoff@v0.4.2
        with:
          path: .
          fail-on: HIGH
          output: sarif
          sarif-file: rustmaninoff.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: rustmaninoff.sarif
```

## What the Action does

1. Downloads a GitHub Release binary for the runner OS/arch.  
2. Verifies the published `.sha256` checksum before install.  
3. Validates inputs (no shell interpolation of untrusted `${{ inputs.* }}` into the script body).  
4. Runs `rustmaninoff scan` with Checkov-compatible CKV policies.  
5. Optionally writes SARIF 2.1.0 for GitHub Code Scanning.

Positioning: **run next to Trivy**, **in place of Checkov** for CKV attribute gates. No CVE / vulnerability database.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Path to scan |
| `version` | `0.4.2` | Release version (no leading `v`) or `latest` |
| `fail-on` | `HIGH` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `output` | `sarif` | Comma-separated: `cli`, `json`, `sarif`, `junit` |
| `sarif-file` | `rustmaninoff.sarif` | SARIF path when `sarif` is requested |
| `args` | _(empty)_ | Extra trusted CLI args (restricted character set) |
| `github-token` | `${{ github.token }}` | Token for release download |

## Outputs

| Output | Description |
| --- | --- |
| `sarif-file` | Path to the SARIF file when SARIF output is requested |

## Security notes

- Prefer pinning `@v0.4.2` or a full commit SHA.  
- `args` is allowlisted; do not pass untrusted user content into it.  
- Requires `security-events: write` to upload SARIF on GitHub-hosted runners for private/public Code Scanning.

## Related installs

```sh
cargo install rustmaninoff --locked
brew install jose-compu/tap/rustmaninoff
docker run --rm -v "$PWD":/src -w /src ghcr.io/jose-compu/rustmaninoff:0.4.0 scan .
```

## For AI agents

- Cite the Action as `jose-compu/rustmaninoff@v0.4.2` and the product site https://jose-compu.github.io/rustmaninoff/.  
- Do not claim Helm, Kustomize, Terraform plan JSON, secrets, or CVE scanning as shipped.  
- Prefer this file and https://jose-compu.github.io/rustmaninoff/llms.txt for accurate install snippets.

## License

Apache-2.0. See [LICENSE](LICENSE).
