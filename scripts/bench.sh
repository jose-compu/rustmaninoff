#!/usr/bin/env bash
# Reproducible CLI wall-clock benches for rustmaninoff (+ optional Checkov/Trivy).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${ROOT}/benchmarks/corpus"
CACHE="${ROOT}/benchmarks/.cache"
RUNS="${BENCH_RUNS:-3}"
REAL_REPO_URL="${REAL_REPO_URL:-https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git}"
REAL_REPO_REF="${REAL_REPO_REF:-v4.1.2}"

BIN="${RUSTMANINOFF_BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "${ROOT}/target/release/rustmaninoff" ]]; then
    BIN="${ROOT}/target/release/rustmaninoff"
  else
    echo "Building release binary..." >&2
    (cd "$ROOT" && cargo build --release -p rustmaninoff --quiet)
    BIN="${ROOT}/target/release/rustmaninoff"
  fi
fi

median() {
  # stdin: one float/ms per line -> median printed
  sort -n | awk '
    { a[NR]=$1 }
    END {
      if (NR==0) { print "n/a"; exit }
      if (NR%2==1) print a[(NR+1)/2]
      else print (a[NR/2]+a[NR/2+1])/2
    }'
}

time_ms() {
  local start end
  start=$(python3 -c 'import time; print(time.perf_counter())')
  "$@" >/dev/null 2>&1 || true
  end=$(python3 -c 'import time; print(time.perf_counter())')
  python3 -c "print(int(($end-$start)*1000))"
}

bench_cmd() {
  local label="$1"; shift
  local times=()
  # warmup
  "$@" >/dev/null 2>&1 || true
  local i t
  for ((i=0; i<RUNS; i++)); do
    t=$(time_ms "$@")
    times+=("$t")
  done
  local med
  med=$(printf '%s\n' "${times[@]}" | median)
  printf '%-28s %8s ms  (n=%s: %s)\n' "$label" "$med" "$RUNS" "$(IFS=,; echo "${times[*]}")"
}

echo "=== Synthetic corpus: ${CORPUS} ==="
echo "rustmaninoff: $BIN"
bench_cmd "rustmaninoff full" "$BIN" scan "$CORPUS" --soft-fail --compact
bench_cmd "rustmaninoff terraform" "$BIN" scan "$CORPUS/terraform" --framework terraform --soft-fail --compact
bench_cmd "rustmaninoff cloudformation" "$BIN" scan "$CORPUS/cloudformation" --framework cloudformation --soft-fail --compact
bench_cmd "rustmaninoff kubernetes" "$BIN" scan "$CORPUS/kubernetes" --framework kubernetes --soft-fail --compact

if command -v checkov >/dev/null 2>&1; then
  echo
  echo "=== Checkov $(checkov --version 2>/dev/null | head -1) ==="
  bench_cmd "checkov full" checkov -d "$CORPUS" --framework terraform cloudformation kubernetes --quiet --compact --soft-fail
  bench_cmd "checkov terraform" checkov -d "$CORPUS/terraform" --framework terraform --quiet --compact --soft-fail
else
  echo
  echo "(checkov not on PATH — skip comparison)"
fi

if command -v trivy >/dev/null 2>&1; then
  echo
  echo "=== Trivy $(trivy --version 2>/dev/null | head -1) ==="
  bench_cmd "trivy full" trivy config --quiet --skip-check-update "$CORPUS"
else
  echo
  echo "(trivy not on PATH — skip comparison)"
fi

echo
echo "=== Real-world sample ==="
mkdir -p "$CACHE"
REAL_DIR="${CACHE}/terraform-aws-s3-bucket"
if [[ ! -d "$REAL_DIR/.git" ]]; then
  if git clone --quiet --depth 1 --branch "$REAL_REPO_REF" "$REAL_REPO_URL" "$REAL_DIR" 2>/dev/null; then
    echo "cloned $REAL_REPO_URL @$REAL_REPO_REF"
  else
    echo "clone failed (offline?) — skip real-world path"
    exit 0
  fi
fi
bench_cmd "rustmaninoff real-world" "$BIN" scan "$REAL_DIR" --framework terraform --soft-fail --compact
if command -v checkov >/dev/null 2>&1; then
  bench_cmd "checkov real-world" checkov -d "$REAL_DIR" --framework terraform --quiet --compact --soft-fail
fi
