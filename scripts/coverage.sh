#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Coverage gate.
#
#   scripts/coverage.sh [CRATE...]     default: every crate of the workspace
#
# Each crate is measured with its own tests only (`cargo llvm-cov -p CRATE`),
# as mutation testing does, so that a crate is not credited for code that
# only another crate's tests execute. Prints per-file line and region
# coverage and the uncovered lines and regions, writes for each crate
#   target/coverage/CRATE.lcov        lcov, exclusions applied
#   target/coverage/CRATE.json        llvm-cov JSON export (raw)
#   target/coverage/CRATE/html/       HTML report (raw: exclusions show as missed)
# and exits non-zero if a gated crate is below its threshold, or if an
# exclusion marker is not listed in docs/coverage-exclusions.md.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

# Thresholds, percent: lines and regions; "-" is not gated.
# 100/100 for xs-wire and xs-core; >= 95% lines for xs-daemon and xs-sys.
gate_for() {
    case "$1" in
        xs-wire | xs-core) echo "100 100" ;;
        xs-sys | xs-daemon) echo "95 -" ;;
        *) echo "- -" ;;
    esac
}

ALL=(xs-wire xs-sys xs-core xs-daemon xs-bench xs-sim)
if [ $# -gt 0 ]; then CRATES=("$@"); else CRATES=("${ALL[@]}"); fi
for c in "${CRATES[@]}"; do
    [ -d "crates/$c" ] || { echo "coverage.sh: no crate $c" >&2; exit 2; }
done

command -v cargo-llvm-cov >/dev/null || {
    echo "coverage.sh: cargo-llvm-cov is missing: cargo install --locked cargo-llvm-cov;" \
        "rustup component add llvm-tools-preview" >&2
    exit 2
}

OUT=target/coverage
mkdir -p "$OUT"
# cargo-llvm-cov keeps its profiles in one directory: one run at a time.
exec 9>"$OUT/.lock"
flock 9

python3 scripts/covgate.py markers

status=0
summary=()
for c in "${CRATES[@]}"; do
    read -r lines regions < <(gate_for "$c")
    echo
    echo "== $c"
    # Start from nothing: with --no-report, cargo-llvm-cov keeps the
    # profiles of earlier runs (other crates' tests would be credited to
    # this crate) and the test binaries of earlier sources (their code
    # would count as never run).
    cargo llvm-cov clean --workspace
    if ! cargo llvm-cov -p "$c" --no-report --quiet >"$OUT/$c.test.log" 2>&1; then
        tail -n 40 "$OUT/$c.test.log"
        echo "  tests FAILED (full log: $OUT/$c.test.log)"
        summary+=("  $c: tests failed")
        status=1
        continue
    fi
    cargo llvm-cov report -p "$c" --json --output-path "$OUT/$c.json" >/dev/null 2>&1
    cargo llvm-cov report -p "$c" --lcov --output-path "$OUT/$c.raw.lcov" >/dev/null 2>&1
    cargo llvm-cov report -p "$c" --html --output-dir "$OUT/$c" >/dev/null 2>&1
    args=()
    [ "$lines" = - ] || args+=(--lines "$lines")
    [ "$regions" = - ] || args+=(--regions "$regions")
    set +e
    python3 scripts/covgate.py report "$c" "$OUT/$c.json" "$OUT/$c.raw.lcov" "$OUT/$c.lcov" "${args[@]}" | tee "$OUT/$c.txt"
    rc=${PIPESTATUS[0]}
    set -e
    rm -f "$OUT/$c.raw.lcov"
    summary+=("$(grep '^  summary ' "$OUT/$c.txt" | sed 's/^  summary /  /')")
    [ "$rc" -eq 0 ] || status=1
done

echo
echo "== coverage summary (reports in $OUT/)"
printf '%s\n' "${summary[@]}"
exit $status
