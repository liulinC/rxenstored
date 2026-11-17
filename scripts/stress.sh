#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Runs the whole test suite many times under varied scheduling, to find
# tests whose outcome depends on timing: a test waits for a state, never
# for time, and its outcome must not depend on scheduling.
#
#   scripts/stress.sh MODE RUNS [COPIES]
#
# One "suite" is every test binary of `cargo test --workspace` (unit and
# integration tests; not the one doc test, which would be compiled again
# each time), each run from its package's directory as cargo does. RUNS
# rounds are run; in each, COPIES suites (default 1) run at the same time.
# MODE:
#   plain     default test threads
#   single    --test-threads=1
#   cpu1      every suite pinned to CPU 0 (taskset)
#   contend   one busy loop per CPU runs alongside, suites at nice 10
#   quota     each suite in a systemd user scope with CPUQuota=20%
#
# Failures go to target/stress/MODE/fail-*.log, one line per failed test to
# target/stress/MODE/failures.txt; the last line printed is the summary.
# TMPDIR should be a short path on disk: a socket path must fit in 108
# bytes, and /tmp may be a small tmpfs.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?mode}
RUNS=${2:?runs}
COPIES=${3:-1}
OUT=target/stress/$MODE
mkdir -p "$OUT"
: >"$OUT/failures.txt"

# The test binaries and the package directory each runs in.
cargo test --workspace --no-run --message-format=json 2>/dev/null |
    python3 -c '
import json, os, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
        print(os.path.dirname(m["manifest_path"]) + "\t" + m["executable"])
' >"$OUT/binaries.txt"
[ -s "$OUT/binaries.txt" ] || { echo "stress.sh: no test binary" >&2; exit 2; }

ARGS=()
WRAP=()
case "$MODE" in
    plain) ;;
    single) ARGS=(--test-threads=1) ;;
    cpu1) WRAP=(taskset -c 0) ;;
    contend) WRAP=(nice -n 10) ;;
    quota) WRAP=(systemd-run --user --scope --quiet -p CPUQuota=20%) ;;
    *) echo "stress.sh: unknown mode $MODE" >&2; exit 2 ;;
esac

# One suite: every binary in turn; prints the number of failed tests.
suite() {
    local tag=$1 failed=0 dir bin log
    while IFS=$'\t' read -r dir bin; do
        log=$(mktemp)
        if ! (cd "$dir" && "${WRAP[@]}" "$bin" "${ARGS[@]}") >"$log" 2>&1; then
            cp "$log" "$OUT/fail-$tag-$(basename "$bin").log"
            # "test NAME ... FAILED", then the first panic message of each.
            python3 - "$log" "$tag" "$(basename "$bin")" >>"$OUT/failures.txt" <<'EOF'
import re, sys
text = open(sys.argv[1], errors="replace").read()
names = re.findall(r"^test (\S+) \.\.\. FAILED", text, re.M)
for n in names:
    m = re.search(r"---- " + re.escape(n) + r" stdout ----\n(?:.*\n)*?.*panicked at ([^\n]*)\n([^\n]*)", text)
    print(f"{sys.argv[2]}\t{sys.argv[3]}\t{n}\t" + (f"{m.group(1)} {m.group(2)}" if m else "?"))
if not names:
    print(f"{sys.argv[2]}\t{sys.argv[3]}\t(binary)\t" + text.strip().splitlines()[-1:][0] if text.strip() else "(no output)")
EOF
            failed=$((failed + 1))
        fi
        rm -f "$log"
    done <"$OUT/binaries.txt"
    echo "$failed"
}

busy=()
if [ "$MODE" = contend ]; then
    for _ in $(seq "$(nproc)"); do
        (while :; do :; done) &
        busy+=($!)
    done
fi
trap '[ ${#busy[@]} -eq 0 ] || kill "${busy[@]}" 2>/dev/null' EXIT

suites=0
bad=0
for r in $(seq "$RUNS"); do
    pids=()
    for c in $(seq "$COPIES"); do
        suite "$r.$c" >"$OUT/.n.$c" &
        pids+=($!)
    done
    wait "${pids[@]}"
    for c in $(seq "$COPIES"); do
        n=$(cat "$OUT/.n.$c")
        suites=$((suites + 1))
        [ "$n" = 0 ] || bad=$((bad + 1))
    done
    echo "round $r/$RUNS: $suites suites, $bad with a failure"
done
rm -f "$OUT"/.n.*
echo "== stress $MODE: $suites suites ($COPIES at a time), $bad with a failure, $(wc -l <"$OUT/failures.txt") failed tests"
