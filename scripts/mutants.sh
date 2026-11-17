#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Mutation gate.
#
#   scripts/mutants.sh CRATE [--max-missed N] [-- CARGO-MUTANTS-ARGS...]
#
# Runs cargo-mutants on CRATE with that crate's own tests, prints caught /
# missed / timeout / unviable counts and the missed mutants, and exits
# non-zero if more than N mutants (default 0) are missed. Extra arguments
# go to cargo-mutants, e.g. `-- --shard 0/20` to run one twentieth of the
# mutants (to time a crate), or `-- --list`.
# Results: target/mutants/CRATE/mutants.out/.
#
# Environment: MUTANTS_JOBS (default 2) parallel builds, each in its own
# copy of the tree in $TMPDIR (where /tmp is a small tmpfs, set TMPDIR to a
# directory on disk: a build that runs out of space counts as unviable);
# MUTANTS_MEM_MAX (default 3G) memory limit of the whole run.
#
# A crate is built with all its features. A `std` feature (the no_std
# crates): the code cargo-mutants writes names std's items
# (`::std::iter::empty()`, `Box::new(..)`), which would not build in the
# no_std library and would go untested as unviable. Any other (xs-sys's
# `gnttab`): code behind a feature that is off is not compiled, so a
# mutant there changes nothing and would count as missed.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

usage() {
    sed -n '5,26p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

[ $# -ge 1 ] || usage
CRATE=$1
shift
[ -d "crates/$CRATE" ] || { echo "mutants.sh: no crate $CRATE" >&2; exit 2; }
MAX_MISSED=0
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --max-missed) MAX_MISSED=${2:?}; shift 2 ;;
        --) shift; EXTRA=("$@"); break ;;
        *) usage ;;
    esac
done

command -v cargo-mutants >/dev/null || {
    echo "mutants.sh: cargo-mutants is missing: cargo install --locked cargo-mutants" >&2
    exit 2
}

FEATURES=()
if grep -q '^\[features\]' "crates/$CRATE/Cargo.toml"; then FEATURES=(--all-features); fi

OUT=target/mutants/$CRATE
mkdir -p "$OUT"
start=$(date +%s)
set +e
# Timeouts: a test run is killed after 5x the unmutated test time, at
# least 30 s (a mutant that turns a loop infinite is caught as a timeout);
# a build after 3x the unmutated build time.
#
# Memory: a mutant can also make a test allocate without bound (`pos += n`
# turned into `pos *= n` makes a decoder return the same message forever)
# and exhaust the machine well before the timeout; the kernel's global OOM
# kill then takes the whole terminal session down with it. So the run gets
# its own cgroup with a hard limit: the runaway test is killed there, its
# mutant counts as caught (the test run failed), and the run carries on
# (OOMPolicy=continue; the default would stop the whole scope).
CAGE=()
if systemd-run --user --scope --quiet -p MemoryMax=1G true 2>/dev/null; then
    CAGE=(systemd-run --user --scope --quiet
        -p "MemoryMax=${MUTANTS_MEM_MAX:-3G}" -p MemorySwapMax=0 -p OOMPolicy=continue)
else
    echo "mutants.sh: no systemd user scope: falling back to ulimit -v" >&2
    ulimit -v $((8 * 1024 * 1024))
fi
"${CAGE[@]}" cargo mutants \
    --package "$CRATE" \
    "${FEATURES[@]}" \
    --output "$OUT" \
    --jobs "${MUTANTS_JOBS:-2}" \
    --timeout-multiplier 5 \
    --minimum-test-timeout 30 \
    --build-timeout-multiplier 3 \
    --no-shuffle \
    --colors never \
    "${EXTRA[@]}"
rc=$?
set -e
elapsed=$(($(date +%s) - start))

for a in "${EXTRA[@]}"; do
    case "$a" in --list | --list-files) exit $rc ;; esac
done

# cargo-mutants: 0 all caught, 2 missed, 3 timeouts, 4 baseline failed.
if [ $rc -ne 0 ] && [ $rc -ne 2 ] && [ $rc -ne 3 ]; then
    echo "mutants.sh: cargo-mutants failed (exit $rc), see $OUT/mutants.out/" >&2
    exit $rc
fi

python3 - "$OUT/mutants.out/outcomes.json" "$CRATE" "$MAX_MISSED" "$elapsed" <<'EOF'
import json, sys
path, crate, max_missed, elapsed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
o = json.load(open(path))
counts = {k: o.get(k, 0) for k in ("total_mutants", "caught", "missed", "timeout", "unviable", "success")}
print()
print(f"== mutants {crate}: {counts['total_mutants']} mutants, {counts['caught']} caught, "
      f"{counts['missed']} missed, {counts['timeout']} timeout, {counts['unviable']} unviable "
      f"({elapsed // 60} min {elapsed % 60} s)")
if counts["missed"]:
    print(open(path.replace("outcomes.json", "missed.txt")).read().rstrip())
if counts["missed"] > max_missed:
    print(f"   gate: FAIL ({counts['missed']} missed > {max_missed} allowed)")
    sys.exit(1)
print(f"   gate: pass ({counts['missed']} missed <= {max_missed} allowed)")
EOF
