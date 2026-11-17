#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Miri gate: the tests run in Miri, the interpreter that detects undefined
# behaviour (out-of-bounds and dangling accesses, invalid values, aliasing
# violations under Stacked Borrows, data races, memory leaks).
#
#   scripts/miri.sh [CRATE...]     default: xs-wire xs-core xs-sys xs-daemon
#
# Flags, every crate: -Zmiri-strict-provenance (no integer-to-pointer casts)
# and -Zmiri-symbolic-alignment-check (alignment from the type, not from
# where the allocator happened to put a value). Per crate:
#   xs-wire    the unit tests.
#   xs-core    the unit tests and the model test, the model with
#              XS_MODEL_SEEDS=${MIRI_MODEL_SEEDS:-2} XS_MODEL_STEPS=${MIRI_MODEL_STEPS:-150}
#              (crates/xs-core/tests/model.rs; it runs 300 + 150 seeds of
#              400 steps natively).
#   xs-sys     the unit tests, with -Zmiri-disable-isolation (some read
#              /proc); then the ring tests that run two threads on one page
#              again, once per seed of -Zmiri-many-seeds=0..${MIRI_SEEDS:-8}:
#              each seed is another scheduling of the threads and another
#              choice among the values the weak memory model allows a load
#              to return.
#   xs-daemon  the unit tests of the library and of the binary, with
#              -Zmiri-disable-isolation.
# A test that needs what Miri does not emulate is marked in the source
# `#[cfg_attr(miri, ignore = "REASON")]`; the run prints each with its
# reason ("ignored, REASON").
#
# Not covered: the integration tests of xs-daemon and xs-sim, and xs-sim's
# and xs-bench's own tests (they start processes or use memfd and file
# mappings, which Miri does not emulate); every ignored test above; code
# no test runs. Miri finds undefined behaviour in the executions it runs,
# not in all executions.
#
# Pass: every test run passes, which in Miri means no undefined behaviour
# and no leak was found. The last line says which. Logs: target/miri/*.log.
#
# Needs: rustup toolchain install nightly --component miri rust-src.
# Environment: MIRI_TARGET_DIR (default target/miri/build); MIRI_SEEDS,
# MIRI_MODEL_SEEDS, MIRI_MODEL_STEPS as above.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if [ $# -gt 0 ]; then CRATES=("$@"); else CRATES=(xs-wire xs-core xs-sys xs-daemon); fi
for c in "${CRATES[@]}"; do
    case "$c" in
        xs-wire | xs-core | xs-sys | xs-daemon) ;;
        *) echo "miri.sh: $c is not run under Miri (see the header)" >&2; exit 2 ;;
    esac
done
cargo +nightly miri --version >/dev/null 2>&1 || {
    echo "miri.sh: Miri is missing: rustup toolchain install nightly --component miri rust-src" >&2
    exit 2
}

OUT=target/miri
mkdir -p "$OUT"
export CARGO_TARGET_DIR=${MIRI_TARGET_DIR:-$OUT/build}
BASE="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check"
# The ring tests with two threads on one page.
THREADED=(ring::tests::two_threads_stream_both_ways
    ring::tests::indices_are_read_once_against_a_racing_peer
    ring::tests::a_peer_rewriting_the_bytes_being_read)

status=0
summary=()
# run NAME MIRIFLAGS CARGO-MIRI-TEST-ARGS...
run() {
    local name=$1 flags=$2 start rc elapsed passed failed ignored
    shift 2
    echo "== $name"
    start=$(date +%s)
    set +e
    MIRIFLAGS="$flags" cargo +nightly miri test "$@" >"$OUT/$name.log" 2>&1
    rc=$?
    set -e
    elapsed=$(($(date +%s) - start))
    passed=$(grep -o '[0-9]* passed' "$OUT/$name.log" | awk '{s += $1} END {print s + 0}')
    failed=$(grep -o '[0-9]* failed' "$OUT/$name.log" | awk '{s += $1} END {print s + 0}')
    ignored=$(grep -o '[0-9]* ignored' "$OUT/$name.log" | awk '{s += $1} END {print s + 0}')
    grep -o 'test [^ ]* \.\.\. ignored, .*' "$OUT/$name.log" | sed 's/^/   /' || true
    summary+=("  $name: $passed passed, $failed failed, $ignored ignored, exit $rc, $((elapsed / 60)) min $((elapsed % 60)) s")
    echo "${summary[-1]}"
    if [ $rc -ne 0 ]; then
        grep -E -A3 'Undefined Behavior|unsupported operation|memory leaked|panicked at|^test .* FAILED' "$OUT/$name.log" | head -n 40 || true
        status=1
    fi
}

for c in "${CRATES[@]}"; do
    case "$c" in
        xs-wire) run xs-wire "$BASE" -p xs-wire --lib ;;
        xs-core)
            run xs-core-lib "$BASE" -p xs-core --lib
            run xs-core-model "$BASE -Zmiri-env-set=XS_MODEL_SEEDS=${MIRI_MODEL_SEEDS:-2} -Zmiri-env-set=XS_MODEL_STEPS=${MIRI_MODEL_STEPS:-150}" \
                -p xs-core --test model
            ;;
        xs-sys)
            run xs-sys "$BASE -Zmiri-disable-isolation" -p xs-sys --lib
            run xs-sys-ring-seeds "$BASE -Zmiri-many-seeds=0..${MIRI_SEEDS:-8}" -p xs-sys --lib -- "${THREADED[@]}"
            ;;
        xs-daemon) run xs-daemon "$BASE -Zmiri-disable-isolation" -p xs-daemon --lib --bins ;;
    esac
done

echo
echo "== miri summary (logs in $OUT/)"
printf '%s\n' "${summary[@]}"
if [ $status -eq 0 ]; then
    echo "== miri: pass"
else
    echo "== miri: FAIL"
fi
exit $status
