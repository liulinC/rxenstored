#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# Lint gate: the formatting (rustfmt.toml), the no-panic rule
# (Cargo.toml), clippy's default lints, and a reason for every sleep.
#
#   scripts/lint.sh [CLIPPY-ARGS...]
#
# Checks that `cargo fmt --all` would change nothing, then runs clippy on
# every target of every crate (libraries, binaries, tests, examples), with
# the default features and with all of them, and fails on any warning. The no-panic lints are denied in
# Cargo.toml ([workspace.lints.clippy]) for the crates that take them (all
# but xs-bench, a load tool): they apply to code that is not a test. A
# crate's own test build allows them (`#![cfg_attr(test, allow(...))]` at
# its root), and so does each integration-test crate and example (an
# `allow` at its root). Extra arguments go to cargo clippy, e.g. `-p xs-core`.
# Then every `sleep(` in crates/ must say why, in a `sleep-ok:` comment.

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

cargo clippy --version >/dev/null 2>&1 || {
    echo "lint.sh: clippy is missing: rustup component add clippy" >&2
    exit 2
}

if ! cargo fmt --all --check; then
    echo "== lint: FAIL (formatting: run cargo fmt --all)" >&2
    exit 1
fi

# Default features, then all of them: code behind a feature (xs-sys's
# `gnttab`, xs-core's `std`) is linted too.
for features in "" --all-features; do
    if ! cargo clippy --workspace --all-targets $features "$@" -- -D warnings; then
        echo "== lint: FAIL" >&2
        exit 1
    fi
done

# Every sleep says why: a test waits for a
# state, not for time. A sleep needs `sleep-ok: REASON` in a comment on
# its line or in the comment lines just above it: a poll bounded by a
# deadline whose expiry is a failure, a test that measures a rate, or the
# daemon's own design.
if ! find crates -name '*.rs' -print0 | xargs -0 awk '
    FNR == 1 { above = "" }
    $0 !~ /^[ \t]*\/\// && /(^|[^A-Za-z0-9_.])sleep\(/ && $0 !~ /sleep-ok:/ && above !~ /sleep-ok:/ {
        print FILENAME ":" FNR ": a sleep without `sleep-ok: REASON`"
        bad = 1
    }
    { above = ($0 ~ /^[ \t]*\/\//) ? above $0 : "" }
    END { exit bad }' >&2; then
    echo "== lint: FAIL" >&2
    exit 1
fi
echo "== lint: pass"
