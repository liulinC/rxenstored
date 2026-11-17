#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
#
# no_std gate: xs-wire and xs-core build for a
# target that has no std at all, only core and alloc, as a stub domain
# would need. A use of std, or a dependency that needs it, fails the build.
#
#   scripts/nostd.sh [TARGET]       default: x86_64-unknown-none
#
# Builds both crates for TARGET with their default features (not xs-core's
# `std`, which only scripts/mutants.sh turns on), then runs clippy on them
# for TARGET with warnings denied (the lints of scripts/lint.sh).
#
# Needs: rustup target add x86_64-unknown-none

set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

T=${1:-x86_64-unknown-none}
if ! rustc --print target-libdir --target "$T" >/dev/null 2>&1 || [ ! -d "$(rustc --print target-libdir --target "$T")" ]; then
    echo "nostd.sh: no standard library for $T: rustup target add $T" >&2
    exit 2
fi

if cargo build -p xs-wire -p xs-core --target "$T" &&
    cargo clippy -p xs-wire -p xs-core --target "$T" -- -D warnings; then
    echo "== nostd: pass ($T)"
else
    echo "== nostd: FAIL ($T)" >&2
    exit 1
fi
