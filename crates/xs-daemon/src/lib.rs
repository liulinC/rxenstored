// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored's event loop, as a library: the binary (`main.rs`) runs it
//! over the Xen devices, the tests over the simulated backend of `xs-sim`.

#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::get_unwrap,
        clippy::unwrap_in_result,
        clippy::panic_in_result_fn,
        clippy::exit,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unchecked_time_subtraction
    )
)]

pub mod fatal;
pub mod log;
pub mod reactor;
mod rings;
