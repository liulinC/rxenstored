// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The daemon's panic hook (`xs_daemon::fatal`): a panic in any thread
//! writes one line to stderr and aborts the process. Run in a child
//! process: this test binary again, told by the environment to be the
//! child.

// A test crate, not the daemon: it may unwrap, index, print and panic (the
// no-panic rule of Cargo.toml is for code that is not a test).
#![allow(
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
)]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

/// Set in the child: the name of the thread that panics.
const CHILD: &str = "RXS_PANIC_HOOK_CHILD";
const TEST: &str = "a_panic_in_any_thread_is_reported_and_the_process_aborted";
const SIGABRT: i32 = 6;

#[test]
fn a_panic_in_any_thread_is_reported_and_the_process_aborted() {
    if let Some(name) = std::env::var_os(CHILD) {
        xs_daemon::fatal::install_panic_hook();
        let none: Vec<u8> = Vec::new();
        let at = none.len() + 3;
        let t = std::thread::Builder::new()
            .name(name.to_string_lossy().into_owned())
            .spawn(move || std::hint::black_box(none[at]))
            .unwrap();
        let _ = t.join();
        // Not reached: the panic ended the process.
        std::process::exit(0);
    }
    for name in ["rxenstored-log", "another"] {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, name)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.signal(),
            Some(SIGABRT),
            "{name}: {:?}, stderr: {err}",
            out.status
        );
        let line = err
            .lines()
            .find(|l| l.starts_with("rxenstored: "))
            .unwrap_or_else(|| panic!("{name}: no line in {err}"));
        assert!(
            line.starts_with(&format!("rxenstored: thread '{name}' panicked at ")),
            "{line}"
        );
        assert!(line.contains("tests/panic_hook.rs:"), "{line}");
        assert!(
            line.ends_with(": index out of bounds: the len is 0 but the index is 3; aborting"),
            "{line}"
        );
    }
}
