// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What happens if the daemon panics anyway. The code is written not
//! to: the no-panic lints of the workspace forbid what clippy can see
//! (`scripts/lint.sh`). Were a panic to happen, in the event loop or in
//! the log thread, the process says so on stderr (a file or the journal,
//! as the service is set up) and aborts: it ends at once, by SIGABRT,
//! which the supervisor and the operator see.
//!
//! Not unwinding, and not going on: a panic in the event loop leaves the
//! store, a transaction or a connection half changed, and serving from
//! there could hand guests a store that is wrong; a panic in the log
//! thread would otherwise end that thread only, and the daemon would go
//! on with no log, its lines dropped once the queue is full. oxenstored,
//! whose logging runs in its one thread, ends on an uncaught exception
//! too. The release profile builds with `panic = "abort"` as well, so
//! that nothing unwinds even before the hook is in place.

use std::any::Any;
use std::io::{self, Write};
use std::panic::{self, Location, PanicHookInfo};

/// The line a panic writes: the thread, where, and the message.
pub fn message(thread: Option<&str>, location: Option<&Location<'_>>, payload: &(dyn Any + Send)) -> String {
    let what = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(no message)");
    let thread = thread.unwrap_or("<unnamed>");
    match location {
        Some(at) => format!("rxenstored: thread '{thread}' panicked at {at}: {what}; aborting\n"),
        None => format!("rxenstored: thread '{thread}' panicked: {what}; aborting\n"),
    }
}

fn hook(info: &PanicHookInfo<'_>) {
    let current = std::thread::current();
    let line = message(current.name(), info.location(), info.payload());
    // One write: the line is not cut by another thread's. Nothing to do
    // about a stderr that cannot be written.
    let _ = io::stderr().write_all(line.as_bytes());
    std::process::abort();
}

/// Makes any panic of the process, in any thread, write `message` to
/// stderr and abort. The daemon installs it first thing.
pub fn install_panic_hook() {
    panic::set_hook(Box::new(hook));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_says_which_thread_where_and_what() {
        let at = Location::caller();
        let line = message(Some("rxenstored-log"), Some(at), &"index out of bounds");
        assert_eq!(
            line,
            format!("rxenstored: thread 'rxenstored-log' panicked at {at}: index out of bounds; aborting\n")
        );
        assert!(line.contains("src/fatal.rs:"));
        assert_eq!(
            message(None, None, &String::from("formatted 7")),
            "rxenstored: thread '<unnamed>' panicked: formatted 7; aborting\n"
        );
        assert_eq!(
            message(Some("main"), None, &7u32),
            "rxenstored: thread 'main' panicked: (no message); aborting\n"
        );
    }
}
