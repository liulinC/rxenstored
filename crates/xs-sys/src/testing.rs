// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! For the tests: what another thread of this process is doing, as
//! `/proc` shows it, so that a test waits for a state rather than for time:
//! a test's outcome must not depend on how fast the machine runs it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// `/proc/self/task/TID` of the calling thread.
pub fn this_task() -> PathBuf {
    PathBuf::from("/proc").join(std::fs::read_link("/proc/thread-self").unwrap())
}

/// The epoll waits, by system call number.
#[cfg(target_arch = "x86_64")]
const EPOLL_WAITS: &[i64] = &[libc::SYS_epoll_wait, libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2];
#[cfg(not(target_arch = "x86_64"))]
const EPOLL_WAITS: &[i64] = &[libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2];

/// If the thread sleeps in one of the system calls `calls`: how many times
/// it went to sleep so far (its voluntary context switches), which grows
/// when it wakes up and sleeps again.
pub fn asleep_in(task: &Path, calls: &[i64]) -> Option<u64> {
    let syscall = std::fs::read_to_string(task.join("syscall")).ok()?;
    let nr: i64 = syscall.split_whitespace().next()?.parse().ok()?;
    let stat = std::fs::read_to_string(task.join("stat")).ok()?;
    let state = stat.rsplit_once(')')?.1.trim_start().chars().next()?;
    let status = std::fs::read_to_string(task.join("status")).ok()?;
    let sleeps = status
        .lines()
        .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))?
        .trim()
        .parse()
        .ok()?;
    (calls.contains(&nr) && state == 'S').then_some(sleeps)
}

/// Waits until `task` sleeps in an epoll wait, having gone to sleep more
/// than `after` times (it woke up since); its count then. Panics after
/// 30 s: a guard against hanging, not a time the test depends on.
pub fn wait_asleep(task: &Path, after: Option<u64>) -> u64 {
    wait_asleep_in(task, EPOLL_WAITS, after)
}

/// As `wait_asleep`, in one of the system calls `calls`.
pub fn wait_asleep_in(task: &Path, calls: &[i64], after: Option<u64>) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(n) = asleep_in(task, calls).filter(|&n| after.is_none_or(|a| n > a)) {
            return n;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not sleep in system call {calls:?}",
            task.display()
        );
        std::thread::yield_now();
    }
}
