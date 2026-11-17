// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What the log thread needs from the system: a thread that no signal is
//! delivered to, the local time zone's offset (a syslog header is in local
//! time, as glibc's `syslog(3)` writes it), and SIGHUP, which reopens the
//! log files (`ox/xenstored.ml:78-80`).

use std::io;
use std::thread::JoinHandle;

pub const SIGHUP: i32 = libc::SIGHUP;

/// Starts a thread with every signal blocked: the event loop reads its
/// signals from a signalfd, and a signal the kernel picked this thread
/// for would be acted on by default (SIGHUP and SIGTERM kill) or lost.
/// Blocked here, before the thread exists, there is no window in which
/// it could take one.
pub fn spawn_masked<F: FnOnce() + Send + 'static>(name: &str, f: F) -> io::Result<JoinHandle<()>> {
    // SAFETY: both sets are valid, writable sigset_t values for every
    // call; `all` is initialised by sigfillset before it is read, `old`
    // is written by pthread_sigmask before it is read.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        let rc = libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        let spawned = std::thread::Builder::new().name(name.into()).spawn(f);
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        spawned
    }
}

/// `CLOCK_REALTIME_COARSE`, seconds and nanoseconds: the time of the last
/// clock tick (1 to 4 ms ago). The vDSO serves it without a system call
/// whatever the clock source, where a precise read is a system call under
/// Xen's (`xen` has no vDSO mode): about 4 ns against 120 ns measured in
/// a Xen guest.
pub fn coarse_now() -> (i64, u32) {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is valid and writable for the call. The clock exists
    // on every Linux since 2.6.32; on failure `ts` stays zero.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut ts) };
    (ts.tv_sec, ts.tv_nsec as u32)
}

/// Seconds east of UTC of the local time at `t` (seconds since the
/// epoch), as `localtime_r` sees it (`TZ`, else /etc/localtime); 0 if it
/// cannot tell.
pub fn utc_offset(t: i64) -> i64 {
    // 64 bits on x86_64, with glibc and with musl alike (libc deprecates
    // the name for 32-bit musl, which changed).
    #[allow(deprecated)]
    let t = t as libc::time_t;
    // SAFETY: all-zero bytes are a valid `tm` (integers and a null
    // pointer); `t` and `tm` are valid for the call, which writes `tm`.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(sig: i32) -> bool {
        // SAFETY: `set` is valid and writable; a null new set only reads the mask.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set), 0);
            libc::sigismember(&set, sig) == 1
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "pthread_sigmask: not emulated by Miri")]
    fn the_thread_blocks_every_signal_and_the_caller_keeps_its_mask() {
        let before = blocked(SIGHUP);
        let h = spawn_masked("masked", || {
            assert!(blocked(SIGHUP) && blocked(libc::SIGTERM) && blocked(libc::SIGUSR1))
        })
        .unwrap();
        assert_eq!(h.thread().name(), Some("masked"));
        h.join().unwrap();
        assert_eq!(blocked(SIGHUP), before);
    }

    #[test]
    fn the_coarse_clock_is_close_behind_the_precise_one() {
        // Read between two precise reads: not after the second, and behind
        // the first by less than a second (a clock tick, in fact), however
        // long this thread waited between the reads.
        let precise = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
        };
        let before = precise();
        let (s, ns) = coarse_now();
        let after = precise();
        let coarse = std::time::Duration::new(s as u64, ns);
        assert!(
            coarse <= after
                && before
                    .checked_sub(coarse)
                    .is_none_or(|d| d < std::time::Duration::from_secs(1)),
            "{before:?} {coarse:?} {after:?}"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's localtime_r stops with an internal error on a time beyond its range"
    )]
    fn offsets() {
        // Whatever the zone of this machine, within a day, and a whole minute.
        let o = utc_offset(1_763_229_787);
        assert!(o.abs() < 86_400 && o % 60 == 0, "{o}");
        // localtime_r refuses a year beyond what `tm` holds.
        assert_eq!(utc_offset(i64::MAX), 0);
    }

    /// The offset is the zone's, summer time included. glibc reads `TZ`
    /// once per process, so the test runs itself again in a child with a
    /// zone of its own (a POSIX rule: no tzdata needed): UTC+1, UTC+2 from
    /// the last Sunday of March to the last Sunday of October.
    #[test]
    #[cfg_attr(miri, ignore = "process spawning: not emulated by Miri")]
    fn the_offset_is_that_of_tz() {
        const CHILD: &str = "XS_SYS_TEST_TZ_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // 2025-11-15 and 2025-07-01, 00:00 UTC.
            println!("offsets {} {}", utc_offset(1_763_164_800), utc_offset(1_751_328_000));
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "log::tests::the_offset_is_that_of_tz", "--nocapture"])
            .env(CHILD, "1")
            .env("TZ", "XST-1XDT,M3.5.0,M10.5.0/3")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("offsets 3600 7200"), "{text}");
    }
}
