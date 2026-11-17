// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Descriptors for the simulated backend (`xs-sim`) and the ring tests:
//! a memfd to hold a shared page, an eventfd to stand for an event
//! channel, and a wait with a timeout.

use crate::map::Mapping;
use crate::{Epoll, Interest};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// An anonymous memory file of a fixed size, zero-filled, sealed so that
/// no one can shrink or grow it: a mapping within it can never fault, so
/// `map` is safe.
#[derive(Debug)]
pub struct Memfd {
    file: File,
    len: u64,
}

/// A `Memfd` of `len` bytes. `name` only shows in `/proc/PID/fd`.
pub fn memfd(name: &str, len: u64) -> io::Result<Memfd> {
    let name = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in a memfd name"))?;
    // SAFETY: `name` is a valid NUL-terminated string for the duration of
    // the call.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor that nothing else owns.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    file.set_len(len)?;
    // SAFETY: plain call on a descriptor this function owns.
    let sealed = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
        )
    };
    (sealed >= 0)
        .then_some(Memfd { file, len })
        .ok_or_else(io::Error::last_os_error)
}

impl Memfd {
    /// Maps `len` bytes from `offset`, which must lie within the file.
    pub fn map(&self, offset: u64, len: usize) -> io::Result<Mapping> {
        if offset.checked_add(len as u64).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a mapping past the end of a memfd",
            ));
        }
        // SAFETY: the range lies within the file, which is sealed against
        // shrinking: every page of it stays backed.
        unsafe { Mapping::of_fd(&self.file, offset, len) }
    }

    /// The file, to read and write it as one.
    pub fn file(&self) -> &File {
        &self.file
    }
}

/// A non-blocking eventfd: readable from the first `signal` until `take`.
#[derive(Debug)]
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    pub fn new() -> io::Result<EventFd> {
        Self::with_flags(libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
    }

    fn with_flags(flags: libc::c_int) -> io::Result<EventFd> {
        // SAFETY: plain syscall, no pointers.
        let fd = unsafe { libc::eventfd(0, flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor that nothing else owns.
        Ok(EventFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Makes the descriptor readable.
    pub fn signal(&self) -> io::Result<()> {
        let one = 1u64.to_ne_bytes();
        // SAFETY: `one` is valid for reading 8 bytes.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), one.as_ptr().cast(), one.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Resets the descriptor and returns how many signals it had seen
    /// since the last reset; 0 if none.
    pub fn take(&self) -> io::Result<u64> {
        let mut count = [0u8; 8];
        // SAFETY: `count` is valid for writing 8 bytes.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), count.as_mut_ptr().cast(), count.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            };
        }
        Ok(u64::from_ne_bytes(count))
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Waits until `fd` is readable, at most `timeout` (None: forever).
/// Returns whether it is. Signals do not cut the wait short.
pub fn wait_readable(fd: &impl AsRawFd, timeout: Option<Duration>) -> io::Result<bool> {
    let ep = Epoll::new()?;
    ep.add(fd.as_raw_fd(), 0, Interest::READ)?;
    // A deadline past what `Instant` can hold is no deadline.
    let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
    let mut ev = Vec::new();
    loop {
        let ms = match deadline {
            None => -1,
            // Rounded up, so that the wait does not end just before the
            // deadline and spin.
            Some(d) => d
                .saturating_duration_since(Instant::now())
                .as_micros()
                .div_ceil(1000)
                .min(i32::MAX as u128) as i32,
        };
        ep.wait(&mut ev, 1, ms)?;
        if !ev.is_empty() {
            return Ok(true);
        }
        // An empty wait before the deadline was interrupted.
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::PAGE_SIZE;
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;

    #[test]
    #[cfg_attr(miri, ignore = "memfd_create: not emulated by Miri")]
    fn a_memfd_is_a_zeroed_shareable_file() {
        let m = memfd("xs-sys-test", PAGE_SIZE as u64).unwrap();
        let f = m.file();
        assert_eq!(f.metadata().unwrap().len(), PAGE_SIZE as u64);
        let a = m.map(0, PAGE_SIZE).unwrap();
        let b = m.map(0, PAGE_SIZE).unwrap();
        // SAFETY: inside both mappings; this test is the only user of the file.
        unsafe {
            assert_eq!(b.as_ptr().add(100).read(), 0);
            a.as_ptr().add(100).write(42);
            assert_eq!(b.as_ptr().add(100).read(), 42);
        }
        let mut byte = [0];
        f.read_at(&mut byte, 100).unwrap();
        assert_eq!(byte, [42]);
        // Sealed: it cannot shrink under a mapping, nor grow.
        assert_eq!(f.set_len(0).unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(
            f.set_len(2 * PAGE_SIZE as u64).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        // A mapping past its end is refused before any mmap.
        for (offset, len) in [(0, PAGE_SIZE + 1), (1, PAGE_SIZE), (u64::MAX, 1)] {
            assert_eq!(
                m.map(offset, len).err().unwrap().kind(),
                io::ErrorKind::InvalidInput,
                "{offset} {len}"
            );
        }
        assert!(
            m.map(PAGE_SIZE as u64, 0).is_err(),
            "an empty mapping, which the kernel refuses"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "memfd_create: not emulated by Miri")]
    fn memfd_names_are_checked() {
        assert_eq!(memfd("a\0b", 1).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        // The kernel limits names to 249 bytes.
        assert_eq!(
            memfd(&"x".repeat(300), 1).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        // A size no file may have.
        assert!(memfd("big", u64::MAX).is_err());
    }

    #[test]
    fn an_eventfd_is_readable_from_signal_to_take() {
        let e = EventFd::new().unwrap();
        assert_eq!(e.take().unwrap(), 0);
        assert!(!wait_readable(&e, Some(Duration::ZERO)).unwrap());
        e.signal().unwrap();
        e.signal().unwrap();
        assert!(wait_readable(&e, Some(Duration::from_secs(1))).unwrap());
        assert!(
            wait_readable(&e.as_fd(), None).unwrap(),
            "still readable: nothing took it"
        );
        // A timeout past what `Instant` holds waits as long as None does,
        // without overflowing `Instant + Duration`.
        assert!(wait_readable(&e, Some(Duration::MAX)).unwrap());
        assert_eq!(e.take().unwrap(), 2);
        assert_eq!(e.take().unwrap(), 0);
        let start = Instant::now();
        assert!(!wait_readable(&e, Some(Duration::from_millis(20))).unwrap());
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    #[cfg_attr(miri, ignore = "eventfd with EFD_SEMAPHORE: not emulated by Miri")]
    fn eventfd_errors_are_reported() {
        assert_eq!(EventFd::with_flags(-1).unwrap_err().raw_os_error(), Some(libc::EINVAL));
        let ro = EventFd {
            fd: File::open("/dev/null").unwrap().into(),
        };
        assert_eq!(ro.signal().unwrap_err().raw_os_error(), Some(libc::EBADF));
        let wo = EventFd {
            fd: std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap()
                .into(),
        };
        assert_eq!(wo.take().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(
            wait_readable(&-1, Some(Duration::ZERO)).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        // A descriptor epoll refuses.
        assert!(wait_readable(&File::open("/dev/null").unwrap(), Some(Duration::ZERO)).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "signal handlers: not emulated by Miri")]
    fn a_signal_does_not_cut_a_wait_short() {
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: `nothing` is async-signal-safe (it does nothing); the
        // only other user of SIGUSR2 in this process installs the same.
        unsafe {
            libc::signal(
                libc::SIGUSR2,
                nothing as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
        let e = Arc::new(EventFd::new().unwrap());
        // SAFETY: plain call; the id stays valid while this thread runs,
        // and the sender stops before this function returns.
        let me = unsafe { libc::pthread_self() } as usize;
        let task = crate::testing::this_task();
        let sender = {
            let e = e.clone();
            std::thread::spawn(move || {
                // Each signal comes while the wait sleeps, which then
                // sleeps again: the wait goes on.
                let mut sleeps = crate::testing::wait_asleep(&task, None);
                for _ in 0..3 {
                    // SAFETY: `me` names a live thread (see above).
                    unsafe { libc::pthread_kill(me as libc::pthread_t, libc::SIGUSR2) };
                    sleeps = crate::testing::wait_asleep(&task, Some(sleeps));
                }
                e.signal().unwrap();
            })
        };
        // Joined first: a wait that returned early would leave the sender
        // waiting for it to sleep again, not signalling a thread gone.
        let woken = wait_readable(&*e, Some(Duration::from_secs(20))).unwrap();
        sender.join().unwrap();
        assert!(woken);
    }

    /// Without a timeout the wait sleeps in the kernel without one (-1),
    /// not in short waits one after the other.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "reads the waiting thread's system call in /proc: Miri's threads have none"
    )]
    fn a_wait_without_a_timeout_sleeps_without_one() {
        let e = Arc::new(EventFd::new().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = {
            let e = e.clone();
            std::thread::spawn(move || {
                tx.send(crate::testing::this_task()).unwrap();
                wait_readable(&*e, None).unwrap()
            })
        };
        let task = rx.recv().unwrap();
        crate::testing::wait_asleep(&task, None);
        // `/proc/TID/syscall`: the number in decimal, then the arguments in
        // hex; the fourth argument of epoll_wait and epoll_pwait is the
        // timeout, an int.
        let syscall = std::fs::read_to_string(task.join("syscall")).unwrap();
        let fields: Vec<&str> = syscall.split_whitespace().collect();
        let nr = fields.first().and_then(|n| n.parse::<i64>().ok());
        let timeout = fields
            .get(4)
            .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
            .map(|t| t as i32);
        e.signal().unwrap();
        assert!(waiter.join().unwrap());
        assert!(
            nr.is_some_and(|n| [libc::SYS_epoll_wait, libc::SYS_epoll_pwait].contains(&n)),
            "{syscall}"
        );
        assert_eq!(timeout, Some(-1), "{syscall}");
    }
}
