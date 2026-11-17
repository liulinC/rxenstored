// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Minimal epoll wrapper and file-descriptor limit, over `xs-sys` (which
//! holds the unsafe code).

use std::io;
use std::os::fd::RawFd;
use xs_sys::{Epoll, Event, Interest};

/// Raises the soft limit on open files to the hard limit and returns it.
/// Every simulated VM holds several connections; the usual soft limit is 1024.
pub use xs_sys::raise_fd_limit;

pub struct Poller {
    epoll: Epoll,
}

impl Poller {
    pub fn new() -> io::Result<Poller> {
        Ok(Poller { epoll: Epoll::new()? })
    }

    /// Watches `fd` for readability (level-triggered).
    pub fn add(&self, fd: RawFd) -> io::Result<()> {
        self.epoll.add(fd, fd as u64, Interest::READ)
    }

    pub fn del(&self, fd: RawFd) -> io::Result<()> {
        self.epoll.delete(fd)
    }

    /// Replaces the content of `ready` with the readable fds, waiting at most `timeout_ms`.
    pub fn wait(&self, ready: &mut Vec<RawFd>, timeout_ms: i32) -> io::Result<()> {
        let mut events: Vec<Event> = Vec::new();
        self.epoll.wait(&mut events, 256, timeout_ms)?;
        ready.clear();
        ready.extend(events.iter().map(|e| e.token as RawFd));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn fd_limit_is_raised_to_the_hard_limit() {
        let limit = raise_fd_limit().unwrap();
        assert!(limit >= 1024);
        assert_eq!(raise_fd_limit().unwrap(), limit);
    }

    #[test]
    fn reports_readable_fds_only() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let (c, _d) = UnixStream::pair().unwrap();
        let p = Poller::new().unwrap();
        p.add(a.as_raw_fd()).unwrap();
        p.add(c.as_raw_fd()).unwrap();
        let mut ready = vec![99];
        p.wait(&mut ready, 0).unwrap();
        assert!(ready.is_empty());
        b.write_all(b"x").unwrap();
        p.wait(&mut ready, 1000).unwrap();
        assert_eq!(ready, [a.as_raw_fd()]);
        p.del(a.as_raw_fd()).unwrap();
        p.wait(&mut ready, 0).unwrap();
        assert!(ready.is_empty());
        assert!(p.del(a.as_raw_fd()).is_err());
        assert!(p.add(-1).is_err());
    }
}
