// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The bounded queue from the event loop to the log thread. The event loop
//! appends fixed-size items and their data, copied into one buffer, under
//! a lock the log thread holds only to swap that buffer for an empty one:
//! neither side waits for the other's work, and in steady state nothing is
//! allocated (both buffers keep their capacity). The daemon log has a share
//! of the room of its own (`Queue::new`), which access-log lines cannot
//! use: a guest that floods the access log fills the rest, and daemon-log
//! lines still go in. When a log's share is full, its item is dropped and
//! counted; the log thread reports the count after the lines that were
//! kept, which is where the gap is. The counts are not items: no flood can
//! drop them. Nothing here blocks the event loop, which only wakes the log
//! thread once per pass (`kick`), not per line.

use super::format::Stamp;
use super::Level;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use xs_core::log::{Op, Record, Who};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Access {
        who: Who,
        tid: u32,
        op: Op,
    },
    Daemon {
        level: Level,
        key: &'static str,
    },
    /// A daemon-log line written as it is, whatever the level
    /// (`ox/logging.ml:169-172`).
    Raw,
}

/// One line to write; its data is `Batch::data`.
#[derive(Debug, Clone, Copy)]
pub struct Item {
    pub time: Stamp,
    pub kind: Kind,
    start: usize,
    end: usize,
    /// The data was longer than what was kept.
    pub cut: bool,
}

#[derive(Debug, Default)]
pub struct Batch {
    pub items: Vec<Item>,
    bytes: Vec<u8>,
}

impl Batch {
    /// The data of an item of this batch (of another: nothing).
    pub fn data(&self, it: &Item) -> &[u8] {
        self.bytes.get(it.start..it.end).unwrap_or_default()
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.bytes.clear();
    }
}

/// What the log thread is asked besides the lines.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Orders {
    /// Access-log and daemon-log lines dropped since the last batch.
    pub dropped_access: u64,
    pub dropped_daemon: u64,
    /// SIGHUP: reopen the files, after this batch.
    pub reopen: bool,
    /// Write this batch, then end.
    pub stop: bool,
}

/// Items and bytes of data queued for one log.
#[derive(Debug, Default, Clone, Copy)]
struct Use {
    items: usize,
    bytes: usize,
}

/// A log's share of the queue.
#[derive(Debug, Clone, Copy)]
struct Room {
    items: usize,
    bytes: usize,
}

impl Room {
    fn has(&self, u: Use) -> bool {
        u.items < self.items && u.bytes < self.bytes
    }
}

#[derive(Default)]
struct Inner {
    batch: Batch,
    /// What each log uses of `batch`.
    access: Use,
    daemon: Use,
    orders: Orders,
    /// The log thread waits for work.
    idle: bool,
    /// The coarse clock at the last record, and the precise time then.
    tick: (i64, u32),
    stamp: Stamp,
}

pub struct Queue {
    inner: Mutex<Inner>,
    wake: Condvar,
    access: Room,
    daemon: Room,
}

/// The daemon log's share of the queue: this fraction of its lines and
/// bytes, rounded up (4,096 lines and 512 KiB of the default queue).
pub const DAEMON_SHARE: usize = 16;

impl Queue {
    /// At most `max_items` lines and about `max_bytes` bytes of data
    /// waiting (one item of each log may go past its bytes): a
    /// `DAEMON_SHARE`th of each, rounded up, for daemon-log lines, the rest
    /// for access-log lines. Neither log can use the other's share.
    pub fn new(max_items: usize, max_bytes: usize) -> Queue {
        let daemon = Room {
            items: max_items.div_ceil(DAEMON_SHARE),
            bytes: max_bytes.div_ceil(DAEMON_SHARE),
        };
        Queue {
            inner: Mutex::default(),
            wake: Condvar::new(),
            access: Room {
                items: max_items.saturating_sub(daemon.items),
                bytes: max_bytes.saturating_sub(daemon.bytes),
            },
            daemon,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A log thread that panicked holding the lock left nothing half done.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Room for one more item in the log's share, or the drop is counted.
    fn room(&self, q: &mut Inner, daemon: bool) -> bool {
        let (room, used, dropped) = if daemon {
            (self.daemon, q.daemon, &mut q.orders.dropped_daemon)
        } else {
            (self.access, q.access, &mut q.orders.dropped_access)
        };
        let has = room.has(used);
        if !has {
            *dropped = dropped.saturating_add(1);
        }
        has
    }

    /// Room for one more item, stamped: with the time of the request to
    /// within a clock tick. The precise time is read when the coarse clock
    /// has ticked since the last item, and items of the same tick share it:
    /// a precise read per item would be a system call per request in a Xen
    /// domain (`xs_sys::log::coarse_now`). None if the item is dropped.
    fn slot(&self, daemon: bool) -> Option<(MutexGuard<'_, Inner>, Stamp)> {
        let tick = xs_sys::log::coarse_now();
        let mut q = self.lock();
        if !self.room(&mut q, daemon) {
            return None;
        }
        if q.tick != tick {
            (q.tick, q.stamp) = (tick, Stamp::now());
        }
        let time = q.stamp;
        Some((q, time))
    }

    fn push(q: &mut Inner, time: Stamp, kind: Kind, start: usize, cut: bool) {
        let end = q.batch.bytes.len();
        let used = match kind {
            Kind::Access { .. } => &mut q.access,
            Kind::Daemon { .. } | Kind::Raw => &mut q.daemon,
        };
        used.items = used.items.saturating_add(1);
        used.bytes = used.bytes.saturating_add(end.saturating_sub(start));
        q.batch.items.push(Item {
            time,
            kind,
            start,
            end,
            cut,
        });
    }

    /// An access-log record, its data cut at `limit` bytes; false if it
    /// was dropped.
    pub fn access(&self, r: &Record, limit: usize) -> bool {
        let Some((mut q, time)) = self.slot(false) else {
            return false;
        };
        let start = q.batch.bytes.len();
        let cut = r.data.copy_to(&mut q.batch.bytes, limit);
        Self::push(
            &mut q,
            time,
            Kind::Access {
                who: r.who,
                tid: r.tid,
                op: r.op,
            },
            start,
            cut,
        );
        true
    }

    /// A daemon-log message; the log thread is woken (they are few, and
    /// may come from outside the event loop). False if it was dropped.
    pub fn daemon(&self, kind: Kind, text: &[u8]) -> bool {
        let Some((mut q, time)) = self.slot(true) else {
            return false;
        };
        let start = q.batch.bytes.len();
        q.batch.bytes.extend_from_slice(text);
        Self::push(&mut q, time, kind, start, false);
        self.wake_if_idle(&q);
        true
    }

    fn wake_if_idle(&self, q: &Inner) {
        if q.idle {
            self.wake.notify_one();
        }
    }

    /// Wakes the log thread if it waits and there is work (lines, or only
    /// drops to tell of, in a share that holds none): the event loop calls
    /// it once per pass.
    pub fn kick(&self) {
        let q = self.lock();
        if !q.batch.items.is_empty() || q.orders != Orders::default() {
            self.wake_if_idle(&q);
        }
    }

    pub fn reopen(&self) {
        let mut q = self.lock();
        q.orders.reopen = true;
        self.wake_if_idle(&q);
    }

    pub fn stop(&self) {
        let mut q = self.lock();
        q.orders.stop = true;
        self.wake_if_idle(&q);
    }

    /// For the log thread: waits until there are lines or orders (lines
    /// queued while it waits wake it at the next `kick`), then swaps the
    /// lines into `out`, which must be empty, and takes the orders.
    pub fn take(&self, out: &mut Batch) -> Orders {
        self.take_within(out, None)
    }

    /// `take`, waiting `wait` at most if given: then, if nothing came,
    /// `out` stays empty and the orders are none.
    pub fn take_within(&self, out: &mut Batch, wait: Option<Duration>) -> Orders {
        // None: no wait given, or one longer than an `Instant` can count.
        let deadline = wait.and_then(|w| Instant::now().checked_add(w));
        let mut q = self.lock();
        while q.batch.items.is_empty() && q.orders == Orders::default() {
            q.idle = true;
            q = match deadline {
                None => self.wake.wait(q).unwrap_or_else(|e| e.into_inner()),
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    self.wake.wait_timeout(q, left).unwrap_or_else(|e| e.into_inner()).0
                }
            };
        }
        q.idle = false;
        std::mem::swap(&mut q.batch, out);
        (q.access, q.daemon) = (Use::default(), Use::default());
        std::mem::take(&mut q.orders)
    }
}
