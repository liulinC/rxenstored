// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The rings: dom0's own, and those of the guests INTRODUCE brings.
//!
//! A ring's port fires → `pending` returns it, masked → the connection
//! is queued → its turn reads the ring and runs the requests → the flush
//! copies what fits of its output → `settle_rings` notifies once if bytes
//! moved either way, then unmasks the port. Unmasking only after the ring
//! was examined avoids waking up for notifications about bytes already
//! read, and loses nothing: a notification that comes while the port is
//! masked leaves it pending, and it fires again when unmasked.
//!
//! A peer need not notify for every update (Linux notifies on a write only
//! if the ring was empty, and on a read only if it was full:
//! drivers/xen/xenbus/xenbus_comms.c), so a ring is looked at again
//! without waiting for a notification until an operation finds nothing to
//! move: a read that moved bytes is followed by another read next pass,
//! and a write that moved bytes but left output by another write. Once a
//! read finds the ring empty, the guest's next write sees it empty and
//! notifies; once a write finds it full, the guest's next read sees it
//! full and notifies. Requests that the budget or the soft limit left in
//! the core are processed before the ring is read again (`Conn::held`),
//! and then it is read again.
//!
//! A guest that notifies less than that, or a notification lost on the
//! way, would leave a ring unread: the safety scan (`Scan`) examines every
//! ring once per `ring-scan-interval`, as oxenstored does. When the event
//! channel device says it dropped notifications (`Pending::Lost`), every
//! ring is examined and every port unmasked at once, and every domain's
//! state read. A device whose reads keep failing is read again less and
//! less often (`Backoff`), each time with every ring and domain examined,
//! instead of being polled in a loop.

use crate::log::Level;
use crate::reactor::{Conn, Io, Kind, Reactor, XEN};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::ops::Bound;
use std::time::{Duration, Instant};
use xs_core::{ConnId, GaveUp, Machine, Status};
use xs_sys::backend::{Dom0Ring, Dom0Source, DomainState, Pending, Port, XenBackend};
use xs_sys::ring::{Ring, CONNECTED, ERROR_COMM, ERROR_PROTO, ERROR_RINGIDX, FEATURE_RECONNECTION};
use xs_sys::Interest;
use xs_wire::Errno;

/// Requests handled per ring per turn: less than for a socket, whose
/// clients are the toolstack.
const RING_BUDGET: usize = 16;
/// Rings examined per tick of the safety scan.
const SCAN_BATCH: usize = 32;
/// The first retry of a failing `pending`; each failure doubles the delay,
/// up to `BACKOFF_MAX`.
const BACKOFF_FIRST: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

/// The safety scan (`ox/xenstored.ml:476-503`): each ring is examined once
/// per interval, as if its port had fired. oxenstored examines them all at
/// once; here a tick examines the next `SCAN_BATCH` after the last one
/// examined, and ticks come often enough for the whole set to go round
/// once per interval, so that the work of a
/// wake-up does not grow with the number of domains, and a host of
/// thousands of idle domains has no burst.
pub(crate) struct Scan {
    interval: Duration,
    next: Option<Instant>,
    /// The last ring examined: ids only grow, so the sweep goes on after it
    /// whatever came or went meanwhile.
    cursor: u64,
}

impl Scan {
    pub(crate) fn new(interval: Duration) -> Scan {
        Scan {
            interval,
            next: None,
            cursor: 0,
        }
    }

    /// Between ticks, for `rings` rings to be examined once per interval.
    fn period(&self, rings: usize) -> Duration {
        self.interval / u32::try_from(rings.div_ceil(SCAN_BATCH)).unwrap_or(u32::MAX).max(1)
    }
}

/// `pending` keeps failing: the device, which would be ready at once
/// again (level-triggered), is out of the epoll set until `due`.
pub(crate) struct Backoff {
    delay: Duration,
    due: Instant,
    failures: u64,
}

pub(crate) struct RingConn {
    domid: u32,
    ring: Ring,
    /// None after a failed rebind: nothing can be signalled.
    port: Option<Port>,
    /// The guest's end, which INTRODUCE gave.
    remote: Port,
    /// Returned by `pending` and not unmasked yet.
    masked: bool,
    /// The ring may hold requests that no notification will announce.
    look: bool,
    /// A write moved bytes and left output: try again without waiting.
    push: bool,
    /// Bytes moved this pass: notify once at its end.
    moved: bool,
    /// In `Io::touched`.
    touched: bool,
    /// No longer served (`ox/connection.ml:143-146`): corrupt indices, or
    /// the core gave up on it. Kept, ignored and masked, until RELEASE or
    /// death, as oxenstored does.
    bad: bool,
    /// Failures already logged, until the next success.
    notify_failed: bool,
    unmask_failed: bool,
}

impl RingConn {
    fn new(domid: u32, ring: Ring, port: Port, remote: Port) -> RingConn {
        RingConn {
            domid,
            ring,
            port: Some(port),
            remote,
            masked: false,
            look: false,
            push: false,
            moved: false,
            touched: false,
            bad: false,
            notify_failed: false,
            unmask_failed: false,
        }
    }

    /// A failure is logged once, until a notification goes through: the
    /// guest may then miss a reply until its own next notification.
    fn notify(&mut self, xen: &mut impl XenBackend) {
        let Some(p) = self.port else { return };
        match xen.notify(p) {
            Ok(()) => self.notify_failed = false,
            Err(e) => {
                if !self.notify_failed {
                    crate::warn!("domains", "domain {}: cannot notify local port {p}: {e}", self.domid);
                }
                self.notify_failed = true;
            }
        }
    }

    /// False on failure: the port stays masked, and its guest unheard
    /// until it is unmasked.
    fn unmask(&mut self, xen: &mut impl XenBackend) -> bool {
        if let Err(e) = self.port.map_or(Ok(()), |p| xen.unmask(p)) {
            if !self.unmask_failed {
                crate::warn!(
                    "domains",
                    "domain {}: cannot unmask its port, trying again: {e}",
                    self.domid
                );
            }
            self.unmask_failed = true;
            return false;
        }
        (self.masked, self.unmask_failed) = (false, false);
        true
    }
}

/// True if it stays masked: the loop then tries again at each pass, as
/// deaths would go unnoticed meanwhile (none is lost: Xen keeps the VIRQ
/// pending while it is masked). `failing`: the last try failed too, and
/// was logged.
fn unmask_virq(xen: &mut impl XenBackend, port: Port, failing: bool) -> bool {
    match xen.unmask(port) {
        Ok(()) => false,
        Err(e) => {
            if !failing {
                crate::warn!(
                    "domains",
                    "cannot unmask VIRQ_DOM_EXC on local port {port}, trying again: {e}"
                );
            }
            true
        }
    }
}

impl<X> Io<X> {
    fn ring(&mut self, id: ConnId) -> Option<&mut RingConn> {
        let Some(Conn {
            kind: Kind::Ring(rc), ..
        }) = self.conns.get_mut(&id.0)
        else {
            return None;
        };
        Some(rc)
    }

    fn touch(&mut self, id: ConnId) {
        if let Some(rc) = self.ring(id).filter(|rc| !rc.touched) {
            rc.touched = true;
            self.touched.push(id);
        }
    }

    /// Serves a ring from now on.
    fn add_ring(&mut self, id: ConnId, rc: RingConn) {
        if let Some(p) = rc.port {
            self.ports.insert(p, id);
        }
        self.conns.insert(id.0, Conn::new(Kind::Ring(rc)));
        self.rings.insert(id.0);
        if let Some(s) = &mut self.scan {
            // Sooner if more rings shorten the period: a ring added waits
            // about one interval at most.
            let first = Instant::now() + s.period(self.rings.len());
            s.next = Some(s.next.map_or(first, |t| t.min(first)));
        }
        // Xen leaves a new port pending; looking at once does not depend on it.
        self.enqueue(id);
    }

    /// Queues a ring for a turn, as its port firing does, unless it is bad.
    fn examine(&mut self, id: ConnId) -> Option<&mut RingConn> {
        self.ring(id).filter(|rc| !rc.bad)?;
        self.enqueue(id);
        self.ring(id)
    }

    fn next_timer(&self) -> Option<Instant> {
        let scan = self.scan.as_ref().and_then(|s| s.next);
        let retry = self.backoff.as_ref().map(|b| b.due);
        scan.into_iter().chain(retry).chain(self.accept_retry).min()
    }
}

impl<X: XenBackend> Reactor<X> {
    /// The start of `ox/xenstored.ml:414-421` with `domain_init`:
    /// `Domains.create0` maps dom0's ring, binds its event channel and
    /// notifies it (`ox/domains.ml:159-175`; dom0's kernel waits for that
    /// to know xenstored is up), `Connections.add_domain` advertises the
    /// reconnection feature on it (`ox/xb.ml:313-315`), then VIRQ_DOM_EXC
    /// is bound. oxenstored does not touch dom0's `connection`: a pending
    /// reconnection is handled at its first turn, as for any ring. Here
    /// VIRQ_DOM_EXC is bound first, and Xen is asked about domain 0 before
    /// anything, so that a hypervisor whose interface the daemon does not
    /// speak fails the start instead of making every domain look dead.
    pub(crate) fn start_xen(&mut self, mut xen: X) -> io::Result<()> {
        let fail = |what: &'static str| move |e: io::Error| io::Error::new(e.kind(), format!("{what}: {e}"));
        if xen.domain_state(0).map_err(fail("cannot ask Xen about domain 0"))? == DomainState::Dead {
            return Err(io::Error::other("Xen says domain 0 does not exist: is this the hypervisor interface rxenstored was built for (Xen 4.17)?"));
        }
        let virq = xen.bind_dom_exc().map_err(fail("cannot bind VIRQ_DOM_EXC"))?;
        let Dom0Ring {
            page,
            port: remote,
            source,
        } = xen.dom0_ring().map_err(fail("cannot map domain 0's ring"))?;
        let mut ring = Ring::new(page).map_err(fail("domain 0's ring"))?;
        let local = xen
            .bind_interdomain(0, remote)
            .map_err(fail("cannot bind domain 0's event channel"))?;
        ring.set_server_features(FEATURE_RECONNECTION);
        xen.notify(local).map_err(fail("cannot notify domain 0"))?;
        self.epoll.add(xen.event_fd(), XEN, Interest::READ)?;
        let id = self.core.open_domain(0);
        self.io.add_ring(id, RingConn::new(0, ring, local, remote));
        self.io.dom_exc = Some(virq);
        self.io.xen = Some(xen);
        let (page_from, port_from, fallback) = dom0_origin(&source);
        if let Some((level, line)) = fallback {
            crate::log::echo(crate::log::Stderr::Always, level, "domains", format_args!("{line}"));
        }
        crate::echo!(
            Always,
            Info,
            "domains",
            "domain 0's ring mapped from {page_from}, event channel {remote} (from {port_from}) on local port {local}; VIRQ_DOM_EXC on local port {virq}"
        );
        Ok(())
    }

    /// The epoll timeout until the next timer, rounded up: woken before
    /// it is due, the loop would wait again for 0 ms until it is. -1: none.
    /// The core's is when a domain paused for conflicts gets credit back:
    /// it is served then even if nothing else happens.
    pub(crate) fn timeout(&self) -> i32 {
        // Past what an `Instant` holds: never.
        let core = self.core.next_tick().and_then(|d| self.epoch.checked_add(d));
        let Some(t) = self.io.next_timer().into_iter().chain(core).min() else {
            return -1;
        };
        let left = t.saturating_duration_since(Instant::now());
        left.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
    }

    /// Runs the timers that are due; the core gets the time at every pass.
    pub(crate) fn timers(&mut self) {
        let now = Instant::now();
        self.core.tick(now - self.epoch);
        let Some(first) = self.io.next_timer() else { return };
        if first > now {
            return;
        }
        if self.io.backoff.as_ref().is_some_and(|b| b.due <= now) {
            self.xen_events();
        }
        if self.io.scan.as_ref().and_then(|s| s.next).is_some_and(|t| t <= now) {
            self.scan_rings(now);
        }
        if self.io.accept_retry.is_some_and(|t| t <= now) {
            self.resume_accept();
        }
    }

    /// One tick of the safety scan.
    fn scan_rings(&mut self, now: Instant) {
        let Io {
            rings, scan: Some(s), ..
        } = &mut self.io
        else {
            return;
        };
        let after = rings.range((Bound::Excluded(s.cursor), Bound::Unbounded));
        let batch: Vec<ConnId> = after
            .chain(rings.range(..=s.cursor))
            .take(SCAN_BATCH)
            .map(|&id| ConnId(id))
            .collect();
        // Domain 0's ring is there for good: it is never released, and
        // never dies (`Core::domains_changed`), so the batch has a ring.
        if let Some(last) = batch.last() {
            s.cursor = last.0;
        }
        let period = s.period(rings.len());
        // `next` is due: the tick is now.
        let next = s.next.unwrap_or(now) + period;
        // Late (the loop was busy): no catching up in a burst.
        s.next = Some(if next > now { next } else { now + period });
        for id in batch {
            self.io.examine(id);
        }
    }

    /// The event channel device is readable, or a retry is due.
    pub(crate) fn xen_events(&mut self) {
        let mut ports = Vec::new();
        // Polled only with a backend.
        let Some(xen) = self.io.xen.as_mut() else { return };
        let r = match self.io.backoff {
            // Watched again before it is read: nothing that fires after
            // the read goes unheard.
            Some(_) => self
                .epoll
                .add(xen.event_fd(), XEN, Interest::READ)
                .and_then(|()| xen.pending(&mut ports)),
            None => xen.pending(&mut ports),
        };
        match r {
            Ok(p) => {
                if let Some(b) = self.io.backoff.take() {
                    crate::warn!(
                        "domains",
                        "the pending event channels can be read again, after {} failures",
                        b.failures
                    );
                }
                if p == Pending::Lost {
                    crate::warn!(
                        "domains",
                        "the event channel device overflowed and was reset: examining every ring and domain"
                    );
                    self.lost_events();
                }
            }
            Err(e) => self.pending_failed(e),
        }
        for p in ports {
            if Some(p) == self.io.dom_exc {
                self.dom_exc();
            } else if let Some(&id) = self.io.ports.get(&p) {
                // (A port unbound since it fired is in no map: ignored.)
                // A port is a ring's.
                if let Some(rc) = self.io.ring(id) {
                    rc.masked = true;
                    // A bad connection's port stays masked: its guest cannot make us spin.
                    if !rc.bad {
                        self.io.enqueue(id);
                    }
                }
            }
        }
    }

    /// `pending` failed: tried again after a delay that doubles at each
    /// failure in a row, up to `BACKOFF_MAX`; logged once per streak. Every
    /// ring and domain is examined at each failure, as none of their
    /// notifications can be read.
    fn pending_failed(&mut self, e: io::Error) {
        // Not in the set if adding it back failed.
        if let Some(xen) = self.io.xen.as_ref() {
            let _ = self.epoll.delete(xen.event_fd());
        }
        let now = Instant::now();
        let b = match self.io.backoff.take() {
            None => {
                crate::error!("domains", "cannot read the pending event channels: {e}; examining every ring and domain, less and less often, until it works again");
                Backoff {
                    delay: BACKOFF_FIRST,
                    due: now + BACKOFF_FIRST,
                    failures: 1,
                }
            }
            Some(b) => {
                let delay = (b.delay * 2).min(BACKOFF_MAX);
                Backoff {
                    delay,
                    due: now + delay,
                    failures: b.failures + 1,
                }
            }
        };
        self.io.backoff = Some(b);
        self.lost_events();
    }

    /// Notifications may have been lost: every ring is examined, and its
    /// port unmasked after (an overflow leaves masked the ports it
    /// dropped), and the domains are checked.
    fn lost_events(&mut self) {
        let ids: Vec<ConnId> = self.io.rings.iter().map(|&id| ConnId(id)).collect();
        for id in ids {
            if let Some(rc) = self.io.examine(id) {
                rc.masked = true;
            }
        }
        self.dom_exc();
    }

    /// VIRQ_DOM_EXC fired (`ox/xenstored.ml:470-481`). A domain whose state
    /// cannot be read is taken as running: wrongly dead, it would lose its
    /// nodes and connection for good, while one wrongly alive is found at
    /// the next VIRQ. oxenstored takes any error as dead
    /// (`ox/domains.ml:101-115`), but there an error is also how a
    /// destroyed domain shows; here that is `Dead`, not an error.
    fn dom_exc(&mut self) {
        // Bound only with a backend.
        let Some(xen) = self.io.xen.as_mut() else { return };
        let mut states = HashMap::new();
        for (domid, _) in self.core.domains().filter(|(d, _)| *d != 0) {
            let s = match xen.domain_state(domid) {
                Ok(DomainState::Running) => xs_core::DomainState::Running,
                Ok(DomainState::Shutdown) => xs_core::DomainState::Shutdown,
                Ok(DomainState::Dead) => xs_core::DomainState::Dead,
                Err(e) => {
                    crate::warn!(
                        "domains",
                        "domain {domid}: cannot read its state from Xen, taken as running: {e}"
                    );
                    xs_core::DomainState::Running
                }
            };
            states.insert(domid, s);
        }
        self.io.dying = true;
        // The core asks about the domains it has, as above: any other is
        // taken as running, as one whose state cannot be read.
        self.core.domains_changed(
            &mut |d| states.get(&d).copied().unwrap_or(xs_core::DomainState::Running),
            &mut self.io,
        );
        self.io.dying = false;
        // After the scan: a VIRQ that comes meanwhile fires again.
        if let (Some(xen), Some(port)) = (self.io.xen.as_mut(), self.io.dom_exc) {
            self.io.virq_masked = unmask_virq(xen, port, self.io.virq_masked);
        }
    }

    pub(crate) fn ring_turn(&mut self, id: ConnId) {
        if self.io.ring(id).is_some_and(|rc| rc.bad) {
            return;
        }
        self.io.touch(id);
        self.io.mark_flush(id);
        let Io { conns, buf, .. } = &mut self.io;
        let Some(Conn {
            kind: Kind::Ring(rc),
            held,
            blocked,
            ..
        }) = conns.get_mut(&id.0)
        else {
            return;
        };
        // `ox/process.ml:716-724`: a guest that asked to reconnect has
        // given up on what is queued; the ring is reset and the guest
        // notified (`ox/xb.ml:192-201`).
        if rc.ring.connection() != CONNECTED {
            self.core.reconnect(id);
            rc.ring.reconnect();
            (rc.moved, rc.look, rc.push, *held, *blocked) = (true, false, false, false, false);
            crate::echo!(Lifecycle, Info, "domains", "domain {}: ring reconnected", rc.domid);
            return;
        }
        // Not reading leaves the requests in the ring: a guest that does
        // not read its replies cannot make the daemon buffer more.
        if !self.core.wants_input(id) {
            *blocked = true;
            return;
        }
        if *held {
            // Requests may have come meanwhile: read once the core's are done.
            rc.look = true;
        } else {
            match rc.ring.read(buf) {
                // `read` copies at most the buffer: past it, the ring is
                // taken as corrupt.
                Ok(n) => match buf.get(..n) {
                    Some(data) => {
                        rc.look = n > 0;
                        rc.moved |= n > 0;
                        self.core.feed(id, data);
                    }
                    None => return self.mark_bad(id, "a read past the buffer", ERROR_RINGIDX),
                },
                Err(e) => return self.mark_bad(id, e, ERROR_RINGIDX),
            }
        }
        let status = self.core.process_on(id, RING_BUDGET, &mut self.io);
        // Gone if it released itself.
        let Some(Conn {
            kind: Kind::Ring(rc),
            held,
            blocked,
            ..
        }) = self.io.conns.get_mut(&id.0)
        else {
            return;
        };
        *held = matches!(status, Status::More | Status::Blocked);
        match status {
            Status::More => self.io.enqueue(id),
            Status::Idle if rc.look => self.io.enqueue(id),
            Status::Blocked => *blocked = true,
            Status::Idle | Status::Closed => {}
        }
    }

    /// Copies what fits of a ring connection's output.
    pub(crate) fn flush_ring(&mut self, id: ConnId) {
        if self.io.ring(id).is_some_and(|rc| rc.bad) {
            return;
        }
        self.io.touch(id);
        let Some(rc) = self.io.ring(id) else { return };
        let out = self.core.output(id);
        if out.is_empty() {
            rc.push = false;
            return self.unblock(id);
        }
        if rc.ring.connection() != CONNECTED {
            // Its turn resets the ring; writing now would be lost.
            return self.io.enqueue(id);
        }
        match rc.ring.write(out) {
            Ok(n) => {
                self.core.consume(id, n);
                rc.moved |= n > 0;
                rc.push = n > 0 && !self.core.output(id).is_empty();
            }
            Err(e) => return self.mark_bad(id, e, ERROR_RINGIDX),
        }
        if rc.push {
            self.io.enqueue(id);
        }
        self.unblock(id);
    }

    /// End of a pass: each ring that moved bytes is notified once, and the
    /// ports that fired are unmasked, now that their ring was examined. A
    /// port that could not be unmasked is tried again at the next pass
    /// (its connection is queued): left masked, it would silence its guest.
    pub(crate) fn settle_rings(&mut self) {
        let Io {
            xen,
            conns,
            touched,
            ready,
            dom_exc,
            virq_masked,
            ..
        } = &mut self.io;
        let Some(xen) = xen else { return };
        for id in touched.drain(..) {
            if let Some(Conn {
                kind: Kind::Ring(rc),
                queued,
                ..
            }) = conns.get_mut(&id.0)
            {
                rc.touched = false;
                if rc.bad {
                    continue;
                }
                if rc.moved {
                    rc.moved = false;
                    rc.notify(xen);
                }
                if rc.masked && !rc.unmask(xen) && !*queued {
                    *queued = true;
                    ready.push_back(id);
                }
            }
        }
        // Masked only once bound.
        if let (true, Some(port)) = (*virq_masked, *dom_exc) {
            *virq_masked = unmask_virq(xen, port, true);
        }
    }

    /// The core gave up on a ring connection. Closing it would make the
    /// core forget the domain: it is kept, ignored, instead, with the
    /// error C xenstored gives (`cx/core.c:2196-2205`; XSA-325).
    pub(crate) fn ring_given_up(&mut self, id: ConnId, why: GaveUp) {
        match why {
            GaveUp::Protocol => self.mark_bad(id, "a request longer than the protocol allows", ERROR_PROTO),
            GaveUp::Overflow => self.mark_bad(id, "unread output over the hard limit", ERROR_COMM),
        }
    }

    /// Stops serving a ring for good (`ox/process.ml:725-729`), with
    /// `error` in its page. The core drops its state for it (watches,
    /// transactions, output) and its input; the domain stays known until
    /// RELEASE or death.
    fn mark_bad(&mut self, id: ConnId, why: impl fmt::Display, error: u32) {
        let Some(Conn {
            kind: Kind::Ring(rc),
            held,
            blocked,
            ..
        }) = self.io.conns.get_mut(&id.0)
        else {
            return;
        };
        rc.bad = true;
        (*held, *blocked) = (false, false);
        rc.ring.set_error(error);
        self.core.ignore(id);
        crate::echo!(
            Lifecycle,
            Error,
            "domains",
            "domain {}: connection marked bad, ignored until released or dead: {why}",
            rc.domid
        );
    }
}

impl<X: XenBackend> Machine for Io<X> {
    /// `ox/domains.ml:153-158` (`create`) and `ox/connections.ml:47-54`:
    /// map, bind, advertise the reconnection feature. oxenstored 4.17
    /// does not notify the guest. Any failure undoes what was done (the
    /// mapping goes with the `Ring`), and is EINVAL (`ox/process.ml:602-607`).
    fn connect(&mut self, conn: ConnId, domid: u32, gfn: u64, remote: u32) -> Result<(), Errno> {
        let Some(xen) = self.xen.as_mut() else {
            return Err(Errno::EINVAL);
        };
        let ring = match xen.map_ring(domid, gfn).and_then(Ring::new) {
            Ok(r) => r,
            Err(e) => {
                crate::warn!(
                    "domains",
                    "INTRODUCE of domain {domid}: cannot map its ring at gfn {gfn:#x}: {e}"
                );
                return Err(Errno::EINVAL);
            }
        };
        let port = match xen.bind_interdomain(domid, remote) {
            Ok(p) => p,
            Err(e) => {
                crate::warn!(
                    "domains",
                    "INTRODUCE of domain {domid}: cannot bind its event channel {remote}: {e}"
                );
                return Err(Errno::EINVAL);
            }
        };
        let mut rc = RingConn::new(domid, ring, port, remote);
        rc.ring.set_server_features(FEATURE_RECONNECTION);
        self.add_ring(conn, rc);
        crate::echo!(
            Lifecycle,
            Info,
            "domains",
            "domain {domid} introduced: ring at gfn {gfn:#x}, event channel {remote} on local port {port}"
        );
        Ok(())
    }

    /// `ox/domain.ml:77-83` (`bind_interdomain`): the old port is unbound
    /// first, as the guest may give the same remote port again; if that
    /// fails, the old binding stays. If the new port cannot be bound, the
    /// old remote port is bound again, if it can be. Errors are EIO
    /// (`ox/process.ml:597-600, 737-740`).
    fn rebind(&mut self, conn: ConnId, domid: u32, remote: u32) -> Result<(), Errno> {
        // Domains are known only with a backend.
        let Some(xen) = self.xen.as_mut() else {
            return Err(Errno::EIO);
        };
        let Some(Conn {
            kind: Kind::Ring(rc), ..
        }) = self.conns.get_mut(&conn.0)
        else {
            return Err(Errno::EIO);
        };
        if let Some(old) = rc.port {
            if let Err(e) = xen.unbind(old) {
                crate::warn!(
                    "domains",
                    "INTRODUCE of domain {domid}: cannot unbind local port {old}: {e}"
                );
                return Err(Errno::EIO);
            }
            self.ports.remove(&old);
            rc.port = None;
        }
        rc.masked = false;
        let r = match xen.bind_interdomain(domid, remote) {
            Ok(p) => {
                rc.remote = remote;
                Ok(p)
            }
            Err(e) => {
                crate::warn!(
                    "domains",
                    "INTRODUCE of domain {domid}: cannot bind its event channel {remote}: {e}"
                );
                Err(e)
            }
        };
        let port = r.as_ref().copied().or_else(|_| xen.bind_interdomain(domid, rc.remote));
        match port {
            Ok(p) => {
                rc.port = Some(p);
                let remote = rc.remote;
                self.ports.insert(p, conn);
                self.enqueue(conn);
                crate::info!(
                    "domains",
                    "domain {domid}: event channel {remote} bound again, on local port {p}"
                );
            }
            Err(e) => crate::error!(
                "domains",
                "domain {domid}: no event channel ({e}): not served until introduced again"
            ),
        }
        r.map(drop).map_err(|_| Errno::EIO)
    }

    /// `ox/domain.ml:86-92` (`close`): unbind and unmap. The ring is left
    /// as it is.
    fn disconnect(&mut self, conn: ConnId, domid: u32) {
        let Some(Conn {
            kind: Kind::Ring(rc), ..
        }) = self.conns.remove(&conn.0)
        else {
            return;
        };
        self.rings.remove(&conn.0);
        if let Some(p) = rc.port {
            self.ports.remove(&p);
            // Domains are known only with a backend.
            if let Some(Err(e)) = self.xen.as_mut().map(|xen| xen.unbind(p)) {
                crate::warn!("domains", "domain {domid}: cannot unbind local port {p}: {e}");
            }
        }
        crate::echo!(
            Lifecycle,
            Info,
            "domains",
            "domain {domid} {}: connection closed",
            if self.dying { "died" } else { "released" }
        );
    }
}

/// For the log: where domain 0's ring page and port came from, and, if
/// the xenbus backend device was tried and not used, a line saying why
/// (a warning unless the device does not exist).
fn dom0_origin(s: &Dom0Source) -> (String, String, Option<(Level, String)>) {
    match s {
        Dom0Source::Device(p) => (p.display().to_string(), p.display().to_string(), None),
        Dom0Source::Files { kva, port, device } => (
            kva.display().to_string(),
            port.display().to_string(),
            device.as_ref().map(|d| {
                (
                    if d.missing { Level::Info } else { Level::Warn },
                    format!(
                        "{d}: domain 0's ring is taken from {} and {} instead",
                        kva.display(),
                        port.display()
                    ),
                )
            }),
        ),
        Dom0Source::Simulated => (
            "the simulated hypervisor".into(),
            "the simulated hypervisor".into(),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use xs_sys::backend::DeviceNotUsed;

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's strerror_r appends the error number, so the error text differs; the code before the check runs under Miri"
    )]
    fn the_log_names_where_dom0_s_ring_came_from() {
        let dev = PathBuf::from("/dev/xen/xenbus_backend");
        assert_eq!(
            dom0_origin(&Dom0Source::Device(dev.clone())),
            (dev.display().to_string(), dev.display().to_string(), None)
        );
        let files = |device| Dom0Source::Files {
            kva: "/proc/xen/xsd_kva".into(),
            port: "/proc/xen/xsd_port".into(),
            device,
        };
        let (k, p, note) = dom0_origin(&files(None));
        assert_eq!(
            (k.as_str(), p.as_str(), note),
            ("/proc/xen/xsd_kva", "/proc/xen/xsd_port", None)
        );
        let not_used = |missing, errno| {
            Some(DeviceNotUsed {
                path: dev.clone(),
                missing,
                error: io::Error::from_raw_os_error(errno),
            })
        };
        let (_, _, note) = dom0_origin(&files(not_used(true, libc::ENOENT)));
        assert_eq!(
            note,
            Some((
                Level::Info,
                "/dev/xen/xenbus_backend: No such file or directory (os error 2): domain 0's ring is taken from \
                 /proc/xen/xsd_kva and /proc/xen/xsd_port instead"
                    .into()
            ))
        );
        let (_, _, note) = dom0_origin(&files(not_used(false, libc::EPERM)));
        let (level, line) = note.unwrap();
        assert_eq!(level, Level::Warn);
        assert!(
            line.starts_with("/dev/xen/xenbus_backend: Operation not permitted (os error 1): "),
            "{line}"
        );
        let (k, _, note) = dom0_origin(&Dom0Source::Simulated);
        assert_eq!((k.as_str(), note), ("the simulated hypervisor", None));
    }
}
