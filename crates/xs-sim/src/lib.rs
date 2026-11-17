// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! A simulated Xen for the daemon's tests: `SimXen` implements
//! `xs_sys::backend::XenBackend` with memfd pages for the rings and an
//! eventfd for the event channel device, over a table of domains that the
//! test drives through a `Handle`.
//!
//! The pieces:
//!
//! - `SimXen`, the backend, owned by the daemon's thread. It is `Send`.
//!   Domain 0 exists from the start; `dom0_ring` gives its page and port.
//! - `Handle`, cloneable and usable from any thread: the hypervisor's
//!   side. It creates domains (each with a ring page, a gfn and a remote
//!   port, the three values of INTRODUCE), changes their state, destroys
//!   them, fires `VIRQ_DOM_EXC`, and makes chosen operations fail.
//! - `Guest`, from `Handle::guest`: the guest of one domain, on its own
//!   mapping of the domain's page. It moves bytes on the ring, notifies
//!   the server, waits for the server's notifications, and is a small
//!   xenstore client (`send_request`, `recv_message`).
//!
//! Event channels behave as `/dev/xen/evtchn` and Xen 4.17 do:
//!
//! - local ports are allocated lowest first, from 1;
//! - a port that fires is returned once by `pending` and stays masked
//!   until `unmask`; one that fires while masked is returned again after
//!   `unmask`, once however many times it fired;
//! - `bind_interdomain` needs the domain's own remote port, not bound yet
//!   (else EINVAL; ESRCH for no domain, or a dead one), and leaves the new
//!   port pending, as Xen does in case a notification was lost;
//! - `notify` and `unbind` of a port that is not bound are ENOTCONN;
//!   `unmask` of one is ignored; a notification to a domain that has gone
//!   is dropped. `pending` may return a port unbound since it fired;
//! - a guest's notification reaches the server only once the server has
//!   bound the domain's port; before that it is dropped, as Xen drops a
//!   send on an unbound channel;
//! - `VIRQ_DOM_EXC` fires when a domain is set to `Shutdown` or `Dead`, and
//!   when it is destroyed;
//! - the device's buffer can overflow (`Handle::overflow`): what fired is
//!   dropped and stays masked, and the next `pending` resets the device
//!   and says `Pending::Lost`, as the real backend does on EFBIG.
//!
//! `map_ring` fails with ESRCH for a domain that does not exist or is
//! dead and EINVAL for a gfn other than the domain's ring, where the real
//! foreign mapping would map whatever page is there.
//!
//! ```
//! use std::time::Duration;
//! use xs_sim::SimXen;
//! use xs_sys::backend::XenBackend;
//! use xs_sys::ring::Ring;
//! use xs_wire::{Message, MsgType};
//!
//! let mut xen = SimXen::new().unwrap();
//! let hv = xen.handle();
//! let dom = hv.create_domain(5).unwrap();
//! let mut guest = hv.guest(5).unwrap();
//!
//! // What the daemon does on INTRODUCE(5, dom.gfn, dom.port).
//! let mut ring = Ring::new(xen.map_ring(5, dom.gfn).unwrap()).unwrap();
//! let local = xen.bind_interdomain(5, dom.port).unwrap();
//!
//! // The guest sends a request and notifies; the server's port fires.
//! guest.send_request(MsgType::Read, 7, 0, b"name\0", Duration::from_secs(1)).unwrap();
//! let mut ports = Vec::new();
//! xen.pending(&mut ports).unwrap(); // xen.event_fd() was readable
//! assert!(ports.contains(&local));
//! xen.unmask(local).unwrap();
//! let mut buf = [0u8; 64];
//! assert_eq!(ring.read(&mut buf).unwrap(), 16 + 5); // header and "name\0"
//!
//! // The server replies and notifies; the guest reads one message.
//! let mut reply = Vec::new();
//! Message::new(MsgType::Read, 7, 0, b"guest".to_vec()).unwrap().encode_into(&mut reply);
//! ring.write(&reply).unwrap();
//! xen.notify(local).unwrap();
//! let msg = guest.recv_message(Duration::from_secs(1)).unwrap();
//! assert_eq!((msg.req_id, &msg.payload[..]), (7, &b"guest"[..]));
//! ```

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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use xs_sys::backend::{DomainState, Pending, Port, XenBackend};
use xs_sys::fd::{memfd, wait_readable, EventFd, Memfd};
use xs_sys::map::{Mapping, PAGE_SIZE};
use xs_sys::ring::{Field, GuestRing, CONNECTED, RING_SIZE};
use xs_wire::{write_header, Decoder, Message, MsgType};

/// The operations of `XenBackend`, for `Handle::fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Pending,
    Unmask,
    BindDomExc,
    BindInterdomain,
    Unbind,
    Notify,
    Dom0Ring,
    MapRing,
    DomainState,
}

/// A domain as the toolstack knows it: what goes into INTRODUCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainInfo {
    pub domid: u32,
    /// Where the ring page is in the guest.
    pub gfn: u64,
    /// The guest's end of its xenstore event channel.
    pub port: Port,
}

struct Domain {
    info: DomainInfo,
    page: Memfd,
    state: DomainState,
    /// The server's notifications to this incarnation of the domain.
    event: Arc<EventFd>,
    /// The server's local port bound to `info.port`.
    bound: Option<Port>,
}

#[derive(Clone, Copy)]
enum Kind {
    Interdomain { domid: u32 },
    DomExc,
}

struct Local {
    kind: Kind,
    masked: bool,
    /// Fired while masked.
    pending: bool,
}

#[derive(Clone, Copy)]
struct Failure {
    errno: i32,
    once: bool,
}

struct State {
    domains: BTreeMap<u32, Domain>,
    locals: BTreeMap<Port, Local>,
    /// Fired and not yet returned by `pending`. `event` is readable while
    /// this is not empty, or while `overflowed`.
    fired: VecDeque<Port>,
    /// The buffer overflowed: until `pending` resets it, what fires is
    /// dropped.
    overflowed: bool,
    event: Arc<EventFd>,
    dom_exc: Option<Port>,
    failures: HashMap<Op, Failure>,
    next_gfn: u64,
    next_remote: Port,
}

fn errno(e: i32) -> io::Error {
    io::Error::from_raw_os_error(e)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "no notification from the server in time")
}

impl State {
    fn check(&mut self, op: Op) -> io::Result<()> {
        match self.failures.get(&op).copied() {
            None => Ok(()),
            Some(f) => {
                if f.once {
                    self.failures.remove(&op);
                }
                Err(errno(f.errno))
            }
        }
    }

    fn fire(&mut self, port: Port) {
        let Some(l) = self.locals.get_mut(&port) else { return };
        if l.masked {
            l.pending = true;
            return;
        }
        l.masked = true;
        if self.overflowed {
            return;
        }
        self.fired.push_back(port);
        // An eventfd counts to 2^64 - 2: a test does not fire that often.
        // Were it to fail, the server would not wake and the test would
        // time out.
        let _ = self.event.signal();
    }

    fn fire_dom_exc(&mut self) {
        if let Some(p) = self.dom_exc {
            self.fire(p);
        }
    }

    fn free_port(&self) -> io::Result<Port> {
        (1..=Port::MAX)
            .find(|p| !self.locals.contains_key(p))
            .ok_or_else(|| errno(ENOSPC))
    }

    fn create_domain(&mut self, domid: u32) -> io::Result<DomainInfo> {
        if self.domains.contains_key(&domid) {
            return Err(errno(EEXIST));
        }
        let info = DomainInfo {
            domid,
            gfn: self.next_gfn,
            port: self.next_remote,
        };
        let page = memfd(&format!("xs-sim-dom{domid}"), PAGE_SIZE as u64)?;
        let event = Arc::new(EventFd::new()?);
        self.next_gfn += 1;
        self.next_remote += 1;
        self.domains.insert(
            domid,
            Domain {
                info,
                page,
                state: DomainState::Running,
                event,
                bound: None,
            },
        );
        Ok(info)
    }

    fn live(&self, domid: u32) -> io::Result<&Domain> {
        match self.domains.get(&domid) {
            Some(d) if d.state != DomainState::Dead => Ok(d),
            _ => Err(errno(ESRCH)),
        }
    }
}

// The errno values of Linux used here (xs-sim depends on xs-sys and
// xs-wire only).
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const ENOTCONN: i32 = 107;

/// `timeout` from now; InvalidInput past what an `Instant` holds.
fn deadline_in(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout too long"))
}

#[derive(Clone)]
struct Shared(Arc<Mutex<State>>);

impl Shared {
    /// The state, even if a test panicked while holding it (that test
    /// has failed; the others go on).
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The simulated backend. See the crate documentation.
pub struct SimXen {
    shared: Shared,
    event: Arc<EventFd>,
}

impl SimXen {
    /// A machine with domain 0 only, running.
    pub fn new() -> io::Result<SimXen> {
        let event = Arc::new(EventFd::new()?);
        let mut state = State {
            domains: BTreeMap::new(),
            locals: BTreeMap::new(),
            fired: VecDeque::new(),
            overflowed: false,
            event: event.clone(),
            dom_exc: None,
            failures: HashMap::new(),
            next_gfn: 0xfe000,
            next_remote: 1,
        };
        state.create_domain(0)?;
        Ok(SimXen {
            shared: Shared(Arc::new(Mutex::new(state))),
            event,
        })
    }

    pub fn handle(&self) -> Handle {
        Handle {
            shared: self.shared.clone(),
        }
    }
}

impl XenBackend for SimXen {
    fn event_fd(&self) -> RawFd {
        self.event.as_raw_fd()
    }

    fn pending(&mut self, out: &mut Vec<Port>) -> io::Result<Pending> {
        let mut s = self.shared.lock();
        s.check(Op::Pending)?;
        s.event.take()?;
        if std::mem::take(&mut s.overflowed) {
            return Ok(Pending::Lost);
        }
        out.extend(s.fired.drain(..));
        Ok(Pending::Complete)
    }

    fn unmask(&mut self, local: Port) -> io::Result<()> {
        let mut s = self.shared.lock();
        s.check(Op::Unmask)?;
        let Some(l) = s.locals.get_mut(&local) else {
            return Ok(());
        };
        let again = l.pending;
        l.masked = false;
        l.pending = false;
        if again {
            s.fire(local);
        }
        Ok(())
    }

    fn bind_dom_exc(&mut self) -> io::Result<Port> {
        let mut s = self.shared.lock();
        s.check(Op::BindDomExc)?;
        if s.dom_exc.is_some() {
            return Err(errno(EEXIST));
        }
        let port = s.free_port()?;
        s.locals.insert(
            port,
            Local {
                kind: Kind::DomExc,
                masked: false,
                pending: false,
            },
        );
        s.dom_exc = Some(port);
        Ok(port)
    }

    fn bind_interdomain(&mut self, domid: u32, remote: Port) -> io::Result<Port> {
        let mut s = self.shared.lock();
        s.check(Op::BindInterdomain)?;
        let d = s.live(domid)?;
        if d.info.port != remote || d.bound.is_some() {
            return Err(errno(EINVAL));
        }
        let port = s.free_port()?;
        if let Some(d) = s.domains.get_mut(&domid) {
            d.bound = Some(port);
        }
        s.locals.insert(
            port,
            Local {
                kind: Kind::Interdomain { domid },
                masked: false,
                pending: false,
            },
        );
        s.fire(port);
        Ok(port)
    }

    fn unbind(&mut self, local: Port) -> io::Result<()> {
        let mut s = self.shared.lock();
        s.check(Op::Unbind)?;
        let l = s.locals.remove(&local).ok_or_else(|| errno(ENOTCONN))?;
        match l.kind {
            Kind::DomExc => s.dom_exc = None,
            Kind::Interdomain { domid } => {
                if let Some(d) = s.domains.get_mut(&domid).filter(|d| d.bound == Some(local)) {
                    d.bound = None;
                }
            }
        }
        Ok(())
    }

    fn notify(&mut self, local: Port) -> io::Result<()> {
        let mut s = self.shared.lock();
        s.check(Op::Notify)?;
        let l = s.locals.get(&local).ok_or_else(|| errno(ENOTCONN))?;
        if let Kind::Interdomain { domid } = l.kind {
            if let Some(d) = s.domains.get(&domid).filter(|d| d.bound == Some(local)) {
                d.event.signal()?;
            }
        }
        Ok(())
    }

    fn dom0_ring(&mut self) -> io::Result<(Mapping, Port)> {
        let mut s = self.shared.lock();
        s.check(Op::Dom0Ring)?;
        let d = s.domains.get(&0).ok_or_else(|| errno(ENOENT))?;
        Ok((d.page.map(0, PAGE_SIZE)?, d.info.port))
    }

    fn map_ring(&mut self, domid: u32, gfn: u64) -> io::Result<Mapping> {
        let mut s = self.shared.lock();
        s.check(Op::MapRing)?;
        let d = s.live(domid)?;
        if d.info.gfn != gfn {
            return Err(errno(EINVAL));
        }
        d.page.map(0, PAGE_SIZE)
    }

    fn domain_state(&mut self, domid: u32) -> io::Result<DomainState> {
        let mut s = self.shared.lock();
        s.check(Op::DomainState)?;
        Ok(s.domains.get(&domid).map_or(DomainState::Dead, |d| d.state))
    }
}

/// The test's side: hypervisor and toolstack. Cloneable, `Send` and
/// `Sync`.
#[derive(Clone)]
pub struct Handle {
    shared: Shared,
}

impl Handle {
    /// A running domain with a fresh, zeroed ring page. EEXIST if `domid`
    /// exists.
    pub fn create_domain(&self, domid: u32) -> io::Result<DomainInfo> {
        self.shared.lock().create_domain(domid)
    }

    pub fn domain(&self, domid: u32) -> Option<DomainInfo> {
        self.shared.lock().domains.get(&domid).map(|d| d.info)
    }

    /// The domain ids in the table, dead ones included, in order.
    pub fn domains(&self) -> Vec<u32> {
        self.shared.lock().domains.keys().copied().collect()
    }

    /// Fires `VIRQ_DOM_EXC` unless the new state is `Running`. ESRCH if no
    /// such domain.
    pub fn set_state(&self, domid: u32, state: DomainState) -> io::Result<()> {
        let mut s = self.shared.lock();
        s.domains.get_mut(&domid).ok_or_else(|| errno(ESRCH))?.state = state;
        if state != DomainState::Running {
            s.fire_dom_exc();
        }
        Ok(())
    }

    /// Removes the domain and fires `VIRQ_DOM_EXC`. Its mappings stay
    /// valid; its channel to the server goes quiet. Domain 0 cannot be
    /// destroyed (EPERM).
    pub fn destroy_domain(&self, domid: u32) -> io::Result<()> {
        if domid == 0 {
            return Err(errno(EPERM));
        }
        let mut s = self.shared.lock();
        s.domains.remove(&domid).ok_or_else(|| errno(ESRCH))?;
        s.fire_dom_exc();
        Ok(())
    }

    pub fn fire_dom_exc(&self) {
        self.shared.lock().fire_dom_exc();
    }

    /// Overflows the event channel device's buffer, as when more ports
    /// fire than it holds (Linux drivers/xen/evtchn.c): the ports fired and
    /// not yet returned by `pending` are dropped, and so is each port that
    /// fires during `during` (which runs without the simulation locked);
    /// all stay masked. Then the device becomes readable, and the next
    /// `pending` resets it and returns `Pending::Lost` and no port. The
    /// server is not woken during `during`, as if it were busy elsewhere;
    /// a `pending` it calls meanwhile ends the overflow early.
    pub fn overflow(&self, during: impl FnOnce()) {
        {
            let mut s = self.shared.lock();
            s.overflowed = true;
            s.fired.clear();
            // Emptied: a failure leaves the device readable, which a test
            // of the overflow sees.
            let _ = s.event.take();
        }
        during();
        let s = self.shared.lock();
        if s.overflowed {
            // As in `fire`.
            let _ = s.event.signal();
        }
    }

    /// Whether the server has bound the domain's event channel: after
    /// INTRODUCE, until RELEASE.
    pub fn is_bound(&self, domid: u32) -> bool {
        self.shared
            .lock()
            .domains
            .get(&domid)
            .is_some_and(|d| d.bound.is_some())
    }

    /// The guest of a domain, on a new mapping of its page. One `Guest` per
    /// domain at a time: they would share the server's notifications.
    pub fn guest(&self, domid: u32) -> io::Result<Guest> {
        let s = self.shared.lock();
        let d = s.domains.get(&domid).ok_or_else(|| errno(ESRCH))?;
        Ok(Guest {
            shared: self.shared.clone(),
            info: d.info,
            ring: GuestRing::new(d.page.map(0, PAGE_SIZE)?)?,
            event: d.event.clone(),
            decoder: Decoder::new(),
        })
    }

    /// Makes `op` fail with `errno` until `heal`.
    pub fn fail(&self, op: Op, errno: i32) {
        self.shared.lock().failures.insert(op, Failure { errno, once: false });
    }

    /// Makes the next `op` fail with `errno`.
    pub fn fail_once(&self, op: Op, errno: i32) {
        self.shared.lock().failures.insert(op, Failure { errno, once: true });
    }

    pub fn heal(&self, op: Op) {
        self.shared.lock().failures.remove(&op);
    }
}

/// The guest of one domain. See the crate documentation.
pub struct Guest {
    shared: Shared,
    info: DomainInfo,
    ring: GuestRing,
    event: Arc<EventFd>,
    decoder: Decoder,
}

impl Guest {
    pub fn info(&self) -> DomainInfo {
        self.info
    }

    /// The raw ring, to misbehave on.
    pub fn ring(&mut self) -> &mut GuestRing {
        &mut self.ring
    }

    /// Signals the server, if it has bound this domain's channel.
    pub fn notify(&self) {
        let mut s = self.shared.lock();
        let port = s
            .domains
            .get(&self.info.domid)
            .filter(|d| Arc::ptr_eq(&d.event, &self.event))
            .and_then(|d| d.bound);
        if let Some(p) = port {
            s.fire(p);
        }
    }

    /// Waits at most `timeout` for a notification from the server, and
    /// consumes it (all of them, if several came).
    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        if !wait_readable(&*self.event, Some(timeout))? {
            return Ok(false);
        }
        self.event.take()?;
        Ok(true)
    }

    /// Queues as many request bytes as fit, and notifies if any did.
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.ring.write(bytes)?;
        if n > 0 {
            self.notify();
        }
        Ok(n)
    }

    /// Takes the reply bytes there are, and notifies if there were any.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.ring.read(buf)?;
        if n > 0 {
            self.notify();
        }
        Ok(n)
    }

    /// Sends all of `bytes`, waiting for the server to make room.
    /// TimedOut if it does not within `timeout`.
    pub fn send_all(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<()> {
        let deadline = deadline_in(timeout)?;
        let mut rest = bytes;
        loop {
            let n = self.send(rest)?;
            // `send` takes at most what it is given.
            rest = rest.get(n..).unwrap_or_default();
            if rest.is_empty() {
                return Ok(());
            }
            self.wait_until(deadline)?;
        }
    }

    /// Sends a header and `payload`, which may be longer than the
    /// protocol allows, to test the server.
    pub fn send_request(
        &mut self,
        ty: MsgType,
        req_id: u32,
        tx_id: u32,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(16 + payload.len());
        write_header(&mut bytes, ty as u32, req_id, tx_id, payload.len() as u32);
        bytes.extend_from_slice(payload);
        self.send_all(&bytes, timeout)
    }

    pub fn send_message(&mut self, msg: &Message, timeout: Duration) -> io::Result<()> {
        let mut bytes = Vec::new();
        msg.encode_into(&mut bytes);
        self.send_all(&bytes, timeout)
    }

    /// The next complete message from the server: a reply or a watch
    /// event. TimedOut if none within `timeout`; InvalidData if the ring
    /// or the message is corrupt.
    pub fn recv_message(&mut self, timeout: Duration) -> io::Result<Message> {
        let deadline = deadline_in(timeout)?;
        let mut buf = [0u8; RING_SIZE];
        loop {
            let next = self
                .decoder
                .next_message()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if let Some(m) = next {
                return Ok(m);
            }
            let n = self.recv(&mut buf)?;
            if n > 0 {
                // `recv` fills at most the buffer.
                self.decoder.push(buf.get(..n).unwrap_or_default());
            } else {
                self.wait_until(deadline)?;
            }
        }
    }

    /// Asks the server to reset the ring and waits until it has. Bytes
    /// of a partial message received before are dropped, as the server
    /// drops its own.
    pub fn reconnect(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = deadline_in(timeout)?;
        self.ring.request_reconnect();
        self.notify();
        while self.ring.get(Field::Connection) != CONNECTED {
            self.wait_until(deadline)?;
        }
        self.decoder = Decoder::new();
        Ok(())
    }

    fn wait_until(&self, deadline: Instant) -> io::Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || !self.wait(left)? {
            return Err(timed_out());
        }
        Ok(())
    }
}
