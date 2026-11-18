// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The simulation's contract: what the daemon's tests rely on.

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

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xs_sim::{Guest, Handle, Op, SimXen};
use xs_sys::backend::{DomainState, Pending, Port, XenBackend};
use xs_sys::ring::{Field, Ring, CONNECTED, FEATURE_RECONNECTION, RECONNECT, RING_SIZE};
use xs_sys::{Epoll, Interest};
use xs_wire::{Decoder, Message, MsgType, PAYLOAD_MAX};

/// A guard against hanging: what should happen at once fails after this.
const LONG: Duration = Duration::from_secs(30);
/// A wait that is to time out.
const SHORT: Duration = Duration::from_millis(20);

/// The epoll waits, by system call number.
#[cfg(target_arch = "x86_64")]
const EPOLL_WAITS: &[i64] = &[libc::SYS_epoll_wait, libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2];
#[cfg(not(target_arch = "x86_64"))]
const EPOLL_WAITS: &[i64] = &[libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2];

/// Waits until thread `task` (`/proc/self/task/TID`) sleeps in an epoll
/// wait (`/proc` shows the system call it is blocked in), within `LONG`.
fn wait_asleep_in_epoll(task: &std::path::Path) {
    let deadline = Instant::now() + LONG;
    loop {
        let syscall = std::fs::read_to_string(task.join("syscall")).unwrap();
        if syscall
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .is_some_and(|n: i64| EPOLL_WAITS.contains(&n))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not sleep in an epoll wait",
            task.display()
        );
        std::thread::yield_now();
    }
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EIO: i32 = 5;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOTCONN: i32 = 107;

fn pending(xen: &mut SimXen) -> Vec<Port> {
    let mut out = Vec::new();
    assert_eq!(xen.pending(&mut out).unwrap(), Pending::Complete);
    out
}

fn os_error<T>(r: io::Result<T>) -> i32 {
    r.err().expect("an error").raw_os_error().expect("an errno")
}

fn readable(xen: &SimXen) -> bool {
    xs_sys::fd::wait_readable(&xen.event_fd(), Some(Duration::ZERO)).unwrap()
}

#[test]
fn types_cross_threads() {
    fn send<T: Send>() {}
    fn shared<T: Send + Sync + Clone>() {}
    send::<SimXen>();
    send::<Guest>();
    shared::<Handle>();
}

#[test]
fn dom0_is_there_from_the_start() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    assert_eq!(hv.domains(), [0]);
    let info = hv.domain(0).unwrap();
    assert_eq!(xen.domain_state(0).unwrap(), DomainState::Running);
    let r = xen.dom0_ring().unwrap();
    let (page, port) = (r.page, r.port);
    assert!(matches!(r.source, xs_sys::backend::Dom0Source::Simulated));
    assert_eq!(port, info.port);
    let mut ring = Ring::new(page).unwrap();
    let mut guest = hv.guest(0).unwrap();
    assert_eq!(guest.info(), info);
    assert_eq!(guest.send(b"dom0").unwrap(), 4);
    let mut buf = [0u8; 8];
    assert_eq!(ring.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"dom0");
    // An ordinary domain otherwise.
    assert!(xen.map_ring(0, info.gfn).is_ok());
    assert!(!hv.is_bound(0));
    xen.bind_interdomain(0, port).unwrap();
    assert!(hv.is_bound(0));
    assert_eq!(os_error(hv.destroy_domain(0)), EPERM);
}

#[test]
fn domains_get_their_own_page_gfn_and_port() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let a = hv.create_domain(1).unwrap();
    let b = hv.create_domain(7).unwrap();
    assert_eq!(os_error(hv.create_domain(7)), EEXIST);
    assert_eq!(hv.domains(), [0, 1, 7]);
    assert_eq!(hv.domain(7), Some(b));
    assert_eq!(hv.domain(8), None);
    assert_eq!((a.domid, b.domid), (1, 7));
    assert_ne!(a.gfn, b.gfn);
    assert_ne!(a.port, b.port);
    let mut ra = Ring::new(xen.map_ring(1, a.gfn).unwrap()).unwrap();
    let mut rb = Ring::new(xen.map_ring(7, b.gfn).unwrap()).unwrap();
    hv.guest(1).unwrap().send(b"from a").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(rb.read(&mut buf).unwrap(), 0);
    assert_eq!(ra.read(&mut buf).unwrap(), 6);
    // A fresh page: indices at 0, no feature, connected, no error.
    let mut g = hv.guest(7).unwrap();
    assert!(Field::ALL.iter().all(|&f| g.ring().get(f) == 0));
    assert_eq!(os_error(hv.guest(8)), ESRCH);
}

#[test]
fn map_ring_fails_as_a_foreign_mapping_would() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(3).unwrap();
    assert_eq!(os_error(xen.map_ring(4, d.gfn)), ESRCH);
    assert_eq!(os_error(xen.map_ring(3, d.gfn + 1)), EINVAL);
    let mut kept = Ring::new(xen.map_ring(3, d.gfn).unwrap()).unwrap();
    hv.set_state(3, DomainState::Shutdown).unwrap();
    assert!(
        xen.map_ring(3, d.gfn).is_ok(),
        "a shut down domain still has its memory"
    );
    hv.set_state(3, DomainState::Dead).unwrap();
    assert_eq!(os_error(xen.map_ring(3, d.gfn)), ESRCH);
    let mut guest = hv.guest(3).unwrap();
    hv.destroy_domain(3).unwrap();
    assert_eq!(os_error(xen.map_ring(3, d.gfn)), ESRCH);
    // Mappings made before outlive the domain.
    guest.ring().write(b"late").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(kept.read(&mut buf).unwrap(), 4);
}

#[test]
fn domain_states_and_dom_exc() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    hv.create_domain(2).unwrap();
    // Nothing fires before VIRQ_DOM_EXC is bound.
    hv.set_state(2, DomainState::Shutdown).unwrap();
    hv.fire_dom_exc();
    let virq = xen.bind_dom_exc().unwrap();
    assert_eq!(os_error(xen.bind_dom_exc()), EEXIST);
    assert!(pending(&mut xen).is_empty());
    assert_eq!(xen.domain_state(2).unwrap(), DomainState::Shutdown);

    hv.set_state(2, DomainState::Running).unwrap();
    assert!(pending(&mut xen).is_empty(), "a domain resuming is not an exception");
    assert_eq!(xen.domain_state(2).unwrap(), DomainState::Running);

    hv.set_state(2, DomainState::Shutdown).unwrap();
    assert_eq!(pending(&mut xen), [virq]);
    xen.unmask(virq).unwrap();
    hv.set_state(2, DomainState::Dead).unwrap();
    assert_eq!(xen.domain_state(2).unwrap(), DomainState::Dead);
    assert_eq!(pending(&mut xen), [virq]);
    xen.unmask(virq).unwrap();
    hv.destroy_domain(2).unwrap();
    assert_eq!(
        xen.domain_state(2).unwrap(),
        DomainState::Dead,
        "no such domain reads as dead"
    );
    assert_eq!(pending(&mut xen), [virq]);
    xen.unmask(virq).unwrap();
    hv.fire_dom_exc();
    assert_eq!(pending(&mut xen), [virq]);

    assert_eq!(os_error(hv.set_state(2, DomainState::Running)), ESRCH);
    assert_eq!(os_error(hv.destroy_domain(2)), ESRCH);
    assert_eq!(xen.domain_state(99).unwrap(), DomainState::Dead);

    // Notifying the VIRQ does nothing; once unbound it can be bound again.
    xen.notify(virq).unwrap();
    xen.unbind(virq).unwrap();
    hv.fire_dom_exc();
    assert!(pending(&mut xen).is_empty());
    assert_eq!(xen.bind_dom_exc().unwrap(), virq, "the lowest free port");
}

#[test]
fn the_event_descriptor_is_pollable() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let ep = Epoll::new().unwrap();
    ep.add(xen.event_fd(), 1, Interest::READ).unwrap();
    let mut ev = Vec::new();
    ep.wait(&mut ev, 4, 0).unwrap();
    assert!(ev.is_empty());
    let virq = xen.bind_dom_exc().unwrap();
    // Fired from another thread, as the tests will.
    std::thread::spawn(move || hv.fire_dom_exc()).join().unwrap();
    ep.wait(&mut ev, 4, 1000).unwrap();
    assert_eq!(ev.len(), 1);
    assert!(readable(&xen), "level-triggered: readable until drained");
    assert_eq!(pending(&mut xen), [virq]);
    assert!(!readable(&xen));
    assert!(pending(&mut xen).is_empty(), "nothing pending is not an error");
}

#[test]
fn a_port_that_fired_stays_masked_until_unmasked() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let guest = hv.guest(1).unwrap();
    let port = xen.bind_interdomain(1, d.port).unwrap();
    // Xen leaves a new interdomain port pending.
    assert_eq!(pending(&mut xen), [port]);
    guest.notify();
    guest.notify();
    assert!(pending(&mut xen).is_empty(), "masked");
    assert!(!readable(&xen));
    xen.unmask(port).unwrap();
    assert_eq!(pending(&mut xen), [port], "what came while masked, once");
    xen.unmask(port).unwrap();
    assert!(pending(&mut xen).is_empty());
    xen.unmask(port).unwrap();
    guest.notify();
    assert_eq!(pending(&mut xen), [port]);
    // Unmasking a port that is not bound is ignored, as the device does.
    xen.unmask(9999).unwrap();
}

#[test]
fn ports_fire_independently() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let virq = xen.bind_dom_exc().unwrap();
    let mut ports = Vec::new();
    let mut guests = Vec::new();
    for domid in 1..=3 {
        let d = hv.create_domain(domid).unwrap();
        ports.push(xen.bind_interdomain(domid, d.port).unwrap());
        guests.push(hv.guest(domid).unwrap());
    }
    assert_eq!(
        [virq, ports[0], ports[1], ports[2]],
        [1, 2, 3, 4],
        "lowest first, from 1"
    );
    assert_eq!(pending(&mut xen), ports);
    for &p in &ports {
        xen.unmask(p).unwrap();
    }
    guests[2].notify();
    hv.fire_dom_exc();
    guests[0].notify();
    assert_eq!(pending(&mut xen), [ports[2], virq, ports[0]]);
    // A freed port is reused.
    xen.unbind(ports[1]).unwrap();
    assert!(!hv.is_bound(2));
    let again = xen.bind_interdomain(2, hv.domain(2).unwrap().port).unwrap();
    assert_eq!(again, ports[1]);
}

#[test]
fn an_overflow_drops_what_fired_and_leaves_it_masked() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let virq = xen.bind_dom_exc().unwrap();
    let mut guests = Vec::new();
    let mut ports = Vec::new();
    for domid in 1..=3 {
        let d = hv.create_domain(domid).unwrap();
        ports.push(xen.bind_interdomain(domid, d.port).unwrap());
        guests.push(hv.guest(domid).unwrap());
    }
    assert_eq!(pending(&mut xen), ports);
    xen.unmask(ports[0]).unwrap();
    xen.unmask(ports[1]).unwrap();
    // Fired before: dropped. Fired during: dropped, masked. Masked
    // already (ports[2]): pending in Xen, as ever.
    guests[0].notify();
    hv.overflow(|| {
        assert!(!readable(&xen), "the server is not woken meanwhile");
        guests[1].notify();
        guests[2].notify();
        hv.fire_dom_exc();
    });
    assert!(readable(&xen));
    let mut out = vec![7];
    assert_eq!(xen.pending(&mut out).unwrap(), Pending::Lost);
    assert_eq!(out, [7], "no port");
    assert!(!readable(&xen), "reset");
    // What the overflow dropped is gone; what comes now, masked, waits.
    guests[0].notify();
    assert!(pending(&mut xen).is_empty(), "all still masked");
    for &p in &ports {
        xen.unmask(p).unwrap();
    }
    xen.unmask(virq).unwrap();
    assert_eq!(
        pending(&mut xen),
        [ports[0], ports[2]],
        "only what Xen kept pending fires again"
    );
    for &p in &ports {
        xen.unmask(p).unwrap();
    }
    guests[1].notify();
    assert_eq!(pending(&mut xen), [ports[1]], "back to normal");
    // A `pending` during the overflow ends it: nothing more to tell.
    hv.overflow(|| assert_eq!(xen.pending(&mut Vec::new()).unwrap(), Pending::Lost));
    assert!(!readable(&xen));
    assert!(pending(&mut xen).is_empty());
}

#[test]
fn bind_interdomain_checks_the_remote_end() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(4).unwrap();
    assert_eq!(os_error(xen.bind_interdomain(5, d.port)), ESRCH);
    assert_eq!(os_error(xen.bind_interdomain(4, d.port + 100)), EINVAL);
    let port = xen.bind_interdomain(4, d.port).unwrap();
    assert_eq!(os_error(xen.bind_interdomain(4, d.port)), EINVAL, "bound already");
    xen.unbind(port).unwrap();
    assert_eq!(os_error(xen.unbind(port)), ENOTCONN);
    let port = xen.bind_interdomain(4, d.port).unwrap();
    hv.set_state(4, DomainState::Dead).unwrap();
    xen.unbind(port).unwrap();
    assert_eq!(os_error(xen.bind_interdomain(4, d.port)), ESRCH);
}

#[test]
fn notifications_reach_the_guest() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let guest = hv.guest(1).unwrap();
    assert_eq!(os_error(xen.notify(1)), ENOTCONN);
    let port = xen.bind_interdomain(1, d.port).unwrap();
    assert!(!guest.wait(Duration::ZERO).unwrap());
    xen.notify(port).unwrap();
    xen.notify(port).unwrap();
    assert!(guest.wait(LONG).unwrap());
    assert!(!guest.wait(Duration::ZERO).unwrap(), "both consumed");
    let start = Instant::now();
    assert!(!guest.wait(SHORT).unwrap());
    assert!(start.elapsed() >= SHORT);
    // Across threads: the notification wakes a guest that sleeps.
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        tx.send(std::fs::read_link("/proc/thread-self").unwrap()).unwrap();
        guest.wait(LONG).unwrap()
    });
    wait_asleep_in_epoll(&std::path::Path::new("/proc").join(rx.recv().unwrap()));
    xen.notify(port).unwrap();
    assert!(waiter.join().unwrap());
}

#[test]
fn a_guest_notification_before_the_bind_is_lost() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let guest = hv.guest(1).unwrap();
    guest.notify();
    assert!(pending(&mut xen).is_empty());
    let port = xen.bind_interdomain(1, d.port).unwrap();
    assert_eq!(
        pending(&mut xen),
        [port],
        "the pending bit of the bind, not the notification"
    );
    xen.unmask(port).unwrap();
    xen.unbind(port).unwrap();
    guest.notify();
    assert!(pending(&mut xen).is_empty());
}

#[test]
fn a_destroyed_domain_goes_quiet() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(6).unwrap();
    let old_guest = hv.guest(6).unwrap();
    let old = xen.bind_interdomain(6, d.port).unwrap();
    assert_eq!(pending(&mut xen), [old]);
    xen.unmask(old).unwrap();
    hv.destroy_domain(6).unwrap();
    assert!(!hv.is_bound(6));
    // The server's end is still its port: notify works, and goes nowhere.
    xen.notify(old).unwrap();
    assert!(!old_guest.wait(Duration::ZERO).unwrap());
    old_guest.notify();
    assert!(pending(&mut xen).is_empty());

    // A new domain with the same id is a new incarnation: the old port
    // and the old guest do not reach it.
    let d = hv.create_domain(6).unwrap();
    let new_guest = hv.guest(6).unwrap();
    let new = xen.bind_interdomain(6, d.port).unwrap();
    assert_ne!(new, old);
    assert_eq!(pending(&mut xen), [new]);
    xen.unmask(new).unwrap();
    xen.notify(old).unwrap();
    assert!(!new_guest.wait(Duration::ZERO).unwrap());
    old_guest.notify();
    assert!(pending(&mut xen).is_empty());
    new_guest.notify();
    assert_eq!(pending(&mut xen), [new]);
    // Unbinding the old port leaves the new binding alone.
    xen.unbind(old).unwrap();
    assert!(hv.is_bound(6));
    xen.notify(new).unwrap();
    assert!(new_guest.wait(LONG).unwrap());
}

#[test]
fn a_port_unbound_after_firing_may_still_be_pending() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let port = xen.bind_interdomain(1, d.port).unwrap();
    xen.unbind(port).unwrap();
    assert_eq!(pending(&mut xen), [port]);
}

#[test]
fn operations_fail_on_demand() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let all = [
        Op::Pending,
        Op::Unmask,
        Op::BindDomExc,
        Op::BindInterdomain,
        Op::Unbind,
        Op::Notify,
        Op::Dom0Ring,
        Op::MapRing,
        Op::DomainState,
    ];
    fn run(xen: &mut SimXen, op: Op, d: &xs_sim::DomainInfo) -> io::Result<()> {
        match op {
            Op::Pending => xen.pending(&mut Vec::new()).map(drop),
            Op::Unmask => xen.unmask(1),
            Op::BindDomExc => xen.bind_dom_exc().map(drop),
            Op::BindInterdomain => xen.bind_interdomain(d.domid, d.port).map(drop),
            Op::Unbind => xen.unbind(1),
            Op::Notify => xen.notify(1),
            Op::Dom0Ring => xen.dom0_ring().map(drop),
            Op::MapRing => xen.map_ring(d.domid, d.gfn).map(drop),
            Op::DomainState => xen.domain_state(d.domid).map(drop),
        }
    }
    for op in all {
        hv.fail(op, EIO);
        assert_eq!(os_error(run(&mut xen, op, &d)), EIO, "{op:?}");
        assert_eq!(os_error(run(&mut xen, op, &d)), EIO, "{op:?}, until healed");
        hv.heal(op);
        hv.fail_once(op, ENOENT);
        assert_eq!(os_error(run(&mut xen, op, &d)), ENOENT, "{op:?}");
    }
    // Healed or spent: each works again, in an order where each can.
    for op in [
        Op::BindDomExc,
        Op::Pending,
        Op::Unmask,
        Op::Notify,
        Op::Unbind,
        Op::BindInterdomain,
        Op::Dom0Ring,
        Op::MapRing,
    ] {
        run(&mut xen, op, &d).unwrap_or_else(|e| panic!("{op:?}: {e}"));
    }
    assert_eq!(xen.domain_state(1).unwrap(), DomainState::Running);
    // A failed bind binds nothing.
    hv.fail_once(Op::BindDomExc, EIO);
    assert!(xen.bind_dom_exc().is_err());
    assert_eq!(xen.bind_dom_exc().unwrap(), 2);
    hv.heal(Op::Pending);
}

/// A minimal server on its own thread, as the daemon will be: polls the
/// event descriptor, reconnects on request, and answers each message with
/// one of the same type and id whose payload is reversed.
struct Echo {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<SimXen>,
}

impl Echo {
    fn start(mut xen: SimXen, domid: u32) -> Echo {
        let d = xen.handle().domain(domid).unwrap();
        let mut ring = Ring::new(xen.map_ring(domid, d.gfn).unwrap()).unwrap();
        ring.set_server_features(FEATURE_RECONNECTION);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let port = xen.bind_interdomain(domid, d.port).unwrap();
            let mut decoder = Decoder::new();
            let mut out: Vec<u8> = Vec::new();
            let mut buf = [0u8; RING_SIZE];
            let mut ports = Vec::new();
            while !flag.load(Ordering::SeqCst) {
                xs_sys::fd::wait_readable(&xen.event_fd(), Some(Duration::from_millis(5))).unwrap();
                ports.clear();
                xen.pending(&mut ports).unwrap();
                for &p in &ports {
                    xen.unmask(p).unwrap();
                }
                if ring.connection() == RECONNECT {
                    decoder = Decoder::new();
                    out.clear();
                    ring.reconnect();
                    xen.notify(port).unwrap();
                    continue;
                }
                let mut moved = false;
                loop {
                    let n = ring.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    moved = true;
                    decoder.push(&buf[..n]);
                }
                while let Some(m) = decoder.next_message().unwrap() {
                    let mut payload = m.payload.clone();
                    payload.reverse();
                    Message { payload, ..m }.encode_into(&mut out);
                }
                let n = ring.write(&out).unwrap();
                out.drain(..n);
                if moved || n > 0 {
                    xen.notify(port).unwrap();
                }
            }
            xen
        });
        Echo { stop, thread }
    }

    fn stop(self) -> SimXen {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.join().unwrap()
    }
}

#[test]
fn a_client_talks_to_a_server_thread() {
    let xen = SimXen::new().unwrap();
    let hv = xen.handle();
    hv.create_domain(9).unwrap();
    let mut guest = hv.guest(9).unwrap();
    let echo = Echo::start(xen, 9);
    // Each message is bigger than the ring: both sides must wait for room.
    for i in 0..20u32 {
        let payload: Vec<u8> = (0..PAYLOAD_MAX as u32).map(|b| (b * 7 + i) as u8).collect();
        guest.send_request(MsgType::Write, i, 3, &payload, LONG).unwrap();
        let reply = guest.recv_message(LONG).unwrap();
        assert_eq!(
            (reply.msg_type(), reply.req_id, reply.tx_id),
            (Some(MsgType::Write), i, 3)
        );
        assert!(reply.payload.iter().rev().eq(payload.iter()));
    }
    // Several messages in flight; replies come back in order.
    for i in 0..5 {
        guest
            .send_message(
                &Message::new(MsgType::Read, 100 + i, 0, b"abc\0".to_vec()).unwrap(),
                LONG,
            )
            .unwrap();
    }
    for i in 0..5 {
        let m = guest.recv_message(LONG).unwrap();
        assert_eq!((m.req_id, &m.payload[..]), (100 + i, &b"\0cba"[..]));
    }
    // A reconnection empties the ring and the partial message is dropped.
    guest.send(&[1, 2, 3]).unwrap();
    guest.reconnect(LONG).unwrap();
    assert_eq!(guest.ring().get(Field::Connection), CONNECTED);
    guest.send_request(MsgType::Directory, 1, 0, b"/\0", LONG).unwrap();
    assert_eq!(guest.recv_message(LONG).unwrap().payload, b"\0/");
    echo.stop();
}

#[test]
fn client_timeouts_and_corruption() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let mut guest = hv.guest(1).unwrap();
    let _port = xen.bind_interdomain(1, d.port).unwrap();
    let timed_out = |r: io::Result<()>| assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);

    // Nobody answers.
    assert_eq!(guest.recv_message(SHORT).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        guest.recv_message(Duration::ZERO).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    // Nobody reads: the ring fills up.
    timed_out(guest.send_all(&[0; RING_SIZE + 1], SHORT));
    timed_out(guest.reconnect(SHORT));
    assert_eq!(guest.ring().get(Field::Connection), RECONNECT);
    guest.send_all(&[], Duration::ZERO).unwrap();

    // A corrupt reply ring.
    let mut ring = Ring::new(xen.map_ring(1, d.gfn).unwrap()).unwrap();
    guest.ring().set(Field::RspProd, 5000);
    assert_eq!(guest.recv_message(LONG).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(guest.recv(&mut [0; 4]).unwrap_err().kind(), io::ErrorKind::InvalidData);
    // A corrupt request ring.
    guest.ring().set(Field::ReqCons, 5000);
    assert_eq!(guest.send(b"x").unwrap_err().kind(), io::ErrorKind::InvalidData);

    // A reply announcing too long a payload.
    for f in [Field::ReqCons, Field::ReqProd, Field::RspCons, Field::RspProd] {
        guest.ring().set(f, 0);
    }
    let mut header = Vec::new();
    xs_wire::write_header(&mut header, MsgType::Read as u32, 1, 0, PAYLOAD_MAX as u32 + 1);
    ring.write(&header).unwrap();
    assert_eq!(guest.recv_message(LONG).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn send_request_does_not_police_the_payload() {
    let mut xen = SimXen::new().unwrap();
    let hv = xen.handle();
    let d = hv.create_domain(1).unwrap();
    let mut guest = hv.guest(1).unwrap();
    let mut ring = Ring::new(xen.map_ring(1, d.gfn).unwrap()).unwrap();
    let port = xen.bind_interdomain(1, d.port).unwrap();
    guest.send_request(MsgType::Write, 1, 0, &[b'x'; 1000], LONG).unwrap();
    let mut buf = [0u8; RING_SIZE];
    assert_eq!(ring.read(&mut buf).unwrap(), 1016);
    assert_eq!(&buf[12..16], &1000u32.to_le_bytes());
    // Longer than the protocol allows: sent as is, for the server to refuse.
    let long = vec![b'y'; PAYLOAD_MAX + 1];
    let sender = std::thread::spawn(move || {
        guest.send_request(MsgType::Write, 2, 0, &long, LONG).unwrap();
    });
    let mut got = Vec::new();
    let start = Instant::now();
    while got.len() < 16 + PAYLOAD_MAX + 1 {
        assert!(start.elapsed() < LONG, "{} bytes", got.len());
        let n = ring.read(&mut buf).unwrap();
        got.extend_from_slice(&buf[..n]);
        // Notified, the guest goes on writing.
        xen.notify(port).unwrap();
        std::thread::yield_now();
    }
    sender.join().unwrap();
    assert_eq!(&got[12..16], &(PAYLOAD_MAX as u32 + 1).to_le_bytes());
    assert_eq!(got.len(), 16 + PAYLOAD_MAX + 1);
}
