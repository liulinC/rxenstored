// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What one ring costs the event loop per notification of its port, in
//! wake-ups (the loop's thread going back to sleep in epoll_wait), CPU and
//! notifications sent back to the guest, for the ways a guest can keep
//! notifying with little or no traffic. Run with `--nocapture` to see the
//! figures; the assertions bound them loosely (a loop that spun without
//! sleeping, or that answered a notification with one, would fail them).
//!
//! The guest here plays Linux's xenbus (drivers/xen/xenbus/xenbus_comms.c):
//! it notifies after writing a request into an empty ring, and does not
//! notify after reading replies unless the reply ring was full.

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
    clippy::unchecked_time_subtraction,
    dead_code
)]

#[path = "common/mod.rs"]
mod common;
#[path = "rings/harness.rs"]
mod harness;

use common::Client;
use harness::{request, Daemon, T};
use std::time::{Duration, Instant};
use xs_sim::Guest;
use xs_sys::ring::{Field, RING_SIZE};
use xs_wire::{nul_terminated, Decoder, Message, MsgType};

fn sync(c: &mut Client) {
    c.ok(MsgType::GetDomainPath, 0, b"0\0");
}

fn settle(c: &mut Client) {
    sync(c);
    sync(c);
}

/// Waits until the loop has gone to sleep more than `after` times and is
/// asleep in epoll_wait.
fn asleep_past(d: &Daemon, after: u64) {
    let deadline = Instant::now() + T;
    while d.sleeps() <= after {
        assert!(Instant::now() < deadline, "the loop did not wake up");
        std::thread::yield_now();
    }
    d.sleeping();
}

/// Notifications from the daemon not consumed yet (consumes them).
fn drain(g: &Guest) -> bool {
    g.wait(Duration::ZERO).unwrap()
}

#[derive(Debug)]
struct Cost {
    what: &'static str,
    pokes: u64,
    wakes: u64,
    cpu_ns: u64,
    /// Pokes after which the guest had a notification from the daemon.
    back: u64,
    elapsed: Duration,
}

impl Cost {
    fn print(&self) {
        let n = self.pokes as f64;
        eprintln!(
            "{:<58} pokes {:>6}  wakes/poke {:>5.2}  notified-back/poke {:>5.2}  cpu/poke {:>6.1} us  ({:.0} pokes/s in the sim)",
            self.what,
            self.pokes,
            self.wakes as f64 / n,
            self.back as f64 / n,
            self.cpu_ns as f64 / 1000.0 / n,
            n / self.elapsed.as_secs_f64()
        );
    }
}

/// `n` times: `poke`, then wait for the loop to have handled it and gone
/// back to sleep, and see whether the guest was notified.
fn paced(d: &Daemon, g: &mut Guest, what: &'static str, n: u64, mut poke: impl FnMut(&mut Guest)) -> Cost {
    d.sleeping();
    drain(g);
    let (s0, c0, t0) = (d.sleeps(), d.cpu_ns(), Instant::now());
    let mut back = 0;
    for _ in 0..n {
        let before = d.sleeps();
        poke(g);
        asleep_past(d, before);
        back += u64::from(drain(g));
    }
    let cost = Cost {
        what,
        pokes: n,
        wakes: d.sleeps() - s0,
        cpu_ns: d.cpu_ns() - c0,
        back,
        elapsed: t0.elapsed(),
    };
    cost.print();
    cost
}

/// A request as Linux writes one: into the ring, then a notification
/// (the ring was empty: the daemon had consumed everything before).
fn linux_send(g: &mut Guest, bytes: &[u8]) {
    assert_eq!(g.ring().write(bytes).unwrap(), bytes.len());
    g.notify();
}

/// The next message, read as Linux reads: no notification after a read
/// (the reply ring was never full here).
fn linux_recv(g: &mut Guest, dec: &mut Decoder) -> Message {
    linux_recv_counted(g, dec, &mut 0)
}

/// As `linux_recv`; `notified` counts the notifications waited for.
fn linux_recv_counted(g: &mut Guest, dec: &mut Decoder, notified: &mut u64) -> Message {
    let mut buf = [0u8; RING_SIZE];
    loop {
        if let Some(m) = dec.next_message().unwrap() {
            return m;
        }
        let n = g.ring().read(&mut buf).unwrap();
        if n > 0 {
            dec.push(&buf[..n]);
            continue;
        }
        assert!(g.wait(T).unwrap(), "no reply");
        *notified += 1;
    }
}

fn start() -> (Daemon, Client) {
    // No safety scan: its ticks would be wake-ups of their own.
    let d = Daemon::start_with(|o, _| o.ring_scan = None);
    let c = d.client();
    (d, c)
}

/// The loop does not spin on its own: asleep with no timer.
fn quiet(d: &Daemon, c: &mut Client) {
    settle(c);
    assert_eq!(d.sleeping(), -1, "asleep with no timer");
    let (s, t) = (d.sleeps(), d.cpu_ns());
    // sleep-ok: measures that nothing happens.
    std::thread::sleep(Duration::from_millis(300));
    assert!(d.sleeps() - s <= 2, "woke {} times on its own", d.sleeps() - s);
    assert!(d.cpu_ns() - t <= 20_000_000, "{} ns of CPU", d.cpu_ns() - t);
}

#[test]
fn notifications_with_an_unchanged_ring_cost_one_wake_up_each_and_none_is_answered() {
    let (d, mut c) = start();
    let mut g = d.vm(&mut c, 3).g;
    settle(&mut c);
    quiet(&d, &mut c);
    let cost = paced(&d, &mut g, "empty ring, notified, paced", 3000, |g| g.notify());
    assert_eq!(cost.back, 0, "a notification with nothing moved is not answered");
    assert!(cost.wakes >= cost.pokes, "one wake-up per notification");
    assert!(cost.wakes <= cost.pokes * 2, "{cost:?}");
    // As fast as the guest can: notifications that come while the port is
    // masked coalesce into one firing.
    d.sleeping();
    let (s0, c0, t0) = (d.sleeps(), d.cpu_ns(), Instant::now());
    let n = 200_000u64;
    for _ in 0..n {
        g.notify();
    }
    settle(&mut c);
    let (wakes, ns, el) = (d.sleeps() - s0, d.cpu_ns() - c0, t0.elapsed());
    eprintln!(
        "{:<58} pokes {n:>6}  wakes/poke {:>5.2}  wakes {wakes} in {el:?}  cpu {:.0} ms",
        "empty ring, notified back-to-back",
        wakes as f64 / n as f64,
        ns as f64 / 1e6
    );
    assert!(!drain(&g), "nothing moved, nothing notified");
    quiet(&d, &mut c);
}

#[test]
fn a_partial_request_is_read_once_and_later_notifications_are_not_answered() {
    let (d, mut c) = start();
    let mut g = d.vm(&mut c, 3).g;
    settle(&mut c);
    // A header announcing 100 bytes, and 30 of them.
    let full = request(
        MsgType::Write,
        9,
        &[b"/local/domain/3/p\0".as_slice(), &[b'x'; 82]].concat(),
    );
    assert_eq!(full.len(), 16 + 100);
    linux_send(&mut g, &full[..46]);
    settle(&mut c);
    assert_eq!(
        g.ring().get(Field::ReqCons),
        g.ring().get(Field::ReqProd),
        "read at once"
    );
    assert!(drain(&g), "the read moved bytes: notified once");
    let cost = paced(&d, &mut g, "partial request buffered, notified, paced", 3000, |g| {
        g.notify()
    });
    assert_eq!(cost.back, 0);
    assert!(cost.wakes <= cost.pokes * 2, "{cost:?}");
    // The rest completes it.
    linux_send(&mut g, &full[46..]);
    let mut dec = Decoder::new();
    let m = linux_recv(&mut g, &mut dec);
    assert_eq!((m.msg_type(), m.req_id), (Some(MsgType::Write), 9));
    quiet(&d, &mut c);
}

#[test]
fn a_full_reply_ring_with_a_backlog_of_watch_events_and_a_notifying_guest() {
    let (d, mut c) = start();
    let mut gg = d.vm(&mut c, 3);
    gg.watch("/local/domain/3/w", "t");
    let mut g = gg.g;
    // The guest stops reading; 200 events, 25 or so fill its reply ring.
    for i in 0..200 {
        c.write(0, &format!("/local/domain/3/w/k{i}"), "v");
    }
    settle(&mut c);
    let used = g.ring().get(Field::RspProd).wrapping_sub(g.ring().get(Field::RspCons));
    assert_eq!(used as usize, RING_SIZE, "reply ring full");
    let cost = paced(
        &d,
        &mut g,
        "reply ring full, events queued, notified, paced",
        3000,
        |g| g.notify(),
    );
    assert_eq!(cost.back, 0, "nothing could be written: no notification");
    assert!(cost.wakes <= cost.pokes * 2, "{cost:?}");
    // A guest that consumes a few bytes at a time and notifies each time
    // (Linux notifies after a read of a full ring) gets them, and each
    // read costs a round: the backlog is finite and drains.
    let mut buf = [0u8; 16];
    let mut rounds = 0u64;
    d.sleeping();
    let (s0, c0) = (d.sleeps(), d.cpu_ns());
    loop {
        let before = d.sleeps();
        let n = g.ring().read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        g.notify();
        rounds += 1;
        asleep_past(&d, before);
        drain(&g);
    }
    eprintln!(
        "{:<58} rounds {rounds:>6}  wakes/round {:>5.2}  cpu/round {:>6.1} us",
        "backlog drained 16 bytes per guest read",
        (d.sleeps() - s0) as f64 / rounds as f64,
        (d.cpu_ns() - c0) as f64 / 1000.0 / rounds as f64
    );
    quiet(&d, &mut c);
}

#[test]
fn a_guest_blocked_by_its_unread_replies_and_notifying() {
    let (d, mut c) = start();
    let mut g = d.vm(&mut c, 3).g;
    settle(&mut c);
    // Requests whose replies the guest never reads: past quota-maxoutstanding
    // (1024) the daemon stops reading, and requests stay in the ring.
    let one = request(MsgType::GetDomainPath, 1, b"3\0");
    let mut sent = 0;
    let mut stalled = 0;
    while stalled < 50 {
        let used = g.ring().get(Field::ReqProd).wrapping_sub(g.ring().get(Field::ReqCons)) as usize;
        if RING_SIZE - used >= one.len() {
            assert_eq!(g.ring().write(&one).unwrap(), one.len());
            g.notify();
            sent += 1;
            stalled = 0;
        } else {
            g.wait(Duration::from_millis(2)).unwrap();
            stalled += 1;
        }
    }
    settle(&mut c);
    let waiting = g.ring().get(Field::ReqProd).wrapping_sub(g.ring().get(Field::ReqCons));
    eprintln!("blocked guest: {sent} requests sent, {waiting} bytes left unread in its request ring");
    assert!(waiting > 0 && sent > 1024, "{sent} {waiting}");
    let cost = paced(
        &d,
        &mut g,
        "blocked (1024 replies unread), notified, paced",
        3000,
        |g| g.notify(),
    );
    assert_eq!(cost.back, 0);
    assert!(cost.wakes <= cost.pokes * 2, "{cost:?}");
    quiet(&d, &mut c);
}

#[test]
fn a_guest_polling_with_reads_costs_one_wake_up_and_one_notification_per_read() {
    let (d, mut c) = start();
    let mut g = d.vm(&mut c, 3).g;
    c.write(0, "/local/domain/3/x", "value");
    settle(&mut c);
    let mut dec = Decoder::new();
    let mut id = 0;
    for (what, path) in [
        ("READ of an existing node, synchronous, paced", "/local/domain/3/x"),
        (
            "READ of a missing node (ENOENT), synchronous, paced",
            "/local/domain/3/none",
        ),
    ] {
        let mut waited = 0;
        let cost = paced(&d, &mut g, what, 3000, |g| {
            id += 1;
            linux_send(g, &request(MsgType::Read, id, &nul_terminated(&[path.as_bytes()])));
            let m = linux_recv_counted(g, &mut dec, &mut waited);
            assert_eq!(m.req_id, id);
        });
        eprintln!(
            "    daemon notifications seen by the guest per read: {:.2}",
            (waited + cost.back) as f64 / cost.pokes as f64
        );
        // The reply's notification was consumed by `linux_recv` or is
        // still there: either way exactly one per request was sent.
        assert!(cost.wakes >= cost.pokes && cost.wakes <= cost.pokes * 2, "{cost:?}");
    }
    // Unpaced: the rate and CPU of a guest that reads back to back.
    d.sleeping();
    let (s0, c0, t0) = (d.sleeps(), d.cpu_ns(), Instant::now());
    let n = 20_000u64;
    for _ in 0..n {
        id += 1;
        linux_send(&mut g, &request(MsgType::Read, id, b"/local/domain/3/x\0"));
        let m = linux_recv(&mut g, &mut dec);
        assert_eq!(m.req_id, id);
    }
    let (wakes, ns, el) = (d.sleeps() - s0, d.cpu_ns() - c0, t0.elapsed());
    eprintln!(
        "{:<58} reads {n:>6}  wakes/read {:>5.2}  cpu/read {:>6.1} us  ({:.0} reads/s in the sim)",
        "READ back to back",
        wakes as f64 / n as f64,
        ns as f64 / 1000.0 / n as f64,
        n as f64 / el.as_secs_f64()
    );
    quiet(&d, &mut c);
}
