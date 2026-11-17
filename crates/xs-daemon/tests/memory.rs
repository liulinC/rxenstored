// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Memory per simulated VM: the shipped scenario's VM start replayed in
//! process against the core (no sockets), with an allocator that counts
//! live bytes. Prints a breakdown with `--nocapture`.

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

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicIsize, Ordering};
use xs_bench::scenario::Scenario;
use xs_bench::trace::{instantiate, ConnId as TraceConn, Op};
use xs_core::{Config, ConnId, Core};
use xs_wire::{nul_terminated, Message, MsgType};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
/// Bytes as glibc would hand them out: 8 bytes of header, 16-byte rounding, 32 minimum.
static CHUNKS: AtomicIsize = AtomicIsize::new(0);

fn chunk(size: usize) -> isize {
    ((size + 8).div_ceil(16) * 16).max(32) as isize
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        CHUNKS.fetch_add(chunk(l.size()), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        CHUNKS.fetch_sub(chunk(l.size()), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new as isize - l.size() as isize, Ordering::Relaxed);
        CHUNKS.fetch_add(chunk(new) - chunk(l.size()), Ordering::Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> (isize, isize) {
    (LIVE.load(Ordering::Relaxed), CHUNKS.load(Ordering::Relaxed))
}

struct Replay {
    core: Core,
    shared: HashMap<TraceConn, ConnId>,
    dirty: Vec<ConnId>,
    req: u32,
    with_watches: bool,
}

impl Replay {
    fn call(&mut self, c: ConnId, ty: MsgType, tx: u32, payload: Vec<u8>) -> Vec<u8> {
        self.req += 1;
        let mut b = Vec::new();
        Message::new(ty, self.req, tx, payload).unwrap().encode_into(&mut b);
        self.core.feed(c, &b);
        self.core.process(c, 10);
        let mut reply = Vec::new();
        self.core.take_dirty(&mut self.dirty);
        for id in self.dirty.drain(..) {
            let out = self.core.output(id).to_vec();
            self.core.consume(id, out.len());
            if id == c {
                reply = out;
            }
        }
        reply
    }

    fn op(&mut self, c: ConnId, op: &Op, tx: u32, domid: u32, uuid: &str) {
        let p = |t: &str| {
            let s = instantiate(t, domid, uuid);
            if s.starts_with('/') { format!("/rxsbench{s}") } else { s }.into_bytes()
        };
        let f = |t: &str| instantiate(t, domid, uuid).into_bytes();
        let (ty, payload) = match op {
            Op::Write { path, value } => (MsgType::Write, [p(path), vec![0], f(value)].concat()),
            Op::Mkdir { path } => (MsgType::Mkdir, nul_terminated(&[&p(path)])),
            Op::Rm { path } => (MsgType::Rm, nul_terminated(&[&p(path)])),
            Op::SetPerms { path, perms } => {
                let mut v = nul_terminated(&[&p(path)]);
                for perm in perms {
                    v.extend(nul_terminated(&[&f(perm)]));
                }
                (MsgType::SetPerms, v)
            }
            Op::Watch { path, token } => (MsgType::Watch, nul_terminated(&[&p(path), &f(token)])),
            Op::Unwatch { path, token } => (MsgType::Unwatch, nul_terminated(&[&p(path), &f(token)])),
        };
        if self.with_watches || !matches!(ty, MsgType::Watch | MsgType::Unwatch) {
            self.call(c, ty, tx, payload);
        }
    }

    /// One VM start; returns its own connections (those still holding watches stay open).
    fn start(&mut self, s: &Scenario, index: u32) -> Vec<ConnId> {
        let domid = 10000 + index;
        let uuid = format!("{index:08x}-5ce0-4000-8000-{index:012x}");
        let mut own: HashMap<TraceConn, ConnId> = HashMap::new();
        let mut txs: HashMap<(TraceConn, u32), u32> = HashMap::new();
        let mut last = HashMap::new();
        for (i, r) in s.start.records.iter().enumerate() {
            if let Some(t) = r.tid {
                last.insert((r.conn, t), i);
            }
        }
        for (i, r) in s.start.records.iter().enumerate() {
            let c = match self.shared.get(&r.conn) {
                Some(c) => *c,
                None => *own.entry(r.conn).or_insert_with(|| self.core.open()),
            };
            let tx = match r.tid {
                None => 0,
                Some(t) => *txs.entry((r.conn, t)).or_insert_with(|| {
                    let reply = self.call(c, MsgType::TransactionStart, 0, vec![0]);
                    String::from_utf8_lossy(&reply[16..reply.len() - 1]).parse().unwrap()
                }),
            };
            self.op(c, &r.op, tx, domid, &uuid);
            if r.tid.is_some() && last[&(r.conn, r.tid.unwrap())] == i {
                self.call(c, MsgType::TransactionEnd, tx, b"T\0".to_vec());
            }
        }
        let watches = s.watches_per_vm();
        own.into_iter()
            .filter_map(|(id, c)| {
                if watches.get(&id).copied().unwrap_or(0) > 0 {
                    Some(c)
                } else {
                    self.core.close(c);
                    None
                }
            })
            .collect()
    }
}

/// Live bytes per VM (requested, in malloc chunks), of which its own
/// connections; watches per VM and store nodes per VM.
struct Cost {
    requested: isize,
    chunks: isize,
    connections: isize,
    watches: usize,
    nodes: usize,
    open: usize,
}

fn count(n: &xs_core::store::Node) -> usize {
    1 + n.children.iter().map(|(_, c)| count(c)).sum::<usize>()
}

/// Starts `n` VMs after a warm-up, with or without their watches.
fn measure(s: &Scenario, n: u32, with_watches: bool) -> Cost {
    const WARM_UP: u32 = 20;
    let mut r = Replay {
        core: Core::new(Config::default(), xs_daemon::reactor::hash_key()),
        shared: HashMap::new(),
        dirty: Vec::new(),
        req: 0,
        with_watches,
    };
    for id in &s.shared {
        let c = r.core.open();
        r.shared.insert(*id, c);
    }
    let first = r.shared.values().next().copied().unwrap();
    r.call(first, MsgType::Mkdir, 0, b"/rxsbench\0".to_vec());
    for rec in &s.baseline {
        let c = r.shared[&rec.conn];
        r.op(c, &rec.op, 0, 0, "");
    }
    // One-off structures do not count.
    let mut conns = Vec::new();
    for i in 0..WARM_UP {
        r.start(s, i);
    }
    let (b0, c0) = live();
    let (w0, n0) = (r.core.watches(), count(r.core.root()));
    for i in WARM_UP..WARM_UP + n {
        conns.extend(r.start(s, i));
    }
    let (b1, c1) = live();
    let watches = (r.core.watches() - w0) / n as usize;
    let nodes = (count(r.core.root()) - n0) / n as usize;
    let open = conns.len() / n as usize;
    for c in conns {
        r.core.close(c);
    }
    let (b2, _) = live();
    let per = |x: isize| x / n as isize;
    Cost {
        requested: per(b1 - b0),
        chunks: per(c1 - c0),
        connections: per(b1 - b2),
        watches,
        nodes,
        open,
    }
}

/// What one more running VM may cost, in bytes of malloc chunks. Measured:
/// 64,541 with glibc on x86_64. Raise it only with a reason.
const BUDGET: isize = 66_000;

#[test]
fn memory_per_simulated_vm() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../xs-bench/scenarios/xcpng83-hvm-2vbd-1vif");
    let s = Scenario::load(&dir).unwrap();
    let all = measure(&s, 400, true);
    // Without the watches: the store, and connections that hold nothing.
    let bare = measure(&s, 400, false);
    let store = bare.requested - bare.connections;
    let watches = all.requested - bare.requested;
    println!(
        "per VM: {} bytes requested, {} in malloc chunks",
        all.requested, all.chunks
    );
    println!(
        "  store: {store} bytes, {} nodes, {} bytes per node",
        all.nodes,
        store / all.nodes as isize
    );
    println!(
        "  watches: {watches} bytes, {} watches, {} bytes per watch",
        all.watches,
        watches / all.watches as isize
    );
    println!("  its {} idle connections: {} bytes", all.open, bare.connections);
    assert_eq!(bare.watches, 0);
    assert!(
        all.chunks > 0 && all.chunks <= BUDGET,
        "{} bytes per VM, budget {BUDGET}",
        all.chunks
    );
}
