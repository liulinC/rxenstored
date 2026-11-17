// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Runs a sequence against one daemon and records what came back.
//!
//! After each operation every open connection gets a barrier, a READ of
//! `/` with a request id the generator never uses, and is read up to its
//! reply: a daemon queues a connection's watch events and replies in one
//! stream, so whatever the operation caused on that connection arrives
//! before the barrier's reply. No timing is involved; a read timeout
//! (`TIMEOUT`) only ends a run whose daemon stopped answering.

use crate::daemon::Daemon;
use crate::gen::{Op, Req, Tx, T_TX_END, T_TX_START};
use crate::wire::{self, Msg, WATCH_EVENT};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// How long a daemon may take to answer before the connection is given up.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The same, after bytes that are not a well-formed message.
pub const RAW_TIMEOUT: Duration = Duration::from_secs(1);
const BARRIER_BASE: u32 = 0xB000_0000;

/// What a connection received.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Item {
    /// A reply: the type of the request it answers (by order), its type,
    /// request id, transaction (as the request named it) and payload.
    Reply {
        /// The request: its type and payload.
        req: Option<(u32, Vec<u8>)>,
        ty: u32,
        req_id: u32,
        tx: TxSym,
        payload: Vec<u8>,
    },
    Event {
        req_id: u32,
        tx_id: u32,
        payload: Vec<u8>,
    },
    /// The daemon closed the connection.
    Closed,
    /// Nothing within the timeout: the harness closed the connection.
    Timeout,
    /// The connection was gone before the operation: nothing sent.
    Dead,
}

/// A reply's transaction id, as it relates to its request's: the
/// daemons number transactions their own way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxSym {
    Zero,
    /// The (non-zero) id the request carried.
    Echo,
    /// Another id.
    Raw(u32),
}

impl Item {
    pub fn is_event(&self) -> bool {
        matches!(self, Item::Event { .. })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Transcript {
    /// Per operation, per connection, what it received.
    pub steps: Vec<Vec<Vec<Item>>>,
    /// The store and the daemon's counters at the end, by key.
    pub end: BTreeMap<String, String>,
    /// The daemon was still running at the end.
    pub alive: bool,
    /// The id of each TRANSACTION_START that got one: operation,
    /// connection, id.
    pub tx_numbers: Vec<(usize, usize, u32)>,
}

struct Conn {
    stream: UnixStream,
    buf: Vec<u8>,
}

enum Got {
    Msg(Msg),
    Closed,
    Timeout,
}

impl Conn {
    fn open(daemon: &Daemon) -> io::Result<Conn> {
        let stream = UnixStream::connect(daemon.socket())?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        Ok(Conn {
            stream,
            buf: Vec::new(),
        })
    }

    fn recv(&mut self) -> Got {
        let mut chunk = [0u8; 65536];
        loop {
            if let Some(m) = wire::decode(&mut self.buf) {
                return Got::Msg(m);
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Got::Closed,
                Ok(n) => self.buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Got::Timeout
                }
                Err(_) => return Got::Closed,
            }
        }
    }
}

struct Side<'a> {
    daemon: &'a Daemon,
    conns: Vec<Option<Conn>>,
    /// Per connection, the id each TRANSACTION_START got (None: refused).
    tx_ids: Vec<Vec<Option<u32>>>,
    barrier: u32,
    step: usize,
    tx_numbers: Vec<(usize, usize, u32)>,
}

/// The lines of a CONTROL `watches` reply, sorted: their order is that of
/// the daemon's hash tables.
fn sorted_lines(payload: &[u8]) -> Vec<u8> {
    let body = payload.strip_suffix(b"\0").unwrap_or(payload);
    let mut lines: Vec<&[u8]> = body.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
    lines.sort();
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    if payload.ends_with(b"\0") {
        out.push(0);
    }
    out
}

/// An id no transaction has, for a `Tx::Nth` with no transaction.
const NO_TX: u32 = 0xDEAD_0000;

impl Side<'_> {
    fn wire_tx(&self, conn: usize, tx: Tx) -> u32 {
        match tx {
            Tx::Zero => 0,
            Tx::Raw(n) => n,
            Tx::Nth(k) => self
                .tx_ids
                .get(conn)
                .and_then(|v| v.get(usize::from(k)))
                .copied()
                .flatten()
                .unwrap_or(NO_TX + u32::from(k)),
        }
    }

    fn sym(tx_id: u32, sent: Option<u32>) -> TxSym {
        if tx_id == 0 {
            TxSym::Zero
        } else if Some(tx_id) == sent {
            TxSym::Echo
        } else {
            TxSym::Raw(tx_id)
        }
    }

    fn next_barrier(&mut self) -> u32 {
        self.barrier = self.barrier.wrapping_add(1);
        BARRIER_BASE | (self.barrier & 0x0FFF_FFFF)
    }

    /// Sends `bytes` (whose requests' types are `sent`, in order) then a
    /// barrier on `conn`, and reads up to the barrier's reply.
    fn exchange(
        &mut self,
        conn: usize,
        parts: &[Vec<u8>],
        sent: Vec<(u32, Vec<u8>, u32)>,
        timeout: Duration,
        out: &mut Vec<Item>,
    ) {
        let barrier = self.next_barrier();
        let Some(Some(c)) = self.conns.get_mut(conn) else {
            out.push(Item::Dead);
            return;
        };
        let _ = c.stream.set_read_timeout(Some(timeout));
        let b = wire::encode(2, barrier, 0, b"/\0");
        let mut ok = true;
        let mut writes = parts.to_vec();
        match writes.last_mut() {
            Some(last) => last.extend_from_slice(&b),
            None => writes.push(b),
        }
        for data in &writes {
            if c.stream.write_all(data).is_err() {
                ok = false;
                break;
            }
        }
        let mut pending: VecDeque<(u32, Vec<u8>, u32)> = sent.into();
        let mut got = Vec::new();
        let end = if ok {
            loop {
                match c.recv() {
                    // A request with no reply leaves its type in `pending`.
                    Got::Msg(m) if m.ty != WATCH_EVENT && m.req_id == barrier => {
                        // Its value is the root's, which a sequence may
                        // write: only a reply that is not a READ's is kept,
                        // with the request id the barrier had (the number
                        // of barriers differs when the daemons retried a
                        // different number of times).
                        if m.ty != 2 {
                            got.push((
                                Some((2, b"/\0".to_vec(), 0)),
                                Msg {
                                    req_id: BARRIER_BASE,
                                    ..m
                                },
                            ));
                        }
                        break None;
                    }
                    Got::Msg(m) if m.ty == WATCH_EVENT => got.push((None, m)),
                    Got::Msg(m) => {
                        let t = pending.pop_front().unwrap_or((u32::MAX, Vec::new(), 0));
                        got.push((Some(t), m));
                    }
                    Got::Closed => break Some(Item::Closed),
                    Got::Timeout => break Some(Item::Timeout),
                }
            }
        } else {
            Some(Item::Closed)
        };
        let _ = c.stream.set_read_timeout(Some(TIMEOUT));
        for (req_ty, m) in got {
            match req_ty {
                None => out.push(Item::Event {
                    req_id: m.req_id,
                    tx_id: m.tx_id,
                    payload: m.payload,
                }),
                Some(t) => {
                    let mut payload = m.payload;
                    if t.0 == T_TX_START {
                        let id = (m.ty == T_TX_START)
                            .then(|| std::str::from_utf8(payload.strip_suffix(b"\0").unwrap_or(&payload)).ok())
                            .flatten()
                            .and_then(|s| s.parse::<u32>().ok());
                        if let Some(v) = self.tx_ids.get_mut(conn) {
                            v.push(id);
                        }
                        // The number itself is compared apart (`tx_numbers`).
                        if let Some(id) = id {
                            self.tx_numbers.push((self.step, conn, id));
                            payload = b"<id>\0".to_vec();
                        }
                    }
                    // Each daemon's own path (`/tool/xenstored`).
                    if t.0 == 2 && m.ty == 2 && t.1 == b"/tool/xenstored\0" {
                        payload = b"<the daemon's path>".to_vec();
                    }
                    if t.0 == 0 && m.ty == 0 && t.1.starts_with(b"watches\0") {
                        payload = sorted_lines(&payload);
                    }
                    let tx = Self::sym(m.tx_id, (t.0 != u32::MAX).then_some(t.2));
                    out.push(Item::Reply {
                        req: (t.0 != u32::MAX).then_some((t.0, t.1)),
                        ty: m.ty,
                        req_id: m.req_id,
                        tx,
                        payload,
                    });
                }
            }
        }
        if let Some(e) = end {
            out.push(e);
            // A barrier that never came: the connection is given up.
            if let Some(slot) = self.conns.get_mut(conn) {
                *slot = None;
            }
        }
    }

    fn encode(&self, conn: usize, r: &Req) -> Vec<u8> {
        wire::encode(r.ty, r.req_id, self.wire_tx(conn, r.tx), &r.payload)
    }

    fn one(&mut self, conn: usize, r: &Req, out: &mut Vec<Item>) {
        let bytes = self.encode(conn, r);
        let sent = vec![(r.ty, r.payload.clone(), self.wire_tx(conn, r.tx))];
        self.exchange(conn, &[bytes], sent, TIMEOUT, out);
    }

    fn reconnect(&mut self, conn: usize) {
        if let Some(slot) = self.conns.get_mut(conn) {
            *slot = None;
            *slot = Conn::open(self.daemon).ok();
        }
        if let Some(v) = self.tx_ids.get_mut(conn) {
            v.clear();
        }
    }

    fn run_op(&mut self, op: &Op, n: usize) -> Vec<Vec<Item>> {
        let mut per: Vec<Vec<Item>> = vec![Vec::new(); n];
        let c = usize::from(op.conn());
        let mut mine = Vec::new();
        match op {
            Op::One { req, .. } => self.one(c, req, &mut mine),
            Op::Burst { reqs, .. } => {
                let bytes: Vec<u8> = reqs.iter().flat_map(|r| self.encode(c, r)).collect();
                let sent = reqs
                    .iter()
                    .map(|r| (r.ty, r.payload.clone(), self.wire_tx(c, r.tx)))
                    .collect();
                self.exchange(c, &[bytes], sent, TIMEOUT, &mut mine);
            }
            Op::Split { req, at, .. } => {
                let bytes = self.encode(c, req);
                let at = (*at).min(bytes.len());
                let (a, b) = bytes.split_at(at);
                let sent = vec![(req.ty, req.payload.clone(), self.wire_tx(c, req.tx))];
                self.exchange(c, &[a.to_vec(), b.to_vec()], sent, TIMEOUT, &mut mine);
            }
            Op::Raw { bytes, .. } => self.exchange(c, std::slice::from_ref(bytes), Vec::new(), RAW_TIMEOUT, &mut mine),
            Op::Reconnect { .. } => self.reconnect(c),
            Op::TxBlock {
                body,
                interfere,
                commit,
                attempts,
                ..
            } => {
                for attempt in 0..*attempts {
                    let start = Req {
                        ty: T_TX_START,
                        req_id: 1,
                        tx: Tx::Zero,
                        payload: b"\0".to_vec(),
                    };
                    self.one(c, &start, &mut mine);
                    // A retry takes the slot of the block's first
                    // transaction: `Tx::Nth` counts as the generator does.
                    let ids = self.tx_ids.get_mut(c);
                    let k = match ids {
                        Some(v) if attempt > 0 && v.len() >= 2 => {
                            let id = v.pop().flatten();
                            if let Some(slot) = v.last_mut() {
                                *slot = id;
                            }
                            v.len() - 1
                        }
                        Some(v) => v.len().saturating_sub(1),
                        None => 0,
                    };
                    let tx = Tx::Nth(u16::try_from(k).unwrap_or(u16::MAX));
                    for r in body {
                        let r = Req { tx, ..r.clone() };
                        self.one(c, &r, &mut mine);
                    }
                    if let Some((o, r)) = interfere {
                        let o = usize::from(*o);
                        if o == c {
                            self.one(c, r, &mut mine);
                        } else if let Some(slot) = per.get_mut(o) {
                            let mut theirs = std::mem::take(slot);
                            self.one(o, r, &mut theirs);
                            if let Some(slot) = per.get_mut(o) {
                                *slot = theirs;
                            }
                        }
                    }
                    let end = Req {
                        ty: T_TX_END,
                        req_id: 2,
                        tx,
                        payload: if *commit { b"T\0".to_vec() } else { b"F\0".to_vec() },
                    };
                    let before = mine.len();
                    self.one(c, &end, &mut mine);
                    let again = mine.get(before..).unwrap_or_default().iter().any(|i| {
                        matches!(i, Item::Reply { ty, payload, .. } if *ty == wire::ERROR && payload == b"EAGAIN\0")
                    });
                    if !again || attempt + 1 == *attempts {
                        break;
                    }
                }
            }
        }
        if let Some(slot) = per.get_mut(c) {
            slot.extend(mine);
        }
        // Barriers: every event the operation caused is now delivered.
        for (i, slot) in per.iter_mut().enumerate() {
            if matches!(self.conns.get(i), Some(Some(_))) {
                self.exchange(i, &[], Vec::new(), TIMEOUT, slot);
            }
        }
        per
    }
}

/// Runs `ops` on `conns` connections to `daemon`, then reads the whole
/// store and the daemon's counters on a new connection.
pub fn execute(daemon: &mut Daemon, ops: &[Op], conns: usize, probes: &[Vec<u8>]) -> Transcript {
    let mut t = Transcript::default();
    {
        let mut side = Side {
            daemon,
            conns: (0..conns).map(|_| Conn::open(daemon).ok()).collect(),
            tx_ids: vec![Vec::new(); conns],
            barrier: 0,
            step: 0,
            tx_numbers: Vec::new(),
        };
        for (i, op) in ops.iter().enumerate() {
            side.step = i;
            t.steps.push(side.run_op(op, conns));
        }
        t.tx_numbers = std::mem::take(&mut side.tx_numbers);
        t.end = final_state(daemon, probes);
    }
    t.alive = daemon.alive();
    t
}

fn ask(c: &mut Conn, ty: u32, payload: &[u8]) -> Option<Msg> {
    c.stream.write_all(&wire::encode(ty, 7, 0, payload)).ok()?;
    loop {
        match c.recv() {
            Got::Msg(m) if m.ty == WATCH_EVENT => {}
            Got::Msg(m) => return Some(m),
            _ => return None,
        }
    }
}

fn answer(m: Option<Msg>) -> String {
    match m {
        None => "<no answer>".into(),
        Some(m) if m.ty == wire::ERROR => format!("error {}", wire::show(&m.payload)),
        Some(m) => format!("{} \"{}\"", wire::type_name(m.ty), wire::show(&m.payload)),
    }
}

/// Keys: `node <path>` (value and permissions), `probe <request> <path>`
/// for the extra paths, `control <command>`.
fn final_state(daemon: &Daemon, probes: &[Vec<u8>]) -> BTreeMap<String, String> {
    let mut end = BTreeMap::new();
    let Ok(mut c) = Conn::open(daemon) else {
        end.insert("connect".into(), "refused".into());
        return end;
    };
    let mut todo = vec![b"/".to_vec()];
    let mut seen = 0usize;
    while let Some(p) = todo.pop() {
        seen += 1;
        if seen > 50_000 {
            end.insert("walk".into(), "more than 50000 nodes".into());
            break;
        }
        let z = [&p[..], b"\0"].concat();
        let value = if p == b"/tool/xenstored" {
            "<the daemon's path>".into()
        } else {
            answer(ask(&mut c, 2, &z))
        };
        let perms = answer(ask(&mut c, 3, &z));
        end.insert(format!("node {}", wire::show(&p)), format!("{value} perms {perms}"));
        match ask(&mut c, 1, &z) {
            Some(m) if m.ty == 1 => {
                for name in m.payload.split(|&b| b == 0).filter(|n| !n.is_empty()) {
                    let child = if p == b"/" {
                        [b"/", name].concat()
                    } else {
                        [&p[..], b"/", name].concat()
                    };
                    todo.push(child);
                }
            }
            other => {
                end.insert(format!("node {} directory", wire::show(&p)), answer(other));
            }
        }
    }
    for p in probes {
        let z = [&p[..], b"\0"].concat();
        for (ty, name) in [(2u32, "READ"), (3, "GET_PERMS"), (1, "DIRECTORY")] {
            end.insert(format!("probe {name} {}", wire::show(p)), answer(ask(&mut c, ty, &z)));
        }
    }
    for d in ["-1", "0", "3", "5", "7", "9", "32752", "65535"] {
        let q = [&b"quota\0"[..], d.as_bytes(), b"\0"].concat();
        end.insert(format!("control quota {d}"), answer(ask(&mut c, 0, &q)));
    }
    // One line per watch; the order of the lines is the daemon's.
    let w = ask(&mut c, 0, b"watches\0");
    let mut lines: Vec<String> = match &w {
        Some(m) if m.ty == 0 => m
            .payload
            .split(|&b| b == b'\n')
            .map(wire::show)
            .filter(|l| !l.is_empty() && l != "\\0")
            .collect(),
        _ => vec![answer(w)],
    };
    lines.sort();
    end.insert("control watches".into(), lines.join("\n"));
    end
}
