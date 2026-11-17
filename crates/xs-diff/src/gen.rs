// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Seeded random request sequences, extended from the generator of
//! `xs-core`'s model test: every request type a socket can send, valid and
//! malformed payloads, special and over-long paths, transactions with
//! conflicts and retries, pipelined requests and split writes.
//!
//! A sequence is a list of [`Op`]s, each run on one or a few of the
//! harness's connections. Transactions are named by their rank among the
//! TRANSACTION_START requests of their connection ([`Tx::Nth`]): each
//! daemon's own id for it is used when the request is sent.

use std::fmt;
use xs_wire::MsgType;

/// xorshift64*.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// In `0..n` (0 if `n` is 0).
    pub fn below(&mut self, n: usize) -> usize {
        match u64::try_from(n) {
            Ok(0) | Err(_) => 0,
            Ok(m) => usize::try_from(self.next_u64() % m).unwrap_or(0),
        }
    }
    pub fn pick<T: Clone + Default>(&mut self, v: &[T]) -> T {
        let i = self.below(v.len());
        v.get(i).cloned().unwrap_or_default()
    }
    pub fn bytes(&mut self, v: &[&[u8]]) -> Vec<u8> {
        let i = self.below(v.len());
        v.get(i).map(|b| b.to_vec()).unwrap_or_default()
    }
    /// True with probability `n / d`.
    pub fn chance(&mut self, n: usize, d: usize) -> bool {
        self.below(d) < n
    }
}

/// The transaction a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// 0: none.
    Zero,
    /// The id the daemon gave the n-th TRANSACTION_START of this
    /// connection (counted from its opening, failed ones included); an id
    /// no transaction has if there is none.
    Nth(u16),
    /// This number as it is.
    Raw(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Req {
    pub ty: u32,
    pub req_id: u32,
    pub tx: Tx,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// One request.
    One { conn: u8, req: Req },
    /// Several requests in one write, then their replies.
    Burst { conn: u8, reqs: Vec<Req> },
    /// One request written in two parts.
    Split { conn: u8, req: Req, at: usize },
    /// TRANSACTION_START, the body in it, optionally a request from
    /// another connection, TRANSACTION_END (`T` if `commit`, else `F`),
    /// the whole retried on EAGAIN up to `attempts` times. The body's and
    /// the end's `tx` is the transaction just started.
    TxBlock {
        conn: u8,
        body: Vec<Req>,
        interfere: Option<(u8, Req)>,
        commit: bool,
        attempts: u8,
    },
    /// Close the connection and open a new one in its place.
    Reconnect { conn: u8 },
    /// Bytes that are not a well-formed message (bad framing).
    Raw {
        conn: u8,
        bytes: Vec<u8>,
        what: &'static str,
    },
}

impl Op {
    pub fn conn(&self) -> u8 {
        match self {
            Op::One { conn, .. }
            | Op::Burst { conn, .. }
            | Op::Split { conn, .. }
            | Op::TxBlock { conn, .. }
            | Op::Reconnect { conn }
            | Op::Raw { conn, .. } => *conn,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenOpts {
    pub steps: usize,
    pub conns: usize,
    /// INTRODUCE, RELEASE and RESUME of made-up domains. Without Xen
    /// neither daemon can map a ring, so their answers to INTRODUCE depend
    /// on the environment, not on the daemon alone.
    pub introduce: bool,
    /// Messages longer than allowed: the daemon drops the connection.
    pub framing: bool,
    /// Bursts of 12 TRANSACTION_STARTs or 515 WATCHes (quota limits).
    pub quota_bursts: bool,
    /// Permissions naming a domid that is negative or beyond 32 bits.
    pub wide_domids: bool,
    /// `@` paths that hold a `/`, on which the two daemons are known to
    /// differ.
    pub at_slash: bool,
}

impl Default for GenOpts {
    fn default() -> Self {
        GenOpts {
            steps: 150,
            conns: 3,
            introduce: false,
            framing: true,
            quota_bursts: true,
            wide_domids: true,
            at_slash: true,
        }
    }
}

const T_CONTROL: u32 = MsgType::Control as u32;
const T_DIRECTORY: u32 = MsgType::Directory as u32;
const T_READ: u32 = MsgType::Read as u32;
const T_GET_PERMS: u32 = MsgType::GetPerms as u32;
const T_WATCH: u32 = MsgType::Watch as u32;
const T_UNWATCH: u32 = MsgType::Unwatch as u32;
pub const T_TX_START: u32 = MsgType::TransactionStart as u32;
pub const T_TX_END: u32 = MsgType::TransactionEnd as u32;
const T_INTRODUCE: u32 = MsgType::Introduce as u32;
const T_RELEASE: u32 = MsgType::Release as u32;
const T_GET_DOMAIN_PATH: u32 = MsgType::GetDomainPath as u32;
const T_WRITE: u32 = MsgType::Write as u32;
const T_MKDIR: u32 = MsgType::Mkdir as u32;
const T_RM: u32 = MsgType::Rm as u32;
const T_SET_PERMS: u32 = MsgType::SetPerms as u32;
const T_IS_INTRODUCED: u32 = MsgType::IsDomainIntroduced as u32;
const T_RESUME: u32 = MsgType::Resume as u32;
const T_SET_TARGET: u32 = MsgType::SetTarget as u32;
const T_RESET_WATCHES: u32 = MsgType::ResetWatches as u32;
const T_DIRECTORY_PART: u32 = MsgType::DirectoryPart as u32;

/// Odd paths: syntax corner cases, the special `@` paths, the homes of
/// domains, nodes the daemon creates.
const ODD_PATHS: &[&[u8]] = &[
    b"/",
    b"",
    b"//",
    b"/a/",
    b"a//b",
    b"//a",
    b"/a//b",
    b"/a b",
    b"/a\x01",
    b"/\xc3\xa4",
    b"/a\tb",
    b"/.",
    b"/..",
    b"/a/./b",
    b"/-_@",
    b"/a@b",
    b"/local/domain/0/a",
    b"/local/domain/5",
    b"/local/domain/5/a",
    b"/local/domain",
    b"/local",
    b"/tool/xenstored",
    b"/tool",
    b"/a\0b",
    b"a/@b",
    b"/@a",
    b"@introduceDomain",
    b"@releaseDomain",
    b"@",
    b"@a",
    b"@a/b",
    b"@/",
    b"@//",
    b"@a/",
    b"@introduceDomain/x",
    b"@x@y",
];

const VALUES: &[&[u8]] = &[b"", b"x", b"yy", b"a\0b", b"\xff\xfe", b"/a"];

const PERMS: &[&[u8]] = &[
    b"n0",
    b"r0",
    b"w0",
    b"b0",
    b"n5",
    b"r5",
    b"w5",
    b"b5",
    b"n3",
    b"r3",
    b"b3",
    b"n7",
    b"w9",
    b"x0",
    b"n",
    b"",
    b"q1",
    b"n-1",
    b"n99999999999",
    b"n4294967296",
    b"n0x10",
    b"n 5",
    b"N0",
    b"r32768",
    b"n65535",
    b"n2147483647",
    b"r1a",
    b"n32752",
];

/// The entries of `PERMS` whose domid is negative or beyond 32 bits.
const WIDE: &[&[u8]] = &[b"n-1", b"n99999999999", b"n4294967296"];

pub const DOMIDS: &[&[u8]] = &[
    b"0",
    b"5",
    b"3",
    b"7",
    b"32752",
    b"32753",
    b"65535",
    b"-1",
    b"abc",
    b"",
    b"4294967296",
    b"99999999999999999999",
    b"0x10",
    b" 5",
    b"5 ",
    b"+5",
    b"05",
];

const TOKENS: &[&[u8]] = &[b"t1", b"t2", b"", b"t1 ", b"\xff"];

fn long_path(rng: &mut Rng, relative: bool) -> Vec<u8> {
    let len = if relative {
        rng.pick(&[1000usize, 1007, 1008, 1009, 2040, 3060, 4080])
    } else {
        rng.pick(&[1023usize, 1024, 1025, 2048, 3072, 3073, 4095])
    };
    let comp = rng.pick(&[1usize, 50, 255, 256, 2000]);
    let mut p = Vec::with_capacity(len);
    if !relative {
        p.push(b'/');
    }
    while p.len() < len {
        let room = len - p.len();
        let n = comp.min(room);
        p.extend(std::iter::repeat_n(b'p', n));
        if p.len() + 1 < len {
            p.push(b'/');
        }
    }
    p
}

pub fn gen_path(rng: &mut Rng) -> Vec<u8> {
    match rng.below(100) {
        0..=19 => ODD_PATHS
            .get(rng.below(ODD_PATHS.len()))
            .map(|p| p.to_vec())
            .unwrap_or_default(),
        20..=22 => {
            let relative = rng.chance(1, 3);
            long_path(rng, relative)
        }
        n => {
            let depth = 1 + rng.below(3);
            let relative = n >= 90;
            let mut s = Vec::new();
            for i in 0..depth {
                if i > 0 || !relative {
                    s.push(b'/');
                }
                s.extend_from_slice(&rng.bytes(&[b"a", b"b", b"c"]));
            }
            s
        }
    }
}

/// A plain absolute path of the small tree that most requests share.
fn tree_path(rng: &mut Rng) -> Vec<u8> {
    let depth = 1 + rng.below(3);
    let mut s = Vec::new();
    for _ in 0..depth {
        s.push(b'/');
        s.extend_from_slice(&rng.bytes(&[b"a", b"b", b"c"]));
    }
    s
}

fn gen_value(rng: &mut Rng) -> Vec<u8> {
    match rng.below(12) {
        0 => vec![b'v'; rng.pick(&[2047usize, 2048, 2049, 3000, 4093])],
        _ => rng.bytes(VALUES),
    }
}

fn z(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
        out.push(0);
    }
    out
}

/// Malformations of a NUL-separated payload: the last NUL dropped, an
/// extra field, or an extra NUL.
fn mangle(rng: &mut Rng, mut p: Vec<u8>) -> Vec<u8> {
    match rng.below(40) {
        0 => {
            if p.last() == Some(&0) {
                p.pop();
            }
        }
        1 => p.extend_from_slice(b"extra\0"),
        2 => p.push(0),
        _ => {}
    }
    p
}

pub struct Gen {
    rng: Rng,
    opts: GenOpts,
    /// TRANSACTION_STARTs sent on each connection since it opened.
    starts: Vec<u16>,
    next_req: u32,
}

impl Gen {
    pub fn new(seed: u64, opts: GenOpts) -> Gen {
        let conns = opts.conns;
        Gen {
            rng: Rng::new(seed),
            opts,
            starts: vec![0; conns],
            next_req: 1,
        }
    }

    fn req_id(&mut self) -> u32 {
        match self.rng.below(50) {
            0 => 0,
            1 => u32::MAX,
            _ => {
                self.next_req = self.next_req.wrapping_add(1);
                self.next_req
            }
        }
    }

    fn started(&self, conn: u8) -> u16 {
        self.starts.get(usize::from(conn)).copied().unwrap_or(0)
    }

    fn count_start(&mut self, conn: u8) {
        if let Some(n) = self.starts.get_mut(usize::from(conn)) {
            *n = n.saturating_add(1);
        }
    }

    fn some_tx(&mut self, conn: u8) -> Tx {
        let n = self.started(conn);
        if n == 0 {
            return Tx::Zero;
        }
        let back = u16::try_from(self.rng.below(usize::from(n.min(3)))).unwrap_or(0);
        Tx::Nth(n - 1 - back)
    }

    /// The `tx` of a request that reads or changes the store.
    fn store_tx(&mut self, conn: u8) -> Tx {
        match self.rng.below(20) {
            0..=10 => Tx::Zero,
            11..=18 => self.some_tx(conn),
            // Ids no transaction gets in a sequence.
            _ => Tx::Raw(self.rng.pick(&[999_999u32, 0x3FFF_FFFF, u32::MAX, 0x7FFF_FFFF])),
        }
    }

    /// The `tx` of a request that does not take one.
    fn other_tx(&mut self, conn: u8) -> Tx {
        match self.rng.below(25) {
            0 => self.some_tx(conn),
            1 => Tx::Raw(999_999),
            _ => Tx::Zero,
        }
    }

    fn store_req(&mut self, conn: u8, path: Vec<u8>) -> (u32, Vec<u8>) {
        let wide = self.opts.wide_domids;
        let rng = &mut self.rng;
        match rng.below(10) {
            0..=3 => {
                let mut v = gen_value(rng);
                // Within the 4096 bytes a message may carry.
                v.truncate(4095usize.saturating_sub(path.len()));
                (T_WRITE, [&path[..], b"\0", &v[..]].concat())
            }
            4 => (T_MKDIR, mangle(rng, z(&[&path]))),
            5 => (T_RM, mangle(rng, z(&[&path]))),
            6 => (T_READ, mangle(rng, z(&[&path]))),
            7 => (T_DIRECTORY, mangle(rng, z(&[&path]))),
            8 => (T_GET_PERMS, mangle(rng, z(&[&path]))),
            _ => {
                let _ = conn;
                let n = rng.below(4);
                // (SET_PERMS)
                let mut parts = vec![path];
                for _ in 0..n {
                    let mut p = rng.bytes(PERMS);
                    if !wide && WIDE.contains(&&p[..]) {
                        p = b"n5".to_vec();
                    }
                    parts.push(p);
                }
                let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
                (T_SET_PERMS, mangle(rng, z(&refs)))
            }
        }
    }

    /// A request of at most 4096 bytes of payload, the most a message may
    /// carry (longer ones are `Op::Raw`).
    pub fn request(&mut self, conn: u8) -> Req {
        loop {
            let r = self.any_request(conn);
            let first = r.payload.split(|&b| b == 0).next().unwrap_or_default();
            let at_slash = first.first() == Some(&b'@') && first.contains(&b'/');
            if r.payload.len() <= xs_wire::PAYLOAD_MAX && (self.opts.at_slash || !at_slash) {
                return r;
            }
        }
    }

    fn any_request(&mut self, conn: u8) -> Req {
        let req_id = self.req_id();
        let path = gen_path(&mut self.rng);
        let (ty, tx, payload) = match self.rng.below(100) {
            0..=44 => {
                let tx = self.store_tx(conn);
                let (ty, p) = self.store_req(conn, path);
                (ty, tx, p)
            }
            45..=47 => {
                let tx = self.store_tx(conn);
                let off = self.rng.bytes(&[b"0", b"1", b"2", b"abc", b"", b"-1", b"99999"]);
                (T_DIRECTORY_PART, tx, mangle(&mut self.rng, z(&[&path, &off])))
            }
            48..=51 => {
                // WRITE without a value field.
                let tx = self.store_tx(conn);
                (T_WRITE, tx, path)
            }
            52..=58 => {
                let tok = self.rng.bytes(TOKENS);
                let tx = self.other_tx(conn);
                (T_WATCH, tx, mangle(&mut self.rng, z(&[&path, &tok])))
            }
            59..=61 => {
                let tok = self.rng.bytes(TOKENS);
                let tx = self.other_tx(conn);
                (T_UNWATCH, tx, mangle(&mut self.rng, z(&[&path, &tok])))
            }
            62..=66 => {
                let tx = self.other_tx(conn);
                let p = self.rng.bytes(&[b"\0", b"\0", b"\0", b"", b"x\0", b"\0\0"]);
                self.count_start(conn);
                (T_TX_START, tx, p)
            }
            67..=72 => {
                let tx = match self.rng.below(20) {
                    0 => Tx::Zero,
                    1 => Tx::Raw(999_999),
                    _ => self.some_tx(conn),
                };
                let p = self.rng.bytes(&[
                    b"T\0", b"T\0", b"T\0", b"F\0", b"F\0", b"X\0", b"", b"T", b"TT\0", b"F\0x\0",
                ]);
                (T_TX_END, tx, p)
            }
            73 => {
                let tx = self.other_tx(conn);
                let p = self.rng.bytes(&[b"", b"\0", b"x\0"]);
                (T_RESET_WATCHES, tx, p)
            }
            74..=76 => {
                let tx = self.other_tx(conn);
                let d = self.rng.bytes(DOMIDS);
                (T_GET_DOMAIN_PATH, tx, mangle(&mut self.rng, z(&[&d])))
            }
            77 => {
                let tx = self.other_tx(conn);
                let d = self.rng.bytes(DOMIDS);
                (T_IS_INTRODUCED, tx, mangle(&mut self.rng, z(&[&d])))
            }
            78 => {
                let tx = self.other_tx(conn);
                let a = self.rng.bytes(DOMIDS);
                let b = self.rng.bytes(DOMIDS);
                (T_SET_TARGET, tx, mangle(&mut self.rng, z(&[&a, &b])))
            }
            79..=81 if self.opts.introduce => {
                let tx = self.other_tx(conn);
                let d = self.rng.bytes(DOMIDS);
                match self.rng.below(3) {
                    0 => (T_RELEASE, tx, z(&[&d])),
                    1 => (T_RESUME, tx, z(&[&d])),
                    _ => (T_INTRODUCE, tx, z(&[&d, b"4096", b"7"])),
                }
            }
            79..=81 => {
                // RELEASE and RESUME of domains that do not exist.
                let tx = self.other_tx(conn);
                let d = self.rng.bytes(&[b"5", b"3", b"7", b"abc", b"", b"-1"]);
                let ty = if self.rng.chance(1, 2) { T_RELEASE } else { T_RESUME };
                (ty, tx, z(&[&d]))
            }
            82..=86 => {
                let tx = self.other_tx(conn);
                let d = self.rng.bytes(DOMIDS);
                let p = match self.rng.below(16) {
                    0..=4 => z(&[b"quota", &d]),
                    5 => z(&[b"quota"]),
                    6..=7 => z(&[b"watches"]),
                    8 => z(&[b"print", b"hello"]),
                    9 => z(&[b"mfn", &d]),
                    10 => z(&[b"xenbus", &d]),
                    11 => z(&[b"compact"]),
                    12 => z(&[b"trim"]),
                    13 => Vec::new(),
                    14 => z(&[b"nonsense"]),
                    _ => z(&[b"txn", &d]),
                };
                (T_CONTROL, tx, p)
            }
            87 => {
                // Types that are not requests, or not of 4.17.
                let ty = self
                    .rng
                    .pick(&[15u32, 16, 20, 23, 24, 25, 26, 27, 128, 0xFFFF, u32::MAX]);
                (ty, Tx::Zero, z(&[&path]))
            }
            88..=91 => {
                // A request of the maximum length.
                let tx = self.store_tx(conn);
                let p = tree_path(&mut self.rng);
                let fill = 4096usize.saturating_sub(p.len() + 1);
                (T_WRITE, tx, [&p[..], b"\0", &vec![b'm'; fill][..]].concat())
            }
            _ => {
                let tx = self.store_tx(conn);
                let p = tree_path(&mut self.rng);
                let (ty, payload) = self.store_req(conn, p);
                (ty, tx, payload)
            }
        };
        Req {
            ty,
            req_id,
            tx,
            payload,
        }
    }

    fn conn(&mut self) -> u8 {
        u8::try_from(self.rng.below(self.opts.conns)).unwrap_or(0)
    }

    fn tx_block(&mut self, conn: u8) -> Op {
        let n = 1 + self.rng.below(4);
        let mut body = Vec::new();
        for _ in 0..n {
            let p = tree_path(&mut self.rng);
            let (ty, payload) = self.store_req(conn, p);
            let req_id = self.req_id();
            body.push(Req {
                ty,
                req_id,
                tx: Tx::Zero,
                payload,
            });
        }
        let interfere = if self.rng.chance(1, 2) {
            let other = self.conn();
            let p = tree_path(&mut self.rng);
            let (ty, payload) = match self.rng.below(4) {
                0 => (T_RM, z(&[&p])),
                1 => (T_MKDIR, z(&[&p])),
                2 => (T_SET_PERMS, z(&[&p, b"n0", b"r5"])),
                _ => (T_WRITE, [&p[..], b"\0i"].concat()),
            };
            let req_id = self.req_id();
            Some((
                other,
                Req {
                    ty,
                    req_id,
                    tx: Tx::Zero,
                    payload,
                },
            ))
        } else {
            None
        };
        let commit = !self.rng.chance(1, 7);
        let attempts = u8::try_from(1 + self.rng.below(3)).unwrap_or(1);
        // Each attempt starts a transaction; count the first only (the
        // others happen only on EAGAIN, the same for both daemons when
        // they agree).
        self.count_start(conn);
        Op::TxBlock {
            conn,
            body,
            interfere,
            commit,
            attempts,
        }
    }

    pub fn op(&mut self) -> Op {
        let conn = self.conn();
        match self.rng.below(100) {
            0..=69 => Op::One {
                conn,
                req: self.request(conn),
            },
            70..=77 => {
                let n = 2 + self.rng.below(6);
                let reqs = (0..n).map(|_| self.request(conn)).collect();
                Op::Burst { conn, reqs }
            }
            78..=80 => {
                let req = self.request(conn);
                let len = xs_wire::HEADER_LEN + req.payload.len();
                let at = 1 + self.rng.below(len.saturating_sub(1).max(1));
                Op::Split { conn, req, at }
            }
            81..=93 => self.tx_block(conn),
            94..=95 => {
                if let Some(n) = self.starts.get_mut(usize::from(conn)) {
                    *n = 0;
                }
                Op::Reconnect { conn }
            }
            96 if self.opts.framing => {
                let (bytes, what) = match self.rng.below(2) {
                    0 => (
                        crate::wire::encode(T_WRITE, 1, 0, &[&b"/big\0"[..], &[b'o'; 4092][..]].concat()),
                        "payload of 4097 bytes",
                    ),
                    _ => {
                        let mut h = crate::wire::encode(T_READ, 1, 0, b"");
                        if let Some(len) = h.get_mut(12..16) {
                            len.copy_from_slice(&u32::MAX.to_le_bytes());
                        }
                        (h, "header announcing 4 GiB")
                    }
                };
                Op::Raw { conn, bytes, what }
            }
            97 if self.opts.quota_bursts => {
                let reqs: Vec<Req> = if self.rng.chance(1, 2) {
                    (0..12)
                        .map(|_| {
                            self.count_start(conn);
                            Req {
                                ty: T_TX_START,
                                req_id: self.req_id(),
                                tx: Tx::Zero,
                                payload: b"\0".to_vec(),
                            }
                        })
                        .collect()
                } else {
                    (0..515)
                        .map(|i| Req {
                            ty: T_WATCH,
                            req_id: self.req_id(),
                            tx: Tx::Zero,
                            payload: z(&[format!("/q/{i}").as_bytes(), b"q"]),
                        })
                        .collect()
                };
                Op::Burst { conn, reqs }
            }
            _ => Op::One {
                conn,
                req: self.request(conn),
            },
        }
    }
}

pub fn generate(seed: u64, opts: &GenOpts) -> Vec<Op> {
    let mut g = Gen::new(seed, opts.clone());
    (0..opts.steps).map(|_| g.op()).collect()
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tx::Zero => write!(f, "0"),
            Tx::Nth(n) => write!(f, "T#{n}"),
            Tx::Raw(n) => write!(f, "{n}"),
        }
    }
}

impl fmt::Display for Req {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} rid={} tx={} \"{}\"",
            crate::wire::type_name(self.ty),
            self.req_id,
            self.tx,
            crate::wire::show(&self.payload)
        )
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::One { conn, req } => write!(f, "c{conn}: {req}"),
            Op::Burst { conn, reqs } if reqs.len() > 20 => {
                let first = reqs.first().map(|r| r.to_string()).unwrap_or_default();
                write!(f, "c{conn}: burst of {} requests, the first: {first}", reqs.len())
            }
            Op::Burst { conn, reqs } => {
                write!(f, "c{conn}: burst [")?;
                for (i, r) in reqs.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{r}")?;
                }
                write!(f, "]")
            }
            Op::Split { conn, req, at } => write!(f, "c{conn}: split at byte {at}: {req}"),
            Op::TxBlock {
                conn,
                body,
                interfere,
                commit,
                attempts,
            } => {
                write!(f, "c{conn}: transaction (up to {attempts} attempts) [")?;
                for (i, r) in body.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{r}")?;
                }
                write!(f, "]")?;
                if let Some((c, r)) = interfere {
                    write!(f, " then c{c}: {r}")?;
                }
                write!(f, " then end {}", if *commit { "T" } else { "F" })
            }
            Op::Reconnect { conn } => write!(f, "c{conn}: reconnect"),
            Op::Raw { conn, what, .. } => write!(f, "c{conn}: raw bytes: {what}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_sequence() {
        let o = GenOpts::default();
        assert_eq!(generate(7, &o), generate(7, &o));
        assert_ne!(generate(7, &o), generate(8, &o));
    }

    #[test]
    fn long_paths_have_the_length_asked() {
        let mut rng = Rng::new(1);
        for _ in 0..200 {
            let p = long_path(&mut rng, false);
            assert!(
                [1023, 1024, 1025, 2048, 3072, 3073, 4095].contains(&p.len()),
                "{}",
                p.len()
            );
            assert_eq!(p.first(), Some(&b'/'));
            assert!(!p.ends_with(b"/"));
        }
    }

    #[test]
    fn sequences_cover_every_request_type_of_a_socket() {
        let o = GenOpts {
            steps: 3000,
            ..GenOpts::default()
        };
        let mut seen = std::collections::BTreeSet::new();
        for op in generate(3, &o) {
            match op {
                Op::One { req, .. } | Op::Split { req, .. } => {
                    seen.insert(req.ty);
                }
                Op::Burst { reqs, .. } => seen.extend(reqs.iter().map(|r| r.ty)),
                _ => {}
            }
        }
        for t in [0u32, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 17, 18, 19, 21, 22] {
            assert!(seen.contains(&t), "type {t} never generated");
        }
    }
}
