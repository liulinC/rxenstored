// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The records a sequence of requests produces, exactly.

use super::*;
use crate::{Config, Core, Machine, Status};
use std::sync::{Arc, Mutex};
use xs_wire::{write_header, Errno};

/// A record, with its data copied whole.
type Line = (Who, u32, Op, Vec<u8>);

#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<Line>>>);

impl Sink for Rec {
    fn record(&self, r: &Record<'_>) {
        let mut data = Vec::new();
        assert!(!r.data.copy_to(&mut data, usize::MAX));
        self.0.lock().unwrap().push((r.who, r.tid, r.op, data));
    }
}

/// INTRODUCE always works.
struct Yes;

impl Machine for Yes {
    fn connect(&mut self, _: ConnId, _: u32, _: u64, _: u32) -> Result<(), Errno> {
        Ok(())
    }

    fn rebind(&mut self, _: ConnId, _: u32, _: u32) -> Result<(), Errno> {
        Ok(())
    }

    fn disconnect(&mut self, _: ConnId, _: u32) {}
}

struct T {
    core: Core,
    rec: Rec,
}

const A: Who = Who::Socket(1);

fn line(who: Who, tid: u32, op: Op, data: &[u8]) -> Line {
    (who, tid, op, data.to_vec())
}

fn req(who: Who, tid: u32, ty: MsgType, data: &[u8]) -> Line {
    line(who, tid, Op::Request(ty as u32), data)
}

impl T {
    /// A core with a socket connection (A1), logging with `sw`.
    fn new(sw: Switches) -> T {
        let mut core = Core::new(Config::default(), crate::tests::random_key());
        let rec = Rec::default();
        core.set_access_log(Some(Box::new(rec.clone())), sw);
        let mut t = T { core, rec };
        assert_eq!(t.core.open(), ConnId(1));
        assert_eq!(t.take(), [line(A, 0, Op::NewConn, b"")]);
        t
    }

    fn all() -> T {
        T::new(Switches {
            read_ops: true,
            transaction_ops: true,
            special_ops: true,
        })
    }

    fn take(&mut self) -> Vec<Line> {
        std::mem::take(&mut *self.rec.0.lock().unwrap())
    }

    /// Handles one request of `c`: the records it produced.
    fn send(&mut self, c: ConnId, ty: u32, tx: u32, payload: &[u8]) -> Vec<Line> {
        let mut bytes = Vec::new();
        write_header(&mut bytes, ty, 7, tx, payload.len() as u32);
        bytes.extend_from_slice(payload);
        self.core.feed(c, &bytes);
        assert_eq!(self.core.process_on(c, 1, &mut Yes), Status::More);
        self.take()
    }

    fn a(&mut self, ty: MsgType, tx: u32, payload: &[u8]) -> Vec<Line> {
        self.send(ConnId(1), ty as u32, tx, payload)
    }
}

#[test]
fn without_a_sink_nothing() {
    let mut t = T::all();
    t.core.set_access_log(None, Switches::default());
    t.a(MsgType::Write, 0, b"/a\0v");
    t.a(MsgType::Rm, 0, b"/nothing\0");
    t.a(MsgType::Watch, 0, b"/a\0tok\0");
    t.a(MsgType::TransactionStart, 0, b"\0");
    t.a(MsgType::Write, 1, b"/a\0w");
    t.a(MsgType::TransactionEnd, 1, b"T\0");
    t.a(MsgType::Control, 0, b"print\0hello\0");
    let g = t.core.open_domain(3);
    t.send(g, MsgType::Watch as u32, 0, b"/a\0g\0");
    t.a(MsgType::Write, 0, b"/a\0x");
    t.core.close(g);
    t.core.open();
    assert_eq!(t.take(), []);
    assert!(!t.core.output(ConnId(1)).is_empty(), "still served");
}

#[test]
fn write_class_requests_are_logged_by_default() {
    let mut t = T::new(Switches::default());
    for (ty, payload) in [
        (MsgType::Write, &b"/a\0value"[..]),
        (MsgType::Mkdir, b"/b\0"),
        (MsgType::SetPerms, b"/b\0n0\0r3\0"),
        (MsgType::Rm, b"/b\0"),
        (MsgType::ResetWatches, b""),
        (MsgType::Control, b"watches\0"),
    ] {
        assert_eq!(t.a(ty, 0, payload), [req(A, 0, ty, payload)], "{ty:?}");
    }
    // Not watched: ENOENT, which only the read switch shows.
    assert_eq!(
        t.a(MsgType::Unwatch, 0, b"/x\0t\0"),
        [req(A, 0, MsgType::Unwatch, b"/x\0t\0")]
    );
    // Other errors are.
    assert_eq!(
        t.a(MsgType::Write, 0, b"/a//b\0"),
        [
            req(A, 0, MsgType::Write, b"/a//b\0"),
            line(A, 0, Op::Error, b"EINVAL\0")
        ]
    );
    // Unknown types, and those only the daemon sends.
    for ty in [20, 99, MsgType::Error as u32, MsgType::WatchEvent as u32] {
        assert_eq!(
            t.send(ConnId(1), ty, 0, b"x\0"),
            [line(A, 0, Op::Request(ty), b"x\0"), line(A, 0, Op::Error, b"ENOSYS\0")],
            "{ty}"
        );
    }
}

#[test]
fn reads_only_with_the_read_switch() {
    let reads = [
        (MsgType::Read, &b"/tool/xenstored\0"[..]),
        (MsgType::Directory, b"/\0"),
        (MsgType::GetPerms, b"/\0"),
        (MsgType::DirectoryPart, b"/\0" as &[u8]),
    ];
    let mut t = T::new(Switches::default());
    for (ty, payload) in reads {
        let p = if ty == MsgType::DirectoryPart {
            &b"/\x000\0"[..]
        } else {
            payload
        };
        assert_eq!(t.a(ty, 0, p), [], "{ty:?}");
    }
    assert_eq!(t.a(MsgType::Read, 0, b"/missing\0"), [], "ENOENT too");
    let mut t = T::new(Switches {
        read_ops: true,
        ..Switches::default()
    });
    for (ty, payload) in reads {
        let p = if ty == MsgType::DirectoryPart {
            &b"/\x000\0"[..]
        } else {
            payload
        };
        assert_eq!(t.a(ty, 0, p), [req(A, 0, ty, p)], "{ty:?}");
    }
    assert_eq!(
        t.a(MsgType::Read, 0, b"/missing\0"),
        [
            req(A, 0, MsgType::Read, b"/missing\0"),
            line(A, 0, Op::Error, b"ENOENT\0")
        ]
    );
    // The read switch shows nothing of the other switches.
    assert_eq!(t.a(MsgType::GetDomainPath, 0, b"3\0"), []);
    assert_eq!(t.a(MsgType::TransactionStart, 0, b"\0"), []);
    assert_eq!(t.a(MsgType::TransactionEnd, 1, b"F\0"), []);
}

#[test]
fn domain_requests_only_with_the_special_switch() {
    let special = [
        (MsgType::Introduce, &b"5\x00123\x009\0"[..]),
        (MsgType::IsDomainIntroduced, b"5\0"),
        (MsgType::GetDomainPath, b"5\0"),
        (MsgType::Resume, b"5\0"),
        (MsgType::Release, b"5\0"),
    ];
    let d5 = Who::Domain(5);
    let mut t = T::new(Switches::default());
    // INTRODUCE creates the domain's connection, RELEASE closes it.
    let got: Vec<Vec<Line>> = special.iter().map(|(ty, p)| t.a(*ty, 0, p)).collect();
    assert_eq!(
        got,
        [
            vec![line(d5, 0, Op::NewConn, b"")],
            vec![],
            vec![],
            vec![],
            vec![line(d5, 0, Op::EndConn, b"")]
        ]
    );
    let mut t = T::new(Switches {
        special_ops: true,
        ..Switches::default()
    });
    let got: Vec<Vec<Line>> = special.iter().map(|(ty, p)| t.a(*ty, 0, p)).collect();
    let mut want: Vec<Vec<Line>> = special.iter().map(|(ty, p)| vec![req(A, 0, *ty, p)]).collect();
    want[0].push(line(d5, 0, Op::NewConn, b""));
    want[4].push(line(d5, 0, Op::EndConn, b""));
    assert_eq!(got, want);
    // A failure is an error, as for any request.
    assert_eq!(
        t.a(MsgType::Resume, 0, b"5\0"),
        [req(A, 0, MsgType::Resume, b"5\0"), line(A, 0, Op::Error, b"EINVAL\0")]
    );
    // Set_target is not a special one (`ox/logging.ml:312-320`).
    let t3 = t.core.open_domain(3);
    assert_eq!(t.take(), [line(Who::Domain(3), 0, Op::NewConn, b"")]);
    assert_eq!(
        t.a(MsgType::SetTarget, 0, b"3\x004\0"),
        [req(A, 0, MsgType::SetTarget, b"3\x004\0")]
    );
    t.core.close(t3);
    assert_eq!(t.take(), [line(Who::Domain(3), 0, Op::EndConn, b"")]);
}

#[test]
fn transactions() {
    let mut t = T::new(Switches::default());
    let b = t.core.open();
    let b_who = Who::Socket(b.0);
    assert_eq!(t.take(), [line(b_who, 0, Op::NewConn, b"")]);
    // Starts and ends are not logged by default; commits are.
    assert_eq!(t.a(MsgType::TransactionStart, 0, b"\0"), []);
    assert_eq!(t.a(MsgType::Write, 1, b"/t\0v"), [req(A, 1, MsgType::Write, b"/t\0v")]);
    assert_eq!(t.a(MsgType::TransactionEnd, 1, b"T\0"), [line(A, 1, Op::Commit, b"")]);
    // Read only, or aborted: nothing to commit.
    t.a(MsgType::TransactionStart, 0, b"\0");
    assert_eq!(t.a(MsgType::TransactionEnd, 2, b"T\0"), []);
    t.a(MsgType::TransactionStart, 0, b"\0");
    t.a(MsgType::Write, 3, b"/t\0w");
    assert_eq!(t.a(MsgType::TransactionEnd, 3, b"F\0"), []);
    // Re-executed and committed.
    t.a(MsgType::TransactionStart, 0, b"\0");
    t.a(MsgType::Write, 4, b"/u\0w");
    t.send(b, MsgType::Write as u32, 0, b"/other\0x");
    assert_eq!(t.a(MsgType::TransactionEnd, 4, b"T\0"), [line(A, 4, Op::Commit, b"")]);
    // A conflict: what was read changed.
    t.a(MsgType::TransactionStart, 0, b"\0");
    t.a(MsgType::Read, 5, b"/t\0");
    t.a(MsgType::Write, 5, b"/u\0z");
    t.send(b, MsgType::Rm as u32, 0, b"/t\0");
    assert_eq!(
        t.a(MsgType::TransactionEnd, 5, b"T\0"),
        [line(A, 5, Op::Conflict, b""), line(A, 5, Op::Error, b"EAGAIN\0")]
    );
    // A bad end: an error, the transaction stays.
    t.a(MsgType::TransactionStart, 0, b"\0");
    assert_eq!(
        t.a(MsgType::TransactionEnd, 6, b"X\0"),
        [line(A, 6, Op::Error, b"EINVAL\0")]
    );

    let mut t = T::new(Switches {
        transaction_ops: true,
        ..Switches::default()
    });
    assert_eq!(t.a(MsgType::TransactionStart, 0, b"\0"), [line(A, 1, Op::Start, b"")]);
    assert_eq!(t.a(MsgType::TransactionEnd, 1, b"T\0"), [line(A, 1, Op::End, b"")]);
    t.a(MsgType::TransactionStart, 0, b"\0");
    t.a(MsgType::Write, 2, b"/t\0v");
    assert_eq!(
        t.a(MsgType::TransactionEnd, 2, b"T\0"),
        [line(A, 2, Op::End, b""), line(A, 2, Op::Commit, b"")]
    );
    // Nested: an error, nothing started.
    t.a(MsgType::TransactionStart, 0, b"\0");
    assert_eq!(
        t.a(MsgType::TransactionStart, 3, b"\0"),
        [line(A, 3, Op::Error, b"EBUSY\0")]
    );
    // Unknown: an error, nothing ended.
    assert_eq!(
        t.a(MsgType::TransactionEnd, 9, b"T\0"),
        [line(A, 9, Op::Error, b"EIO\0")]
    );
}

#[test]
fn watch_events_and_the_transaction_ids_of_lines() {
    let mut t = T::new(Switches::default());
    // A WATCH in a transaction: the line has the request's id, the
    // reply and the event none (`ox/process.ml:659-664`).
    t.a(MsgType::TransactionStart, 0, b"\0");
    assert_eq!(
        t.a(MsgType::Watch, 1, b"/w\0tok\0"),
        [
            req(A, 1, MsgType::Watch, b"/w\0tok\0"),
            line(A, 0, Op::Event, b"/w\0tok\0")
        ]
    );
    assert_eq!(
        t.a(MsgType::Watch, 1, b"/w\0tok\0"),
        [
            req(A, 1, MsgType::Watch, b"/w\0tok\0"),
            line(A, 0, Op::Error, b"EEXIST\0")
        ]
    );
    // An event for a guest, relative to its home.
    let g = t.core.open_domain(3);
    let d3 = Who::Domain(3);
    assert_eq!(t.take(), [line(d3, 0, Op::NewConn, b"")]);
    t.a(MsgType::Write, 0, b"/local/domain/3/data\0");
    t.a(MsgType::SetPerms, 0, b"/local/domain/3/data\0n3\0");
    t.take();
    assert_eq!(
        t.send(g, MsgType::Watch as u32, 0, b"data\0g\0"),
        [
            req(d3, 0, MsgType::Watch, b"data\0g\0"),
            line(d3, 0, Op::Event, b"data\0g\0")
        ]
    );
    assert_eq!(
        t.a(MsgType::Write, 0, b"/local/domain/3/data\0x"),
        [
            req(A, 0, MsgType::Write, b"/local/domain/3/data\0x"),
            line(d3, 0, Op::Event, b"data\0g\0")
        ]
    );
    // A write in a transaction fires at its commit, after the line.
    t.a(MsgType::Write, 1, b"/w\0v");
    assert_eq!(
        t.a(MsgType::TransactionEnd, 1, b"T\0"),
        [line(A, 1, Op::Commit, b""), line(A, 0, Op::Event, b"/w\0tok\0")]
    );
    // A guest's reply too long for a ring is an error.
    t.a(MsgType::Mkdir, 0, b"/local/domain/3/big\0");
    t.a(MsgType::SetPerms, 0, b"/local/domain/3/big\0n3\0");
    let mut many = b"/local/domain/3/big/".to_vec();
    many.extend_from_slice(&[b'n'; 200]);
    for i in 0..30 {
        let mut p = many.clone();
        p.extend_from_slice(format!("{i}\0").as_bytes());
        t.a(MsgType::Mkdir, 0, &p);
    }
    assert_eq!(
        t.send(g, MsgType::Directory as u32, 0, b"big\0"),
        [line(d3, 0, Op::Error, b"E2BIG\0")]
    );
}

#[test]
fn watches_that_do_not_fire_say_why() {
    let mut t = T::new(Switches::default());
    let g = t.core.open_domain(3);
    let d3 = Who::Domain(3);
    t.take();
    t.a(MsgType::Write, 0, b"/a/b\0v");
    t.send(g, MsgType::Watch as u32, 0, b"/a\0t\0");
    t.send(g, MsgType::Watch as u32, 0, b"/a/b\0u\0");
    t.send(g, MsgType::Watch as u32, 0, b"@releaseDomain\0r\0");
    t.take();
    // The guest may read neither the node nor its parent.
    assert_eq!(
        t.a(MsgType::Write, 0, b"/a\0x"),
        [
            req(A, 0, MsgType::Write, b"/a\0x"),
            line(d3, 0, Op::NotFired, b"EPERM perms=[n0, n0] path=/a")
        ]
    );
    // Below a removed node, with the watch's own path.
    assert_eq!(
        t.a(MsgType::Rm, 0, b"/a\0"),
        [
            req(A, 0, MsgType::Rm, b"/a\0"),
            line(d3, 0, Op::NotFired, b"EPERM perms=[n0, n0] path=/a"),
            line(d3, 0, Op::NotFired, b"EPERM perms=[n0, n0] path=/a/b")
        ]
    );
    t.core.fire_special(b"@releaseDomain");
    assert_eq!(
        t.take(),
        [line(d3, 0, Op::NotFired, b"EPERM perms=[n0, n0] path=@releaseDomain")]
    );
    // Readable: it fires.
    t.a(MsgType::Write, 0, b"/c\0v");
    t.a(MsgType::SetPerms, 0, b"/c\0n0\0r3\0");
    t.send(g, MsgType::Watch as u32, 0, b"/c\0c\0");
    t.take();
    assert_eq!(
        t.a(MsgType::Write, 0, b"/c\0w"),
        [req(A, 0, MsgType::Write, b"/c\0w"), line(d3, 0, Op::Event, b"/c\0c\0")]
    );
}

#[test]
fn control_print() {
    let mut t = T::new(Switches::default());
    assert_eq!(
        t.a(MsgType::Control, 0, b"print\0hello\0"),
        [
            req(A, 0, MsgType::Control, b"print\0hello\0"),
            line(A, 0, Op::Print, b"hello")
        ]
    );
    assert!(t.core.output(ConnId(1)).ends_with(b"OK\0"));
    // For domain 0 only.
    let g = t.core.open_domain(3);
    t.take();
    assert_eq!(
        t.send(g, MsgType::Control as u32, 0, b"print\0x\0"),
        [req(Who::Domain(3), 0, MsgType::Control, b"print\0x\0")]
    );
}

#[test]
fn copy_is_bounded() {
    let data = Data::Parts(&[b"ab", b"", b"cd"]);
    for (max, out, cut) in [
        (0, "", true),
        (1, "a", true),
        (2, "ab", true),
        (3, "abc", true),
        (4, "abcd", false),
        (9, "abcd", false),
    ] {
        let mut v = b"<".to_vec();
        assert_eq!(data.copy_to(&mut v, max), cut, "{max}");
        assert_eq!(v, format!("<{out}").as_bytes(), "{max}");
    }
    let mut v = Vec::new();
    assert!(!Data::Parts(&[]).copy_to(&mut v, 0));
    let (p, q) = (Perms::parse(b"n0\0").unwrap(), Perms::parse(b"b3\0w5\0r0\0").unwrap());
    let all = Data::NotFired {
        perms: &[&p, &q],
        path: b"/x",
    };
    let whole = b"EPERM perms=[n0, b3 w5 r0] path=/x";
    for max in 0..whole.len() + 2 {
        let mut v = Vec::new();
        assert_eq!(all.copy_to(&mut v, max), max < whole.len(), "{max}");
        assert_eq!(v, whole[..max.min(whole.len())], "{max}");
    }
    let mut v = Vec::new();
    assert!(!Data::NotFired { perms: &[], path: b"" }.copy_to(&mut v, 99));
    assert_eq!(v, b"EPERM perms=[] path=");
}
