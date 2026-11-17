// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Fixed sequences, for questions a random sequence answers only by
//! chance: `xs-diff --case NAME` prints both daemons' answers side by side.

use crate::gen::{Op, Req, Tx};

fn z(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
        out.push(0);
    }
    out
}

pub fn one(conn: u8, ty: u32, payload: Vec<u8>) -> Op {
    Op::One {
        conn,
        req: Req {
            ty,
            req_id: 1,
            tx: Tx::Zero,
            payload,
        },
    }
}

fn in_tx(conn: u8, ty: u32, tx: u16, payload: Vec<u8>) -> Op {
    Op::One {
        conn,
        req: Req {
            ty,
            req_id: 1,
            tx: Tx::Nth(tx),
            payload,
        },
    }
}

/// `@` paths with a `/`: what node is made, what the watches see.
fn at_paths() -> Vec<Op> {
    let mut ops = vec![
        one(1, 4, z(&[b"@a/b", b"w-at-a-b"])),
        one(1, 4, z(&[b"@a", b"w-at-a"])),
        one(1, 4, z(&[b"@", b"w-at"])),
        one(1, 4, z(&[b"/", b"w-root"])),
        one(1, 4, z(&[b"@/", b"w-at-slash"])),
    ];
    for p in [&b"@/"[..], b"@a/b", b"@a", b"@a/b/c", b"@introduceDomain/x", b"@//"] {
        ops.push(one(0, 11, [p, b"\0v"].concat()));
        ops.push(one(0, 2, z(&[p])));
        ops.push(one(0, 3, z(&[p])));
        ops.push(one(0, 1, z(&[p])));
    }
    ops.push(one(0, 12, z(&[b"@m/n"])));
    ops.push(one(0, 14, z(&[b"@a/b", b"n5"])));
    ops.push(one(0, 3, z(&[b"@a/b"])));
    ops.push(one(0, 13, z(&[b"@a/b"])));
    ops.push(one(0, 13, z(&[b"@a"])));
    ops.push(one(0, 2, z(&[b"@a/b"])));
    // Where the nodes are: listed under the root?
    ops.push(one(0, 1, z(&[b"/"])));
    // The same in a transaction, then a write elsewhere first.
    ops.push(one(0, 6, b"\0".to_vec()));
    ops.push(in_tx(0, 11, 0, [&b"@t/x"[..], b"\0v"].concat()));
    ops.push(in_tx(0, 7, 0, b"T\0".to_vec()));
    ops.push(one(0, 6, b"\0".to_vec()));
    ops.push(in_tx(0, 11, 1, [&b"@u/x"[..], b"\0v"].concat()));
    ops.push(one(1, 11, [&b"/elsewhere"[..], b"\0v"].concat()));
    ops.push(in_tx(0, 7, 1, b"T\0".to_vec()));
    ops.push(one(0, 1, z(&[b"/"])));
    ops.push(one(0, 2, z(&[b"@t/x"])));
    ops.push(one(0, 2, z(&[b"@u/x"])));
    ops
}

/// Transaction ids after a commit that had to be re-executed, and the
/// order of the events of one change to two watches of one connection.
fn tx_ids_and_event_order() -> Vec<Op> {
    vec![
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 11, 0, [&b"/a"[..], b"\0", b"1"].concat()),
        one(1, 11, [&b"/b"[..], b"\0", b"2"].concat()),
        in_tx(0, 7, 0, b"T\0".to_vec()),
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 7, 1, b"T\0".to_vec()),
        one(2, 4, z(&[b"/w", b"first"])),
        one(2, 4, z(&[b"/w", b"second"])),
        one(2, 4, z(&[b"/w", b"third"])),
        one(0, 11, [&b"/w"[..], b"\0v"].concat()),
    ]
}

/// The watch events of commits and of single requests: which requests of
/// a transaction fire at its commit (one written twice, written then
/// removed, failed, read only, made by a commit merged or run again,
/// on nodes made and removed in it, SET_PERMS), the order of the events
/// one change sends to the watches of a connection (several tokens on
/// one path, a watch on an ancestor, an RM with watches below), and
/// where they come among the replies.
fn commit_events() -> Vec<Op> {
    let w = |c: u8, p: &[u8], v: &[u8]| one(c, 11, [p, b"\0", v].concat());
    let w_tx = |c: u8, k: u16, p: &[u8], v: &[u8]| in_tx(c, 11, k, [p, b"\0", v].concat());
    let watch = |c: u8, p: &[u8], t: &[u8]| one(c, 4, z(&[p, t]));
    let start = || one(0, 6, b"\0".to_vec());
    let end = |k: u16| in_tx(0, 7, k, b"T\0".to_vec());
    let mut ops = Vec::new();
    for p in [
        &b"/A"[..],
        b"/B",
        b"/C",
        b"/D",
        b"/E1",
        b"/E2",
        b"/E3",
        b"/E4",
        b"/F",
        b"/G",
    ] {
        ops.push(one(0, 12, z(&[p])));
    }
    for p in [&b"/E3/n"[..], b"/E4/n", b"/H/a/b/c", b"/H/b", b"/H/c"] {
        ops.push(w(0, p, b"v"));
    }
    // Several tokens on one path; a node's watch older than its ancestor's.
    for (p, t) in [
        (&b"/A"[..], &b"a1"[..]),
        (b"/A", b"a2"),
        (b"/A", b"a3"),
        (b"/B/x", b"bx"),
        (b"/B", b"b"),
        (b"/B2/x", b"b2x"),
        (b"/B2", b"b2"),
        (b"/C", b"c"),
        (b"/D", b"d"),
        (b"/E1", b"e1"),
        (b"/E2", b"e2"),
        (b"/E3", b"e3"),
        (b"/E4", b"e4"),
        (b"/F/n/a", b"fna"),
        (b"/F/n", b"fn"),
        (b"/F", b"f"),
        (b"/G", b"g"),
        (b"/", b"slash"),
    ] {
        ops.push(watch(2, p, t));
    }
    // Below /H, registered out of order, one path twice, one below a
    // node that does not exist.
    for (p, t) in [
        (&b"/H/c"[..], &b"hc"[..]),
        (b"/H/a/b/c", b"habc"),
        (b"/H/b", b"hb"),
        (b"/H/a", b"ha1"),
        (b"/H/a/b", b"hab"),
        (b"/H/a", b"ha2"),
        (b"/H", b"h"),
        (b"/H/z/q", b"hzq"),
        (b"/H/z", b"hz"),
    ] {
        ops.push(watch(2, p, t));
    }
    ops.push(watch(1, b"/H/a", b"c1ha"));
    ops.push(watch(1, b"/", b"c1root"));
    ops.push(watch(0, b"/A", b"c0a"));
    // 0: one path written twice; the committer watches it too.
    ops.push(start());
    ops.push(w_tx(0, 0, b"/A/x", b"1"));
    ops.push(w_tx(0, 0, b"/A/x", b"2"));
    ops.push(end(0));
    // 1, 2: written then removed, below a node that exists, and below
    // one the transaction makes.
    ops.push(start());
    ops.push(w_tx(0, 1, b"/B/x", b"v"));
    ops.push(in_tx(0, 13, 1, z(&[b"/B/x"])));
    ops.push(end(1));
    ops.push(start());
    ops.push(w_tx(0, 2, b"/B2/x", b"v"));
    ops.push(in_tx(0, 13, 2, z(&[b"/B2/x"])));
    ops.push(end(2));
    // 3: requests that fail or change nothing, and one that writes.
    ops.push(start());
    ops.push(in_tx(0, 13, 3, z(&[b"/C/missing/x"])));
    ops.push(in_tx(0, 12, 3, z(&[b"/C"])));
    ops.push(w_tx(0, 3, b"/C/big/y", &[b'v'; 3000]));
    ops.push(in_tx(0, 14, 3, z(&[b"/C/none", b"n0"])));
    ops.push(in_tx(0, 13, 3, z(&[b"/C/none"])));
    ops.push(w_tx(0, 3, b"/C/y", b"v"));
    ops.push(end(3));
    // 4: read only.
    ops.push(start());
    ops.push(in_tx(0, 2, 4, z(&[b"/D"])));
    ops.push(in_tx(0, 1, 4, z(&[b"/D"])));
    ops.push(in_tx(0, 3, 4, z(&[b"/D"])));
    ops.push(in_tx(0, 13, 4, z(&[b"/D/missing"])));
    ops.push(end(4));
    // 5: MKDIR, the node written meanwhile (run again at the commit).
    ops.push(start());
    ops.push(in_tx(0, 12, 5, z(&[b"/E1/n"])));
    ops.push(w(1, b"/E1/n", b"v"));
    ops.push(end(5));
    // 6: MKDIR, something else written meanwhile (merged).
    ops.push(start());
    ops.push(in_tx(0, 12, 6, z(&[b"/E2/n"])));
    ops.push(w(1, b"/elsewhere", b"v"));
    ops.push(end(6));
    // 7: RM, the node removed meanwhile.
    ops.push(start());
    ops.push(in_tx(0, 13, 7, z(&[b"/E3/n"])));
    ops.push(one(1, 13, z(&[b"/E3/n"])));
    ops.push(end(7));
    // 8: MKDIR of a node that exists, which is removed meanwhile.
    ops.push(start());
    ops.push(in_tx(0, 12, 8, z(&[b"/E4/n"])));
    ops.push(w_tx(0, 8, b"/E4/w", b"v"));
    ops.push(one(1, 13, z(&[b"/E4/n"])));
    ops.push(end(8));
    // 9: a node made and removed in the transaction.
    ops.push(start());
    ops.push(w_tx(0, 9, b"/F/n/a", b"v"));
    ops.push(in_tx(0, 13, 9, z(&[b"/F/n"])));
    ops.push(end(9));
    // 10: SET_PERMS.
    ops.push(start());
    ops.push(in_tx(0, 14, 10, z(&[b"/G", b"n0", b"r5"])));
    ops.push(w_tx(0, 10, b"/G/k", b"v"));
    ops.push(in_tx(0, 14, 10, z(&[b"/G/k", b"n0", b"b7"])));
    ops.push(end(10));
    // RM of a subtree with watches below, alone, then in a transaction
    // (11) with SET_PERMS and a write below it before.
    ops.push(one(0, 13, z(&[b"/H/a"])));
    ops.push(w(0, b"/H/a/b/c", b"v"));
    ops.push(start());
    ops.push(in_tx(0, 14, 11, z(&[b"/H/b", b"n0"])));
    ops.push(w_tx(0, 11, b"/H/a/b", b"w"));
    ops.push(in_tx(0, 13, 11, z(&[b"/H"])));
    ops.push(end(11));
    // 12: the root.
    ops.push(start());
    ops.push(in_tx(0, 12, 12, z(&[b"/"])));
    ops.push(w_tx(0, 12, b"/A/y", b"v"));
    ops.push(end(12));
    ops.push(one(0, 12, z(&[b"/"])));
    // A single request of the committer, with its own watch.
    ops.push(w(0, b"/A/z", b"v"));
    ops.push(one(0, 13, z(&[b"/A"])));
    // 13: the same value written twice; a MKDIR of what it made.
    ops.push(start());
    ops.push(w_tx(0, 13, b"/A/s", b"v"));
    ops.push(w_tx(0, 13, b"/A/s", b"v"));
    ops.push(in_tx(0, 12, 13, z(&[b"/A/s"])));
    ops.push(end(13));
    // A watch registered again is the newest.
    ops.push(one(2, 5, z(&[b"/A", b"a2"])));
    ops.push(watch(2, b"/A", b"a2"));
    ops.push(w(0, b"/A", b"v"));
    // A relative watch and an absolute one on one path.
    ops.push(watch(2, b"rel", b"r1"));
    ops.push(watch(2, b"/local/domain/0/rel", b"r2"));
    ops.push(w(0, b"/local/domain/0/rel/x", b"v"));
    // Names in byte order, a node before what is below it, and a chain
    // below a node that does not exist.
    for p in [&b"/S/b"[..], b"/S/B", b"/S/10", b"/S/9", b"/S/a-", b"/S/a/x"] {
        ops.push(w(0, p, b"v"));
    }
    for (c, p, t) in [
        (2u8, &b"/S/b"[..], &b"sb"[..]),
        (2, b"/S/a/x", b"sax"),
        (2, b"/S/B", b"sB"),
        (2, b"/S/a-", b"sa-"),
        (2, b"/S/9", b"s9"),
        (2, b"/S/a", b"sa"),
        (2, b"/S/10", b"s10"),
        (2, b"/S/q/r/s/t", b"sqrst"),
        (2, b"/S/q/r/u", b"sqru"),
        (2, b"/S/q", b"sq"),
        (1, b"/S/b", b"c1sb"),
        (1, b"/S/a", b"c1sa"),
    ] {
        ops.push(watch(c, p, t));
    }
    ops.push(one(0, 13, z(&[b"/S"])));
    // Everything.
    ops.push(one(0, 13, z(&[b"/"])));
    ops
}

/// A WRITE refused for its size, where its parent is missing; and
/// CONTROL quota in a transaction after a write elsewhere.
fn too_big() -> Vec<Op> {
    let big = [&b"/nx/y"[..], b"\0", &[b'v'; 3000][..]].concat();
    let big_tx = [&b"/ny/y"[..], b"\0", &[b'v'; 3000][..]].concat();
    vec![
        one(0, 11, big),
        one(0, 2, z(&[b"/nx"])),
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 11, 0, big_tx),
        in_tx(0, 2, 0, z(&[b"/ny"])),
        in_tx(0, 7, 0, b"T\0".to_vec()),
        one(0, 2, z(&[b"/ny"])),
        one(0, 6, b"\0".to_vec()),
        one(1, 11, [&b"/q/r/s"[..], b"\0v"].concat()),
        in_tx(0, 0, 1, z(&[b"quota", b"0"])),
        one(0, 0, z(&[b"quota", b"0"])),
        in_tx(0, 7, 1, b"F\0".to_vec()),
        // The refused WRITE with a WRITE that succeeds, nothing else written.
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 11, 2, [&b"/nz/y"[..], b"\0", &[b'v'; 3000][..]].concat()),
        in_tx(0, 11, 2, [&b"/ok"[..], b"\0v"].concat()),
        in_tx(0, 7, 2, b"T\0".to_vec()),
        one(0, 2, z(&[b"/nz"])),
        // The same, with a write elsewhere before the commit.
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 11, 3, [&b"/nw/y"[..], b"\0", &[b'v'; 3000][..]].concat()),
        in_tx(0, 11, 3, [&b"/ok2"[..], b"\0v"].concat()),
        one(1, 11, [&b"/elsewhere"[..], b"\0v"].concat()),
        in_tx(0, 7, 3, b"T\0".to_vec()),
        one(0, 2, z(&[b"/nw"])),
    ]
}

/// A request in a transaction that fails, then a commit that cannot be
/// merged as it is.
fn bad_end_in_tx() -> Vec<Op> {
    vec![
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 7, 0, b"TT\0".to_vec()),
        one(1, 11, [&b"/elsewhere"[..], b"\0v"].concat()),
        in_tx(0, 11, 0, [&b"/x"[..], b"\0v"].concat()),
        in_tx(0, 7, 0, b"T\0".to_vec()),
        one(0, 6, b"\0".to_vec()),
        in_tx(1, 2, 1, z(&[b"/nonexistent"])),
        one(1, 11, [&b"/elsewhere"[..], b"\0w"].concat()),
        in_tx(0, 11, 1, [&b"/y"[..], b"\0v"].concat()),
        in_tx(0, 7, 1, b"T\0".to_vec()),
        // A request that succeeds, but is not a store operation.
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 10, 2, z(&[b"5"])),
        one(1, 11, [&b"/elsewhere"[..], b"\0x"].concat()),
        in_tx(0, 11, 2, [&b"/z"[..], b"\0v"].concat()),
        in_tx(0, 7, 2, b"T\0".to_vec()),
        // The same with nothing written meanwhile.
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 10, 3, z(&[b"5"])),
        in_tx(0, 11, 3, [&b"/zz"[..], b"\0v"].concat()),
        in_tx(0, 7, 3, b"T\0".to_vec()),
    ]
}

/// A transaction that commits while nothing else was committed.
fn quiet_commit() -> Vec<Op> {
    vec![
        one(0, 11, [&b"/x"[..], b"\0", b"1"].concat()),
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 11, 0, [&b"/x"[..], b"\0", b"2"].concat()),
        one(1, 14, z(&[b"/x", b"n5"])),
        in_tx(0, 7, 0, b"T\0".to_vec()),
        one(0, 2, z(&[b"/x"])),
    ]
}

/// The CONTROL commands of oxenstored 4.17 a socket may send.
fn control() -> Vec<Op> {
    [
        &b"quota\x000\0"[..],
        b"quota\x005\0",
        b"quota\0abc\0",
        b"watches\0",
        b"print\0hello\0",
        b"mfn\x000\0",
        b"xenbus\x000\0",
        b"compact\0",
        b"trim\0",
        b"txn\x000\0",
        b"nonsense\0",
        b"",
    ]
    .iter()
    .map(|p| one(0, 0, p.to_vec()))
    .collect()
}

/// The domain requests, for domains that do not exist (INTRODUCE cannot
/// map a ring without Xen).
fn domains() -> Vec<Op> {
    vec![
        one(0, 8, z(&[b"5", b"4096", b"7"])),
        one(0, 17, z(&[b"5"])),
        one(0, 10, z(&[b"5"])),
        one(0, 19, z(&[b"5", b"3"])),
        one(0, 18, z(&[b"5"])),
        one(0, 9, z(&[b"5"])),
        one(0, 9, z(&[b"0"])),
        one(0, 17, z(&[b"32752"])),
        one(0, 17, z(&[b""])),
        one(0, 10, z(&[b"abc"])),
    ]
}

/// Permissions naming domids outside 0..2^32, and RELEASE of a domain
/// that was never introduced but owns nodes.
fn wide_domids() -> Vec<Op> {
    let mut ops = Vec::new();
    for (p, d) in [
        (&b"/w1"[..], &b"n-1"[..]),
        (b"/w2", b"n99999999999"),
        (b"/w3", b"n4294967296"),
        (b"/w4", b"n4294967295"),
        (b"/w5", b"n5"),
    ] {
        ops.push(one(0, 11, z(&[p])));
        ops.push(one(0, 14, z(&[p, d])));
        ops.push(one(0, 3, z(&[p])));
    }
    ops.push(one(0, 0, z(&[b"quota", b"-1"])));
    ops.push(one(0, 9, z(&[b"-1"])));
    ops.push(one(0, 9, z(&[b"5"])));
    ops.push(one(0, 2, z(&[b"/w1"])));
    ops.push(one(0, 2, z(&[b"/w5"])));
    ops
}

/// The root after the domain that owns it went: what its owner reads as,
/// in the nodes created below it since, in CONTROL quota, in a
/// transaction, given back to SET_PERMS; and a node owned by 4294967295.
fn lost_owner() -> Vec<Op> {
    vec![
        one(0, 11, z(&[b"/kept"])),
        one(0, 14, z(&[b"/", b"n5", b"r7"])),
        one(0, 11, z(&[b"/gone"])),
        one(0, 14, z(&[b"/gone", b"b5"])),
        one(0, 9, z(&[b"5"])),
        one(0, 3, z(&[b"/"])),
        one(0, 3, z(&[b"/kept"])),
        one(0, 2, z(&[b"/gone"])),
        one(0, 11, [&b"/new/a"[..], b"\0v"].concat()),
        one(0, 12, z(&[b"/new/b"])),
        one(0, 3, z(&[b"/new"])),
        one(0, 3, z(&[b"/new/a"])),
        one(0, 1, z(&[b"/new"])),
        one(0, 0, z(&[b"quota", b"-1"])),
        one(0, 0, z(&[b"quota", b"4294967295"])),
        one(0, 0, z(&[b"quota", b"9223372036854775807"])),
        one(0, 0, z(&[b"quota", b"0x7fffffffffffffff"])),
        one(0, 0, z(&[b"quota", b"0x4000000000000000"])),
        // A domain numbered 4294967295 is another owner.
        one(0, 11, z(&[b"/w4"])),
        one(0, 14, z(&[b"/w4", b"n4294967295"])),
        one(0, 11, z(&[b"/w4/c"])),
        one(0, 3, z(&[b"/w4/c"])),
        one(0, 0, z(&[b"quota", b"-1"])),
        one(0, 0, z(&[b"quota", b"4294967295"])),
        // In a transaction.
        one(0, 6, b"\0".to_vec()),
        in_tx(0, 3, 0, z(&[b"/"])),
        in_tx(0, 11, 0, [&b"/new/t"[..], b"\0v"].concat()),
        in_tx(0, 3, 0, z(&[b"/new/t"])),
        in_tx(0, 0, 0, z(&[b"quota", b"-1"])),
        in_tx(0, 7, 0, b"T\0".to_vec()),
        one(0, 0, z(&[b"quota", b"-1"])),
        // The printed owner given back.
        one(0, 14, z(&[b"/new", b"n9223372036854775807"])),
        one(0, 14, z(&[b"/", b"n9223372036854775807", b"r7"])),
        one(0, 3, z(&[b"/"])),
        // The root given an owner again.
        one(0, 14, z(&[b"/", b"n0"])),
        one(0, 3, z(&[b"/"])),
        one(0, 0, z(&[b"quota", b"-1"])),
        one(0, 0, z(&[b"quota", b"0"])),
        // RELEASE of -1 and of 4294967295, and -1 given by SET_PERMS.
        one(0, 9, z(&[b"-1"])),
        one(0, 9, z(&[b"4294967295"])),
        one(0, 1, z(&[b"/"])),
        one(0, 14, z(&[b"/kept", b"n0x7fffffffffffffff"])),
        one(0, 3, z(&[b"/kept"])),
    ]
}

pub fn case(name: &str) -> Option<Vec<Op>> {
    match name {
        "lost-owner" => Some(lost_owner()),
        "at-paths" => Some(at_paths()),
        "quiet-commit" => Some(quiet_commit()),
        "control" => Some(control()),
        "domains" => Some(domains()),
        "wide-domids" => Some(wide_domids()),
        "bad-end-in-tx" => Some(bad_end_in_tx()),
        "too-big" => Some(too_big()),
        "tx-ids-and-event-order" => Some(tx_ids_and_event_order()),
        "commit-events" => Some(commit_events()),
        _ => None,
    }
}

pub const NAMES: [&str; 10] = [
    "lost-owner",
    "too-big",
    "tx-ids-and-event-order",
    "commit-events",
    "at-paths",
    "quiet-commit",
    "control",
    "domains",
    "wide-domids",
    "bad-end-in-tx",
];
