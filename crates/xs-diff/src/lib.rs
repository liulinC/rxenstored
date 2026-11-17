// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Differential test of rxenstored against oxenstored: the same seeded
//! random request sequences go to both daemons, each started fresh on its
//! own socket with the same configuration, and what comes back is
//! compared: every reply (type, request id, transaction, payload), the
//! watch events of each connection, and at the end the whole store (every
//! node's value and permissions), the `@` nodes, the per-domain node
//! counts (CONTROL `quota`) and the watches (CONTROL `watches`).
//!
//! All connections are sockets, so every request comes from dom0: what
//! depends on the caller being a guest (its quotas, its permissions, the
//! filtering of its watch events, conflict credit) is not exercised.
//!
//! The `xs-diff` binary runs seeds and shrinks what differs; the test
//! `differential` of xs-daemon runs a few seeds when `RXS_OXENSTORED`
//! names an oxenstored launcher (see `daemon`).

#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::unwrap_in_result,
        clippy::panic_in_result_fn
    )
)]

pub mod cases;
pub mod compare;
pub mod daemon;
pub mod exec;
pub mod gen;
pub mod shrink;
pub mod wire;

use compare::Diff;
use daemon::{Daemon, Spec};
use exec::Transcript;
use gen::Op;
use std::collections::BTreeSet;
use std::io;

#[derive(Debug, Clone)]
pub struct Pair {
    pub ox: Spec,
    pub rx: Spec,
    pub conns: usize,
}

/// The `@` paths the sequence names, and the two the daemons create: read
/// back at the end, as the walk from `/` does not reach them.
pub fn probes(ops: &[Op]) -> Vec<Vec<u8>> {
    let mut set: BTreeSet<Vec<u8>> = [b"@introduceDomain".to_vec(), b"@releaseDomain".to_vec()].into();
    let mut add = |r: &gen::Req| {
        if [11u32, 12, 14].contains(&r.ty) {
            let p = r.payload.split(|&b| b == 0).next().unwrap_or_default();
            if p.first() == Some(&b'@') {
                set.insert(p.to_vec());
            }
        }
    };
    for op in ops {
        match op {
            Op::One { req, .. } | Op::Split { req, .. } => add(req),
            Op::Burst { reqs, .. } => reqs.iter().for_each(&mut add),
            Op::TxBlock { body, interfere, .. } => {
                body.iter().for_each(&mut add);
                if let Some((_, r)) = interfere {
                    add(r);
                }
            }
            _ => {}
        }
    }
    set.into_iter().collect()
}

/// Both daemons, fresh, run `ops` (concurrently, each on its own thread).
pub fn run_pair(pair: &Pair, ops: &[Op]) -> io::Result<(Transcript, Transcript)> {
    let probes = probes(ops);
    let run = |spec: &Spec| -> io::Result<Transcript> {
        let mut d = Daemon::start(spec)?;
        let mut t = exec::execute(&mut d, ops, pair.conns, &probes);
        // The launcher's stand-in for Xen says on stderr when a request
        // reached it: a difference, so that it is seen.
        let shim: Vec<String> = d
            .stderr()
            .lines()
            .filter(|l| l.contains("xenshim"))
            .map(String::from)
            .collect();
        if !shim.is_empty() {
            t.end
                .insert("stderr of the daemon: calls into Xen".into(), shim.join("\n"));
        }
        Ok(t)
    };
    std::thread::scope(|s| {
        let ox = s.spawn(|| run(&pair.ox));
        let rx = run(&pair.rx);
        let ox = ox
            .join()
            .map_err(|_| io::Error::other("the oxenstored thread panicked"))?;
        Ok((ox?, rx?))
    })
}

/// The differences on `ops`, those `tolerated` left out.
pub fn diffs(pair: &Pair, ops: &[Op], tolerated: &dyn Fn(&str) -> bool) -> io::Result<Vec<Diff>> {
    let (ox, rx) = run_pair(pair, ops)?;
    Ok(compare::compare(&ox, &rx, tolerated))
}

/// A tolerance list: one signature per line, `*` at the end for a prefix;
/// blank lines and lines starting with `#` ignored.
pub fn tolerance(text: &str) -> impl Fn(&str) -> bool + use<> {
    let pats: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    move |sig: &str| {
        pats.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => sig.starts_with(prefix),
            None => sig == p,
        })
    }
}
