// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! rxenstored side by side with oxenstored (crate `xs-diff`): the same
//! seeded random request sequences on three socket connections to each,
//! replies, watch events and the final store compared. Skipped unless
//! `RXS_OXENSTORED` names an oxenstored launcher (see `xs_diff::daemon`);
//! `RXS_DIFF_SEEDS` sets how many sequences (default 20).
//!
//! Then, against rxenstored alone, answers oxenstored 4.17 gave: where the
//! two differed and now agree, as tests; where they differ, as ignored
//! tests, each saying what rxenstored does instead.

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

mod common;

use common::{Client, Daemon};
use xs_diff::daemon::{Kind, Spec};
use xs_diff::gen::{generate, GenOpts};
use xs_diff::Pair;
use xs_wire::{nul_terminated, MsgType};

/// The differences known and triaged, by signature (`xs_diff::compare`).
const KNOWN: &str = "
# Different on purpose, documented: DIRECTORY_PART is implemented.
DIRECTORY_PART *
# The reply text of CONTROL compact and trim.
CONTROL compact: ox data / rx OK
CONTROL trim: ox data / rx OK
# IS_DOMAIN_INTRODUCED of something that is not a number: EIO there, EINVAL here.
IS_DOMAIN_INTRODUCED: ox EIO / rx EINVAL
# Transaction ids: a commit that had to be re-executed uses one up there.
TRANSACTION_START: ids numbered differently
# The order of the events one change sends to several watches of one connection.
watch events: same set, other order
# Commit: merged by the lowest paths read and written there, re-executed here;
# each refuses some commits the other makes.
TRANSACTION_END T: ox OK / rx EAGAIN
TRANSACTION_END T: ox EAGAIN / rx OK
";

fn pair() -> Option<Pair> {
    let ox = std::env::var_os("RXS_OXENSTORED")?;
    let spec = |kind, exe: std::path::PathBuf| Spec {
        kind,
        exe,
        conf_extra: String::new(),
    };
    Some(Pair {
        ox: spec(Kind::Ox, ox.into()),
        rx: spec(Kind::Rx, env!("CARGO_BIN_EXE_rxenstored").into()),
        conns: 3,
    })
}

#[test]
fn random_sequences_get_the_answers_oxenstored_gives() {
    let Some(pair) = pair() else {
        eprintln!("skipped: RXS_OXENSTORED does not name an oxenstored launcher");
        return;
    };
    let seeds: u64 = std::env::var("RXS_DIFF_SEEDS").map_or(20, |s| s.parse().unwrap());
    // The classes left out are reported on their own by `xs-diff`.
    let opts = GenOpts {
        framing: false,
        wide_domids: false,
        at_slash: false,
        ..GenOpts::default()
    };
    let known = xs_diff::tolerance(KNOWN);
    let mut unexpected = Vec::new();
    for seed in 1..=seeds {
        let ops = generate(seed, &opts);
        let all = xs_diff::diffs(&pair, &ops, &|_| false).unwrap();
        // The first operation that differs decides: once the stores differ
        // (a commit one daemon refuses), what follows differs too. It is
        // explained if one of its differences is known.
        let first = all.iter().map(|d| d.step.unwrap_or(usize::MAX)).min();
        let at_first: Vec<_> = all
            .iter()
            .filter(|d| Some(d.step.unwrap_or(usize::MAX)) == first)
            .collect();
        if !at_first.is_empty() && !at_first.iter().any(|d| known(&d.sig)) {
            for d in at_first {
                unexpected.push(format!(
                    "seed {seed}, operation {:?}: {}\n{}",
                    d.step.map(|s| ops[s].to_string()),
                    d.sig,
                    d.detail
                ));
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "{} differences (xs-diff --seed N --seeds 1 --no-framing --no-wide-domids --no-at-slash shrinks one):\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
}

fn z(parts: &[&str]) -> Vec<u8> {
    nul_terminated(&parts.iter().map(|p| p.as_bytes()).collect::<Vec<_>>())
}

fn client() -> (Daemon, Client) {
    let d = Daemon::start();
    let c = d.client();
    (d, c)
}

#[test]
#[ignore = "differs from oxenstored: EINVAL here, EIO there"]
fn is_domain_introduced_of_an_empty_domid_is_eio() {
    let (_d, mut c) = client();
    assert_eq!(c.error(MsgType::IsDomainIntroduced, 0, b"\0"), "EIO");
}

#[test]
#[ignore = "differs from oxenstored: both answer OK\\0 here"]
fn control_compact_and_trim_answer_their_own_text() {
    let (_d, mut c) = client();
    assert_eq!(c.ok(MsgType::Control, 0, &z(&["compact"])), b"Compacted");
    assert_eq!(c.ok(MsgType::Control, 0, &z(&["trim"])), b"trimmed");
}

#[test]
#[ignore = "differs from oxenstored: the ids here go on from the last one given"]
fn a_commit_that_was_re_executed_uses_up_a_transaction_id() {
    let (d, mut c) = client();
    let mut other = d.client();
    let t1 = c.start();
    c.write(t1, "/a", "1");
    other.write(0, "/b", "2");
    c.end(t1, true).unwrap();
    assert_eq!(c.start(), t1 + 2);
}

#[test]
#[ignore = "differs from oxenstored: the oldest watch fires first here"]
fn one_change_fires_the_watches_of_one_connection_newest_first() {
    let (d, mut c) = client();
    let mut w = d.client();
    for t in ["first", "second", "third"] {
        w.watch("/w", t);
    }
    w.wait_events(3);
    c.write(0, "/w", "v");
    w.wait_events(6);
    let tokens: Vec<&str> = w.events[3..].iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(tokens, ["third", "second", "first"]);
}

#[test]
fn control_quota_in_a_transaction_counts_the_store_the_transaction_started_from() {
    let (d, mut c) = client();
    let mut other = d.client();
    let before = c.ok(MsgType::Control, 0, &z(&["quota", "0"]));
    let t = c.start();
    other.write(0, "/q/r/s", "v");
    assert_eq!(c.ok(MsgType::Control, t, &z(&["quota", "0"])), before);
}

#[test]
fn the_root_whose_owner_is_released_reads_as_owner_minus_one_printed_unsigned() {
    let (_d, mut c) = client();
    c.ok(MsgType::SetPerms, 0, &z(&["/", "n5"]));
    // Domain 5 was never introduced: EINVAL, but its nodes go all the same.
    let _ = c.call(MsgType::Release, 0, &z(&["5"]));
    assert_eq!(c.ok(MsgType::GetPerms, 0, &z(&["/"])), b"n9223372036854775807\0");
}
