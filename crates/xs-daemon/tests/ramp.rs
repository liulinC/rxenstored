// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The load generator's shipped scenario against the daemon.

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

use common::Daemon;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use xs_bench::run::{ramp, Config};
use xs_bench::scenario::Scenario;

#[test]
fn shipped_scenario_gives_the_errors_oxenstored_gives_and_leaves_the_store_empty() {
    xs_sys::raise_fd_limit().unwrap();
    let mut d = Daemon::start();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../xs-bench/scenarios/xcpng83-hvm-2vbd-1vif");
    let scenario = Scenario::load(&dir).unwrap();
    let cfg = Config {
        socket: d.socket.clone(),
        prefix: "/rxsbench".into(),
        vms: 60,
        parallel: 8,
        band: 20,
        first_domid: 10000,
        daemon_pid: Some(d.pid()),
        teardown: true,
        keep: false,
        timeout: Duration::from_secs(60),
    };
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.bands.len(), 6);
    // What oxenstored 4.17 gives on the same scenario (xs-bench against
    // the oxenstored of an XCP-ng 8.3 host, 600 VMs): only removals
    // under a missing parent, 2 per start once the sandbox exists and 6 per
    // stop; 411 watch events per start and 86 per stop.
    let errors = report.errors();
    let kinds: BTreeSet<&str> = errors.keys().map(String::as_str).collect();
    assert_eq!(kinds, ["rm: ENOENT"].into_iter().collect(), "{errors:?}");
    for (i, band) in report.bands.iter().enumerate() {
        assert_eq!(band.vms, 20);
        assert!(band.daemon_cpu.is_some());
        let n = band.vms as u64;
        let (events, rm_errors) = if band.phase == "start" { (411, 2) } else { (86, 6) };
        assert_eq!(band.events, events * n, "band {i}");
        // The first starts race to create shared parents: a few more there.
        if i > 0 {
            assert_eq!(band.errors.get("rm: ENOENT").copied(), Some(rm_errors * n), "band {i}");
        }
    }

    // Back to the initial store.
    let mut c = d.client();
    assert_eq!(c.ls(0, "/"), ["@introduceDomain", "@releaseDomain", "local", "tool"]);
    assert!(c.ls(0, "/local").is_empty());
    assert_eq!(c.ls(0, "/tool"), ["xenstored"]);
    assert!(d.alive());
}
