// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What the access log costs the event loop per request, with logging off
//! and on: reported, not asserted (timings on a shared machine are not
//! stable enough to gate on). For figures:
//!
//!   cargo test --release -p xs-daemon --test log_bench -- --nocapture

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

use std::hint::black_box;
use std::time::Instant;
use xs_core::log::{Record, Sink, Switches};
use xs_core::{Config, ConnId, Core};
use xs_daemon::log::queue::{Batch, Queue};
use xs_daemon::log::{self, Dest, Logger, Output, Settings};
use xs_wire::{write_header, MsgType};

/// The core's part alone: the record is built and handed over.
struct Null;

impl Sink for Null {
    fn record(&self, r: &Record<'_>) {
        black_box(r);
    }
}

/// The queue without its thread: the bench drains it itself, on the same
/// core, so what is left is the cost of a record as such (clock, lock,
/// copy), without lines moving between caches.
struct Local(std::sync::Arc<Queue>);

impl Sink for Local {
    fn record(&self, r: &Record<'_>) {
        self.0.access(r, 180);
    }
}

/// `n` requests of type `ty` on paths `/bench/<i % 1000>`.
fn stream(ty: MsgType, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let payload = match ty {
            MsgType::Write => format!("/bench/{}\0value-{i}", i % 1000),
            _ => format!("/bench/{}\0", i % 1000),
        };
        write_header(&mut out, ty as u32, i as u32, 0, payload.len() as u32);
        out.extend_from_slice(payload.as_bytes());
    }
    out
}

/// Nanoseconds per request of `bytes` (`n` requests), in batches of 1000.
fn run(core: &mut Core, c: ConnId, bytes: &[u8], n: usize, local: Option<&Queue>) -> f64 {
    let mut batch = Batch::default();
    let per = bytes.len() / n;
    let start = Instant::now();
    for chunk in bytes.chunks(per * 1000) {
        core.feed(c, chunk);
        core.process(c, 1000);
        let out = core.output(c).len();
        core.consume(c, out);
        log::kick();
        if let Some(q) = local {
            q.take(&mut batch);
            batch.clear();
        }
    }
    start.elapsed().as_nanos() as f64 / n as f64
}

#[derive(Clone, Copy)]
enum Mode {
    Off,
    NullSink,
    Local,
    Thread,
}

/// Per request, WRITE and READ; and the lines written and dropped.
fn measure(mode: Mode, n: usize, dir: &std::path::Path) -> ((f64, f64), (u64, u64)) {
    let _ = std::fs::remove_file(dir.join("access.log"));
    let mut logger = None;
    let q = std::sync::Arc::new(Queue::new(log::QUEUE_LINES, log::QUEUE_BYTES));
    let mut local = None;
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    match mode {
        Mode::Off => {}
        Mode::NullSink => core.set_access_log(Some(Box::new(Null)), Switches::default()),
        Mode::Local => {
            core.set_access_log(Some(Box::new(Local(q.clone()))), Switches::default());
            local = Some(&*q);
        }
        Mode::Thread => {
            let out = Output {
                dest: Dest::File(dir.join("access.log")),
                nb_files: 2,
                nb_lines: 1 << 40,
                nb_chars: 180,
            };
            let s = Settings {
                daemon: None,
                access: Some((out, Switches::default())),
                ident: "bench".into(),
                syslog_socket: dir.join("none"),
                queue_lines: log::QUEUE_LINES,
                queue_bytes: log::QUEUE_BYTES,
            };
            let l = Logger::start(&s).unwrap();
            l.install();
            log::attach(&mut core);
            logger = Some(l);
        }
    }
    let c = core.open();
    let writes = stream(MsgType::Write, n);
    let reads = stream(MsgType::Read, n);
    // Once to warm up (and to create the nodes the reads find).
    run(&mut core, c, &writes, n, local);
    let w = run(&mut core, c, &writes, n, local);
    // No record: nothing to drain (and `take` would wait).
    let r = run(&mut core, c, &reads, n, None);
    log::uninstall();
    drop(logger);
    let text = std::fs::read_to_string(dir.join("access.log")).unwrap_or_default();
    let dropped = text
        .lines()
        .filter_map(|l| l.split_once(" dropped   "))
        .map(|(_, n)| n.split(' ').next().unwrap().parse::<u64>().unwrap())
        .sum();
    ((w, r), (text.lines().count() as u64, dropped))
}

#[test]
fn cost_of_the_access_log_per_request() {
    let n = if cfg!(debug_assertions) { 20_000 } else { 1_000_000 };
    let dir = std::env::temp_dir().join(format!("rxenstored-log-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut rows = Vec::new();
    for (name, mode) in [
        ("off", Mode::Off),
        ("on, core only (null sink)", Mode::NullSink),
        ("on, queue drained on this core", Mode::Local),
        ("on, queue and log thread (file)", Mode::Thread),
    ] {
        // Best of three: the machine is shared.
        let runs: Vec<_> = (0..3).map(|_| measure(mode, n, &dir)).collect();
        let best = runs
            .iter()
            .fold((f64::MAX, f64::MAX), |a, b| (a.0.min(b.0 .0), a.1.min(b.0 .1)));
        rows.push((name, best, runs.last().unwrap().1));
    }
    let _ = std::fs::remove_dir_all(&dir);
    let build = if cfg!(debug_assertions) { "debug" } else { "release" };
    eprintln!(
        "access log cost, {build} build, {n} requests, ns per request (WRITE: logged by default; READ: not logged)"
    );
    for (name, (w, r), (lines, dropped)) in &rows {
        eprintln!("  {name:<34} WRITE {w:>7.0}   READ {r:>7.0}   (last run: {lines} lines written, {dropped} dropped)");
    }
    let (off, on) = (rows[0].1, rows[3].1);
    eprintln!(
        "  logging on - off                   WRITE {:>7.0}   READ {:>7.0}",
        on.0 - off.0,
        on.1 - off.1
    );
    assert!(rows.iter().all(|(_, (w, r), _)| *w > 0.0 && *r > 0.0));
}
