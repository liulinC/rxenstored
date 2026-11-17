// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use xs_diff::compare::{show_item, Diff};
use xs_diff::daemon::{Kind, Spec};
use xs_diff::gen::{generate, GenOpts, Op};
use xs_diff::{cases, Pair};

const USAGE: &str = "\
xs-diff: the same request sequences to oxenstored and rxenstored, compared

  xs-diff [options]                 run seeds, shrink and print each new difference
  xs-diff --case NAME [options]     run a fixed sequence, print both daemons' answers
  xs-diff --seed N --only I,J,...   the same with operations I, J, ... of seed N's sequence

  --ox PATH          oxenstored launcher (default $RXS_OXENSTORED)
  --rx PATH          rxenstored (default $RXS_RXENSTORED, else next to xs-diff)
  --seed N           first seed (default 1)
  --seeds N          how many seeds (default 100)
  --minutes M        stop starting seeds after M minutes
  --steps N          operations per sequence (default 150)
  --conns N          socket connections per daemon (default 3)
  --jobs N           sequences run at once (default 2)
  --tolerate FILE    signatures to leave out, one per line (`*` at the end: prefix)
  --no-shrink        do not shrink
  --budget N         runs a shrink may take (default 400)
  --introduce        also INTRODUCE (answers depend on the absence of Xen)
  --no-framing       no malformed framing (over-long messages)
  --no-quota-bursts  no bursts of 12 transactions or 515 watches
  --no-wide-domids   no permissions naming a domid < 0 or >= 2^32
  --no-at-slash      no `@` paths holding a `/`
  --conf LINE        a configuration line for both daemons (repeatable)
";

struct Args {
    ox: Option<PathBuf>,
    rx: Option<PathBuf>,
    seed: u64,
    seeds: u64,
    minutes: Option<f64>,
    gen: GenOpts,
    jobs: usize,
    tolerate: String,
    shrink: bool,
    budget: usize,
    conf: String,
    case: Option<String>,
    only: Option<Vec<usize>>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        ox: std::env::var_os("RXS_OXENSTORED").map(PathBuf::from),
        rx: std::env::var_os("RXS_RXENSTORED").map(PathBuf::from),
        seed: 1,
        seeds: 100,
        minutes: None,
        gen: GenOpts::default(),
        jobs: 2,
        tolerate: String::new(),
        shrink: true,
        budget: 400,
        conf: String::new(),
        case: None,
        only: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(o) = it.next() {
        let mut val = || it.next().ok_or(format!("{o} needs a value"));
        let num = |v: String| v.parse::<u64>().map_err(|e| format!("{o}: {e}"));
        match o.as_str() {
            "--ox" => a.ox = Some(val()?.into()),
            "--rx" => a.rx = Some(val()?.into()),
            "--seed" => a.seed = num(val()?)?,
            "--seeds" => a.seeds = num(val()?)?,
            "--minutes" => a.minutes = Some(val()?.parse::<f64>().map_err(|e| format!("{o}: {e}"))?),
            "--steps" => a.gen.steps = usize::try_from(num(val()?)?).map_err(|e| e.to_string())?,
            "--conns" => a.gen.conns = usize::try_from(num(val()?)?).map_err(|e| e.to_string())?.clamp(1, 32),
            "--jobs" => a.jobs = usize::try_from(num(val()?)?).map_err(|e| e.to_string())?.clamp(1, 8),
            "--budget" => a.budget = usize::try_from(num(val()?)?).map_err(|e| e.to_string())?,
            "--tolerate" => {
                let f = val()?;
                a.tolerate = std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))?;
            }
            "--no-shrink" => a.shrink = false,
            "--introduce" => a.gen.introduce = true,
            "--no-framing" => a.gen.framing = false,
            "--no-quota-bursts" => a.gen.quota_bursts = false,
            "--no-wide-domids" => a.gen.wide_domids = false,
            "--no-at-slash" => a.gen.at_slash = false,
            "--conf" => {
                a.conf.push_str(&val()?);
                a.conf.push('\n');
            }
            "--case" => a.case = Some(val()?),
            "--only" => {
                let v = val()?;
                let ix = v
                    .split(',')
                    .map(|x| x.trim().parse::<usize>())
                    .collect::<Result<Vec<_>, _>>();
                a.only = Some(ix.map_err(|e| format!("--only: {e}"))?);
            }
            "--help" | "-h" => return Err(String::new()),
            _ => return Err(format!("unknown option {o}")),
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let mut out = io::stdout().lock();
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(io::stderr(), "{e}{}{USAGE}", if e.is_empty() { "" } else { "\n\n" });
            return ExitCode::from(2);
        }
    };
    let rx = a.rx.clone().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rxenstored")))
    });
    let (Some(ox), Some(rx)) = (a.ox.clone(), rx) else {
        let _ = writeln!(io::stderr(), "xs-diff: no oxenstored (--ox or RXS_OXENSTORED)");
        return ExitCode::from(2);
    };
    let pair = Pair {
        ox: Spec {
            kind: Kind::Ox,
            exe: ox,
            conf_extra: a.conf.clone(),
        },
        rx: Spec {
            kind: Kind::Rx,
            exe: rx,
            conf_extra: a.conf.clone(),
        },
        conns: a.gen.conns,
    };
    match (&a.case, &a.only) {
        (Some(name), _) => match cases::case(name) {
            Some(ops) => run_case(&mut out, &pair, &ops),
            None => {
                let _ = writeln!(out, "no case {name}; cases: {}", cases::NAMES.join(", "));
                ExitCode::from(2)
            }
        },
        (None, Some(only)) => {
            let all = generate(a.seed, &a.gen);
            let ops: Vec<Op> = only.iter().filter_map(|&i| all.get(i).cloned()).collect();
            run_case(&mut out, &pair, &ops)
        }
        (None, None) => run_seeds(&mut out, &pair, &a),
    }
}

fn run_case(out: &mut impl Write, pair: &Pair, ops: &[Op]) -> ExitCode {
    let (ox, rx) = match xs_diff::run_pair(pair, ops) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(out, "xs-diff: {e}");
            return ExitCode::FAILURE;
        }
    };
    for (i, op) in ops.iter().enumerate() {
        let _ = writeln!(out, "[{i}] {op}");
        for (name, t) in [("ox", &ox), ("rx", &rx)] {
            for (c, items) in t.steps.get(i).map(|v| &v[..]).unwrap_or_default().iter().enumerate() {
                for item in items {
                    let _ = writeln!(out, "    {name} c{c}: {}", show_item(item));
                }
            }
        }
    }
    let _ = writeln!(out, "== final state (keys that differ, and the @ probes)");
    let keys: std::collections::BTreeSet<&String> = ox.end.keys().chain(rx.end.keys()).collect();
    for k in keys {
        let (x, y) = (ox.end.get(k), rx.end.get(k));
        if x != y || k.contains(" @") || k.starts_with("node @") {
            let _ = writeln!(
                out,
                "  {k}\n    ox: {}\n    rx: {}",
                x.map_or("<none>", |s| s.as_str()),
                y.map_or("<none>", |s| s.as_str())
            );
        }
    }
    let ids = |t: &xs_diff::exec::Transcript| -> String {
        let v: Vec<String> = t
            .tx_numbers
            .iter()
            .map(|(s, c, id)| format!("[{s}] c{c}: {id}"))
            .collect();
        v.join(", ")
    };
    let _ = writeln!(
        out,
        "transaction ids: ox {}\n                 rx {}",
        ids(&ox),
        ids(&rx)
    );
    let _ = writeln!(out, "alive: ox {} rx {}", ox.alive, rx.alive);
    ExitCode::SUCCESS
}

/// Left-out differences after which the daemons hold different things.
fn diverging(sig: &str) -> bool {
    sig.starts_with("TRANSACTION_END") || sig.starts_with("(connection)") || sig.starts_with("(no request)")
}

struct Seen {
    seeds: u64,
    example: u64,
}

fn print_repro(out: &mut impl Write, seed: u64, ops: &[(usize, Op)], d: &Diff, from: usize) {
    let _ = writeln!(out, "== new difference: {}", d.sig);
    let _ = writeln!(
        out,
        "   seed {seed}; {} of {from} operations kept; at operation {} (connection {}):",
        ops.len(),
        d.step.map_or("end".into(), |s| s.to_string()),
        d.conn.map_or("-".into(), |c| c.to_string())
    );
    for (i, op) in ops {
        let _ = writeln!(out, "   [{i}] {op}");
    }
    let only: Vec<String> = ops.iter().map(|(i, _)| i.to_string()).collect();
    let _ = writeln!(out, "   (again: --seed {seed} --only {})", only.join(","));
    let _ = write!(out, "{}", d.detail);
    let _ = out.flush();
}

fn run_seeds(out: &mut impl Write, pair: &Pair, a: &Args) -> ExitCode {
    let tol = xs_diff::tolerance(&a.tolerate);
    let started = Instant::now();
    let deadline = a.minutes.map(|m| started + Duration::from_secs_f64(m * 60.0));
    let next = AtomicU64::new(a.seed);
    let end = a.seed.saturating_add(a.seeds);
    let (tx, rx) = mpsc::channel::<(u64, Vec<Op>, Result<Vec<Diff>, String>)>();
    let mut seen: BTreeMap<String, Seen> = BTreeMap::new();
    let mut runs = 0u64;
    let mut clean = 0u64;
    let mut known_only = 0u64;
    let mut left_out: BTreeMap<String, u64> = BTreeMap::new();
    let mut errors = 0u64;
    std::thread::scope(|s| {
        for _ in 0..a.jobs {
            let tx = tx.clone();
            let (next, tol, gen) = (&next, &tol, &a.gen);
            s.spawn(move || loop {
                if deadline.is_some_and(|d| Instant::now() > d) {
                    break;
                }
                let seed = next.fetch_add(1, Ordering::Relaxed);
                if seed >= end {
                    break;
                }
                let ops = generate(seed, gen);
                let r = xs_diff::diffs(pair, &ops, &|_| false).map_err(|e| e.to_string());
                let _ = tol;
                if tx.send((seed, ops, r)).is_err() {
                    break;
                }
            });
        }
        drop(tx);
        for (seed, ops, r) in rx {
            runs += 1;
            let diffs = match r {
                Ok(d) => d,
                Err(e) => {
                    errors += 1;
                    let _ = writeln!(out, "seed {seed}: harness error: {e}");
                    continue;
                }
            };
            // After a left-out difference that changes what the daemons
            // hold (a commit one refuses, a connection one drops), what
            // follows differs as a consequence: not counted.
            let cut = diffs
                .iter()
                .filter(|d| tol(&d.sig) && diverging(&d.sig))
                .filter_map(|d| d.step)
                .min();
            let all = diffs.len();
            let mut left: Vec<&str> = diffs.iter().filter(|d| tol(&d.sig)).map(|d| d.sig.as_str()).collect();
            left.sort_unstable();
            left.dedup();
            for sig in left {
                *left_out.entry(sig.to_string()).or_insert(0) += 1;
            }
            let diffs: Vec<Diff> = diffs
                .into_iter()
                .filter(|d| !tol(&d.sig))
                .filter(|d| match (cut, d.step) {
                    (Some(c), Some(s)) => s < c,
                    (Some(_), None) => false,
                    (None, _) => true,
                })
                .collect();
            if all == 0 {
                clean += 1;
            } else if diffs.is_empty() {
                known_only += 1;
            }
            let mut sigs: Vec<&Diff> = Vec::new();
            for d in &diffs {
                if !sigs.iter().any(|x| x.sig == d.sig) {
                    sigs.push(d);
                }
            }
            for d in sigs {
                if let Some(e) = seen.get_mut(&d.sig) {
                    e.seeds += 1;
                    continue;
                }
                seen.insert(
                    d.sig.clone(),
                    Seen {
                        seeds: 1,
                        example: seed,
                    },
                );
                if a.shrink {
                    let sig = d.sig.clone();
                    let mut last: Option<Diff> = None;
                    let mut others: Vec<String> = Vec::new();
                    let mut still = |cand: &[Op]| match xs_diff::diffs(pair, cand, &|_| false) {
                        Ok(ds) => match ds.iter().find(|x| x.sig == sig) {
                            Some(x) => {
                                last = Some(x.clone());
                                others = ds
                                    .iter()
                                    .filter(|x| x.sig != sig)
                                    .map(|x| format!("{}{}", x.sig, if tol(&x.sig) { " (left out)" } else { "" }))
                                    .collect();
                                others.dedup();
                                true
                            }
                            None => false,
                        },
                        Err(_) => false,
                    };
                    let indexed: Vec<(usize, Op)> = ops.iter().cloned().enumerate().collect();
                    let mut still_indexed = |cand: &[(usize, Op)]| {
                        let c: Vec<Op> = cand.iter().map(|(_, o)| o.clone()).collect();
                        still(&c)
                    };
                    let simpler = |(i, o): &(usize, Op)| -> Vec<(usize, Op)> {
                        xs_diff::shrink::simpler(o).into_iter().map(|s| (*i, s)).collect()
                    };
                    let small = xs_diff::shrink::shrink(indexed, &mut still_indexed, a.budget, &simpler);
                    let shown = last.unwrap_or_else(|| d.clone());
                    print_repro(out, seed, &small, &shown, ops.len());
                    for o in &others {
                        let _ = writeln!(out, "   with, on the same operations: {o}");
                    }
                } else {
                    print_repro(out, seed, &[], d, ops.len());
                }
            }
        }
    });
    let _ = writeln!(
        out,
        "== {runs} sequences of {} operations on {} connections in {:.0} s: {clean} without difference, {known_only} with left-out ones only, {errors} harness errors",
        a.gen.steps,
        a.gen.conns,
        started.elapsed().as_secs_f64()
    );
    for (sig, n) in &left_out {
        let _ = writeln!(out, "  {n:5} seeds  {sig}  (left out)");
    }
    for (sig, e) in &seen {
        let _ = writeln!(out, "  {:5} seeds  {sig}  (e.g. seed {})", e.seeds, e.example);
    }
    if seen.is_empty() && errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
