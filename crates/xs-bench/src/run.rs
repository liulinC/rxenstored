// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The `ramp` run: start simulated VMs band after band, measuring what one
//! start costs as the population grows; optionally stop them again.

#![forbid(unsafe_code)]

use crate::client::{Conn, Pump};
use crate::scenario::{Phase, Scenario};
use crate::trace::{instantiate, ConnId, Op, Record};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xs_wire::{nul_terminated, Message, MsgType};

#[derive(Debug, Clone)]
pub struct Config {
    pub socket: PathBuf,
    /// Prepended to every absolute path, so a run can share a live daemon
    /// without touching real nodes. Removed at the end unless `keep`.
    pub prefix: String,
    pub vms: u32,
    pub parallel: usize,
    /// VMs per measurement band.
    pub band: u32,
    pub first_domid: u32,
    /// The daemon's pid, to read its CPU time and memory from /proc.
    pub daemon_pid: Option<u32>,
    pub teardown: bool,
    pub keep: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Percentiles {
    pub p50: u64,
    pub p99: u64,
    pub max: u64,
}

impl Percentiles {
    pub fn of(mut samples: Vec<u64>) -> Percentiles {
        if samples.is_empty() {
            return Percentiles::default();
        }
        samples.sort_unstable();
        let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
        Percentiles {
            p50: at(0.50),
            p99: at(0.99),
            max: samples[samples.len() - 1],
        }
    }
}

pub const KINDS: [&str; 8] = [
    "write", "mkdir", "rm", "setperms", "watch", "unwatch", "tx_start", "tx_end",
];

fn kind_index(name: &str) -> u8 {
    KINDS.iter().position(|k| *k == name).expect("known kind") as u8
}

#[derive(Debug, Clone)]
pub struct Band {
    pub phase: &'static str,
    /// Simulated VMs existing when the band ended.
    pub population: u32,
    pub vms: u32,
    pub wall: Duration,
    /// Duration of one VM's replay, microseconds.
    pub vm_us: Percentiles,
    /// Request latency, microseconds, all kinds together and per kind.
    pub op_us: Percentiles,
    pub kind_us: BTreeMap<&'static str, Percentiles>,
    pub requests: u64,
    pub events: u64,
    pub tx_retries: u64,
    pub errors: BTreeMap<String, u64>,
    /// Daemon CPU seconds spent during the band.
    pub daemon_cpu: Option<f64>,
    pub daemon_rss_kb: Option<u64>,
}

impl Band {
    pub fn error_count(&self) -> u64 {
        self.errors.values().sum()
    }

    pub fn header() -> String {
        format!(
            "{:<6} {:>6} {:>9} {:>10} {:>10} {:>9} {:>9} {:>9} {:>7} {:>7} {:>11} {:>8}",
            "phase",
            "VMs",
            "VM/s",
            "vm p50 ms",
            "vm p99 ms",
            "op p50 us",
            "op p99 us",
            "events/VM",
            "errors",
            "retries",
            "cpu ms/VM",
            "rss MB"
        )
    }

    pub fn row(&self) -> String {
        let n = self.vms.max(1) as f64;
        let opt = |v: Option<f64>| v.map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".into());
        format!(
            "{:<6} {:>6} {:>9.1} {:>10.1} {:>10.1} {:>9} {:>9} {:>9.0} {:>7} {:>7} {:>11} {:>8}",
            self.phase,
            self.population,
            n / self.wall.as_secs_f64().max(1e-9),
            self.vm_us.p50 as f64 / 1000.0,
            self.vm_us.p99 as f64 / 1000.0,
            self.op_us.p50,
            self.op_us.p99,
            self.events as f64 / n,
            self.error_count(),
            self.tx_retries,
            opt(self.daemon_cpu.map(|c| c * 1000.0 / n)),
            opt(self.daemon_rss_kb.map(|k| k as f64 / 1024.0)),
        )
    }

    pub fn csv_header() -> String {
        let mut cols: Vec<String> = [
            "phase",
            "population",
            "vms",
            "wall_s",
            "vm_p50_us",
            "vm_p99_us",
            "vm_max_us",
            "op_p50_us",
            "op_p99_us",
            "op_max_us",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for k in KINDS {
            cols.push(format!("{k}_p50_us"));
            cols.push(format!("{k}_p99_us"));
        }
        for c in [
            "requests",
            "events",
            "tx_retries",
            "errors",
            "daemon_cpu_s",
            "daemon_rss_kb",
        ] {
            cols.push(c.to_string());
        }
        cols.join(",")
    }

    pub fn csv_row(&self) -> String {
        let mut cols = vec![
            self.phase.to_string(),
            self.population.to_string(),
            self.vms.to_string(),
            format!("{:.6}", self.wall.as_secs_f64()),
            self.vm_us.p50.to_string(),
            self.vm_us.p99.to_string(),
            self.vm_us.max.to_string(),
            self.op_us.p50.to_string(),
            self.op_us.p99.to_string(),
            self.op_us.max.to_string(),
        ];
        for k in KINDS {
            let p = self.kind_us.get(k).copied().unwrap_or_default();
            cols.push(p.p50.to_string());
            cols.push(p.p99.to_string());
        }
        cols.push(self.requests.to_string());
        cols.push(self.events.to_string());
        cols.push(self.tx_retries.to_string());
        cols.push(self.error_count().to_string());
        cols.push(self.daemon_cpu.map(|c| format!("{c:.2}")).unwrap_or_default());
        cols.push(self.daemon_rss_kb.map(|k| k.to_string()).unwrap_or_default());
        cols.join(",")
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub baseline_errors: BTreeMap<String, u64>,
    pub bands: Vec<Band>,
}

impl Report {
    pub fn errors(&self) -> BTreeMap<String, u64> {
        let mut all = self.baseline_errors.clone();
        for b in &self.bands {
            for (k, v) in &b.errors {
                *all.entry(k.clone()).or_default() += v;
            }
        }
        all
    }
}

/// CPU seconds (user + system) a process has used. Assumes 100 ticks per second.
pub fn process_cpu(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces: fields are counted after its closing parenthesis.
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace().skip(11);
    let utime: f64 = fields.next()?.parse().ok()?;
    let stime: f64 = fields.next()?.parse().ok()?;
    Some((utime + stime) / 100.0)
}

/// Resident memory of a process, assuming 4 KiB pages.
pub fn process_rss_kb(pid: u32) -> Option<u64> {
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    statm
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()
        .map(|pages| pages * 4)
}

#[derive(Default)]
struct Tally {
    ops: Vec<(u8, u32)>,
    vm_us: Vec<u64>,
    tx_retries: u64,
    errors: BTreeMap<String, u64>,
}

impl Tally {
    fn error(&mut self, what: String) {
        *self.errors.entry(what).or_default() += 1;
    }

    fn merge(&mut self, other: Tally) {
        self.ops.extend(other.ops);
        self.vm_us.extend(other.vm_us);
        self.tx_retries += other.tx_retries;
        for (k, v) in other.errors {
            *self.errors.entry(k).or_default() += v;
        }
    }
}

#[derive(Default)]
struct VmState {
    conns: HashMap<ConnId, Arc<Conn>>,
    watches: HashMap<ConnId, i32>,
}

struct Runner<'a> {
    cfg: &'a Config,
    pump: &'a Pump,
    shared: HashMap<ConnId, Arc<Conn>>,
    vms: Vec<Mutex<VmState>>,
}

/// A recorded transaction: the daemon numbers them per connection.
type TxKey = (ConnId, u32);

/// Index of the last record of each transaction.
fn last_of_tx(records: &[Record]) -> HashMap<TxKey, usize> {
    let mut last = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        if let Some(t) = r.tid {
            last.insert((r.conn, t), i);
        }
    }
    last
}

fn vm_uuid(index: u32) -> String {
    format!("{index:08x}-5ce0-4000-8000-{index:012x}")
}

impl Runner<'_> {
    fn path(&self, template: &str, domid: u32, uuid: &str) -> Vec<u8> {
        let p = instantiate(template, domid, uuid);
        if p.starts_with('/') {
            format!("{}{p}", self.cfg.prefix).into_bytes()
        } else {
            p.into_bytes()
        }
    }

    fn encode(&self, op: &Op, domid: u32, uuid: &str) -> (MsgType, Vec<u8>) {
        let fill = |t: &str| instantiate(t, domid, uuid).into_bytes();
        match op {
            Op::Write { path, value } => {
                let mut p = nul_terminated(&[&self.path(path, domid, uuid)]);
                p.extend_from_slice(&fill(value));
                (MsgType::Write, p)
            }
            Op::Mkdir { path } => (MsgType::Mkdir, nul_terminated(&[&self.path(path, domid, uuid)])),
            Op::Rm { path } => (MsgType::Rm, nul_terminated(&[&self.path(path, domid, uuid)])),
            Op::SetPerms { path, perms } => {
                let mut p = nul_terminated(&[&self.path(path, domid, uuid)]);
                for perm in perms {
                    p.extend_from_slice(&nul_terminated(&[&fill(perm)]));
                }
                (MsgType::SetPerms, p)
            }
            Op::Watch { path, token } => (
                MsgType::Watch,
                nul_terminated(&[&self.path(path, domid, uuid), &fill(token)]),
            ),
            Op::Unwatch { path, token } => (
                MsgType::Unwatch,
                nul_terminated(&[&self.path(path, domid, uuid), &fill(token)]),
            ),
        }
    }

    /// One request. `Err` carries the error name the daemon returned, or the
    /// local failure; it is already counted, except `EAGAIN`.
    fn request(
        &self,
        conn: &Conn,
        ty: MsgType,
        tx: u32,
        payload: Vec<u8>,
        kind: &'static str,
        tally: &mut Tally,
    ) -> Result<Message, String> {
        let t0 = Instant::now();
        let reply = conn.call(ty, tx, payload);
        tally
            .ops
            .push((kind_index(kind), t0.elapsed().as_micros().min(u32::MAX as u128) as u32));
        let err = match reply {
            Ok(m) if m.ty == MsgType::Error as u32 => {
                String::from_utf8_lossy(m.fields().first().copied().unwrap_or_default()).into_owned()
            }
            Ok(m) => return Ok(m),
            Err(e) => e.to_string(),
        };
        if err != "EAGAIN" {
            tally.error(format!("{kind}: {err}"));
        }
        Err(err)
    }

    fn tx_start(&self, conn: &Conn, tally: &mut Tally) -> u32 {
        self.request(conn, MsgType::TransactionStart, 0, vec![0], "tx_start", tally)
            .ok()
            .and_then(|m| std::str::from_utf8(m.fields().first().copied()?).ok()?.parse().ok())
            .unwrap_or(0)
    }

    fn run_op(&self, conn: &Conn, rec: &Record, tx: u32, domid: u32, uuid: &str, tally: &mut Tally) -> bool {
        let (ty, payload) = self.encode(&rec.op, domid, uuid);
        self.request(conn, ty, tx, payload, rec.op.name(), tally).is_ok()
    }

    fn conn_for(&self, id: ConnId, state: &mut VmState, tally: &mut Tally) -> Option<Arc<Conn>> {
        if let Some(c) = self.shared.get(&id) {
            return Some(c.clone());
        }
        if let Some(c) = state.conns.get(&id) {
            return Some(c.clone());
        }
        match self.pump.connect(&self.cfg.socket) {
            Ok(c) => {
                state.conns.insert(id, c.clone());
                Some(c)
            }
            Err(e) => {
                tally.error(format!("connect: {e}"));
                None
            }
        }
    }

    /// Replays one phase for one VM, in the recorded order.
    fn replay(&self, index: u32, phase: &Phase, last: &HashMap<TxKey, usize>, close_all: bool, tally: &mut Tally) {
        let domid = self.cfg.first_domid + index;
        let uuid = vm_uuid(index);
        let mut state = self.vms[index as usize].lock().unwrap();
        // Open transactions: daemon-side id, and the records issued in them.
        let mut open: HashMap<TxKey, (u32, Vec<usize>)> = HashMap::new();
        let t0 = Instant::now();
        for (i, rec) in phase.records.iter().enumerate() {
            let Some(conn) = self.conn_for(rec.conn, &mut state, tally) else {
                continue;
            };
            let tx = match rec.tid {
                None => 0,
                Some(t) => {
                    let entry = open
                        .entry((rec.conn, t))
                        .or_insert_with(|| (self.tx_start(&conn, tally), Vec::new()));
                    entry.1.push(i);
                    entry.0
                }
            };
            if self.run_op(&conn, rec, tx, domid, &uuid, tally) && !self.shared.contains_key(&rec.conn) {
                match rec.op {
                    Op::Watch { .. } => *state.watches.entry(rec.conn).or_default() += 1,
                    Op::Unwatch { .. } => *state.watches.entry(rec.conn).or_default() -= 1,
                    _ => {}
                }
            }
            let Some(key) = rec.tid.map(|t| (rec.conn, t)).filter(|k| last[k] == i) else {
                continue;
            };
            let (mut tx, ops) = open.remove(&key).expect("open transaction");
            let mut attempts = 0;
            // A commit refused with EAGAIN is retried from the start, as clients do.
            while let Err(e) = self.request(&conn, MsgType::TransactionEnd, tx, b"T\0".to_vec(), "tx_end", tally) {
                attempts += 1;
                if e != "EAGAIN" || tx == 0 {
                    break;
                }
                if attempts > 20 {
                    tally.error("tx_end: gave up after 20 EAGAIN".into());
                    break;
                }
                tally.tx_retries += 1;
                tx = self.tx_start(&conn, tally);
                for &j in &ops {
                    self.run_op(&conn, &phase.records[j], tx, domid, &uuid, tally);
                }
            }
        }
        tally.vm_us.push(t0.elapsed().as_micros() as u64);
        // Clients that hold no watch were short-lived tools: they disconnect.
        let watches = std::mem::take(&mut state.watches);
        state.conns.retain(|id, conn| {
            let keep = !close_all && watches.get(id).copied().unwrap_or(0) > 0;
            if !keep {
                self.pump.close(conn);
            }
            keep
        });
        state.watches = watches;
    }

    fn band(&self, name: &'static str, phase: &Phase, indexes: &[u32], population: u32) -> Band {
        let last = last_of_tx(&phase.records);
        let close_all = name == "stop";
        let cpu0 = self.cfg.daemon_pid.and_then(process_cpu);
        let events0 = self.pump.events();
        let next = AtomicU32::new(0);
        let total = Mutex::new(Tally::default());
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..self.cfg.parallel.max(1) {
                s.spawn(|| {
                    let mut tally = Tally::default();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                        let Some(&index) = indexes.get(i) else { break };
                        self.replay(index, phase, &last, close_all, &mut tally);
                    }
                    total.lock().unwrap().merge(tally);
                });
            }
        });
        let wall = t0.elapsed();
        // Let the daemon finish delivering watch events before reading its CPU time.
        self.pump.quiesce(Duration::from_millis(50), Duration::from_secs(20));
        let daemon_cpu = self.cfg.daemon_pid.and_then(process_cpu).zip(cpu0).map(|(a, b)| a - b);
        let daemon_rss_kb = self.cfg.daemon_pid.and_then(process_rss_kb);
        // The events of this band, each counted, and none left for the
        // next: the quiet periods above only make that likely. After the
        // CPU time, which does not include these round trips.
        self.pump.barrier(self.cfg.parallel);
        let tally = total.into_inner().unwrap();
        let mut by_kind: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
        for (k, us) in &tally.ops {
            by_kind.entry(KINDS[*k as usize]).or_default().push(*us as u64);
        }
        Band {
            phase: name,
            population,
            vms: indexes.len() as u32,
            wall,
            vm_us: Percentiles::of(tally.vm_us),
            op_us: Percentiles::of(tally.ops.iter().map(|(_, us)| *us as u64).collect()),
            kind_us: by_kind.into_iter().map(|(k, v)| (k, Percentiles::of(v))).collect(),
            requests: tally.ops.len() as u64,
            events: self.pump.events() - events0,
            tx_retries: tally.tx_retries,
            errors: tally.errors,
            daemon_cpu,
            daemon_rss_kb,
        }
    }
}

/// Runs the scenario. `on_band` is called as each band completes.
pub fn ramp(cfg: &Config, scenario: &Scenario, mut on_band: impl FnMut(&Band)) -> Result<Report, String> {
    if cfg.band == 0 || cfg.vms == 0 {
        return Err("the number of VMs and the band size must be positive".into());
    }
    let pump = Pump::new(cfg.timeout).map_err(|e| format!("epoll: {e}"))?;
    let connect = |what: &str| {
        pump.connect(&cfg.socket)
            .map_err(|e| format!("{}: {what}: {e}", cfg.socket.display()))
    };
    let control = connect("connect")?;
    let mut shared = HashMap::new();
    for id in &scenario.shared {
        shared.insert(*id, connect("connect")?);
    }
    let runner = Runner {
        cfg,
        pump: &pump,
        shared,
        vms: (0..cfg.vms).map(|_| Mutex::default()).collect(),
    };
    let mut report = Report::default();

    std::thread::scope(|s| {
        let reader = s.spawn(|| pump.run());
        let mut setup = Tally::default();
        if !cfg.prefix.is_empty() {
            let payload = nul_terminated(&[cfg.prefix.as_bytes()]);
            let _ = runner.request(&control, MsgType::Mkdir, 0, payload, "mkdir", &mut setup);
        }
        for rec in &scenario.baseline {
            runner.run_op(&runner.shared[&rec.conn], rec, 0, 0, "", &mut setup);
        }
        pump.quiesce(Duration::from_millis(50), Duration::from_secs(5));
        // None of the baseline's events is counted in the first band.
        pump.barrier(cfg.parallel);
        report.baseline_errors = std::mem::take(&mut setup.errors);

        let all: Vec<u32> = (0..cfg.vms).collect();
        let mut done = 0;
        for chunk in all.chunks(cfg.band as usize) {
            done += chunk.len() as u32;
            let band = runner.band("start", &scenario.start, chunk, done);
            on_band(&band);
            report.bands.push(band);
        }
        if let (true, Some(stop)) = (cfg.teardown, &scenario.stop) {
            for chunk in all.chunks(cfg.band as usize) {
                done -= chunk.len() as u32;
                let band = runner.band("stop", stop, chunk, done);
                on_band(&band);
                report.bands.push(band);
            }
        }

        for vm in &runner.vms {
            for conn in vm.lock().unwrap().conns.values() {
                pump.close(conn);
            }
        }
        if !cfg.keep && !cfg.prefix.is_empty() {
            let payload = nul_terminated(&[cfg.prefix.as_bytes()]);
            let _ = runner.request(&control, MsgType::Rm, 0, payload, "rm", &mut setup);
            for (k, v) in setup.errors {
                *report.baseline_errors.entry(format!("cleanup {k}")).or_default() += v;
            }
        }
        for conn in runner.shared.values().chain([&control]) {
            pump.close(conn);
        }
        pump.stop();
        reader.join().expect("pump thread").map_err(|e| format!("epoll: {e}"))
    })?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        assert_eq!(Percentiles::of(vec![]), Percentiles::default());
        assert_eq!(Percentiles::of(vec![7]), Percentiles { p50: 7, p99: 7, max: 7 });
        let p = Percentiles::of((1..=101).rev().collect());
        assert_eq!(
            p,
            Percentiles {
                p50: 51,
                p99: 100,
                max: 101
            }
        );
    }

    #[test]
    fn reads_proc() {
        let me = std::process::id();
        assert!(process_cpu(me).unwrap() >= 0.0);
        assert!(process_rss_kb(me).unwrap() > 0);
        assert_eq!(process_cpu(u32::MAX), None);
        assert_eq!(process_rss_kb(u32::MAX), None);
    }

    #[test]
    fn uuids_are_distinct_and_well_formed() {
        assert_eq!(vm_uuid(0x2a), "0000002a-5ce0-4000-8000-00000000002a");
        assert_ne!(vm_uuid(1), vm_uuid(2));
    }

    fn band() -> Band {
        Band {
            phase: "start",
            population: 100,
            vms: 50,
            wall: Duration::from_secs(5),
            vm_us: Percentiles {
                p50: 20_000,
                p99: 90_500,
                max: 100_000,
            },
            op_us: Percentiles {
                p50: 40,
                p99: 900,
                max: 5000,
            },
            kind_us: [(
                "write",
                Percentiles {
                    p50: 41,
                    p99: 901,
                    max: 5000,
                },
            )]
            .into_iter()
            .collect(),
            requests: 30_000,
            events: 21_000,
            tx_retries: 3,
            errors: [("rm: ENOENT".to_string(), 2), ("watch: EEXIST".to_string(), 1)]
                .into_iter()
                .collect(),
            daemon_cpu: Some(2.5),
            daemon_rss_kb: Some(20480),
        }
    }

    #[test]
    fn formats_rows() {
        let b = band();
        let row = b.row();
        let cells: Vec<&str> = row.split_whitespace().collect();
        assert_eq!(
            cells,
            ["start", "100", "10.0", "20.0", "90.5", "40", "900", "420", "3", "3", "50.0", "20.0"]
        );
        let mut b2 = band();
        b2.daemon_cpu = None;
        b2.daemon_rss_kb = None;
        let cells: Vec<String> = b2.row().split_whitespace().map(str::to_string).collect();
        assert_eq!(&cells[10..], ["-", "-"]);
        assert!(Band::header().starts_with("phase"));
        assert!(Band::header().ends_with("rss MB"));
        assert_eq!(Band::header().len(), row.len());
    }

    #[test]
    fn formats_csv() {
        let b = band();
        let header: Vec<String> = Band::csv_header().split(',').map(str::to_string).collect();
        let row: Vec<String> = b.csv_row().split(',').map(str::to_string).collect();
        assert_eq!(header.len(), row.len());
        let get = |name: &str| row[header.iter().position(|h| h == name).unwrap()].clone();
        assert_eq!(get("population"), "100");
        assert_eq!(get("wall_s"), "5.000000");
        assert_eq!(get("write_p99_us"), "901");
        assert_eq!(get("rm_p50_us"), "0");
        assert_eq!(get("errors"), "3");
        assert_eq!(get("daemon_cpu_s"), "2.50");
        assert_eq!(get("daemon_rss_kb"), "20480");
        let mut b2 = band();
        b2.daemon_cpu = None;
        b2.daemon_rss_kb = None;
        assert!(b2.csv_row().ends_with(",3,,"));
    }

    #[test]
    fn report_sums_errors() {
        let mut r = Report::default();
        r.baseline_errors.insert("watch: EEXIST".into(), 1);
        r.bands.push(band());
        r.bands.push(band());
        let e = r.errors();
        assert_eq!(e["watch: EEXIST"], 3);
        assert_eq!(e["rm: ENOENT"], 4);
    }

    #[test]
    fn last_record_of_each_transaction() {
        let rec = |n, tid| Record {
            conn: ConnId::Socket(n),
            tid,
            op: Op::Rm { path: "/a".into() },
        };
        let last = last_of_tx(&[
            rec(1, Some(5)),
            rec(1, None),
            rec(1, Some(5)),
            rec(1, Some(6)),
            rec(2, Some(5)),
        ]);
        let (a, b) = (ConnId::Socket(1), ConnId::Socket(2));
        assert_eq!(last, [((a, 5), 2), ((a, 6), 3), ((b, 5), 4)].into_iter().collect());
    }
}
