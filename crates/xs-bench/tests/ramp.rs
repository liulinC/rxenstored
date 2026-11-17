// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! End-to-end runs of the load generator against a small fake xenstored.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xs_bench::run::{ramp, Config};
use xs_bench::scenario::Scenario;
use xs_wire::{Decoder, Message, MsgType};

/// How the fake daemon misbehaves, for the error paths.
#[derive(Default, Clone, Copy)]
struct Faults {
    /// Every commit is refused with EAGAIN this many times per connection.
    eagain_per_conn: u32,
    /// Refuse every commit with EAGAIN.
    always_eagain: bool,
    /// Answer every SET_PERMS with EACCES.
    deny_setperms: bool,
    /// Refuse TRANSACTION_START with ENOSPC.
    no_transactions: bool,
    /// Close a connection instead of answering its first RM.
    hang_up_on_rm: bool,
}

#[derive(Default)]
struct State {
    nodes: BTreeMap<String, Vec<u8>>,
    /// (connection, path, token)
    watches: Vec<(usize, String, String)>,
    outputs: HashMap<usize, Arc<Mutex<UnixStream>>>,
    requests: u64,
    max_conns: usize,
}

struct Fake {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}

fn send(out: &Mutex<UnixStream>, ty: MsgType, req_id: u32, payload: &[u8]) {
    let mut bytes = Vec::new();
    Message::new(ty, req_id, 0, payload.to_vec())
        .unwrap()
        .encode_into(&mut bytes);
    let _ = out.lock().unwrap().write_all(&bytes);
}

fn fire(state: &State, path: &str) {
    for (conn, wpath, token) in &state.watches {
        if path == wpath || path.starts_with(&format!("{wpath}/")) {
            let payload = [path.as_bytes(), b"\0", token.as_bytes(), b"\0"].concat();
            send(&state.outputs[conn], MsgType::WatchEvent, 0, &payload);
        }
    }
}

fn serve(id: usize, mut stream: UnixStream, state: Arc<Mutex<State>>, faults: Faults) {
    let out = Arc::new(Mutex::new(stream.try_clone().unwrap()));
    {
        let mut st = state.lock().unwrap();
        st.outputs.insert(id, out.clone());
        st.max_conns = st.max_conns.max(st.outputs.len());
    }
    let mut decoder = Decoder::new();
    let mut buf = [0u8; 4096];
    let mut eagain_left = faults.eagain_per_conn;
    // Transactions are numbered per connection, from 1.
    let mut next_tx = 1u32;
    let mut open_txs: Vec<u32> = Vec::new();
    'conn: loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        decoder.push(&buf[..n]);
        while let Some(msg) = decoder.next_message().unwrap() {
            let fields: Vec<String> = msg
                .fields()
                .iter()
                .map(|f| String::from_utf8_lossy(f).into_owned())
                .collect();
            let path = fields.first().cloned().unwrap_or_default();
            let mut st = state.lock().unwrap();
            st.requests += 1;
            let ok = |st: &State| {
                let _ = st;
                send(&out, MsgType::from_u32(msg.ty).unwrap(), msg.req_id, b"OK\0")
            };
            let error = |name: &str| send(&out, MsgType::Error, msg.req_id, &[name.as_bytes(), b"\0"].concat());
            if msg.tx_id != 0 && !open_txs.contains(&msg.tx_id) {
                // What oxenstored answers to a request in a transaction it does not know.
                error("EIO");
                continue;
            }
            match msg.msg_type().unwrap() {
                MsgType::Write | MsgType::Mkdir => {
                    st.nodes
                        .insert(path.clone(), fields.get(1).cloned().unwrap_or_default().into_bytes());
                    ok(&st);
                    fire(&st, &path);
                }
                MsgType::Rm => {
                    if faults.hang_up_on_rm {
                        break 'conn;
                    }
                    st.nodes
                        .retain(|k, _| k != &path && !k.starts_with(&format!("{path}/")));
                    ok(&st);
                    fire(&st, &path);
                }
                MsgType::SetPerms if faults.deny_setperms => error("EACCES"),
                MsgType::SetPerms => ok(&st),
                MsgType::Watch => {
                    let token = fields.get(1).cloned().unwrap_or_default();
                    if st.watches.iter().any(|w| *w == (id, path.clone(), token.clone())) {
                        error("EEXIST");
                    } else {
                        st.watches.push((id, path.clone(), token.clone()));
                        ok(&st);
                        // A new watch fires once immediately.
                        send(
                            &out,
                            MsgType::WatchEvent,
                            0,
                            &[path.as_bytes(), b"\0", token.as_bytes(), b"\0"].concat(),
                        );
                    }
                }
                MsgType::Unwatch => {
                    let token = fields.get(1).cloned().unwrap_or_default();
                    let before = st.watches.len();
                    st.watches.retain(|w| *w != (id, path.clone(), token.clone()));
                    if st.watches.len() == before {
                        error("ENOENT");
                    } else {
                        ok(&st);
                    }
                }
                MsgType::TransactionStart if faults.no_transactions => error("ENOSPC"),
                MsgType::TransactionStart => {
                    open_txs.push(next_tx);
                    send(
                        &out,
                        MsgType::TransactionStart,
                        msg.req_id,
                        format!("{next_tx}\0").as_bytes(),
                    );
                    next_tx += 1;
                }
                MsgType::TransactionEnd => {
                    open_txs.retain(|t| *t != msg.tx_id);
                    if faults.always_eagain || eagain_left > 0 {
                        eagain_left = eagain_left.saturating_sub(1);
                        error("EAGAIN");
                    } else {
                        ok(&st);
                    }
                }
                _ => error("ENOSYS"),
            }
        }
    }
    let mut st = state.lock().unwrap();
    st.outputs.remove(&id);
    st.watches.retain(|w| w.0 != id);
}

static NEXT: AtomicU32 = AtomicU32::new(0);

impl Fake {
    fn start(faults: Faults) -> Fake {
        let path = std::env::temp_dir().join(format!(
            "xs-bench-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for (id, stream) in listener.incoming().enumerate() {
                let state = shared.clone();
                std::thread::spawn(move || serve(id, stream.unwrap(), state, faults));
            }
        });
        Fake { path, state }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn config(socket: &Path) -> Config {
    Config {
        socket: socket.to_path_buf(),
        prefix: "/rxsbench".into(),
        vms: 6,
        parallel: 3,
        band: 4,
        first_domid: 1000,
        daemon_pid: Some(std::process::id()),
        teardown: true,
        keep: false,
        timeout: Duration::from_secs(20),
    }
}

fn shipped() -> Scenario {
    Scenario::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios/xcpng83-hvm-2vbd-1vif")).unwrap()
}

const P: &str = "Jan  1 07:41:11 h oxenstored:  ";

fn small(start: &[&str], stop: Option<&[&str]>) -> Scenario {
    let log = |lines: &[&str]| lines.iter().map(|l| format!("{P}{l}\n")).collect::<String>();
    let baseline = log(&["A1 watch backend/vbd3 master", "A11 watch @introduceDomain"]);
    Scenario::from_texts("domid=4\nuuid=u-u", &baseline, &log(start), stop.map(log).as_deref()).unwrap()
}

#[test]
fn shipped_scenario_ramps_up_and_down_cleanly() {
    let fake = Fake::start(Faults::default());
    let scenario = shipped();
    let mut seen = 0;
    let report = ramp(&config(&fake.path), &scenario, |_| seen += 1).unwrap();
    assert_eq!(report.errors(), BTreeMap::new());
    // Two start bands (4 + 2 VMs), then two stop bands.
    assert_eq!(seen, 4);
    let phases: Vec<_> = report.bands.iter().map(|b| (b.phase, b.population, b.vms)).collect();
    assert_eq!(
        phases,
        [("start", 4, 4), ("start", 6, 2), ("stop", 2, 4), ("stop", 0, 2)]
    );

    let start = &scenario.start;
    let txs = start
        .records
        .iter()
        .filter_map(|r| r.tid.map(|t| (r.conn, t)))
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    let per_vm = start.records.len() as u64 + 2 * txs;
    assert_eq!(report.bands[0].requests, 4 * per_vm);
    assert_eq!(report.bands[1].requests, 2 * per_vm);
    // The recorded start delivered 433 events. The fake daemon has neither
    // the guest's own ring nor the real domain events: 382 per start here,
    // and 91 per stop, each counted in its band, whatever the timing.
    let events: Vec<u64> = report.bands.iter().map(|b| b.events).collect();
    assert_eq!(events, [4 * 382, 2 * 382, 4 * 91, 2 * 91]);
    assert!(report.bands[0].daemon_cpu.is_some());
    assert!(report.bands[0].daemon_rss_kb.unwrap() > 0);
    assert!(report.bands[0].vm_us.p50 > 0);

    let st = fake.state.lock().unwrap();
    assert!(
        st.nodes.is_empty(),
        "left behind: {:?}",
        st.nodes.keys().take(5).collect::<Vec<_>>()
    );
    assert!(st.max_conns > scenario.shared.len() + 6);
}

#[test]
fn nodes_are_per_vm_and_under_the_prefix() {
    let fake = Fake::start(Faults::default());
    let scenario = small(
        &[
            "A11.22 mkdir /local/domain/4",
            "A11.22 setperms /local/domain/4 n0 r4",
            "A11.22 write /vm/u-u/domains/4 /local/domain/4",
            "A11 watch /local/domain/4/attr xenopsd-xc:domain-4",
            "A326 watch backend/vbd3/4 tapback-4-back",
            "A326 write backend/vbd3/4/768/state 4",
            "A349 write /local/domain/4/tool 1",
            "D4 write data/x 1",
        ],
        None,
    );
    let mut cfg = config(&fake.path);
    cfg.vms = 3;
    cfg.keep = true;
    cfg.daemon_pid = None;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.errors(), BTreeMap::new());
    assert_eq!(report.bands.len(), 1, "no stop phase in the scenario");
    assert_eq!(report.bands[0].daemon_cpu, None);
    assert_eq!(report.bands[0].requests, 3 * (8 + 2));
    // Per VM: 2 new watches fire once, the tapback write fires the per-VM and the master watch.
    assert_eq!(report.bands[0].events, 3 * 4);

    let st = fake.state.lock().unwrap();
    let keys: Vec<&str> = st.nodes.keys().map(String::as_str).collect();
    for domid in [1000, 1001, 1002] {
        for suffix in ["", "/data/x", "/tool"] {
            assert!(
                keys.contains(&format!("/rxsbench/local/domain/{domid}{suffix}").as_str()),
                "{keys:?}"
            );
        }
        assert!(keys.contains(&format!("/rxsbench/local/domain/0/backend/vbd3/{domid}/768/state").as_str()));
    }
    assert_eq!(st.nodes["/rxsbench/local/domain/0/backend/vbd3/1001/768/state"], b"4");
    assert_eq!(
        st.nodes["/rxsbench/vm/00000001-5ce0-4000-8000-000000000001/domains/1001"], b"/local/domain/1001",
        "values are not prefixed"
    );
    assert!(st.nodes.contains_key("/rxsbench"), "kept on request");
    assert_eq!(keys.iter().filter(|k| !k.starts_with("/rxsbench")).count(), 0);
}

#[test]
fn an_empty_prefix_leaves_paths_alone() {
    let fake = Fake::start(Faults::default());
    let scenario = small(&["A11 write /local/domain/4/name vm"], None);
    let mut cfg = config(&fake.path);
    cfg.prefix = String::new();
    cfg.vms = 1;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.errors(), BTreeMap::new());
    let st = fake.state.lock().unwrap();
    assert_eq!(st.nodes.keys().collect::<Vec<_>>(), ["/local/domain/1000/name"]);
}

#[test]
fn transactions_with_the_same_recorded_id_on_two_connections_are_distinct() {
    let fake = Fake::start(Faults::default());
    let scenario = small(
        &[
            "A11.1 write /local/domain/4/a 1",
            "A11.2 write /local/domain/4/b 1",
            "A326.1 write /local/domain/4/c 1",
            "A11.2 write /local/domain/4/d 1",
            "A326.1 write /local/domain/4/e 1",
            "A11.1 write /local/domain/4/f 1",
        ],
        None,
    );
    let mut cfg = config(&fake.path);
    cfg.vms = 2;
    cfg.keep = true;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.errors(), BTreeMap::new());
    assert_eq!(report.bands[0].requests, 2 * (6 + 3 * 2));
    assert_eq!(fake.state.lock().unwrap().nodes.len(), 1 + 2 * 6);
}

#[test]
fn refused_commits_are_retried() {
    let fake = Fake::start(Faults {
        eagain_per_conn: 2,
        ..Faults::default()
    });
    let scenario = small(
        &["A11.5 write /local/domain/4/a 1", "A11.5 write /local/domain/4/b 2"],
        None,
    );
    let mut cfg = config(&fake.path);
    cfg.vms = 1;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.errors(), BTreeMap::new());
    assert_eq!(report.bands[0].tx_retries, 2);
    // start + 2 writes + refused end, twice; then start + 2 writes + end.
    assert_eq!(report.bands[0].requests, 3 * 4);
}

#[test]
fn a_commit_that_never_passes_is_given_up() {
    let fake = Fake::start(Faults {
        always_eagain: true,
        ..Faults::default()
    });
    let scenario = small(&["A11.5 write /local/domain/4/a 1"], None);
    let mut cfg = config(&fake.path);
    cfg.vms = 1;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    assert_eq!(report.bands[0].tx_retries, 20);
    assert_eq!(
        report.errors(),
        [("tx_end: gave up after 20 EAGAIN".to_string(), 1)]
            .into_iter()
            .collect()
    );
}

#[test]
fn daemon_errors_are_counted_by_kind() {
    let fake = Fake::start(Faults {
        deny_setperms: true,
        no_transactions: true,
        ..Faults::default()
    });
    let scenario = small(
        &[
            "A11.5 setperms /local/domain/4 n0",
            "A11 setperms /local/domain/4/x n0",
            "A11 unwatch /local/domain/4/none t",
        ],
        None,
    );
    let mut cfg = config(&fake.path);
    cfg.vms = 2;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    let expected: BTreeMap<String, u64> = [("setperms: EACCES", 4), ("tx_start: ENOSPC", 2), ("unwatch: ENOENT", 2)]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    assert_eq!(report.errors(), expected);
    assert_eq!(report.bands[0].error_count(), 8);
}

#[test]
fn a_connection_closed_by_the_daemon_is_reported() {
    let fake = Fake::start(Faults {
        hang_up_on_rm: true,
        ..Faults::default()
    });
    let scenario = small(&["A326 rm /local/domain/4", "A326 write /local/domain/4/a 1"], None);
    let mut cfg = config(&fake.path);
    cfg.vms = 1;
    let report = ramp(&cfg, &scenario, |_| {}).unwrap();
    let errors = report.errors();
    assert_eq!(errors["rm: connection closed by the daemon"], 1);
    // The write on the dead connection fails too, as an i/o error or a closed connection.
    assert!(errors.keys().any(|k| k.starts_with("write: ")), "{errors:?}");
    // The clean-up `rm` of the prefix is refused the same way.
    assert_eq!(errors["cleanup rm: connection closed by the daemon"], 1);
}

#[test]
fn bad_arguments_and_missing_daemon() {
    let scenario = small(&["A11 write /a 1"], None);
    let mut cfg = config(Path::new("/nonexistent/socket"));
    assert!(ramp(&cfg, &scenario, |_| {})
        .unwrap_err()
        .contains("/nonexistent/socket"));
    cfg.vms = 0;
    assert!(ramp(&cfg, &scenario, |_| {}).unwrap_err().contains("positive"));
    cfg.vms = 1;
    cfg.band = 0;
    assert!(ramp(&cfg, &scenario, |_| {}).unwrap_err().contains("positive"));
}
