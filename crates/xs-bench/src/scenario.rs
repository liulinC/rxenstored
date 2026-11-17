// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! A scenario directory: `meta` (domid and uuid of the recorded VM),
//! `start.log`, and optionally `baseline.log` (watches the long-lived
//! clients hold before any VM starts) and `stop.log`.

#![forbid(unsafe_code)]

use crate::trace::{parse_line, ConnId, Line, Op, Record, Templater};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Census {
    /// Requests kept for replay, per connection and operation.
    pub requests: BTreeMap<(ConnId, &'static str), u32>,
    /// Watch events the daemon delivered in the recording, per connection.
    pub events: BTreeMap<ConnId, u32>,
    /// Logged lines not replayed: other operations, other guests, unparsable lines.
    pub skipped: BTreeMap<String, u32>,
}

impl Census {
    pub fn total_requests(&self) -> u32 {
        self.requests.values().sum()
    }
    pub fn total_events(&self) -> u32 {
        self.events.values().sum()
    }
}

#[derive(Debug, Clone)]
pub struct Phase {
    /// Templated records, in the order the daemon logged them.
    pub records: Vec<Record>,
    pub census: Census,
}

#[derive(Debug, Clone)]
pub struct Scenario {
    /// Connections that exist once for the host (toolstack, dom0 kernel...):
    /// those of the baseline. Every other connection is opened per VM.
    pub shared: BTreeSet<ConnId>,
    /// Not templated: issued once on the shared connections.
    pub baseline: Vec<Record>,
    pub start: Phase,
    pub stop: Option<Phase>,
}

fn parse_meta(text: &str) -> Result<(u32, String), String> {
    let mut domid = None;
    let mut uuid = String::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match line.split_once('=') {
            Some(("domid", v)) => domid = Some(v.trim().parse::<u32>().map_err(|e| format!("meta: domid: {e}"))?),
            Some(("uuid", v)) => uuid = v.trim().to_string(),
            _ => return Err(format!("meta: unexpected line: {line}")),
        }
    }
    Ok((domid.ok_or("meta: domid is missing")?, uuid))
}

fn parse_baseline(text: &str) -> Vec<Record> {
    text.lines()
        .filter_map(|l| match parse_line(l) {
            Line::Request(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn parse_phase(text: &str, domid: u32, uuid: &str, shared: &BTreeSet<ConnId>) -> Phase {
    let templater = Templater::new(domid, uuid);
    let mut records = Vec::new();
    let mut census = Census::default();
    let skip = |census: &mut Census, what: String| *census.skipped.entry(what).or_default() += 1;
    for line in text.lines() {
        match parse_line(line) {
            Line::Request(r) => {
                // Rings of other guests are their own chatter, not part of this VM.
                let other_guest = matches!(r.conn, ConnId::Domain(d) if d != domid) && !shared.contains(&r.conn);
                if other_guest {
                    skip(&mut census, "request of another guest".into());
                    continue;
                }
                *census.requests.entry((r.conn, r.op.name())).or_default() += 1;
                records.push(Record {
                    conn: r.conn,
                    tid: r.tid,
                    op: templater.op(&r.op),
                });
            }
            Line::Event(conn) => *census.events.entry(conn).or_default() += 1,
            Line::Other(op) => skip(&mut census, format!("operation {op}")),
            Line::Unparsed => skip(&mut census, "unparsed line".into()),
        }
    }
    Phase { records, census }
}

impl Scenario {
    pub fn from_texts(meta: &str, baseline: &str, start: &str, stop: Option<&str>) -> Result<Scenario, String> {
        let (domid, uuid) = parse_meta(meta)?;
        let baseline = parse_baseline(baseline);
        let shared: BTreeSet<ConnId> = baseline.iter().map(|r| r.conn).collect();
        let start = parse_phase(start, domid, &uuid, &shared);
        if start.records.is_empty() {
            return Err("start.log holds no request".into());
        }
        let stop = stop.map(|s| parse_phase(s, domid, &uuid, &shared));
        Ok(Scenario {
            shared,
            baseline,
            start,
            stop,
        })
    }

    pub fn load(dir: &Path) -> Result<Scenario, String> {
        let read = |name: &str| {
            std::fs::read(dir.join(name))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| format!("{}: {e}", dir.join(name).display()))
        };
        let meta = read("meta")?;
        let start = read("start.log")?;
        let baseline = read("baseline.log").unwrap_or_default();
        let stop = read("stop.log").ok();
        Scenario::from_texts(&meta, &baseline, &start, stop.as_deref())
    }

    /// Watches a running VM leaves registered after its start, per connection.
    pub fn watches_per_vm(&self) -> BTreeMap<ConnId, i32> {
        let mut out = BTreeMap::new();
        for r in &self.start.records {
            match r.op {
                Op::Watch { .. } => *out.entry(r.conn).or_default() += 1,
                Op::Unwatch { .. } => *out.entry(r.conn).or_default() -= 1,
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::DOMID;

    const P: &str = "Jan  1 07:41:11 h oxenstored:  ";

    fn log(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{P}{l}\n")).collect()
    }

    #[test]
    fn meta_errors() {
        assert_eq!(parse_meta("domid=4\n\nuuid= abc \n"), Ok((4, "abc".into())));
        assert_eq!(parse_meta("domid=4"), Ok((4, String::new())));
        assert!(parse_meta("uuid=abc").unwrap_err().contains("missing"));
        assert!(parse_meta("domid=x").unwrap_err().contains("domid"));
        assert!(parse_meta("domid=4\nfoo").unwrap_err().contains("unexpected"));
        assert!(parse_meta("domid=4\nfoo=1").unwrap_err().contains("unexpected"));
    }

    #[test]
    fn classifies_and_counts() {
        let baseline = log(&[
            "A1 watch backend/vbd3 master",
            "D0 watch backend K",
            "A1 w event x y",
            "junk",
        ]);
        let start = log(&[
            "A11.22 mkdir /local/domain/4",
            "A11.22 setperms /local/domain/4 n0 r4",
            "A11 watch /local/domain/4/attr xenopsd-xc:domain-4",
            "A11 watch /local/domain/4/tmp t",
            "A11 unwatch /local/domain/4/tmp t",
            "A326 watch backend/vbd3/4 tapback-4-back",
            "D4 write data/x 1",
            "D0 write backend/vif/4/0/state 4",
            "D3 write data/meminfo_free 1",
            "A11 w event /local/domain/4/attr xenopsd-xc:domain-4",
            "D4 reset",
            "garbage",
        ]);
        let s = Scenario::from_texts(
            "domid=4\nuuid=u",
            &baseline,
            &start,
            Some(&log(&["A11 rm /local/domain/4"])),
        )
        .unwrap();
        assert_eq!(s.shared, [ConnId::Socket(1), ConnId::Domain(0)].into_iter().collect());
        assert_eq!(s.baseline.len(), 2);
        assert_eq!(s.start.records.len(), 8);
        assert_eq!(s.start.census.total_requests(), 8);
        assert_eq!(s.start.census.total_events(), 1);
        assert_eq!(s.start.census.skipped["request of another guest"], 1);
        assert_eq!(s.start.census.skipped["operation reset"], 1);
        assert_eq!(s.start.census.skipped["unparsed line"], 1);
        assert_eq!(
            s.start.records[0].op,
            Op::Mkdir {
                path: format!("/local/domain/{DOMID}")
            }
        );
        // A state value equal to the domid stays a state.
        assert_eq!(
            s.start.records[7].op,
            Op::Write {
                path: format!("/local/domain/0/backend/vif/{DOMID}/0/state"),
                value: "4".into()
            }
        );
        let w = s.watches_per_vm();
        assert_eq!(w[&ConnId::Socket(11)], 1);
        assert_eq!(w[&ConnId::Socket(326)], 1);
        assert_eq!(s.stop.unwrap().records.len(), 1);
    }

    #[test]
    fn rejects_an_empty_start() {
        assert!(Scenario::from_texts("domid=4", "", "nothing", None)
            .unwrap_err()
            .contains("no request"));
        assert!(Scenario::from_texts("", "", "", None).is_err());
    }

    #[test]
    fn loads_the_shipped_scenario() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios/xcpng83-hvm-2vbd-1vif");
        let s = Scenario::load(&dir).unwrap();
        assert_eq!(s.start.census.total_events(), 433);
        assert!(s.shared.contains(&ConnId::Socket(11)));
        assert!(s.stop.is_some());
        assert!(Scenario::load(Path::new("/nonexistent")).unwrap_err().contains("meta"));
    }
}
