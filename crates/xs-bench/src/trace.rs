// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Parsing of oxenstored access-log lines, and turning the paths, values,
//! permissions and tokens of one recorded VM into templates.

#![forbid(unsafe_code)]

/// A connection as oxenstored names it: `A<n>` for a socket, `D<domid>` for a ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConnId {
    Socket(u32),
    Domain(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Write { path: String, value: String },
    Mkdir { path: String },
    Rm { path: String },
    SetPerms { path: String, perms: Vec<String> },
    Watch { path: String, token: String },
    Unwatch { path: String, token: String },
}

impl Op {
    pub fn name(&self) -> &'static str {
        match self {
            Op::Write { .. } => "write",
            Op::Mkdir { .. } => "mkdir",
            Op::Rm { .. } => "rm",
            Op::SetPerms { .. } => "setperms",
            Op::Watch { .. } => "watch",
            Op::Unwatch { .. } => "unwatch",
        }
    }
}

/// One logged request. `tid` is the daemon's transaction id, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub conn: ConnId,
    pub tid: Option<u32>,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Request(Record),
    /// A watch event delivered to `conn`: output of the daemon, not replayed.
    Event(ConnId),
    /// A logged operation the replay does not issue (its name is kept for the census).
    Other(String),
    Unparsed,
}

fn parse_conn(s: &str) -> Option<(ConnId, Option<u32>)> {
    // A transaction replayed by oxenstored is logged as "r(<n>):<conn>".
    let s = match s.strip_prefix("r(") {
        Some(rest) => rest.split_once("):")?.1,
        None => s,
    };
    let (name, tid) = match s.split_once('.') {
        Some((n, t)) => (n, Some(t.parse().ok()?)),
        None => (s, None),
    };
    let num: u32 = name.get(1..)?.parse().ok()?;
    match name.as_bytes()[0] {
        b'A' => Some((ConnId::Socket(num), tid)),
        b'D' => Some((ConnId::Domain(num), tid)),
        _ => None,
    }
}

fn word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.split_once(' ') {
        Some((w, rest)) => (w, rest),
        None => (s, ""),
    }
}

/// Paths are logged as the client sent them: relative ones are relative to
/// the connection's home, `/local/domain/<domid>` (domain 0 for sockets).
fn absolute(conn: ConnId, path: &str) -> String {
    if path.starts_with('/') || path.starts_with('@') {
        return path.to_string();
    }
    let home = match conn {
        ConnId::Domain(d) => d,
        ConnId::Socket(_) => 0,
    };
    format!("/local/domain/{home}/{path}")
}

pub fn parse_line(line: &str) -> Line {
    let Some((_, rest)) = line.split_once("oxenstored:") else {
        return Line::Unparsed;
    };
    let (conn_s, rest) = word(rest);
    let Some((conn, tid)) = parse_conn(conn_s) else {
        return Line::Unparsed;
    };
    let (op, rest) = word(rest);
    let (first, rest) = word(rest);
    if op == "w" && first == "event" {
        return Line::Event(conn);
    }
    if first.is_empty() {
        return Line::Other(op.to_string());
    }
    let path = absolute(conn, first);
    let op = match op {
        "write" => Op::Write {
            path,
            value: rest.to_string(),
        },
        "mkdir" => Op::Mkdir { path },
        "rm" => Op::Rm { path },
        "setperms" => Op::SetPerms {
            path,
            perms: rest.split_whitespace().map(str::to_string).collect(),
        },
        "watch" => Op::Watch {
            path,
            token: rest.trim().to_string(),
        },
        "unwatch" => Op::Unwatch {
            path,
            token: rest.trim().to_string(),
        },
        other => return Line::Other(other.to_string()),
    };
    Line::Request(Record { conn, tid, op })
}

/// Placeholders left in templates.
pub const DOMID: char = '\u{1}';
pub const UUID: char = '\u{2}';

/// Words in which a number is a domid: `vif4.0`, `dom4`, `domain-4`, `tapback-4-back`.
const DOMID_PREFIXES: [&str; 5] = ["domain-", "tapback-", "dom", "vif", "tap"];

/// Replaces the number `domid` inside a word when it is a whole number
/// directly after one of `DOMID_PREFIXES`. Any other number is left alone:
/// a bare `4` is far more often a state, and `ipv4` is not about domain 4.
fn word_rule(s: &str, domid: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let before = &s[..start];
            let prefixed = DOMID_PREFIXES.iter().any(|p| {
                before
                    .strip_suffix(p)
                    .is_some_and(|rest| !rest.ends_with(|c: char| c.is_ascii_alphanumeric()))
            });
            if prefixed && &s[start..i] == domid {
                out.push(DOMID);
            } else {
                out.push_str(&s[start..i]);
            }
        } else {
            // Copy one whole character (the log may hold non-ASCII bytes).
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn path_rule(s: &str, domid: &str) -> String {
    s.split('/')
        .map(|c| {
            if c == domid {
                DOMID.to_string()
            } else {
                word_rule(c, domid)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Turns the strings of a record of the recorded VM into templates.
pub struct Templater {
    domid: String,
    uuid: String,
}

impl Templater {
    pub fn new(domid: u32, uuid: &str) -> Templater {
        Templater {
            domid: domid.to_string(),
            uuid: uuid.to_string(),
        }
    }

    fn uuid(&self, s: &str) -> String {
        if self.uuid.is_empty() {
            s.to_string()
        } else {
            s.replace(&self.uuid, &UUID.to_string())
        }
    }

    pub fn path(&self, s: &str) -> String {
        path_rule(&self.uuid(s), &self.domid)
    }

    pub fn value(&self, s: &str) -> String {
        let s = self.uuid(s);
        if s.starts_with('/') {
            path_rule(&s, &self.domid)
        } else {
            word_rule(&s, &self.domid)
        }
    }

    /// A permission is a letter (`n`, `r`, `w`, `b`) followed by a domid.
    pub fn perm(&self, s: &str) -> String {
        match s.get(1..) {
            Some(d) if d == self.domid => format!("{}{}", &s[..1], DOMID),
            _ => s.to_string(),
        }
    }

    pub fn token(&self, s: &str) -> String {
        if s == self.domid {
            return DOMID.to_string();
        }
        word_rule(&self.uuid(s), &self.domid)
    }

    pub fn op(&self, op: &Op) -> Op {
        match op {
            Op::Write { path, value } => Op::Write {
                path: self.path(path),
                value: self.value(value),
            },
            Op::Mkdir { path } => Op::Mkdir { path: self.path(path) },
            Op::Rm { path } => Op::Rm { path: self.path(path) },
            Op::SetPerms { path, perms } => Op::SetPerms {
                path: self.path(path),
                perms: perms.iter().map(|p| self.perm(p)).collect(),
            },
            Op::Watch { path, token } => Op::Watch {
                path: self.path(path),
                token: self.token(token),
            },
            Op::Unwatch { path, token } => Op::Unwatch {
                path: self.path(path),
                token: self.token(token),
            },
        }
    }
}

/// Fills a template for one simulated VM.
pub fn instantiate(template: &str, domid: u32, uuid: &str) -> String {
    if !template.contains([DOMID, UUID]) {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len() + 40);
    for ch in template.chars() {
        match ch {
            DOMID => out.push_str(&domid.to_string()),
            UUID => out.push_str(uuid),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "Jan  1 07:41:11 xcp-ng-host oxenstored:  ";

    fn req(line: &str) -> Record {
        match parse_line(&format!("{P}{line}")) {
            Line::Request(r) => r,
            other => panic!("not a request: {other:?}"),
        }
    }

    #[test]
    fn parses_each_operation() {
        assert_eq!(
            req("A11.22       setperms  /local/domain/4 n0 r4"),
            Record {
                conn: ConnId::Socket(11),
                tid: Some(22),
                op: Op::SetPerms {
                    path: "/local/domain/4".into(),
                    perms: vec!["n0".into(), "r4".into()]
                }
            }
        );
        assert_eq!(
            req("A11.22       write     /vm/u/name test guest"),
            Record {
                conn: ConnId::Socket(11),
                tid: Some(22),
                op: Op::Write {
                    path: "/vm/u/name".into(),
                    value: "test guest".into()
                }
            }
        );
        assert_eq!(req("A6  mkdir /a").op, Op::Mkdir { path: "/a".into() });
        assert_eq!(req("A6  rm /a").op, Op::Rm { path: "/a".into() });
        assert_eq!(
            req("A11          watch     /local/domain/4/attr xenopsd-xc:domain-4").op,
            Op::Watch {
                path: "/local/domain/4/attr".into(),
                token: "xenopsd-xc:domain-4".into()
            }
        );
        assert_eq!(
            req("A11          unwatch   @introduceDomain").op,
            Op::Unwatch {
                path: "@introduceDomain".into(),
                token: "".into()
            }
        );
        assert_eq!(
            req("A6 write /a").op,
            Op::Write {
                path: "/a".into(),
                value: "".into()
            }
        );
    }

    #[test]
    fn relative_paths_use_the_connection_home() {
        assert_eq!(
            req("D4           write     data/meminfo_free 366312").op,
            Op::Write {
                path: "/local/domain/4/data/meminfo_free".into(),
                value: "366312".into()
            }
        );
        assert_eq!(
            req("A1           watch     backend/vbd3 tapback-master-back").op,
            Op::Watch {
                path: "/local/domain/0/backend/vbd3".into(),
                token: "tapback-master-back".into()
            }
        );
    }

    #[test]
    fn replayed_transactions_keep_their_connection() {
        let r = req("r(30):A11.31 rm        /xenops/domain/4");
        assert_eq!((r.conn, r.tid), (ConnId::Socket(11), Some(31)));
    }

    #[test]
    fn events_other_and_unparsed() {
        assert_eq!(
            parse_line(&format!("{P}A7           w event   /local/domain/2/data/x tok")),
            Line::Event(ConnId::Socket(7))
        );
        assert_eq!(
            parse_line(&format!("{P}D4           reset")),
            Line::Other("reset".into())
        );
        assert_eq!(
            parse_line(&format!("{P}D4           debug     x y")),
            Line::Other("debug".into())
        );
        assert_eq!(parse_line("no daemon tag here"), Line::Unparsed);
        assert_eq!(parse_line(&format!("{P}X9 write /a b")), Line::Unparsed);
        assert_eq!(parse_line(&format!("{P}A write /a b")), Line::Unparsed);
        assert_eq!(parse_line(&format!("{P}A1.x write /a b")), Line::Unparsed);
        assert_eq!(parse_line(&format!("{P}r(3A1 write /a b")), Line::Unparsed);
        assert_eq!(parse_line(P), Line::Unparsed);
    }

    #[test]
    fn op_names() {
        let names: Vec<_> = [
            "write /a b",
            "mkdir /a",
            "rm /a",
            "setperms /a n0",
            "watch /a t",
            "unwatch /a t",
        ]
        .iter()
        .map(|l| req(&format!("A1 {l}")).op.name())
        .collect();
        assert_eq!(names, ["write", "mkdir", "rm", "setperms", "watch", "unwatch"]);
    }

    #[test]
    fn templates_domid_only_where_it_is_one() {
        let t = Templater::new(4, "f2107a4b-98b2");
        let d = DOMID;
        let u = UUID;
        assert_eq!(
            t.path("/local/domain/4/device/vbd/768"),
            format!("/local/domain/{d}/device/vbd/768")
        );
        assert_eq!(
            t.path("/local/domain/0/backend/vif/4/0/state"),
            format!("/local/domain/0/backend/vif/{d}/0/state")
        );
        assert_eq!(t.path("/vm/f2107a4b-98b2/domains/4"), format!("/vm/{u}/domains/{d}"));
        assert_eq!(t.path("/local/domain/44/x14"), "/local/domain/44/x14");
        assert_eq!(t.value("4"), "4");
        assert_eq!(t.value("vif4.0"), format!("vif{d}.0"));
        assert_eq!(t.value("/local/domain/4"), format!("/local/domain/{d}"));
        assert_eq!(t.value("f2107a4b-98b2"), u.to_string());
        assert_eq!(t.value("état 4"), "état 4");
        assert_eq!(t.perm("r4"), format!("r{d}"));
        assert_eq!(t.perm("n0"), "n0");
        assert_eq!(t.perm("r44"), "r44");
        assert_eq!(t.perm(""), "");
        assert_eq!(t.token("xenopsd-xc:domain-4"), format!("xenopsd-xc:domain-{d}"));
        assert_eq!(t.token("tapback-4-back"), format!("tapback-{d}-back"));
        assert_eq!(t.token("4"), d.to_string());
        assert_eq!(t.token("auto:4"), "auto:4");
        assert_eq!(t.token("dom4"), format!("dom{d}"));
        assert_eq!(
            t.path("/local/domain/4/device/vif/0/feature-gso-tcpv4"),
            format!("/local/domain/{d}/device/vif/0/feature-gso-tcpv4")
        );
        assert_eq!(t.path("/a/ipv4/0"), "/a/ipv4/0");
        assert_eq!(t.path("/a/acpi_s4"), "/a/acpi_s4");
        assert_eq!(t.value("random4"), "random4");
        assert_eq!(t.value("tap4.0 vif44.0"), format!("tap{d}.0 vif44.0"));
        assert_eq!(Templater::new(4, "").path("/vm/x"), "/vm/x");
    }

    #[test]
    fn templates_every_field_of_an_op() {
        let t = Templater::new(4, "U");
        let d = DOMID;
        assert_eq!(
            t.op(&Op::Write {
                path: "/libxl/4".into(),
                value: "dom4".into()
            }),
            Op::Write {
                path: format!("/libxl/{d}"),
                value: format!("dom{d}")
            }
        );
        assert_eq!(
            t.op(&Op::Mkdir {
                path: "/libxl/4".into()
            }),
            Op::Mkdir {
                path: format!("/libxl/{d}")
            }
        );
        assert_eq!(
            t.op(&Op::Rm {
                path: "/libxl/4".into()
            }),
            Op::Rm {
                path: format!("/libxl/{d}")
            }
        );
        assert_eq!(
            t.op(&Op::SetPerms {
                path: "/libxl/4".into(),
                perms: vec!["n0".into(), "r4".into()]
            }),
            Op::SetPerms {
                path: format!("/libxl/{d}"),
                perms: vec!["n0".into(), format!("r{d}")]
            }
        );
        assert_eq!(
            t.op(&Op::Watch {
                path: "/libxl/4".into(),
                token: "dom4".into()
            }),
            Op::Watch {
                path: format!("/libxl/{d}"),
                token: format!("dom{d}")
            }
        );
        assert_eq!(
            t.op(&Op::Unwatch {
                path: "/libxl/4".into(),
                token: "dom4".into()
            }),
            Op::Unwatch {
                path: format!("/libxl/{d}"),
                token: format!("dom{d}")
            }
        );
    }

    #[test]
    fn instantiate_fills_placeholders() {
        let t = Templater::new(4, "U-U");
        let templ = t.path("/vm/U-U/domains/4");
        assert_eq!(instantiate(&templ, 1234, "abcd"), "/vm/abcd/domains/1234");
        assert_eq!(instantiate("/plain", 1, "x"), "/plain");
    }
}
