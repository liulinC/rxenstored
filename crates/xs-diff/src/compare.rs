// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Compares two transcripts of the same sequence.
//!
//! Each difference gets a signature, a short line that names the kind of
//! request, the kind of its path and both answers ("WRITE @-path with /:
//! ox OK / rx EINVAL"): the unit of triage and of shrinking. Differences
//! whose signature the caller tolerates are skipped.

use crate::exec::{Item, Transcript, TxSym};
use crate::wire::{show, type_name, ERROR};
use std::collections::BTreeSet;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// The operation (index in the sequence); None for the final state.
    pub step: Option<usize>,
    pub conn: Option<usize>,
    pub sig: String,
    pub detail: String,
}

const PATH_TYPES: [u32; 10] = [1, 2, 3, 4, 5, 11, 12, 13, 14, 22];

/// What kind of path a request names.
pub fn path_class(p: &[u8]) -> &'static str {
    let ok = |b: &u8| b.is_ascii_alphanumeric() || b"/_@-".contains(b);
    if p.is_empty() {
        "empty path"
    } else if p.first() == Some(&b'@') {
        if p.contains(&b'/') {
            "@-path with /"
        } else {
            "@-path"
        }
    } else if p.len() > 900 {
        "long path"
    } else if p.first() != Some(&b'/') {
        if p.windows(2).any(|w| w == b"//") || p.ends_with(b"/") {
            "relative path with odd slashes"
        } else if !p.iter().all(ok) {
            "relative path with odd chars"
        } else {
            "relative path"
        }
    } else if p.windows(2).any(|w| w == b"//") || (p.len() > 1 && p.ends_with(b"/")) {
        "path with odd slashes"
    } else if !p.iter().all(ok) {
        "path with odd chars"
    } else if p.starts_with(b"/local/domain") || p.starts_with(b"/tool") {
        "daemon's path"
    } else {
        "path"
    }
}

/// The request, for a signature: its type and what kind of argument.
pub fn req_class(req: &Option<(u32, Vec<u8>)>) -> String {
    let Some((ty, payload)) = req else {
        return "(no request)".into();
    };
    let first = payload.split(|&b| b == 0).next().unwrap_or_default();
    let name = type_name(*ty);
    if PATH_TYPES.contains(ty) {
        format!("{name} {}", path_class(first))
    } else if *ty == 0 || *ty == 7 {
        format!("{name} {}", show(first))
    } else if *ty == 6 {
        format!("{name} \"{}\"", show(payload))
    } else {
        name
    }
}

fn answer(item: Option<&Item>) -> String {
    match item {
        None => "nothing".into(),
        Some(Item::Closed) => "closed".into(),
        Some(Item::Timeout) => "no answer".into(),
        Some(Item::Dead) => "connection gone".into(),
        Some(Item::Event { .. }) => "event".into(),
        Some(Item::Reply { req, ty, payload, .. }) => {
            if *ty == ERROR {
                show(payload.strip_suffix(b"\0").unwrap_or(payload))
            } else if req.as_ref().is_some_and(|r| r.0 == *ty) {
                if payload == b"OK\0" {
                    "OK".into()
                } else {
                    "data".into()
                }
            } else {
                format!("reply of type {}", type_name(*ty))
            }
        }
    }
}

pub fn show_item(i: &Item) -> String {
    match i {
        Item::Reply {
            req,
            ty,
            req_id,
            tx,
            payload,
        } => {
            let tx = match tx {
                TxSym::Zero => "0".to_string(),
                TxSym::Echo => "(its request's)".to_string(),
                TxSym::Raw(n) => n.to_string(),
            };
            let to = match req {
                Some((t, p)) => format!("{} \"{}\"", type_name(*t), show(p)),
                None => "?".into(),
            };
            format!(
                "{} rid={req_id} tx={tx} \"{}\"   <- {to}",
                type_name(*ty),
                show(payload)
            )
        }
        Item::Event { req_id, tx_id, payload } => {
            format!("WATCH_EVENT rid={req_id} tx={tx_id} \"{}\"", show(payload))
        }
        Item::Closed => "<closed by the daemon>".into(),
        Item::Timeout => "<no answer: given up>".into(),
        Item::Dead => "<connection already gone>".into(),
    }
}

fn show_items(v: &[Item]) -> String {
    let mut s = String::new();
    for i in v {
        let _ = writeln!(s, "      {}", show_item(i));
    }
    s
}

fn reply_sig(x: Option<&Item>, y: Option<&Item>) -> String {
    let req = match (x, y) {
        (Some(Item::Reply { req, .. }), _) | (_, Some(Item::Reply { req, .. })) => req_class(req),
        _ => "(connection)".into(),
    };
    let (ax, ay) = (answer(x), answer(y));
    if ax != ay {
        return format!("{req}: ox {ax} / rx {ay}");
    }
    match (x, y) {
        (
            Some(Item::Reply {
                req_id: r1,
                tx: t1,
                payload: p1,
                ..
            }),
            Some(Item::Reply {
                req_id: r2,
                tx: t2,
                payload: p2,
                ..
            }),
        ) => {
            if r1 != r2 {
                format!("{req}: request id differs")
            } else if t1 != t2 {
                format!("{req}: transaction id differs")
            } else if p1 != p2 {
                format!("{req}: payload differs")
            } else {
                format!("{req}: differs")
            }
        }
        _ => format!("{req}: ox {ax} / rx {ay}"),
    }
}

/// The differences between oxenstored's transcript and rxenstored's.
pub fn compare(ox: &Transcript, rx: &Transcript, tolerated: &dyn Fn(&str) -> bool) -> Vec<Diff> {
    let mut out = Vec::new();
    let mut push = |d: Diff| {
        if !tolerated(&d.sig) {
            out.push(d);
        }
    };
    for (step, (a, b)) in ox.steps.iter().zip(&rx.steps).enumerate() {
        for (conn, (a, b)) in a.iter().zip(b).enumerate() {
            if a == b {
                continue;
            }
            let (ar, ae): (Vec<&Item>, Vec<&Item>) = a.iter().partition(|i| !i.is_event());
            let (br, be): (Vec<&Item>, Vec<&Item>) = b.iter().partition(|i| !i.is_event());
            let detail = format!("    oxenstored:\n{}    rxenstored:\n{}", show_items(a), show_items(b));
            for j in 0..ar.len().max(br.len()) {
                let (x, y) = (ar.get(j).copied(), br.get(j).copied());
                if x != y {
                    push(Diff {
                        step: Some(step),
                        conn: Some(conn),
                        sig: reply_sig(x, y),
                        detail: detail.clone(),
                    });
                    break;
                }
            }
            if ae != be {
                let mut sa = ae.clone();
                let mut sb = be.clone();
                sa.sort();
                sb.sort();
                let sig = if sa == sb {
                    "watch events: same set, other order".to_string()
                } else {
                    // Counted: the same event twice is not the same as once.
                    let only = |p: &[&Item], q: &[&Item]| {
                        let mut q = q.to_vec();
                        p.iter()
                            .filter(|i| match q.iter().position(|x| x == *i) {
                                Some(k) => {
                                    q.remove(k);
                                    false
                                }
                                None => true,
                            })
                            .count()
                    };
                    format!(
                        "watch events differ (ox {} not in rx, rx {} not in ox)",
                        if only(&sa, &sb) > 0 { "has some" } else { "none" },
                        if only(&sb, &sa) > 0 { "has some" } else { "none" }
                    )
                };
                push(Diff {
                    step: Some(step),
                    conn: Some(conn),
                    sig,
                    detail,
                });
            } else if ar == br {
                // The same replies and events, interleaved otherwise.
                push(Diff {
                    step: Some(step),
                    conn: Some(conn),
                    sig: "watch events: same, in another place among the replies".to_string(),
                    detail,
                });
            }
        }
    }
    if ox.tx_numbers != rx.tx_numbers {
        let first = ox.tx_numbers.iter().zip(&rx.tx_numbers).find(|(a, b)| a != b);
        push(Diff {
            step: first.map(|(a, _)| a.0),
            conn: first.map(|(a, _)| a.1),
            sig: "TRANSACTION_START: ids numbered differently".into(),
            detail: format!(
                "    first difference (operation, connection, id): ox {:?} rx {:?}\n",
                first.map(|x| x.0),
                first.map(|x| x.1)
            ),
        });
    }
    if ox.steps.len() != rx.steps.len() {
        push(Diff {
            step: None,
            conn: None,
            sig: "transcripts of different lengths".into(),
            detail: String::new(),
        });
    }
    let keys: BTreeSet<&String> = ox.end.keys().chain(rx.end.keys()).collect();
    let mut by_sig: Vec<(String, String)> = Vec::new();
    for k in keys {
        let (a, b) = (ox.end.get(k), rx.end.get(k));
        if a == b {
            continue;
        }
        let sig = if k.starts_with("node ") {
            match (a, b) {
                (Some(_), None) => "final store: node only in oxenstored".to_string(),
                (None, Some(_)) => "final store: node only in rxenstored".to_string(),
                _ => "final store: value or permissions differ".to_string(),
            }
        } else if let Some(rest) = k.strip_prefix("probe ") {
            format!("final probe {} differs", rest.split(' ').next().unwrap_or_default())
        } else if k.starts_with("control quota") {
            "final CONTROL quota differs".to_string()
        } else {
            format!("final {k} differs")
        };
        let line = format!(
            "    {k}\n      ox: {}\n      rx: {}\n",
            a.map_or("<none>", |s| s.as_str()),
            b.map_or("<none>", |s| s.as_str())
        );
        match by_sig.iter_mut().find(|(s, _)| *s == sig) {
            Some((_, d)) => {
                if d.len() < 4000 {
                    d.push_str(&line);
                }
            }
            None => by_sig.push((sig, line)),
        }
    }
    for (sig, detail) in by_sig {
        push(Diff {
            step: None,
            conn: None,
            sig,
            detail,
        });
    }
    if ox.alive != rx.alive {
        push(Diff {
            step: None,
            conn: None,
            sig: format!("daemon exited: ox alive {} / rx alive {}", ox.alive, rx.alive),
            detail: String::new(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(payload: &[u8]) -> Item {
        Item::Reply {
            req: Some((11, b"/a\0".to_vec())),
            ty: 11,
            req_id: 1,
            tx: crate::exec::TxSym::Zero,
            payload: payload.to_vec(),
        }
    }

    fn event(payload: &[u8]) -> Item {
        Item::Event {
            req_id: 0,
            tx_id: 0,
            payload: payload.to_vec(),
        }
    }

    fn one_step(items: Vec<Item>) -> Transcript {
        Transcript {
            steps: vec![vec![items]],
            alive: true,
            ..Transcript::default()
        }
    }

    #[test]
    fn events_are_compared_in_order_and_among_the_replies() {
        let sigs = |a: Vec<Item>, b: Vec<Item>| -> Vec<String> {
            compare(&one_step(a), &one_step(b), &|_| false)
                .into_iter()
                .map(|d| d.sig)
                .collect()
        };
        let (r, e1, e2) = (reply(b"OK\0"), event(b"/a\0t1\0"), event(b"/a\0t2\0"));
        assert!(sigs(vec![r.clone(), e1.clone()], vec![r.clone(), e1.clone()]).is_empty());
        assert_eq!(
            sigs(
                vec![r.clone(), e1.clone(), e2.clone()],
                vec![r.clone(), e2.clone(), e1.clone()]
            ),
            ["watch events: same set, other order"]
        );
        assert_eq!(
            sigs(vec![e1.clone(), r.clone()], vec![r.clone(), e1.clone()]),
            ["watch events: same, in another place among the replies"]
        );
        assert_eq!(
            sigs(vec![r.clone(), e1.clone()], vec![r.clone(), e1.clone(), e1.clone()]),
            ["watch events differ (ox none not in rx, rx has some not in ox)"]
        );
        assert_eq!(
            sigs(vec![r.clone()], vec![reply(b"EIO\0")]),
            ["WRITE path: ox OK / rx data"]
        );
    }

    #[test]
    fn classes_of_paths() {
        assert_eq!(path_class(b"@a/b"), "@-path with /");
        assert_eq!(path_class(b"@introduceDomain"), "@-path");
        assert_eq!(path_class(b"a//b"), "relative path with odd slashes");
        assert_eq!(path_class(b"/a b"), "path with odd chars");
        assert_eq!(path_class(b"/a/b"), "path");
        assert_eq!(path_class(b"/"), "path");
    }
}
