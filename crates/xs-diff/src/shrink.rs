// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Shrinks a failing sequence: removes chunks of operations, then single
//! ones, then parts of bursts and transactions, keeping each change after
//! which the difference is still there (ddmin, simplified).

use crate::gen::Op;

/// `still(ops)`: the difference is still there. At most `budget` calls.
/// `simpler` gives simpler versions of one item.
pub fn shrink<T: Clone>(
    mut ops: Vec<T>,
    still: &mut dyn FnMut(&[T]) -> bool,
    budget: usize,
    simpler: &dyn Fn(&T) -> Vec<T>,
) -> Vec<T> {
    let mut calls = 0usize;
    let mut try_it = |cand: &[T], calls: &mut usize| -> bool {
        if *calls >= budget {
            return false;
        }
        *calls += 1;
        still(cand)
    };
    // Chunks, halving.
    let mut n = 2usize;
    while ops.len() > 1 && calls < budget {
        let chunk = ops.len().div_ceil(n);
        let mut removed = false;
        let mut start = 0;
        while start < ops.len() {
            let end = (start + chunk).min(ops.len());
            let cand: Vec<T> = ops
                .iter()
                .enumerate()
                .filter(|(i, _)| *i < start || *i >= end)
                .map(|(_, o)| o.clone())
                .collect();
            if !cand.is_empty() && try_it(&cand, &mut calls) {
                ops = cand;
                removed = true;
            } else {
                start = end;
            }
        }
        if removed {
            n = n.saturating_sub(1).max(2);
        } else if chunk <= 1 {
            break;
        } else {
            n = (n * 2).min(ops.len());
        }
    }
    // Parts of bursts and transactions.
    let mut i = 0;
    while i < ops.len() && calls < budget {
        let options = ops.get(i).map(simpler).unwrap_or_default();
        for cand_op in options {
            let mut cand = ops.clone();
            if let Some(slot) = cand.get_mut(i) {
                *slot = cand_op;
            }
            if try_it(&cand, &mut calls) {
                ops = cand;
                break;
            }
        }
        i += 1;
    }
    ops
}

/// Simpler versions of one operation.
pub fn simpler(op: &Op) -> Vec<Op> {
    let mut out = Vec::new();
    match op {
        Op::Burst { conn, reqs } => {
            for r in reqs.iter().take(8) {
                out.push(Op::One {
                    conn: *conn,
                    req: r.clone(),
                });
            }
            if reqs.len() > 2 {
                let half = reqs.len() / 2;
                out.push(Op::Burst {
                    conn: *conn,
                    reqs: reqs.iter().take(half).cloned().collect(),
                });
                out.push(Op::Burst {
                    conn: *conn,
                    reqs: reqs.iter().skip(half).cloned().collect(),
                });
            }
        }
        Op::Split { conn, req, .. } => out.push(Op::One {
            conn: *conn,
            req: req.clone(),
        }),
        Op::TxBlock {
            conn,
            body,
            interfere,
            commit,
            attempts,
        } => {
            if interfere.is_some() {
                out.push(Op::TxBlock {
                    conn: *conn,
                    body: body.clone(),
                    interfere: None,
                    commit: *commit,
                    attempts: *attempts,
                });
            }
            for k in 0..body.len() {
                out.push(Op::TxBlock {
                    conn: *conn,
                    body: body
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != k)
                        .map(|(_, r)| r.clone())
                        .collect(),
                    interfere: interfere.clone(),
                    commit: *commit,
                    attempts: *attempts,
                });
            }
            if *attempts > 1 {
                out.push(Op::TxBlock {
                    conn: *conn,
                    body: body.clone(),
                    interfere: interfere.clone(),
                    commit: *commit,
                    attempts: 1,
                });
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{Req, Tx};

    fn op(n: u32) -> Op {
        Op::One {
            conn: 0,
            req: Req {
                ty: 2,
                req_id: n,
                tx: Tx::Zero,
                payload: Vec::new(),
            },
        }
    }

    #[test]
    fn keeps_only_what_the_difference_needs() {
        let ops: Vec<Op> = (0..40).map(op).collect();
        let needs = |o: &[Op]| o.contains(&op(7)) && o.contains(&op(31));
        let mut still = |o: &[Op]| needs(o);
        let out = shrink(ops, &mut still, 1000, &simpler);
        assert_eq!(out, vec![op(7), op(31)]);
    }
}
