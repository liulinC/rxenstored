// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Node counts per owner, for `quota-maxentity` (`ox/quota.ml`).
//!
//! Every node but the root counts for the domain that owns it: a node is
//! created with its parent's permissions, so for the parent's owner
//! (`ox/store.ml:415-436`); SET_PERMS moves it to its new owner
//! (`ox/store.ml:446-457`); removing a subtree uncounts every node in it,
//! whoever owns it (`ox/store.ml:438-444`). The counts are kept as the
//! store changes, one update per node created, removed or given away.
//!
//! The store has its counts; a transaction has its changes to them, and
//! its checks see the store's counts plus those changes. (oxenstored's
//! see the counts as they were when the transaction started: keeping a
//! copy per transaction would make TRANSACTION_START cost a domain count.)
//!
//! Where oxenstored's counts are not what the store holds, they are not
//! copied: the root never counts (oxenstored does not count it but moves
//! or removes a count for it on SET_PERMS and on RM of the root), and a
//! dead domain's subtree uncounts what other domains owned in it
//! (oxenstored forgets the dead domain's count only, `ox/store.ml:459-470`).

use crate::store::Node;
use alloc::collections::BTreeMap;

/// Nodes per owner in a version of the store; owners with none are absent.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Entries(BTreeMap<i64, usize>);

impl Entries {
    pub fn get(&self, owner: i64) -> usize {
        self.0.get(&owner).copied().unwrap_or(0)
    }

    /// Never below zero, and never a panic: a guest must not be able to
    /// crash the daemon through a miscount (XSA-440). The auditor finds one.
    fn add(&mut self, owner: i64, n: isize) {
        let v = self.0.entry(owner).or_insert(0);
        *v = v.saturating_add_signed(n);
        if *v == 0 {
            self.0.remove(&owner);
        }
    }

    /// A transaction's changes, at its commit.
    pub fn apply(&mut self, d: Delta) {
        for (owner, n) in d.0 {
            self.add(owner, n);
        }
    }

    /// The counts of a version of the store, from its nodes (the auditor's).
    pub fn recount(root: &Node) -> Entries {
        let mut e = Entries::default();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            for (_, c) in n.children.iter() {
                e.add(c.perms.owner, 1);
                stack.push(c);
            }
        }
        e
    }

    /// The owners and their counts, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (i64, usize)> + '_ {
        self.0.iter().map(|(o, n)| (*o, *n))
    }
}

/// A transaction's changes to the counts of the store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Delta(BTreeMap<i64, isize>);

impl Delta {
    pub fn get(&self, owner: i64) -> isize {
        self.0.get(&owner).copied().unwrap_or(0)
    }
}

/// The counts an operation reads and changes: the store's, or a
/// transaction's changes over the store's.
pub enum Acct<'a> {
    Store(&'a mut Entries),
    Txn(&'a Entries, &'a mut Delta),
}

/// The changes that make counts `from` into `to` (the auditor's).
pub fn diff(to: &Entries, from: &Entries) -> Delta {
    let mut d = Delta::default();
    let mut acct = Acct::Txn(from, &mut d);
    for (o, n) in to.iter() {
        acct.add(o, n as isize);
    }
    for (o, n) in from.iter() {
        acct.add(o, -(n as isize));
    }
    d
}

/// What a transaction with changes `d` counts for `owner`. Others may
/// have removed some since it started: never below none.
fn txn_count(e: &Entries, d: &Delta, owner: i64) -> usize {
    (e.get(owner) as isize + d.get(owner)).max(0) as usize
}

impl Acct<'_> {
    pub fn get(&self, owner: i64) -> usize {
        match self {
            Acct::Store(e) => e.get(owner),
            Acct::Txn(e, d) => txn_count(e, d, owner),
        }
    }

    pub fn add(&mut self, owner: i64, n: isize) {
        match self {
            Acct::Store(e) => e.add(owner, n),
            Acct::Txn(_, d) => {
                let v = d.0.entry(owner).or_insert(0);
                *v += n;
                if *v == 0 {
                    d.0.remove(&owner);
                }
            }
        }
    }

    /// Uncounts a subtree that goes, its top included.
    pub fn remove_tree(&mut self, top: &Node) {
        let mut stack = vec![top];
        while let Some(n) = stack.pop() {
            self.add(n.perms.owner, -1);
            stack.extend(n.children.iter().map(|(_, c)| c));
        }
    }

    /// How many more nodes `owner` may be given by a caller held to `max`
    /// (None: not held): `Quota.check` refuses once the count, if any, is
    /// at the limit; domain 0 and the root's lost owner, -1, never are
    /// (`ox/quota.ml:51-66`, `id > 0`). So with a limit of 0 a domain may
    /// still get one node.
    pub fn room(&self, owner: i64, max: Option<usize>) -> usize {
        match max {
            Some(max) if owner > 0 => match self.get(owner) {
                0 => max.max(1),
                n => max.saturating_sub(n),
            },
            _ => usize::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::perms::Perms;
    use crate::store::NO_OWNER;
    use std::sync::Arc;

    #[test]
    fn counts_go_up_and_down_and_vanish_at_zero() {
        let mut e = Entries::default();
        let mut a = Acct::Store(&mut e);
        a.add(5, 2);
        a.add(5, -1);
        a.add(6, 1);
        assert_eq!((a.get(5), a.get(6), a.get(7)), (1, 1, 0));
        a.add(6, -1);
        assert_eq!(e.0.len(), 1, "no count left for 6");
        let mut d = Delta::default();
        let mut t = Acct::Txn(&e, &mut d);
        t.add(5, -1);
        t.add(7, 3);
        t.add(7, -3);
        assert_eq!((t.get(5), t.get(7)), (0, 0));
        assert_eq!(d.0.len(), 1, "no change left for 7");
        // Others removed more than the transaction saw.
        d.0.insert(9, -4);
        assert_eq!(Acct::Txn(&e, &mut d).get(9), 0);
        d.0.remove(&9);
        e.apply(d);
        assert_eq!(e, Entries::default());
    }

    #[test]
    fn a_count_never_goes_below_zero() {
        let mut e = Entries::default();
        Acct::Store(&mut e).add(5, -1);
        assert_eq!(e, Entries::default());
        Acct::Store(&mut e).add(5, 2);
        Acct::Store(&mut e).add(5, -3);
        assert_eq!(e, Entries::default());
    }

    #[test]
    fn room_left() {
        let mut e = Entries::default();
        let mut a = Acct::Store(&mut e);
        assert_eq!(a.room(5, None), usize::MAX);
        assert_eq!(a.room(5, Some(3)), 3);
        a.add(5, 2);
        assert_eq!(a.room(5, Some(3)), 1);
        a.add(5, 2);
        assert_eq!(a.room(5, Some(3)), 0, "over the limit (given by domain 0)");
        assert_eq!(a.room(6, Some(0)), 1, "none yet: one more (`with Not_found -> ()`)");
        assert_eq!(a.room(5, Some(0)), 0);
        a.add(0, 10);
        a.add(NO_OWNER, 10);
        assert_eq!(
            (a.room(0, Some(1)), a.room(NO_OWNER, Some(1))),
            (usize::MAX, usize::MAX)
        );
        // Any domid above 0 is held to it, the largest too.
        a.add(u32::MAX.into(), 10);
        assert_eq!(a.room(u32::MAX.into(), Some(1)), 0);
        assert_eq!(a.room(1, Some(1)), 1);
    }

    #[test]
    fn recount_and_removal_skip_the_root() {
        let p = |o| {
            Arc::new(Perms {
                owner: o,
                ..Perms::default0()
            })
        };
        let mut root = Node::new(p(5), Bytes::EMPTY, 0);
        let mut a = Node::new(p(6), Bytes::EMPTY, 0);
        a.children.insert(Bytes::from(b"b"), Node::new(p(7), Bytes::EMPTY, 0));
        a.children.insert(Bytes::from(b"c"), Node::new(p(6), Bytes::EMPTY, 0));
        root.children.insert(Bytes::from(b"a"), a.clone());
        let e = Entries::recount(&root);
        let mut seen: Vec<_> = e.iter().collect();
        seen.sort();
        assert_eq!(seen, [(6, 2), (7, 1)]);
        let mut e2 = e.clone();
        Acct::Store(&mut e2).remove_tree(&a);
        assert_eq!(e2, Entries::default());
    }
}
