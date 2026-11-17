// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! XSA-206: a domain whose changes keep making others' transactions fail
//! loses credit, and without credit gets no request processed until time
//! gives it some back (oxenstored 4.17: `ox/history.ml`,
//! `ox/domains.ml:177-246`, `ox/process.ml:438-507`, `ox/xenstored.ml:404-452`).
//!
//! History: each change of the store by a domain other than 0 (a request
//! outside a transaction, or a commit) is recorded with the store before
//! and after it. A commit that fails blames each other connection with a
//! record since the transaction started such that the transaction would
//! have committed on the store before it and not after it. Records are
//! kept only while a transaction younger than `conflict-max-history-seconds`
//! may need them: protection is for short transactions.
//!
//! Credit: a domain starts with `conflict-burst-limit`, loses one per
//! blame (down to -1), and is paused at 0 or less. Every period one point
//! is given back: to the domain at the front of the queue of paused
//! domains, else of penalised ones (aggregate), or to every penalised
//! domain. Domain 0 and sockets are never recorded, so never blamed.

use crate::prelude::*;
use crate::store::Node;
use crate::{Config, ConnId, Conns};
use alloc::collections::{BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::time::Duration;

/// A change of the store by a connection that may be blamed.
struct Record {
    con: ConnId,
    before: Arc<Node>,
    after: Arc<Node>,
    /// `finish_count`: records are numbered from 1, in order.
    finish: u64,
}

/// A transaction started, until it ends or is older than a period.
struct Short {
    start: Duration,
    count: u64,
    serial: u64,
}

pub(crate) struct Conflicts {
    burst: f64,
    period: Duration,
    aggregate: bool,
    /// The time the loop last gave.
    pub(crate) now: Duration,
    /// When credit is given next (`next_frequent_ops`).
    next: Duration,
    /// Records made so far (`Transaction.counter`).
    count: u64,
    serials: u64,
    /// Transactions open, all connections: with none, no record can
    /// ever be looked at, and none is made.
    pub(crate) open: usize,
    /// Oldest first (`short_running_txns`).
    short: VecDeque<Short>,
    /// Transactions of `short` that ended, removed when they reach its front.
    pub(crate) ended: BTreeSet<u64>,
    /// Oldest first.
    history: VecDeque<Record>,
    /// Credit 0 or less, in the order they got there.
    pub(crate) paused: VecDeque<ConnId>,
    /// Below the burst limit: in the order they got there (aggregate), or
    /// all of them (otherwise).
    penalised: VecDeque<ConnId>,
    /// Paused (not aggregate).
    pub(crate) n_paused: usize,
}

/// A transaction as the history sees it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Started {
    /// Records made before it started.
    pub count: u64,
    pub serial: u64,
}

impl Conflicts {
    pub(crate) fn new(cfg: &Config) -> Conflicts {
        Conflicts {
            // A NaN limit never pauses anybody in oxenstored: its
            // comparisons are all false.
            burst: if cfg.conflict_burst_limit.is_nan() {
                f64::INFINITY
            } else {
                cfg.conflict_burst_limit
            },
            period: cfg.conflict_max_history,
            aggregate: cfg.conflict_rate_limit_is_aggregate,
            now: Duration::ZERO,
            next: Duration::ZERO,
            count: 0,
            serials: 0,
            open: 0,
            short: VecDeque::new(),
            ended: BTreeSet::new(),
            history: VecDeque::new(),
            paused: VecDeque::new(),
            penalised: VecDeque::new(),
            n_paused: 0,
        }
    }

    /// The credit of a new connection: the limit for those that may be
    /// blamed (`ox/domain.ml:107`), unlimited for the others.
    pub(crate) fn initial(&self, blamable: bool) -> f64 {
        if blamable {
            self.burst
        } else {
            f64::INFINITY
        }
    }

    /// A transaction starts (`ox/transaction.ml:121-138`).
    pub(crate) fn start(&mut self) -> Started {
        self.serials += 1;
        self.open += 1;
        self.short.push_back(Short {
            start: self.now,
            count: self.count,
            serial: self.serials,
        });
        Started {
            count: self.count,
            serial: self.serials,
        }
    }

    /// A transaction ended (committed or not): it protects nothing more
    /// (`ox/history.ml:37-40`).
    pub(crate) fn end(&mut self, t: Started) {
        crate::uncount(&mut self.open, 1, "open transactions");
        // Out of `short` already if it expired; entries leave from the front only.
        if self.short.front().is_some_and(|s| s.serial <= t.serial) {
            self.ended.insert(t.serial);
        }
        self.trim();
    }

    /// Records a change by a connection that may be blamed
    /// (`ox/history.ml:46-50`); the caller makes none while no
    /// transaction is open, as none could need it.
    pub(crate) fn record(&mut self, con: ConnId, before: Arc<Node>, after: &Arc<Node>) {
        // A request that changed nothing cannot be blamed: both stores
        // give the same replies.
        if !Arc::ptr_eq(&before, after) {
            self.count += 1;
            self.history.push_back(Record {
                con,
                before,
                after: after.clone(),
                finish: self.count,
            });
        }
    }

    /// Drops what no transaction young enough can need (`ox/history.ml:26-35`).
    pub(crate) fn trim(&mut self) {
        let cutoff = self.now.saturating_sub(self.period);
        while let Some(s) = self.short.front() {
            let ended = self.ended.remove(&s.serial);
            if !ended && s.start >= cutoff {
                break;
            }
            self.short.pop_front();
        }
        match self.short.front() {
            None => self.history.clear(),
            Some(s) => {
                while self.history.front().is_some_and(|r| r.finish <= s.count) {
                    self.history.pop_front();
                }
            }
        }
    }

    /// The connections other than `victim` to blame for the failure of a
    /// transaction (`ox/process.ml:472-499`, `ox/history.ml:52-62`):
    /// `commits(store)` says whether it would commit on that store.
    /// `same(before, after)` says that the transaction cannot tell the
    /// two apart, so that it commits on both or on neither: the record is
    /// not judged, which needs no run of the transaction (with `|_, _|
    /// false`, every record is judged).
    pub(crate) fn culprits(
        &self,
        t: Started,
        victim: ConnId,
        same: impl Fn(&Node, &Node) -> bool,
        mut commits: impl FnMut(&Arc<Node>) -> bool,
    ) -> Vec<ConnId> {
        let mut guilty = Vec::new();
        let mut seen = BTreeSet::new();
        for r in self.history.iter().filter(|r| r.finish > t.count && r.con != victim) {
            if !seen.contains(&r.con) && !same(&r.before, &r.after) && commits(&r.before) && !commits(&r.after) {
                seen.insert(r.con);
                guilty.push(r.con);
            }
        }
        guilty
    }

    /// One point less for a connection (`ox/domains.ml:177-206`).
    pub(crate) fn penalise(&mut self, conns: &mut Conns, id: ConnId) {
        let Some(c) = conns.map.get_mut(&id) else { return };
        let before = c.credit;
        let after = (before - 1.0).max(-1.0);
        c.credit = after;
        let newly_penalised = before >= self.burst && after < self.burst;
        let newly_paused = before > 0.0 && after <= 0.0;
        if self.aggregate {
            if newly_penalised && after > 0.0 {
                self.penalised.push_back(id);
            } else if newly_paused {
                if self.paused.is_empty() {
                    self.first_pause();
                }
                self.paused.push_back(id);
            }
        } else {
            if newly_penalised {
                self.penalised.push_back(id);
            }
            if newly_paused {
                self.n_paused += 1;
                if self.n_paused == 1 {
                    self.first_pause();
                }
            }
        }
    }

    /// The first credit comes a whole period after the first pause
    /// (`on_first_conflict_pause`, `ox/xenstored.ml:405-411`).
    fn first_pause(&mut self) {
        self.next = self.now.saturating_add(self.period);
    }

    /// The loop gives the time; once per period, history is trimmed and
    /// credit given (`ox/xenstored.ml:447-452`). Those resumed are marked
    /// dirty, for `take_dirty` to report.
    pub(crate) fn tick(&mut self, conns: &mut Conns, now: Duration) {
        self.now = now;
        if now < self.next {
            return;
        }
        self.trim();
        self.next = now.saturating_add(self.period);
        let burst = self.burst;
        // A connection that goes leaves the queues (`forget`); one that
        // were still there would be taken as having all its credit, and
        // leave them.
        let give = |id: ConnId, conns: &mut Conns| {
            let credit = conns.map.get_mut(&id).map(|c| {
                let before = c.credit;
                c.credit = (c.credit + 1.0).min(burst);
                (before, c.credit)
            });
            let (before, after) = credit.unwrap_or((burst, burst));
            if before <= 0.0 && after > 0.0 {
                conns.mark_dirty(id);
            }
            (before, after)
        };
        if self.aggregate {
            // One point, to one domain (`ox/domains.ml:208-229`).
            if let Some(id) = self.paused.pop_front() {
                if give(id, conns).1 <= 0.0 {
                    self.paused.push_back(id);
                }
            } else if let Some(id) = self.penalised.pop_front() {
                if give(id, conns).1 < burst {
                    self.penalised.push_back(id);
                }
            }
        } else {
            // A point each (`ox/domains.ml:231-246`).
            let mut resumed = 0;
            self.penalised.retain(|&id| {
                let (before, after) = give(id, conns);
                resumed += (before <= 0.0 && after > 0.0) as usize;
                after < burst
            });
            crate::uncount(&mut self.n_paused, resumed, "paused domains");
        }
    }

    /// When `tick` must be called at the latest: never while every domain
    /// has all its credit (`ox/xenstored.ml:595-600`).
    pub(crate) fn deadline(&self) -> Option<Duration> {
        (!self.paused.is_empty() || !self.penalised.is_empty()).then_some(self.next)
    }

    /// A connection goes: out of the queues (`ox/domains.ml:126-131`).
    pub(crate) fn forget(&mut self, id: ConnId, credit: f64) {
        if credit < self.burst {
            self.paused.retain(|c| *c != id);
            self.penalised.retain(|c| *c != id);
            if !self.aggregate && credit <= 0.0 {
                crate::uncount(&mut self.n_paused, 1, "paused domains");
            }
        }
    }

    /// Records kept.
    #[cfg(test)]
    pub(crate) fn records(&self) -> usize {
        self.history.len()
    }

    /// The versions before and after each record kept.
    #[cfg(test)]
    pub(crate) fn versions(&self) -> impl Iterator<Item = (&Node, &Node)> {
        self.history.iter().map(|r| (&*r.before, &*r.after))
    }

    /// Checks the queues and counts against the credits (the auditor's).
    pub(crate) fn audit(&self, conns: &Conns) -> Result<(), String> {
        let open: usize = conns.map.values().map(|c| c.txns.len()).sum();
        if open != self.open {
            return Err(format!(
                "conflicts: {} transactions counted open, {open} are",
                self.open
            ));
        }
        if let Some(s) = self.ended.iter().find(|s| !self.short.iter().any(|t| t.serial == **s)) {
            return Err(format!("conflicts: transaction {s} ended, not young"));
        }
        let count = |q: &VecDeque<ConnId>, id: &ConnId| q.iter().filter(|c| *c == id).count();
        for q in [&self.paused, &self.penalised] {
            if let Some(id) = q.iter().find(|id| !conns.map.get(id).is_some_and(|c| c.blamable())) {
                return Err(format!("conflicts: {id:?} queued, not open or not blamable"));
            }
        }
        let mut n_paused = 0;
        for (id, c) in &conns.map {
            // A limit of 0 or less pauses a domain from its start, for good,
            // in no queue: only credit taken away puts one there.
            let below = c.credit < self.burst;
            let paused = below && c.credit <= 0.0;
            n_paused += paused as usize;
            let (p, q) = (count(&self.paused, id), count(&self.penalised, id));
            let ok = if !c.blamable() {
                c.credit == f64::INFINITY
            } else if self.aggregate {
                p == paused as usize && q <= 1 && below == (p + q > 0)
            } else {
                p == 0 && q == below as usize
            };
            if !ok {
                return Err(format!(
                    "conflicts: {id:?} has credit {}, queued {p} paused and {q} penalised",
                    c.credit
                ));
            }
        }
        if !self.aggregate && n_paused != self.n_paused {
            return Err(format!("conflicts: {} counted paused, {n_paused} are", self.n_paused));
        }
        Ok(())
    }
}
