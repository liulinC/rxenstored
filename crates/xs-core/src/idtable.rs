// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! A hash set of `u32` ids whose keys live elsewhere: the caller owns the
//! records the ids name, and gives the hash of a record and the test that
//! tells whether a record is the one looked for. Four bytes per slot, a
//! quarter to three quarters of them used: where a record is small, a
//! `HashMap` entry holding a copy of its key would cost more than the
//! record.
//!
//! Open addressing with linear probing; a removed id leaves a tombstone,
//! and the table is rebuilt when it fills up or empties, which keeps every
//! operation O(1) amortised.

use crate::prelude::*;

const EMPTY: u32 = u32::MAX;
const TOMB: u32 = u32::MAX - 1;
/// Smallest table.
const MIN_SLOTS: usize = 8;

#[derive(Debug, Default)]
pub struct IdTable {
    /// Empty, or a power of two slots, at least one of them `EMPTY`.
    slots: Vec<u32>,
    live: usize,
    tombs: usize,
}

impl IdTable {
    pub fn new() -> IdTable {
        IdTable::default()
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The slots from the one `hash` names, each once.
    fn probe(&self, hash: u64) -> impl Iterator<Item = usize> {
        let mask = self.slots.len().wrapping_sub(1);
        (0..self.slots.len()).map(move |i| (hash as usize).wrapping_add(i) & mask)
    }

    /// The id with this hash that `is` accepts.
    pub fn find(&self, hash: u64, is: impl Fn(u32) -> bool) -> Option<u32> {
        self.probe(hash)
            .map_while(|i| self.slots.get(i).copied())
            .take_while(|&id| id != EMPTY)
            .find(|&id| id != TOMB && is(id))
    }

    /// Adds `id`, which is not in the table and is below `u32::MAX - 1`.
    /// `hash_of` gives the hash of any id of the table.
    pub fn insert(&mut self, hash: u64, id: u32, hash_of: impl Fn(u32) -> u64) {
        debug_assert!(id < TOMB);
        if (self.live + self.tombs + 1) * 4 > self.slots.len() * 3 {
            self.rebuild(self.live + 1, &hash_of);
        }
        self.place(hash, id, &hash_of);
        self.live += 1;
    }

    /// Puts `id` in the first free slot from the one `hash` names. There is
    /// one: the table is at most three quarters full (`insert`); were it
    /// full, it is rebuilt larger first.
    fn place(&mut self, hash: u64, id: u32, hash_of: &impl Fn(u32) -> u64) {
        let free = self
            .probe(hash)
            .find(|&i| self.slots.get(i).is_some_and(|&s| s >= TOMB));
        match free.and_then(|i| self.slots.get_mut(i)) {
            Some(slot) => {
                if *slot == TOMB {
                    self.tombs -= 1;
                }
                *slot = id;
            }
            None => {
                self.rebuild(self.slots.len() + 1, hash_of);
                self.place(hash, id, hash_of);
            }
        }
    }

    /// Removes `id`, which is in the table with this hash (if it is not,
    /// nothing changes).
    pub fn remove(&mut self, hash: u64, id: u32, hash_of: impl Fn(u32) -> u64) {
        let found = self.probe(hash).find(|&i| self.slots.get(i) == Some(&id));
        let Some(slot) = found.and_then(|i| self.slots.get_mut(i)) else {
            return;
        };
        *slot = TOMB;
        self.live -= 1;
        self.tombs += 1;
        if self.slots.len() > MIN_SLOTS && self.live * 8 < self.slots.len() {
            self.rebuild(self.live, &hash_of);
        }
    }

    /// A table without tombstones, at most half full with `n` ids.
    fn rebuild(&mut self, n: usize, hash_of: &impl Fn(u32) -> u64) {
        let size = (n * 2).next_power_of_two().max(MIN_SLOTS);
        let old = core::mem::replace(&mut self.slots, vec![EMPTY; size]);
        self.tombs = 0;
        for id in old {
            if id < TOMB {
                self.place(hash_of(id), id, hash_of);
            }
        }
    }

    #[cfg(test)]
    fn slots(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids are their own keys; the hash spreads them, or not.
    fn spread(id: u32) -> u64 {
        (id as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 20
    }

    fn check(t: &IdTable, present: &[u32], absent: &[u32], hash: fn(u32) -> u64) {
        assert_eq!(t.len(), present.len());
        assert_eq!(t.is_empty(), present.is_empty());
        for &id in present {
            assert_eq!(t.find(hash(id), |x| x == id), Some(id));
        }
        for &id in absent {
            assert_eq!(t.find(hash(id), |x| x == id), None);
        }
        assert_eq!(t.slots.iter().filter(|&&s| s < TOMB).count(), t.live);
        assert_eq!(t.slots.iter().filter(|&&s| s == TOMB).count(), t.tombs);
        assert!(t.slots.is_empty() || t.slots.len().is_power_of_two());
        assert!(
            t.slots.is_empty() || (t.live + t.tombs) * 4 <= t.slots.len() * 3,
            "always a free slot"
        );
    }

    #[test]
    fn empty() {
        let t = IdTable::new();
        check(&t, &[], &[0, 1, 77], spread);
        assert_eq!(t.slots(), 0);
    }

    #[test]
    fn grows_and_shrinks() {
        let mut t = IdTable::new();
        let ids: Vec<u32> = (0..1000).collect();
        for (n, &id) in ids.iter().enumerate() {
            t.insert(spread(id), id, spread);
            if n % 97 == 0 {
                check(&t, &ids[..=n], &ids[n + 1..], spread);
            }
        }
        check(&t, &ids, &[1000, 5000], spread);
        assert_eq!(t.slots(), 2048, "between a quarter and three quarters full");
        for (n, &id) in ids.iter().enumerate() {
            t.remove(spread(id), id, spread);
            if n % 97 == 0 {
                check(&t, &ids[n + 1..], &ids[..=n], spread);
            }
            assert!(
                t.slots() <= MIN_SLOTS || t.len() * 8 >= t.slots(),
                "{n}: {} ids in {} slots",
                t.len(),
                t.slots()
            );
        }
        check(&t, &[], &ids, spread);
        assert_eq!(t.slots(), MIN_SLOTS);
    }

    #[test]
    fn sizes() {
        let mut t = IdTable::new();
        t.insert(spread(1), 1, spread);
        assert_eq!(t.slots(), MIN_SLOTS);
        for id in 2..=6 {
            t.insert(spread(id), id, spread);
        }
        assert_eq!(t.slots(), MIN_SLOTS, "six of eight slots");
        t.insert(spread(7), 7, spread);
        assert_eq!(t.slots(), 16);
        check(&t, &[1, 2, 3, 4, 5, 6, 7], &[0, 8], spread);
    }

    #[test]
    fn shrinks_below_an_eighth() {
        let mut t = IdTable::new();
        for id in 0..7 {
            t.insert(spread(id), id, spread);
        }
        assert_eq!(t.slots(), 16);
        t.remove(spread(0), 0, spread);
        assert_eq!((t.slots(), t.tombs), (16, 1), "a removal leaves a tombstone");
        for id in 1..5 {
            t.remove(spread(id), id, spread);
        }
        assert_eq!((t.slots(), t.tombs), (16, 5), "two of sixteen slots: an eighth");
        t.remove(spread(5), 5, spread);
        assert_eq!((t.slots(), t.tombs), (MIN_SLOTS, 0), "rebuilt below an eighth");
        check(&t, &[6], &[0, 1, 2, 3, 4, 5], spread);
        t.remove(spread(6), 6, spread);
        assert_eq!(
            (t.slots(), t.tombs),
            (MIN_SLOTS, 1),
            "the smallest table is not rebuilt"
        );
        check(&t, &[], &[6], spread);
    }

    #[test]
    fn a_rebuild_makes_room_for_the_new_id() {
        let mut t = IdTable::new();
        for id in 0..6 {
            t.insert(spread(id), id, spread);
        }
        t.remove(spread(0), 0, spread);
        t.remove(spread(1), 1, spread);
        assert_eq!((t.slots(), t.len(), t.tombs), (MIN_SLOTS, 4, 2));
        // Seven of eight slots would be in use: rebuilt for five ids, at
        // most half full.
        t.insert(spread(6), 6, spread);
        assert_eq!((t.slots(), t.tombs), (16, 0));
        check(&t, &[2, 3, 4, 5, 6], &[0, 1], spread);
    }

    #[test]
    fn colliding_hashes_and_tombstones() {
        // Every id in the same chain, wrapping around the end of the table.
        let same = |_: u32| 6u64;
        let mut t = IdTable::new();
        for id in 0..5 {
            t.insert(same(id), id, same);
        }
        assert_eq!(t.slots[6..], [0, 1]);
        assert_eq!(t.slots[..3], [2, 3, 4]);
        check(&t, &[0, 1, 2, 3, 4], &[5], same);
        // A tombstone does not cut the chain, and is reused.
        t.remove(same(1), 1, same);
        check(&t, &[0, 2, 3, 4], &[1], same);
        assert_eq!(t.tombs, 1);
        t.insert(same(9), 9, same);
        assert_eq!(t.slots[7], 9);
        assert_eq!(t.tombs, 0);
        check(&t, &[0, 2, 3, 4, 9], &[1], same);
        // `is` picks among ids with the same hash.
        assert_eq!(t.find(6, |x| x == 3), Some(3));
        assert_eq!(t.find(6, |_| false), None);
    }

    #[test]
    fn a_full_table_grows_instead_of_losing_the_id() {
        // Not reachable through `insert`, which keeps a quarter free.
        let mut t = IdTable {
            slots: (0..8).collect(),
            live: 0,
            tombs: 0,
        };
        t.insert(spread(8), 8, spread);
        assert_eq!(t.slots(), 32);
        assert_eq!(t.slots.iter().filter(|&&s| s < TOMB).count(), 9);
        for id in 0..9 {
            assert_eq!(t.find(spread(id), |x| x == id), Some(id));
        }
    }

    #[test]
    fn removing_an_absent_id_changes_nothing() {
        let mut t = IdTable::new();
        t.insert(spread(1), 1, spread);
        t.remove(spread(2), 2, spread);
        check(&t, &[1], &[2], spread);
        assert_eq!(t.tombs, 0);
    }

    #[test]
    fn churn_rebuilds_in_place() {
        // Adding and removing at a constant size fills the table with
        // tombstones: it is rebuilt at the same size, not grown.
        let mut t = IdTable::new();
        for id in 0..4 {
            t.insert(spread(id), id, spread);
        }
        for id in 4..10_000u32 {
            t.insert(spread(id), id, spread);
            t.remove(spread(id - 4), id - 4, spread);
            assert!(t.slots() <= 16);
        }
        check(&t, &[9996, 9997, 9998, 9999], &[0, 9995], spread);
    }
}
