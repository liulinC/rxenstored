// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! A persistent ordered map: a copy-on-write B+ tree with reference-counted
//! nodes. Cloning a map is O(1); an update copies the O(log₁₆ n) nodes on
//! the path from the root to the entry, and only those that are shared with
//! another version (unshared nodes are modified in place).

use crate::prelude::*;
use alloc::sync::Arc;
use core::borrow::Borrow;

/// Most entries in a leaf, most children of a branch.
const MAX: usize = 16;
/// Fewest entries or children of any node but the root.
const MIN: usize = MAX / 2;

#[derive(Clone)]
enum Node<K, V> {
    Leaf(Vec<(K, V)>),
    /// Each child with a lower bound of its keys. All keys of child `i` are
    /// at least its bound and less than the bound of child `i + 1`.
    Branch(Vec<(K, Arc<Node<K, V>>)>),
}

impl<K: Clone + Ord, V: Clone> Node<K, V> {
    fn len(&self) -> usize {
        match self {
            Node::Leaf(e) => e.len(),
            Node::Branch(c) => c.len(),
        }
    }

    /// The lowest key of the node, `None` if it is empty. A node has an
    /// entry: a root at least one (an emptied one is replaced), any other
    /// at least `MIN`, a half of a split more than `MAX / 2`
    /// (`check_invariants`, run after every step of the tests against
    /// `BTreeMap`). The callers' fallback for an empty one loses nothing.
    fn first_key(&self) -> Option<&K> {
        match self {
            Node::Leaf(e) => e.first().map(|(k, _)| k),
            Node::Branch(c) => c.first().map(|(k, _)| k),
        }
    }

    fn split_off(&mut self, at: usize) -> Node<K, V> {
        match self {
            Node::Leaf(e) => Node::Leaf(e.split_off(at)),
            Node::Branch(c) => Node::Branch(c.split_off(at)),
        }
    }

    /// Moves the entries of `other`, a node of the same kind, to the end
    /// of this one. Siblings are of the same kind: all leaves are at the
    /// same depth (`check_invariants`); a node of the other kind is given
    /// back untouched.
    fn append(&mut self, other: Node<K, V>) -> Result<(), Node<K, V>> {
        match (self, other) {
            (Node::Leaf(a), Node::Leaf(b)) => a.extend(b),
            (Node::Branch(a), Node::Branch(b)) => a.extend(b),
            (_, other) => return Err(other),
        }
        Ok(())
    }
}

/// Index of the child whose range holds `k`, `None` if `k` is below every bound.
fn child_index<K: Borrow<Q>, Q: Ord + ?Sized, T>(children: &[(K, T)], k: &Q) -> Option<usize> {
    match children.binary_search_by(|(ck, _)| ck.borrow().cmp(k)) {
        Ok(i) => Some(i),
        Err(0) => None,
        Err(i) => Some(i - 1),
    }
}

/// The value of `k` in the tree below `node`.
fn get_in<'a, K: Borrow<Q>, Q: Ord + ?Sized, V>(node: &'a Node<K, V>, k: &Q) -> Option<&'a V> {
    match node {
        Node::Leaf(e) => e
            .binary_search_by(|(ek, _)| ek.borrow().cmp(k))
            .ok()
            .and_then(|i| e.get(i))
            .map(|(_, v)| v),
        Node::Branch(c) => child_index(c, k)
            .and_then(|i| c.get(i))
            .and_then(|(_, child)| get_in(child, k)),
    }
}

/// As `get_in`, copying the shared nodes on the way.
fn get_mut_in<'a, K: Clone + Ord + Borrow<Q>, Q: Ord + ?Sized, V: Clone>(
    node: &'a mut Node<K, V>,
    k: &Q,
) -> Option<&'a mut V> {
    match node {
        Node::Leaf(e) => e
            .binary_search_by(|(ek, _)| ek.borrow().cmp(k))
            .ok()
            .and_then(|i| e.get_mut(i))
            .map(|(_, v)| v),
        Node::Branch(c) => child_index(c, k)
            .and_then(|i| c.get_mut(i))
            .and_then(|(_, child)| get_mut_in(Arc::make_mut(child), k)),
    }
}

fn take<K: Clone, V: Clone>(node: Arc<Node<K, V>>) -> Node<K, V> {
    Arc::try_unwrap(node).unwrap_or_else(|shared| (*shared).clone())
}

/// One pointer: a store node holds one of these, and most have no child.
pub struct PMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
}

impl<K, V> Clone for PMap<K, V> {
    fn clone(&self) -> Self {
        PMap {
            root: self.root.clone(),
        }
    }
}

impl<K, V> Default for PMap<K, V> {
    fn default() -> Self {
        PMap { root: None }
    }
}

impl<K: core::fmt::Debug + Clone + Ord, V: core::fmt::Debug + Clone> core::fmt::Debug for PMap<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Clone + Ord, V: Clone> PMap<K, V> {
    pub fn new() -> Self {
        PMap::default()
    }

    /// Counts the entries: O(n).
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// True if both maps are the same version (cheap identity, not equality).
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub fn get<Q: Ord + ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        get_in(self.root.as_deref()?, k)
    }

    pub fn contains_key<Q: Ord + ?Sized>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.get(k).is_some()
    }

    /// Mutable access to an entry; copies the shared nodes on its path.
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        // Check first, so that a miss copies nothing.
        let root = self.root.as_mut().filter(|r| get_in(r, k).is_some())?;
        get_mut_in(Arc::make_mut(root), k)
    }

    /// Inserts or replaces; returns the previous value.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let Some(root) = self.root.as_mut() else {
            self.root = Some(Arc::new(Node::Leaf(vec![(k, v)])));
            return None;
        };
        let (old, split) = insert_rec(Arc::make_mut(root), k, v);
        if let Some((sk, right)) = split {
            // An empty left half (impossible) would leave the right one alone.
            let left = core::mem::replace(root, right);
            for (lk, left, sk) in left.first_key().cloned().map(|lk| (lk, left, sk)).into_iter() {
                let right = root.clone();
                *root = Arc::new(Node::Branch(vec![(lk, left), (sk, right)]));
            }
        }
        old
    }

    pub fn remove<Q: Ord + ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        let root = self.root.as_mut().filter(|r| get_in(r, k).is_some())?;
        let old = remove_rec(Arc::make_mut(root), k);
        let replacement = match &**root {
            Node::Leaf(e) if e.is_empty() => Some(None),
            Node::Branch(c) if c.len() == 1 => c.first().map(|(_, only)| Some(only.clone())),
            _ => None,
        };
        if let Some(r) = replacement {
            self.root = r;
        }
        old
    }

    /// Entries in ascending key order.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            stack: self.root.as_deref().map(|r| vec![(r, 0)]).unwrap_or_default(),
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    /// Same set of keys (values are not compared).
    pub fn same_keys(&self, other: &Self) -> bool {
        self.ptr_eq(other) || self.keys().eq(other.keys())
    }

    #[cfg(test)]
    fn check_invariants(&self) {
        fn walk<K: Ord + Clone, V: Clone>(
            n: &Node<K, V>,
            lo: Option<&K>,
            hi: Option<&K>,
            root: bool,
            depth: usize,
            leaf_depth: &mut Option<usize>,
        ) -> usize {
            assert!(n.len() <= MAX);
            assert!(root || n.len() >= MIN, "underfull node");
            match n {
                Node::Leaf(e) => {
                    match leaf_depth {
                        Some(d) => assert_eq!(*d, depth, "leaves at different depths"),
                        None => *leaf_depth = Some(depth),
                    }
                    for w in e.windows(2) {
                        assert!(w[0].0 < w[1].0);
                    }
                    for (k, _) in e {
                        assert!(lo.is_none_or(|lo| lo <= k));
                        assert!(hi.is_none_or(|hi| k < hi));
                    }
                    e.len()
                }
                Node::Branch(c) => {
                    let mut total = 0;
                    for (i, (b, child)) in c.iter().enumerate() {
                        assert!(lo.is_none_or(|lo| lo <= b));
                        let next = c.get(i + 1).map(|x| &x.0).or(hi);
                        total += walk(child, Some(b), next, false, depth + 1, leaf_depth);
                    }
                    total
                }
            }
        }
        match &self.root {
            None => {}
            Some(r) => {
                if let Node::Branch(c) = &**r {
                    assert!(c.len() >= 2, "a branch root has at least two children");
                }
                assert!(r.len() > 0);
                assert_eq!(walk(r, None, None, true, 0, &mut None), self.len());
            }
        }
    }
}

type Split<K, V> = Option<(K, Arc<Node<K, V>>)>;

fn insert_rec<K: Clone + Ord, V: Clone>(node: &mut Node<K, V>, k: K, v: V) -> (Option<V>, Split<K, V>) {
    let (old, overfull) = match node {
        Node::Leaf(e) => match e.binary_search_by(|(ek, _)| ek.cmp(&k)) {
            Ok(i) => return (e.get_mut(i).map(|(_, old)| core::mem::replace(old, v)), None),
            Err(i) => {
                // Most store nodes have a handful of children, and an entry
                // is large (a name and a node): grow by a quarter, by one
                // while small, instead of doubling.
                if e.len() == e.capacity() {
                    e.reserve_exact(1 + e.len() / 4);
                }
                e.insert(i, (k, v));
                (None, e.len() > MAX)
            }
        },
        Node::Branch(c) => {
            let i = match child_index(c, &k) {
                Some(i) => i,
                None => {
                    // Below every bound: into the first child, whose bound it becomes.
                    for (bound, _) in c.iter_mut().take(1) {
                        *bound = k.clone();
                    }
                    0
                }
            };
            let (old, split) = match c.get_mut(i) {
                Some((_, child)) => insert_rec(Arc::make_mut(child), k, v),
                // A branch has children (`check_invariants`); an empty one
                // would get the entry in a leaf of its own.
                None => {
                    crate::impossible("an empty branch");
                    c.push((k.clone(), Arc::new(Node::Leaf(vec![(k, v)]))));
                    (None, None)
                }
            };
            if let Some(s) = split {
                c.insert(i + 1, s);
            }
            (old, c.len() > MAX)
        }
    };
    if !overfull {
        return (old, None);
    }
    let right = node.split_off(node.len() / 2);
    if let Node::Leaf(e) = node {
        e.shrink_to_fit();
    }
    // An empty right half (impossible) holds nothing to link.
    (old, right.first_key().cloned().map(|k| (k, Arc::new(right))))
}

/// Removes `k` from the tree below `node`, where the caller found it.
fn remove_rec<K: Clone + Ord + Borrow<Q>, V: Clone, Q: Ord + ?Sized>(node: &mut Node<K, V>, k: &Q) -> Option<V> {
    match node {
        // `i` is a position `binary_search` found: `remove` is in bounds.
        Node::Leaf(e) => e
            .binary_search_by(|(ek, _)| ek.borrow().cmp(k))
            .ok()
            .map(|i| e.remove(i).1),
        Node::Branch(c) => {
            // The caller found `k`: it is not below every bound.
            let Some((i, (_, child))) = child_index(c, k).and_then(|i| c.get_mut(i).map(|x| (i, x))) else {
                crate::impossible("a key below every bound of a branch");
                return None;
            };
            let child = Arc::make_mut(child);
            let old = remove_rec(child, k);
            // A branch has a second child: see `check_invariants`.
            if child.len() < MIN {
                rebalance(c, i);
            }
            old
        }
    }
}

/// Child `i` is underfull: merge it with a neighbour, or share entries.
/// A branch has at least two children (`check_invariants`), so `i` has a
/// neighbour, of its kind; were it not so, the child stays underfull and
/// nothing is lost.
fn rebalance<K: Clone + Ord, V: Clone>(c: &mut Vec<(K, Arc<Node<K, V>>)>, i: usize) {
    // With its right neighbour, or its left one if it is the last.
    let l = if i + 1 < c.len() { i } else { i.saturating_sub(1) };
    let Some([(_, left), (right_bound, right)]) = c.get_mut(l..l + 2) else {
        crate::impossible("a branch with one child");
        return;
    };
    let left = Arc::make_mut(left);
    if let Err(back) = left.append(take(core::mem::replace(right, Arc::new(Node::Leaf(Vec::new()))))) {
        crate::impossible("siblings of different kinds");
        *right = Arc::new(back);
        return;
    }
    if left.len() > MAX {
        let at = left.len() / 2;
        let half = left.split_off(at);
        // A half without entries (impossible) keeps the bound it had.
        let k = half.first_key().unwrap_or(&*right_bound).clone();
        *right_bound = k;
        *right = Arc::new(half);
    } else {
        // In bounds: the pair above was there.
        c.remove(l + 1);
    }
}

pub struct Iter<'a, K, V> {
    stack: Vec<(&'a Node<K, V>, usize)>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, i) = self.stack.last_mut()?;
            let node: &'a Node<K, V> = node;
            match node {
                Node::Leaf(e) => {
                    if let Some((k, v)) = e.get(*i) {
                        *i += 1;
                        return Some((k, v));
                    }
                }
                Node::Branch(c) => {
                    if let Some((_, child)) = c.get(*i) {
                        *i += 1;
                        self.stack.push((child, 0));
                        continue;
                    }
                }
            }
            self.stack.pop();
        }
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq> PartialEq for PMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr_eq(other) || self.iter().eq(other.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// xorshift64*: deterministic, no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn same(m: &PMap<u32, u32>, r: &BTreeMap<u32, u32>) {
        m.check_invariants();
        assert_eq!(m.len(), r.len());
        assert_eq!(m.is_empty(), r.is_empty());
        let a: Vec<_> = m.iter().map(|(k, v)| (*k, *v)).collect();
        let b: Vec<_> = r.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn empty() {
        let mut m: PMap<u32, u32> = PMap::new();
        assert!(m.is_empty());
        assert_eq!(m.get(&1), None);
        assert_eq!(m.get_mut(&1), None);
        assert_eq!(m.remove(&1), None);
        assert_eq!(m.iter().count(), 0);
        assert!(m.ptr_eq(&PMap::new()));
        assert_eq!(format!("{m:?}"), "{}");
    }

    #[test]
    fn ascending_descending_and_random_against_btreemap() {
        for seed in 1..40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15));
            let mut m = PMap::new();
            let mut r = BTreeMap::new();
            let range = [20, 200, 2000][seed as usize % 3];
            for step in 0..3000 {
                let k = match seed % 4 {
                    0 => step % range as u32,
                    1 => (range as u32).wrapping_sub(step % range as u32),
                    _ => rng.below(range) as u32,
                };
                match rng.below(10) {
                    0..=4 => assert_eq!(m.insert(k, step), r.insert(k, step)),
                    5..=7 => assert_eq!(m.remove(&k), r.remove(&k)),
                    8 => {
                        if let Some(v) = m.get_mut(&k) {
                            *v += 1;
                        }
                        if let Some(v) = r.get_mut(&k) {
                            *v += 1;
                        }
                    }
                    _ => assert_eq!(m.get(&k), r.get(&k)),
                }
                if step % 97 == 0 {
                    same(&m, &r);
                }
            }
            same(&m, &r);
            let keys: Vec<u32> = r.keys().copied().collect();
            for k in keys {
                assert_eq!(m.remove(&k), r.remove(&k));
            }
            same(&m, &r);
        }
    }

    #[test]
    fn old_versions_are_unchanged() {
        let mut rng = Rng(77);
        let mut m = PMap::new();
        let mut r = BTreeMap::new();
        let mut versions = Vec::new();
        for step in 0..2000u32 {
            let k = rng.below(500) as u32;
            if rng.below(3) == 0 {
                m.remove(&k);
                r.remove(&k);
            } else {
                m.insert(k, step);
                r.insert(k, step);
            }
            if step % 50 == 0 {
                versions.push((m.clone(), r.clone()));
            }
        }
        for (m, r) in &versions {
            same(m, r);
        }
        let (a, _) = &versions[3];
        let b = a.clone();
        assert!(a.ptr_eq(&b));
        assert!(!a.ptr_eq(&PMap::new()) && !PMap::new().ptr_eq(a));
        assert!(a == &b);
        let mut c = b.clone();
        let k = *c.keys().next().unwrap();
        *c.get_mut(&k).unwrap() += 1;
        assert!(!a.ptr_eq(&c));
        assert!(a != &c);
        assert!(a.same_keys(&c));
        c.insert(100_000, 1);
        assert!(!a.same_keys(&c));
    }

    #[test]
    fn large_map_is_shallow_and_cheap_to_update() {
        let mut m = PMap::new();
        for k in 0..5000u32 {
            m.insert(k, k);
        }
        m.check_invariants();
        // A snapshot shares everything; an update of the copy leaves it alone.
        let snap = m.clone();
        m.insert(2500, 0);
        assert_eq!(snap.get(&2500), Some(&2500));
        assert_eq!(m.get(&2500), Some(&0));
        let mut depth = 0;
        let mut n = m.root.as_deref().unwrap();
        while let Node::Branch(c) = n {
            depth += 1;
            n = &c[0].1;
        }
        assert!(depth <= 4, "depth {depth}");
    }

    fn root(m: &PMap<u32, u32>) -> &Node<u32, u32> {
        m.root.as_deref().unwrap()
    }

    /// Sizes of the root's children.
    fn children(m: &PMap<u32, u32>) -> Vec<usize> {
        match root(m) {
            Node::Leaf(_) => panic!("the root is a leaf"),
            Node::Branch(c) => c.iter().map(|(_, n)| n.len()).collect(),
        }
    }

    #[test]
    fn nodes_split_above_max_and_merge_below_min() {
        let mut m = PMap::new();
        for k in 0..MAX as u32 {
            m.insert(k, k);
        }
        assert!(
            matches!(root(&m), Node::Leaf(e) if e.len() == MAX),
            "a full leaf is not split"
        );
        m.insert(16, 16);
        assert_eq!(children(&m), [8, 9]);
        // A leaf at the minimum is left alone.
        m.remove(&16);
        assert_eq!(children(&m), [8, 8]);
        // Below it, it takes its neighbour's entries: 7 and 9 fit in one leaf.
        m.insert(16, 16);
        m.remove(&0);
        assert!(
            matches!(root(&m), Node::Leaf(e) if e.len() == MAX),
            "a full leaf is not split again"
        );
        // 7 and 10 do not: they are shared out.
        m.insert(0, 0);
        m.insert(17, 17);
        assert_eq!(children(&m), [8, 10]);
        m.remove(&0);
        assert_eq!(children(&m), [8, 9]);
        m.check_invariants();
    }

    #[test]
    fn a_full_branch_is_not_split() {
        // Ascending keys: a leaf splits in 8 and 9, the 9 fill up again.
        let mut m = PMap::new();
        for k in 0..129u32 {
            m.insert(k, k);
        }
        assert_eq!(children(&m).len(), MAX);
        assert!(
            children(&m).iter().all(|&n| n == 8 || n == 9),
            "the children are leaves"
        );
        for k in 129..137u32 {
            m.insert(k, k);
        }
        assert_eq!(children(&m), [8, 9], "two branches");
        m.check_invariants();
    }

    #[test]
    fn a_leaf_grows_by_a_quarter() {
        let mut m = PMap::new();
        let mut capacities = Vec::new();
        for k in 0..MAX as u32 {
            m.insert(k, k);
            match root(&m) {
                Node::Leaf(e) => capacities.push(e.capacity()),
                Node::Branch(_) => panic!("the root is a branch"),
            }
        }
        assert_eq!(capacities, [1, 2, 3, 4, 6, 6, 8, 8, 11, 11, 11, 14, 14, 14, 18, 18]);
    }

    fn leaf(keys: &[u32]) -> Arc<Node<u32, u32>> {
        Arc::new(Node::Leaf(keys.iter().map(|&k| (k, k)).collect()))
    }

    // What follows cannot happen in a tree that `check_invariants` accepts:
    // were it to, nothing panics and no entry is lost.

    #[test]
    fn a_key_below_every_bound_of_a_branch_is_not_removed() {
        let _g = crate::tests::expect_impossible();
        let mut n = Node::Branch(vec![(5, leaf(&[5, 6])), (7, leaf(&[7, 8]))]);
        assert_eq!(remove_rec(&mut n, &1), None);
        assert_eq!(n.len(), 2);
    }

    #[test]
    fn an_empty_branch_gets_a_leaf_for_an_insertion() {
        let _g = crate::tests::expect_impossible();
        let mut n: Node<u32, u32> = Node::Branch(Vec::new());
        assert!(matches!(insert_rec(&mut n, 3, 4), (None, None)));
        assert!(matches!(&n, Node::Branch(c) if c.len() == 1 && c[0].0 == 3 && c[0].1.first_key() == Some(&3)));
    }

    #[test]
    fn an_underfull_child_merges_with_its_right_neighbour_unless_it_is_the_last() {
        let keys = |from: u32, n: u32| (from..from + n).collect::<Vec<_>>();
        let sizes = |c: &[(u32, Arc<Node<u32, u32>>)]| c.iter().map(|(_, n)| n.len()).collect::<Vec<_>>();
        let three = || {
            vec![
                (0, leaf(&keys(0, 8))),
                (10, leaf(&keys(10, 7))),
                (20, leaf(&keys(20, 8))),
            ]
        };
        let mut c = three();
        rebalance(&mut c, 1);
        assert_eq!(sizes(&c), [8, 15]);
        let mut c = vec![
            (0, leaf(&keys(0, 8))),
            (10, leaf(&keys(10, 8))),
            (20, leaf(&keys(20, 7))),
        ];
        rebalance(&mut c, 2);
        assert_eq!(sizes(&c), [8, 15]);
    }

    #[test]
    fn a_lone_child_is_not_rebalanced() {
        let _g = crate::tests::expect_impossible();
        let mut c = vec![(0, leaf(&[0]))];
        rebalance(&mut c, 0);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn siblings_of_different_kinds_are_left_as_they_are() {
        let _g = crate::tests::expect_impossible();
        let branch = Arc::new(Node::Branch(vec![(9, leaf(&[9]))]));
        let mut c = vec![(0, leaf(&[0])), (9, branch)];
        rebalance(&mut c, 0);
        assert_eq!(c.len(), 2);
        assert!(matches!(&*c[0].1, Node::Leaf(e) if e.len() == 1));
        assert!(matches!(&*c[1].1, Node::Branch(b) if b.len() == 1));
    }

    #[test]
    fn equality_is_by_content() {
        let build = |keys: &[u32]| {
            let mut m = PMap::new();
            for &k in keys {
                m.insert(k, k * 2);
            }
            m
        };
        let (a, b) = (build(&[1, 2, 3]), build(&[3, 2, 1]));
        assert!(!a.ptr_eq(&b));
        assert!(a == b);
        assert!(a != build(&[1, 2]));
        let mut c = build(&[1, 2, 3]);
        c.insert(2, 0);
        assert!(a != c);
    }

    #[test]
    fn borrowed_lookups() {
        let mut m: PMap<Arc<[u8]>, u32> = PMap::new();
        m.insert(Arc::from(&b"local"[..]), 1);
        m.insert(Arc::from(&b"tool"[..]), 2);
        assert_eq!(m.get(&b"tool"[..]), Some(&2));
        assert!(m.contains_key(&b"local"[..]));
        assert!(!m.contains_key(&b"x"[..]));
        assert_eq!(format!("{:?}", PMap::<u8, u8>::new()), "{}");
        let mut d = PMap::new();
        d.insert(1u8, 2u8);
        assert_eq!(format!("{d:?}"), "{1: 2}");
    }
}
