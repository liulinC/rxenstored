// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The global watch index: a trie keyed by path component, each trie node
//! holding the watches registered at that path. The special `@...` paths
//! are the children of a second root. Adding or removing a watch costs
//! O(depth); finding the watches on a path and its ancestors costs O(depth
//! + matches).
//!
//! Compact on purpose: a host has tens of watches per VM. Trie nodes and
//! watches live in two arrays and are linked by index (children of a node,
//! by name, and watches of a node, newest first, in the order oxenstored
//! walks them, `ox/trie.ml:73-78`, `ox/connections.ml:138`; watches of a
//! connection). Two tables of indices find a child by (parent, name) and a
//! watch by (connection, path, token). A watch does not keep its path: the
//! trie spells it.

use crate::bytes::Bytes;
use crate::idtable::IdTable;
use crate::impossible;
use crate::path::{Name, Path};
use crate::prelude::*;
use crate::sip::SipKey;
use crate::ConnId;
use alloc::collections::BTreeMap;
use core::hash::BuildHasher;

pub type WatchId = u32;

/// Where a watch is registered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// An absolute path, as components.
    Tree(Path),
    /// A path starting with `@`, taken as a whole.
    Special(Name),
}

#[derive(Debug)]
pub struct Watch {
    pub conn: ConnId,
    pub token: Bytes,
    /// The client gave a relative path: its events are reported relative
    /// to the connection's home.
    pub relative: bool,
    /// The trie node the watch is registered at.
    node: u32,
    /// Neighbours in the node's list of watches.
    prev: u32,
    next: u32,
    /// Neighbours in the connection's list of watches.
    conn_prev: u32,
    conn_next: u32,
}

#[derive(Debug)]
struct TrieNode {
    parent: u32,
    name: Name,
    first_child: u32,
    last_child: u32,
    prev_sibling: u32,
    next_sibling: u32,
    /// The newest watch registered here.
    first_watch: u32,
    /// Where a walk of the subtree that fires nothing on the way can go
    /// straight to: the end of the chain of single children without
    /// watches below this node (`WatchIndex::down`). NONE: the node itself.
    down: u32,
}

impl TrieNode {
    const fn new(parent: u32, name: Name) -> TrieNode {
        TrieNode {
            parent,
            name,
            first_child: NONE,
            last_child: NONE,
            prev_sibling: NONE,
            next_sibling: NONE,
            first_watch: NONE,
            down: NONE,
        }
    }
}

// Trie nodes and watches are found by indices the index itself keeps.
// Were one stale, it would be read as a blank, linked to nothing and
// child of the root (so that a walk up ends), and written to a spare that
// nothing reads: a lost link rather than a panic (tests at the end).

/// What a stale node index reads.
static BLANK_NODE: TrieNode = TrieNode::new(ROOT, Name::EMPTY);

/// What a stale watch id reads: a watch of no connection.
static BLANK_WATCH: Watch = Watch::blank();

fn node_in(nodes: &[TrieNode], i: u32) -> &TrieNode {
    nodes.get(i as usize).unwrap_or_else(|| {
        impossible("a stale trie node index");
        &BLANK_NODE
    })
}

fn watch_in(watches: &[Option<Watch>], id: WatchId) -> &Watch {
    watches.get(id as usize).and_then(Option::as_ref).unwrap_or_else(|| {
        impossible("a stale watch id");
        &BLANK_WATCH
    })
}

impl Watch {
    const fn blank() -> Watch {
        Watch {
            conn: ConnId(u64::MAX),
            token: Bytes::EMPTY,
            relative: false,
            node: NONE,
            prev: NONE,
            next: NONE,
            conn_prev: NONE,
            conn_next: NONE,
        }
    }
}

#[derive(Debug)]
pub struct WatchIndex {
    watches: Vec<Option<Watch>>,
    free_watches: Vec<WatchId>,
    nodes: Vec<TrieNode>,
    free_nodes: Vec<u32>,
    /// Every node but the two roots, by (parent, name).
    children: IdTable,
    /// Every watch, by (connection, node, token): a connection's watches
    /// are told apart by path and token.
    by_owner: IdTable,
    /// The first watch of each connection that has one.
    heads: BTreeMap<ConnId, WatchId>,
    /// Keyed at random: clients choose the names and tokens.
    hasher: SipKey,
    /// Where writes through a stale index go.
    spare_node: TrieNode,
    spare_watch: Watch,
}

const NONE: u32 = u32::MAX;
/// The root of the store paths.
const ROOT: u32 = 0;
/// The parent of the special paths.
const SPECIAL: u32 = 1;

fn owner_hash_of(hasher: &SipKey, w: &Watch) -> u64 {
    hasher.hash_one((w.conn, w.node, &w.token[..]))
}

/// Walks a list linked by index.
fn chain(first: u32, next: impl Fn(u32) -> u32) -> impl Iterator<Item = u32> {
    let some = |i: u32| (i != NONE).then_some(i);
    core::iter::successors(some(first), move |&i| some(next(i)))
}

impl WatchIndex {
    /// An empty index whose tables hash under `key`.
    pub fn new(key: SipKey) -> WatchIndex {
        WatchIndex {
            watches: Vec::new(),
            free_watches: Vec::new(),
            nodes: vec![TrieNode::new(NONE, Name::EMPTY), TrieNode::new(NONE, Name::EMPTY)],
            free_nodes: Vec::new(),
            children: IdTable::new(),
            by_owner: IdTable::new(),
            heads: BTreeMap::new(),
            hasher: key,
            spare_node: TrieNode::new(ROOT, Name::EMPTY),
            spare_watch: Watch::blank(),
        }
    }

    pub fn len(&self) -> usize {
        self.by_owner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_owner.is_empty()
    }

    pub fn get(&self, id: WatchId) -> &Watch {
        watch_in(&self.watches, id)
    }

    fn watch_mut(&mut self, id: WatchId) -> &mut Watch {
        match self.watches.get_mut(id as usize).and_then(Option::as_mut) {
            Some(w) => w,
            None => {
                impossible("a stale watch id");
                self.spare_watch = Watch::blank();
                &mut self.spare_watch
            }
        }
    }

    fn tnode(&self, i: u32) -> &TrieNode {
        node_in(&self.nodes, i)
    }

    fn tnode_mut(&mut self, i: u32) -> &mut TrieNode {
        match self.nodes.get_mut(i as usize) {
            Some(n) => n,
            None => {
                impossible("a stale trie node index");
                self.spare_node = TrieNode::new(ROOT, Name::EMPTY);
                &mut self.spare_node
            }
        }
    }

    fn child_hash(&self, parent: u32, name: &[u8]) -> u64 {
        self.hasher.hash_one((parent, name))
    }

    fn owner_hash(&self, conn: ConnId, node: u32, token: &[u8]) -> u64 {
        self.hasher.hash_one((conn, node, token))
    }

    fn child(&self, parent: u32, name: &[u8]) -> Option<u32> {
        self.children.find(self.child_hash(parent, name), |c| {
            let n = self.tnode(c);
            n.parent == parent && *n.name == *name
        })
    }

    /// The child `name` of `parent`, created if missing, in its place
    /// among its siblings by name: found from the last, so that names that
    /// come in order cost nothing, others a walk of the siblings after it.
    fn child_or_new(&mut self, parent: u32, name: &Name) -> u32 {
        if let Some(c) = self.child(parent, name) {
            return c;
        }
        let mut prev = self.tnode(parent).last_child;
        while prev != NONE && self.tnode(prev).name[..].cmp(&name[..]).is_gt() {
            prev = self.tnode(prev).prev_sibling;
        }
        let next = match prev {
            NONE => self.tnode(parent).first_child,
            p => self.tnode(p).next_sibling,
        };
        let mut node = TrieNode::new(parent, name.clone());
        node.prev_sibling = prev;
        node.next_sibling = next;
        // A free index is reused (a stale one is dropped).
        let c = match self
            .free_nodes
            .pop()
            .and_then(|i| self.nodes.get_mut(i as usize).map(|slot| (i, slot)))
        {
            Some((i, slot)) => {
                *slot = node;
                i
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        match prev {
            NONE => self.tnode_mut(parent).first_child = c,
            p => self.tnode_mut(p).next_sibling = c,
        }
        match next {
            NONE => self.tnode_mut(parent).last_child = c,
            n => self.tnode_mut(n).prev_sibling = c,
        }
        let (nodes, hasher) = (&self.nodes, &self.hasher);
        self.children.insert(hasher.hash_one((parent, &name[..])), c, |i| {
            let n = node_in(nodes, i);
            hasher.hash_one((n.parent, &n.name[..]))
        });
        c
    }

    /// The trie node of `key`, if any watch is registered on or below it.
    pub fn locate(&self, key: &Key) -> Option<u32> {
        match key {
            Key::Tree(p) => self.node(p),
            Key::Special(s) => self.child(SPECIAL, s),
        }
    }

    /// The watch of a connection on `key` with `token`.
    pub fn find(&self, conn: ConnId, key: &Key, token: &[u8]) -> Option<WatchId> {
        let node = self.locate(key)?;
        self.by_owner.find(self.owner_hash(conn, node, token), |id| {
            let w = self.get(id);
            w.conn == conn && w.node == node && *w.token == *token
        })
    }

    /// The watches of a connection, in no particular order.
    pub fn of(&self, conn: ConnId) -> impl Iterator<Item = WatchId> + '_ {
        chain(self.heads.get(&conn).copied().unwrap_or(NONE), |w| {
            self.get(w).conn_next
        })
    }

    /// Registers a watch; the caller has checked with `find` that the
    /// connection has no such watch.
    pub fn add(&mut self, conn: ConnId, key: &Key, token: Bytes, relative: bool) -> WatchId {
        let node = match key {
            Key::Tree(p) => p.iter().fold(ROOT, |n, name| self.child_or_new(n, name)),
            Key::Special(s) => self.child_or_new(SPECIAL, s),
        };
        let next = self.tnode(node).first_watch;
        let hash = self.owner_hash(conn, node, &token);
        let conn_next = self.heads.get(&conn).copied().unwrap_or(NONE);
        let watch = Some(Watch {
            conn,
            token,
            relative,
            node,
            prev: NONE,
            next,
            conn_prev: NONE,
            conn_next,
        });
        let id = match self
            .free_watches
            .pop()
            .and_then(|id| self.watches.get_mut(id as usize).map(|slot| (id, slot)))
        {
            Some((id, slot)) => {
                *slot = watch;
                id
            }
            None => {
                self.watches.push(watch);
                (self.watches.len() - 1) as WatchId
            }
        };
        // First of the node's watches (`ox/connections.ml:138`).
        if next != NONE {
            self.watch_mut(next).prev = id;
        }
        self.tnode_mut(node).first_watch = id;
        self.refresh(node);
        if conn_next != NONE {
            self.watch_mut(conn_next).conn_prev = id;
        }
        self.heads.insert(conn, id);
        let (watches, hasher) = (&self.watches, &self.hasher);
        self.by_owner
            .insert(hash, id, |i| owner_hash_of(hasher, watch_in(watches, i)));
        id
    }

    /// Removes a watch, and returns it (a blank one if `id` is not a
    /// watch).
    pub fn remove(&mut self, id: WatchId) -> Watch {
        let (watches, hasher) = (&self.watches, &self.hasher);
        let hash_of = |i: u32| owner_hash_of(hasher, watch_in(watches, i));
        self.by_owner.remove(hash_of(id), id, hash_of);
        let Some(w) = self.watches.get_mut(id as usize).and_then(Option::take) else {
            // No such watch: nothing to unlink, and no connection is to
            // start from it (`remove_all` goes on).
            self.heads.retain(|_, head| *head != id);
            return Watch::blank();
        };
        self.free_watches.push(id);
        match (w.conn_prev, w.conn_next) {
            (NONE, NONE) => {
                self.heads.remove(&w.conn);
            }
            (NONE, n) => {
                self.heads.insert(w.conn, n);
            }
            (p, _) => self.watch_mut(p).conn_next = w.conn_next,
        }
        if w.conn_next != NONE {
            self.watch_mut(w.conn_next).conn_prev = w.conn_prev;
        }
        match w.prev {
            NONE => self.tnode_mut(w.node).first_watch = w.next,
            p => self.watch_mut(p).next = w.next,
        }
        if w.next != NONE {
            self.watch_mut(w.next).prev = w.prev;
        }
        let kept = self.prune(w.node);
        self.refresh(kept);
        w
    }

    /// Where a walk below `node` that fires nothing on its way (the store
    /// has nothing there) may go at once: following single children that
    /// have no watch, the first node that has several children or none,
    /// or whose only child has a watch. Taking that node from the walk's
    /// stack does what taking `node` does: each node on the way would
    /// only have pushed its one child. Without it, a walk visits every
    /// trie node below.
    pub fn down(&self, node: u32) -> u32 {
        match self.tnode(node).down {
            NONE => node,
            d => d,
        }
    }

    /// `down` of `n` and of each of its ancestors, from what is below
    /// them: after a change of the children or watches of `n` or of one
    /// of its children. Costs O(depth), as the change did.
    fn refresh(&mut self, mut n: u32) {
        loop {
            let node = self.tnode(n);
            let only = node.first_child;
            let down = if only != NONE && only == node.last_child && self.tnode(only).first_watch == NONE {
                self.down(only)
            } else {
                NONE
            };
            let parent = node.parent;
            self.tnode_mut(n).down = down;
            if n == ROOT || n == SPECIAL {
                return;
            }
            n = parent;
        }
    }

    /// Removes the watches of a connection.
    pub fn remove_all(&mut self, conn: ConnId) {
        while let Some(&w) = self.heads.get(&conn) {
            self.remove(w);
        }
    }

    /// Frees trie nodes left without watches or children, upwards from
    /// `n`; returns the first one kept.
    fn prune(&mut self, mut n: u32) -> u32 {
        while n != ROOT && n != SPECIAL {
            let node = self.tnode_mut(n);
            if node.first_watch != NONE || node.first_child != NONE {
                return n;
            }
            let (parent, prev, next) = (node.parent, node.prev_sibling, node.next_sibling);
            let name = core::mem::replace(&mut node.name, Name::EMPTY);
            match prev {
                NONE => self.tnode_mut(parent).first_child = next,
                p => self.tnode_mut(p).next_sibling = next,
            }
            match next {
                NONE => self.tnode_mut(parent).last_child = prev,
                x => self.tnode_mut(x).prev_sibling = prev,
            }
            let (nodes, hasher) = (&self.nodes, &self.hasher);
            self.children.remove(hasher.hash_one((parent, &name[..])), n, |i| {
                let x = node_in(nodes, i);
                hasher.hash_one((x.parent, &x.name[..]))
            });
            self.free_nodes.push(n);
            n = parent;
        }
        n
    }

    /// Watches registered on `path` or on one of its ancestors: root first,
    /// each path's newest first (`ox/connections.ml:165`, `ox/trie.ml:129-137`).
    pub fn on_path(&self, path: &[Name], out: &mut Vec<WatchId>) {
        let mut n = ROOT;
        out.extend(self.watches_at(n));
        for name in path {
            match self.child(n, name) {
                Some(c) => n = c,
                None => return,
            }
            out.extend(self.watches_at(n));
        }
    }

    /// The trie node of `path`, if any watch is registered on or below it.
    pub fn node(&self, path: &[Name]) -> Option<u32> {
        path.iter().try_fold(ROOT, |n, name| self.child(n, name))
    }

    /// The children of a trie node with their names, by name (bytes
    /// compared in order).
    pub fn children(&self, node: u32) -> impl Iterator<Item = (&Name, u32)> {
        chain(self.tnode(node).first_child, |c| self.tnode(c).next_sibling).map(|c| (&self.tnode(c).name, c))
    }

    /// The watches registered at a trie node, newest first.
    pub fn watches_at(&self, node: u32) -> impl Iterator<Item = WatchId> + '_ {
        chain(self.tnode(node).first_watch, |w| self.get(w).next)
    }

    /// The watches on a special path, newest first: so are each
    /// connection's (`ox/connections.ml:174-177`, `ox/connection.ml:287`).
    pub fn special(&self, path: &[u8]) -> impl Iterator<Item = WatchId> + '_ {
        self.child(SPECIAL, path).into_iter().flat_map(|n| self.watches_at(n))
    }

    /// The absolute path a watch is registered on: `/a/b`, `/`, or `@special`.
    pub fn path(&self, id: WatchId) -> Vec<u8> {
        let mut names = Vec::new();
        let mut n = self.get(id).node;
        while n != ROOT && n != SPECIAL {
            names.push(&self.tnode(n).name);
            n = self.tnode(n).parent;
        }
        if n == SPECIAL {
            // The one name below SPECIAL.
            return names.first().map(|name| name.to_vec()).unwrap_or_default();
        }
        let mut out = Vec::new();
        for name in names.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(name);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    }

    /// Number of trie nodes in use, the root of the store paths included.
    #[cfg(test)]
    pub fn trie_size(&self) -> usize {
        self.nodes.len() - self.free_nodes.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Path {
        crate::path::components(s.as_bytes()).unwrap()
    }

    fn add(ix: &mut WatchIndex, conn: u64, path: &str) -> WatchId {
        let key = if path.starts_with('@') {
            Key::Special(path.as_bytes().into())
        } else {
            Key::Tree(p(path))
        };
        ix.add(ConnId(conn), &key, b"t".into(), false)
    }

    fn on(ix: &WatchIndex, path: &str) -> Vec<WatchId> {
        let mut v = Vec::new();
        ix.on_path(&p(path), &mut v);
        v.sort();
        v
    }

    #[test]
    fn matches_the_path_and_its_ancestors() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let root = add(&mut ix, 1, "/");
        let a = add(&mut ix, 1, "/a");
        let ab = add(&mut ix, 2, "/a/b");
        let abc = add(&mut ix, 2, "/a/b/c");
        let x = add(&mut ix, 3, "/x");
        assert_eq!(ix.len(), 5);
        assert_eq!(on(&ix, "/a/b"), [root, a, ab]);
        assert_eq!(on(&ix, "/a/b/c/d"), [root, a, ab, abc]);
        assert_eq!(on(&ix, "/x"), [root, x]);
        assert_eq!(on(&ix, "/y/z"), [root]);
        assert_eq!(on(&ix, "/"), [root]);
        assert_eq!(ix.get(ab).conn, ConnId(2));
        assert_eq!(ix.path(ab), b"/a/b");
        assert_eq!(ix.path(root), b"/");
        assert_eq!(ix.get(abc).node, ix.node(&p("/a/b/c")).unwrap());
    }

    #[test]
    fn subtree_walk() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let ab = add(&mut ix, 1, "/a/b");
        let abc = add(&mut ix, 1, "/a/b/c");
        add(&mut ix, 1, "/z");
        let n = ix.node(&p("/a")).unwrap();
        let kids: Vec<_> = ix.children(n).map(|(k, _)| k.to_vec()).collect();
        assert_eq!(kids, [b"b".to_vec()]);
        let b = ix.node(&p("/a/b")).unwrap();
        assert_eq!(ix.watches_at(b).collect::<Vec<_>>(), [ab]);
        assert_eq!(ix.watches_at(ix.node(&p("/a/b/c")).unwrap()).collect::<Vec<_>>(), [abc]);
        assert_eq!(ix.node(&p("/q")), None);
    }

    #[test]
    fn removal_keeps_slots_consistent_and_prunes() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let ids: Vec<_> = (0..10).map(|i| add(&mut ix, i, "/a/b")).collect();
        let deep = add(&mut ix, 99, "/a/b/c/d");
        assert_eq!(ix.trie_size(), 5);
        assert!(!ix.is_empty());
        for &i in [3, 0, 9, 5].iter() {
            let w = ix.remove(ids[i]);
            assert_eq!(w.conn, ConnId(i as u64));
        }
        let mut left = on(&ix, "/a/b");
        left.sort();
        let mut expect: Vec<_> = [1, 2, 4, 6, 7, 8].iter().map(|&i| ids[i]).collect();
        expect.sort();
        assert_eq!(left, expect);
        ix.remove(deep);
        assert_eq!(ix.trie_size(), 3, "c and d pruned");
        for &i in [1, 2, 4, 6, 7, 8].iter() {
            ix.remove(ids[i]);
        }
        assert_eq!(ix.trie_size(), 1);
        assert!(ix.is_empty());
        // Freed ids and nodes are reused.
        let again = add(&mut ix, 1, "/q/r");
        assert!(ids.contains(&again) || again == deep);
        assert_eq!(ix.trie_size(), 3);
        assert_eq!(ix.path(again), b"/q/r");
    }

    #[test]
    fn watches_of_a_connection() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let key = |s: &str| Key::Tree(p(s));
        let of = |ix: &WatchIndex, c: u64| ix.of(ConnId(c)).collect::<Vec<_>>();
        let a = add(&mut ix, 1, "/a");
        let b = add(&mut ix, 1, "/b");
        let c = add(&mut ix, 2, "/a");
        let d = ix.add(ConnId(1), &key("/a"), b"other".into(), true);
        assert!(ix.get(d).relative && !ix.get(a).relative);
        assert_eq!(ix.find(ConnId(1), &key("/a"), b"t"), Some(a));
        assert_eq!(ix.find(ConnId(1), &key("/a"), b"other"), Some(d));
        assert_eq!(ix.find(ConnId(2), &key("/a"), b"t"), Some(c));
        assert_eq!(ix.find(ConnId(2), &key("/b"), b"t"), None, "another connection's");
        assert_eq!(ix.find(ConnId(1), &key("/a"), b"x"), None, "another token");
        assert_eq!(ix.find(ConnId(1), &key("/b"), b"other"), None, "another path");
        assert_eq!(ix.find(ConnId(1), &key("/nowhere"), b"t"), None);
        assert_eq!(ix.find(ConnId(3), &key("/a"), b"t"), None);
        // Newest first; removing from the middle, the head and the tail.
        assert_eq!(of(&ix, 1), [d, b, a]);
        assert_eq!(of(&ix, 2), [c]);
        assert_eq!(of(&ix, 3), []);
        ix.remove(b);
        assert_eq!(of(&ix, 1), [d, a]);
        ix.remove(d);
        assert_eq!(of(&ix, 1), [a]);
        let e = add(&mut ix, 1, "/e");
        ix.remove(a);
        assert_eq!(of(&ix, 1), [e]);
        let f = add(&mut ix, 1, "/f");
        assert_eq!(of(&ix, 1), [f, e]);
        assert_eq!(ix.find(ConnId(1), &key("/a"), b"t"), None);
        ix.remove_all(ConnId(1));
        assert_eq!(of(&ix, 1), []);
        assert_eq!(ix.len(), 1);
        ix.remove_all(ConnId(1));
        assert_eq!(of(&ix, 2), [c]);
        ix.remove_all(ConnId(2));
        assert!(ix.is_empty() && ix.heads.is_empty());
        assert_eq!(ix.trie_size(), 1);
    }

    #[test]
    fn a_stale_index_reads_a_blank_and_writes_nowhere() {
        let _g = crate::tests::expect_impossible();
        // Not reachable: every index the index uses comes from itself.
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let a = add(&mut ix, 1, "/a");
        assert_eq!(ix.get(999).conn, ConnId(u64::MAX));
        assert_eq!(ix.of(ConnId(u64::MAX)).count(), 0);
        assert_eq!(ix.path(999), b"/");
        assert_eq!(ix.children(999).count(), 0);
        assert_eq!(ix.watches_at(999).count(), 0);
        ix.watch_mut(999).next = a;
        ix.tnode_mut(999).first_watch = a;
        assert_eq!((ix.get(999).next, ix.watches_at(999).count()), (NONE, 0));
        assert_eq!(ix.remove(999).conn, ConnId(u64::MAX));
        assert_eq!(ix.len(), 1);
        // A connection whose first watch is stale loses it, and nothing else.
        ix.heads.insert(ConnId(7), 999);
        ix.remove_all(ConnId(7));
        assert!(!ix.heads.contains_key(&ConnId(7)));
        assert_eq!(ix.of(ConnId(1)).collect::<Vec<_>>(), [a]);
        // Stale free indices are dropped, not reused.
        ix.free_nodes.push(999);
        ix.free_watches.push(999);
        let b = add(&mut ix, 2, "/b");
        assert_eq!(ix.path(b), b"/b");
        assert!(ix.free_nodes.is_empty() && ix.free_watches.is_empty());
    }

    /// The watches below `top` in the order an RM's walk meets them where
    /// the store has nothing (`Core::dispatch`), going `down` or not.
    fn walk(ix: &WatchIndex, top: u32, skip: bool) -> Vec<WatchId> {
        let mut out = Vec::new();
        let mut stack = vec![top];
        while let Some(tn) = stack.pop() {
            let tn = if skip { ix.down(tn) } else { tn };
            for (_, c) in ix.children(tn) {
                out.extend(ix.watches_at(c));
                stack.push(c);
            }
        }
        out
    }

    /// Every node's `down`, against its definition.
    fn check_down(ix: &WatchIndex) {
        for n in 0..ix.nodes.len() as u32 {
            if ix.free_nodes.contains(&n) {
                continue;
            }
            let mut want = n;
            loop {
                let kids: Vec<u32> = ix.children(want).map(|(_, c)| c).collect();
                match kids[..] {
                    [only] if ix.watches_at(only).next().is_none() => want = only,
                    _ => break,
                }
            }
            assert_eq!(ix.down(n), want, "node {n} {:?}", ix.tnode(n).name);
        }
    }

    #[test]
    fn down_ends_a_chain_of_single_children_without_watches() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let n = |ix: &WatchIndex, s: &str| ix.node(&p(s)).unwrap();
        let w = add(&mut ix, 1, "/w/a/b/c/d");
        check_down(&ix);
        assert_eq!(ix.down(ROOT), n(&ix, "/w/a/b/c"), "the chain ends above the watch");
        assert_eq!(ix.down(n(&ix, "/w/a/b/c")), n(&ix, "/w/a/b/c"));
        assert_eq!(ix.down(n(&ix, "/w/a/b/c/d")), n(&ix, "/w/a/b/c/d"), "no child");
        // A watch on the way ends it there; a branch ends it at the branch.
        let b = add(&mut ix, 2, "/w/a/b");
        assert_eq!(ix.down(ROOT), n(&ix, "/w/a"));
        assert_eq!(ix.down(n(&ix, "/w/a/b")), n(&ix, "/w/a/b/c"));
        let e = add(&mut ix, 3, "/w/a/e/f");
        assert_eq!(ix.down(ROOT), n(&ix, "/w/a"));
        assert_eq!(ix.down(n(&ix, "/w/a/e")), n(&ix, "/w/a/e"));
        check_down(&ix);
        assert_eq!(walk(&ix, ROOT, true), walk(&ix, ROOT, false));
        // Removals mend it, up to the root.
        ix.remove(e);
        assert_eq!(ix.down(ROOT), n(&ix, "/w/a"));
        ix.remove(b);
        assert_eq!(ix.down(ROOT), n(&ix, "/w/a/b/c"));
        check_down(&ix);
        ix.remove(w);
        assert_eq!(ix.down(ROOT), ROOT);
        check_down(&ix);
        // Special paths have theirs, which no walk uses.
        let s = add(&mut ix, 1, "@x");
        check_down(&ix);
        ix.remove(s);
        check_down(&ix);
    }

    #[test]
    fn a_walk_that_goes_down_meets_the_same_watches_in_the_same_order() {
        // Random watches on a few deep, branching paths, added and removed
        // by several connections; after every change each node's `down`
        // is checked, and the walk below each node of a few paths.
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..40 {
            let mut ix = WatchIndex::new(SipKey::new([round, 2]));
            let mut live = Vec::new();
            for _ in 0..60 {
                if live.is_empty() || next(3) > 0 {
                    let depth = 1 + next(8) as usize;
                    // Mostly `a`: long chains, with a branch now and then.
                    let mut path = Vec::new();
                    for _ in 0..depth {
                        let spread = if next(4) == 0 { 3 } else { 1 };
                        path.push(["a", "b", "c"][next(spread) as usize]);
                    }
                    let key = Key::Tree(p(&format!("/{}", path.join("/"))));
                    let conn = ConnId(next(3));
                    let token = Bytes::from(format!("{}", next(2)).as_bytes());
                    if ix.find(conn, &key, &token).is_none() {
                        live.push(ix.add(conn, &key, token, false));
                    }
                } else {
                    let i = next(live.len() as u64) as usize;
                    ix.remove(live.swap_remove(i));
                }
                check_down(&ix);
                for top in ["/", "/a", "/a/a", "/a/b", "/b", "/a/a/a/a"] {
                    if let Some(t) = ix.node(&p(top)) {
                        assert_eq!(walk(&ix, t, true), walk(&ix, t, false), "round {round}, below {top}");
                    }
                }
            }
            ix.remove_all(ConnId(0));
            check_down(&ix);
        }
    }

    #[test]
    fn the_children_of_a_node_are_listed_by_name() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let kids = |ix: &WatchIndex| {
            let n = ix.node(&p("/s")).unwrap();
            let names: Vec<String> = ix
                .children(n)
                .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
                .collect();
            // Linked both ways.
            let mut back = Vec::new();
            let mut c = ix.tnode(n).last_child;
            while c != NONE {
                back.insert(0, String::from_utf8(ix.tnode(c).name.to_vec()).unwrap());
                c = ix.tnode(c).prev_sibling;
            }
            assert_eq!(names, back);
            names
        };
        let mut ids = Vec::new();
        for name in ["b", "B", "10", "9", "a-", "a", "c", "a/x"] {
            ids.push(add(&mut ix, 1, &format!("/s/{name}")));
        }
        assert_eq!(kids(&ix), ["10", "9", "B", "a", "a-", "b", "c"]);
        // Removed first, in the middle and last, then made again.
        for (i, left) in [
            (2, ["9", "B", "a", "a-", "b", "c"].as_slice()),
            (4, &["9", "B", "a", "b", "c"]),
            (6, &["9", "B", "a", "b"]),
        ] {
            ix.remove(ids[i]);
            assert_eq!(kids(&ix), left);
        }
        add(&mut ix, 1, "/s/10");
        add(&mut ix, 1, "/s/c");
        add(&mut ix, 1, "/s/a-");
        assert_eq!(kids(&ix), ["10", "9", "B", "a", "a-", "b", "c"]);
    }

    #[test]
    fn the_watches_of_a_path_are_listed_newest_first() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let at = |ix: &WatchIndex| ix.watches_at(ix.node(&p("/a")).unwrap()).collect::<Vec<_>>();
        let ws: Vec<_> = (0..4).map(|c| add(&mut ix, c, "/a")).collect();
        let below = add(&mut ix, 9, "/a/b");
        assert_eq!(at(&ix), [ws[3], ws[2], ws[1], ws[0]]);
        let mut v = Vec::new();
        ix.on_path(&p("/a/b"), &mut v);
        assert_eq!(v, [ws[3], ws[2], ws[1], ws[0], below], "ancestors first");
        // Removed from the middle, the end and the front; one added again
        // is the newest.
        ix.remove(ws[1]);
        assert_eq!(at(&ix), [ws[3], ws[2], ws[0]]);
        ix.remove(ws[0]);
        assert_eq!(at(&ix), [ws[3], ws[2]]);
        ix.remove(ws[3]);
        assert_eq!(at(&ix), [ws[2]]);
        let again = add(&mut ix, 0, "/a");
        assert_eq!(at(&ix), [again, ws[2]]);
        ix.remove(ws[2]);
        ix.remove(again);
        assert_eq!(ix.watches_at(ix.node(&p("/a")).unwrap()).count(), 0);
        ix.remove(below);
        assert_eq!(ix.trie_size(), 1);
    }

    #[test]
    fn special_paths() {
        let mut ix = WatchIndex::new(SipKey::new([1, 2]));
        let a = add(&mut ix, 1, "@introduceDomain");
        let b = add(&mut ix, 2, "@introduceDomain");
        let c = add(&mut ix, 2, "@releaseDomain");
        let special = |ix: &WatchIndex, s: &[u8]| ix.special(s).collect::<Vec<_>>();
        assert_eq!(special(&ix, b"@introduceDomain"), [b, a], "newest first");
        assert_eq!(special(&ix, b"@releaseDomain"), [c]);
        assert_eq!(special(&ix, b"@other"), []);
        assert_eq!(ix.path(c), b"@releaseDomain");
        assert_eq!(ix.locate(&Key::Special(b"@releaseDomain".into())), Some(ix.get(c).node));
        assert_eq!(ix.locate(&Key::Special(b"@other".into())), None);
        assert_eq!(on(&ix, "/"), Vec::<WatchId>::new(), "not in the tree");
        ix.remove(a);
        assert_eq!(special(&ix, b"@introduceDomain"), [b]);
        ix.remove(b);
        ix.remove(c);
        assert!(ix.children.is_empty());
        assert_eq!(ix.trie_size(), 1);
    }
}
