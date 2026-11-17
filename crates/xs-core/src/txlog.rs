// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! What a transaction keeps of each of its store requests until it ends:
//! the request, the reply its client got, and whether it changed what
//! watches see. A commit after other changes runs the requests again on
//! the store and compares the replies (`ox/process.ml:473-501`).
//!
//! Nothing here holds a version of the store: a version kept per request
//! would make the next request of the transaction copy every page on its
//! path, and keep the copy, so that a request would cost what its path
//! costs in the store. Paths are kept packed, a
//! byte per byte of the path (`path::pack`); a listing as the names it
//! had, shared by the requests that saw the same one.

use crate::bytes::Bytes;
use crate::path::{self, Name, Path};
use crate::perms::Perms;
use crate::prelude::*;
use crate::store::{ChangeKind, Node, Op, Outcome};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use xs_wire::Errno;

/// A store request without its path.
#[derive(Debug)]
enum Req {
    Read,
    GetPerms,
    Directory,
    Write(Bytes),
    Mkdir,
    Rm,
    SetPerms(Arc<Perms>),
}

/// The reply a request got, as much of it as tells whether a request run
/// again gets the same.
#[derive(Debug)]
enum Reply {
    Done,
    Value { vgen: u64, value: Bytes },
    Perms { vgen: u64, perms: Arc<Perms> },
    Children { cgen: u64, names: Arc<Listing> },
    Failed(Errno),
}

/// The names of a listing, in order, in little room: a short name (one a
/// `Name` keeps inline) as its bytes, a long one shared with the store
/// (`long`, in order) and marked by the byte 0xFF, which no name is; each
/// followed by a NUL. About what oxenstored keeps, the reply, for short
/// names, and less for long ones.
#[derive(Debug)]
pub(crate) struct Listing {
    bytes: Box<[u8]>,
    long: Box<[Name]>,
}

/// What stands for a long name in `Listing::bytes`.
const LONG: &[u8] = &[0xFF];

impl Listing {
    fn of<'a>(names: impl Iterator<Item = &'a Name>) -> Listing {
        let (mut bytes, mut long) = (Vec::new(), Vec::new());
        for name in names {
            if name.len() > crate::bytes::INLINE {
                bytes.extend_from_slice(LONG);
                long.push(name.clone());
            } else {
                bytes.extend_from_slice(name);
            }
            bytes.push(0);
        }
        Listing {
            bytes: bytes.into_boxed_slice(),
            long: long.into_boxed_slice(),
        }
    }

    /// The names, in order.
    fn names(&self) -> impl Iterator<Item = &[u8]> {
        let mut long = self.long.iter();
        let pieces = self.bytes.split(|c| *c == 0);
        // The last piece is what follows the last NUL: nothing.
        let n = self.bytes.iter().filter(|c| **c == 0).count();
        pieces.take(n).map(move |piece| match piece {
            LONG => long.next().map_or(piece, |name| &name[..]),
            _ => piece,
        })
    }
}

/// A store request of a transaction, as the transaction keeps it.
#[derive(Debug)]
pub(crate) struct Entry {
    req: Req,
    path: Bytes,
    reply: Reply,
    /// The change it made that may fire watches, if any.
    pub(crate) fired: Option<ChangeKind>,
    /// About the bytes it keeps that nothing else does (`cost`).
    cost: usize,
}

/// The bytes an allocation of `Bytes` takes, if it has one: its contents
/// and the two counts of its `Arc`.
fn heap(b: &Bytes) -> usize {
    if b.len() > crate::bytes::INLINE {
        b.len() + 16
    } else {
        0
    }
}

impl Listing {
    /// About the bytes it takes.
    fn cost(&self) -> usize {
        core::mem::size_of::<Listing>() + 16 + self.bytes.len() + self.long.len() * core::mem::size_of::<Name>()
    }
}

/// The listings a transaction's requests saw, by path and generation of
/// the set of children: a listing seen again is kept once.
#[derive(Debug, Default)]
pub(crate) struct Listings(BTreeMap<(Bytes, u64), Arc<Listing>>);

impl Entry {
    /// `op` got `outcome` and made a change of kind `fired`, if any.
    pub(crate) fn new(op: Op, outcome: &Outcome, fired: Option<ChangeKind>, seen: &mut Listings) -> Entry {
        let (req, path) = match op {
            Op::Read(p) => (Req::Read, p),
            Op::GetPerms(p) => (Req::GetPerms, p),
            Op::Directory(p) => (Req::Directory, p),
            Op::Write(p, v) => (Req::Write(v), p),
            Op::Mkdir(p) => (Req::Mkdir, p),
            Op::Rm(p) => (Req::Rm, p),
            Op::SetPerms(p, perms) => (Req::SetPerms(perms), p),
        };
        let path = path::pack(&path);
        let mut cost = core::mem::size_of::<Entry>() + heap(&path);
        cost += match &req {
            Req::Write(v) => heap(v),
            Req::SetPerms(p) => {
                core::mem::size_of::<Perms>() + 16 + p.acl.len() * core::mem::size_of::<(u32, crate::perms::Access)>()
            }
            _ => 0,
        };
        let reply = match outcome {
            Outcome::Done => Reply::Done,
            Outcome::Value { vgen, value } => {
                // Shared with the store, until the store changes it.
                cost += heap(value);
                Reply::Value {
                    vgen: *vgen,
                    value: value.clone(),
                }
            }
            Outcome::Perms { vgen, perms } => Reply::Perms {
                vgen: *vgen,
                perms: perms.clone(),
            },
            Outcome::Children { cgen, children } => {
                let names = match seen.0.entry((path.clone(), *cgen)) {
                    alloc::collections::btree_map::Entry::Occupied(o) => o.get().clone(),
                    alloc::collections::btree_map::Entry::Vacant(v) => {
                        let listing = Arc::new(Listing::of(children.keys()));
                        // The listing, and its key in `seen`.
                        cost += listing.cost() + heap(&path) + core::mem::size_of::<(Bytes, u64, usize)>();
                        v.insert(listing).clone()
                    }
                };
                Reply::Children { cgen: *cgen, names }
            }
            Outcome::Failed(e) => Reply::Failed(*e),
        };
        Entry {
            req,
            path,
            reply,
            fired,
            cost,
        }
    }

    /// About the bytes the entry keeps that nothing else does: itself,
    /// its path and value if they are not inline, the permissions it sets,
    /// the value of its reply (shared with the store until the store
    /// changes it), and a listing it was the first to see. What a quota on
    /// a connection's transactions counts (`Config::transaction_bytes_max`).
    pub(crate) fn cost(&self) -> usize {
        self.cost
    }

    /// The path of the request.
    pub(crate) fn path(&self) -> Path {
        path::unpack(&self.path)
    }

    /// The path of the request, packed.
    fn packed(&self) -> &[u8] {
        &self.path
    }

    /// The request, to run again.
    pub(crate) fn op(&self) -> Op {
        let p = self.path();
        match &self.req {
            Req::Read => Op::Read(p),
            Req::GetPerms => Op::GetPerms(p),
            Req::Directory => Op::Directory(p),
            Req::Write(v) => Op::Write(p, v.clone()),
            Req::Mkdir => Op::Mkdir(p),
            Req::Rm => Op::Rm(p),
            Req::SetPerms(perms) => Op::SetPerms(p, perms.clone()),
        }
    }

    /// Would the client have got the same reply? Generations decide when
    /// they are equal (an equal generation is the same change); contents
    /// are compared otherwise.
    pub(crate) fn same_reply(&self, outcome: &Outcome) -> bool {
        match (&self.reply, outcome) {
            (Reply::Done, Outcome::Done) => true,
            (Reply::Failed(a), Outcome::Failed(b)) => a == b,
            (Reply::Value { vgen: g1, value: v1 }, Outcome::Value { vgen: g2, value: v2 }) => g1 == g2 || v1 == v2,
            (Reply::Perms { vgen: g1, perms: p1 }, Outcome::Perms { vgen: g2, perms: p2 }) => g1 == g2 || p1 == p2,
            (Reply::Children { cgen: g1, names }, Outcome::Children { cgen: g2, children }) => {
                g1 == g2 || names.names().eq(children.keys().map(|k| &k[..]))
            }
            _ => false,
        }
    }
}

/// What of a version of the store the requests of a transaction can see
/// when they run on it: the nodes on their paths (whether each exists,
/// its value and permissions, the names of its children), and all of
/// what is below a node one of them removes (an RM counts the nodes it
/// removes, for their owners' quotas). Nothing else: a request finds its
/// node from the root by name, and only a removal looks below it.
///
/// So the transaction gives the same replies on two versions that agree
/// on these nodes, and XSA-206 blame need not run it on both to know
/// that a change between them did not make it fail. A node agrees with
/// another if it is the same node in memory (versions share what they did
/// not change: then so does everything below it), or if it has the same
/// generations: `vgen` and `cgen` come from one counter, bumped by every
/// change of a value, permissions or set of children, so equal ones are
/// the same change and the same contents (what `Entry::same_reply` relies
/// on too). Below a removed node, only sharing is taken as agreeing.
#[derive(Debug, Default)]
pub(crate) struct Footprint {
    /// The root, and below it the paths of the requests.
    root: Spot,
}

#[derive(Debug, Default)]
struct Spot {
    children: BTreeMap<Name, Spot>,
    /// A request removes this node: what is below it counts.
    removed: bool,
}

impl Footprint {
    pub(crate) fn of(log: &[Entry]) -> Footprint {
        // Each path once (a transaction often repeats one).
        let mut paths: BTreeMap<&[u8], bool> = BTreeMap::new();
        for e in log {
            *paths.entry(e.packed()).or_insert(false) |= matches!(e.req, Req::Rm);
        }
        let mut f = Footprint::default();
        for (packed, removed) in paths {
            let mut at = &mut f.root;
            for name in path::unpack(packed) {
                at = at.children.entry(name).or_default();
            }
            at.removed |= removed;
        }
        f
    }

    /// Do the two versions agree on what the transaction can see?
    pub(crate) fn same(&self, a: &Node, b: &Node) -> bool {
        agree(&self.root, Some(a), Some(b))
    }
}

fn agree(spot: &Spot, a: Option<&Node>, b: Option<&Node>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            core::ptr::eq(a, b)
                || (a.vgen == b.vgen
                    && a.cgen == b.cgen
                    && (!spot.removed || a.children.ptr_eq(&b.children))
                    && spot
                        .children
                        .iter()
                        .all(|(name, below)| agree(below, a.child(name), b.child(name))))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pmap::PMap;
    use crate::store::Node;

    fn p(s: &str) -> Path {
        path::components(s.as_bytes()).unwrap()
    }

    fn entry(op: Op, outcome: &Outcome) -> Entry {
        Entry::new(op, outcome, None, &mut Listings::default())
    }

    #[test]
    fn a_request_comes_back_as_it_was() {
        let perms = Arc::new(Perms::parse(b"n5\0r6\0").unwrap());
        let ops = [
            Op::Read(p("/a/b")),
            Op::GetPerms(p("/a")),
            Op::Directory(p("/")),
            Op::Write(p("/a/b/c"), Bytes::from(&b"value"[..])),
            Op::Mkdir(p("@special")),
            Op::Rm(p("/a/@x")),
            Op::SetPerms(p("/a"), perms),
        ];
        for op in ops {
            let want = format!("{op:?}");
            let e = entry(op, &Outcome::Done);
            assert_eq!(format!("{:?}", e.op()), want);
        }
        let e = Entry::new(
            Op::Rm(p("/a/b")),
            &Outcome::Done,
            Some(ChangeKind::Rm),
            &mut Listings::default(),
        );
        assert_eq!((e.path(), e.fired), (p("/a/b"), Some(ChangeKind::Rm)));
    }

    fn value(g: u64, s: &str) -> Outcome {
        Outcome::Value {
            vgen: g,
            value: Bytes::from(s.as_bytes()),
        }
    }

    fn perms(g: u64, s: &[u8]) -> Outcome {
        Outcome::Perms {
            vgen: g,
            perms: Arc::new(Perms::parse(s).unwrap()),
        }
    }

    fn children(g: u64, names: &[&str]) -> Outcome {
        let mut m = PMap::new();
        for n in names {
            m.insert(
                Name::from(n.as_bytes()),
                Node::new(Arc::new(Perms::default0()), Bytes::EMPTY, 0),
            );
        }
        Outcome::Children { cgen: g, children: m }
    }

    #[test]
    fn replies_compare_by_generation_then_by_content() {
        let same = |a: &Outcome, b: &Outcome| entry(Op::Read(p("/a")), a).same_reply(b);
        assert!(same(&value(1, "a"), &value(1, "b")), "equal generations decide");
        assert!(same(&value(1, "a"), &value(2, "a")));
        assert!(!same(&value(1, "a"), &value(2, "b")));
        assert!(same(&Outcome::Done, &Outcome::Done));
        assert!(!same(&Outcome::Done, &Outcome::Failed(Errno::ENOENT)));
        assert!(same(&Outcome::Failed(Errno::ENOENT), &Outcome::Failed(Errno::ENOENT)));
        assert!(!same(&Outcome::Failed(Errno::ENOENT), &Outcome::Failed(Errno::E2BIG)));
        assert!(same(&perms(1, b"n0\0"), &perms(2, b"n0\0")));
        assert!(same(&perms(1, b"n0\0"), &perms(1, b"r0\0")));
        assert!(!same(&perms(1, b"n0\0"), &perms(2, b"r0\0")));
        assert!(same(&children(1, &["a"]), &children(2, &["a"])), "same names");
        assert!(!same(&children(1, &["a"]), &children(2, &["a", "b"])));
        assert!(!same(&children(1, &["a", "b"]), &children(2, &["a"])));
        assert!(
            same(&children(5, &["a"]), &children(5, &["a", "b"])),
            "equal generations decide"
        );
        assert!(!same(&value(1, "a"), &Outcome::Done));
        assert!(!same(&children(1, &[]), &value(1, "")));
    }

    #[test]
    fn a_listing_seen_again_is_kept_once() {
        let mut seen = Listings::default();
        let names = |e: &Entry| match &e.reply {
            Reply::Children { names, .. } => names.clone(),
            r => panic!("{r:?}"),
        };
        let a = Entry::new(Op::Directory(p("/a")), &children(3, &["x", "y"]), None, &mut seen);
        let b = Entry::new(Op::Directory(p("/a")), &children(3, &["x", "y"]), None, &mut seen);
        assert!(Arc::ptr_eq(&names(&a), &names(&b)));
        assert_eq!(names(&a).names().count(), 2);
        // Another generation, another path: another listing.
        let c = Entry::new(Op::Directory(p("/a")), &children(4, &["x"]), None, &mut seen);
        let d = Entry::new(Op::Directory(p("/b")), &children(3, &[]), None, &mut seen);
        assert_eq!((names(&c).names().count(), names(&d).names().count()), (1, 0));
        assert_eq!(seen.0.len(), 3);
    }

    #[test]
    fn a_listing_keeps_short_names_as_bytes_and_shares_long_ones() {
        let long = "l".repeat(crate::bytes::INLINE + 1);
        let longer = "m".repeat(1000);
        let names = ["a", "@x\u{ff}", &long, "b", &"s".repeat(crate::bytes::INLINE), &longer];
        let names: Vec<Name> = names.iter().map(|n| Name::from(n.as_bytes())).collect();
        let l = Listing::of(names.iter());
        assert!(l.names().eq(names.iter().map(|n| &n[..])));
        assert_eq!(l.long.len(), 2);
        assert_eq!(l.bytes.len(), 2 + 5 + 2 + 2 + 23 + 2);
        // Shared, not copied.
        assert!(matches!((&l.long[1], &names[5]), (Bytes::Shared(a), Bytes::Shared(b)) if Arc::ptr_eq(a, b)));
        assert_eq!(Listing::of([].iter()).names().count(), 0);
        // What it costs: itself, its two counts, its bytes, a `Name` per
        // long name.
        let base = core::mem::size_of::<Listing>() + 16;
        assert_eq!(l.cost(), base + 36 + 2 * core::mem::size_of::<Name>());
        assert_eq!(Listing::of([].iter()).cost(), base);
        // A `Bytes` costs its allocation only when it has one.
        let inline = Bytes::from(&[b'i'; crate::bytes::INLINE][..]);
        let shared = Bytes::from(&[b's'; crate::bytes::INLINE + 1][..]);
        assert_eq!((heap(&inline), heap(&shared)), (0, crate::bytes::INLINE + 1 + 16));
        // Compared as the names: one more, one less, one other.
        let reply = |names: &[&str]| entry(Op::Directory(p("/a")), &children(1, names));
        let (short, mixed) = (["a", "b"], ["a", long.as_str()]);
        assert!(reply(&short).same_reply(&children(2, &short)));
        assert!(reply(&mixed).same_reply(&children(2, &mixed)));
        assert!(!reply(&mixed).same_reply(&children(2, &["a", &"l".repeat(crate::bytes::INLINE + 2)])));
        assert!(!reply(&mixed).same_reply(&children(2, &["a"])));
        assert!(!reply(&short).same_reply(&children(2, &["a", "b", "c"])));
    }

    #[test]
    fn a_footprint_sees_the_nodes_on_the_paths_and_below_what_is_removed() {
        use crate::quota::{Acct, Entries};
        use crate::store::{execute, Ctx, Gen};
        let (mut gen, mut entries) = (Gen::default(), Entries::default());
        let mut root = crate::store::initial(&mut gen, b"", &mut Acct::Store(&mut entries));
        let mut run = |root: &mut Arc<Node>, op: Op| {
            let mut acct = Acct::Store(&mut entries);
            execute(root, &mut gen, &op, &Ctx::DOM0, &mut acct, &mut Vec::new());
        };
        for s in ["/a/b/c", "/a/x", "/r/s/t", "/q"] {
            run(&mut root, Op::Write(p(s), Bytes::EMPTY));
        }
        let log = [
            entry(Op::Read(p("/a/b/c")), &Outcome::Done),
            entry(Op::Write(p("/a/b/c"), Bytes::EMPTY), &Outcome::Done),
            entry(Op::Directory(p("/n/m")), &Outcome::Done),
            entry(Op::Rm(p("/r")), &Outcome::Done),
        ];
        let f = Footprint::of(&log);
        let same = |root: &Arc<Node>, change: Op, run: &mut dyn FnMut(&mut Arc<Node>, Op)| {
            let mut after = root.clone();
            run(&mut after, change);
            f.same(root, &after)
        };
        // Off the paths: the same, whatever changed there.
        assert!(f.same(&root, &root.clone()));
        assert!(same(&root, Op::Write(p("/a/x"), Bytes::from(&b"1"[..])), &mut run));
        assert!(same(&root, Op::Write(p("/q/new"), Bytes::EMPTY), &mut run));
        // The root is on every path: a child more there is seen.
        assert!(!same(&root, Op::Write(p("/n2"), Bytes::EMPTY), &mut run));
        // On them: a value, permissions, a child more or less, a node that
        // appears where none was.
        assert!(!same(&root, Op::Write(p("/a/b/c"), Bytes::from(&b"1"[..])), &mut run));
        assert!(!same(&root, Op::Write(p("/a/b"), Bytes::from(&b"1"[..])), &mut run));
        let perms = Arc::new(Perms::parse(b"n0\0r5\0").unwrap());
        assert!(!same(&root, Op::SetPerms(p("/a"), perms), &mut run));
        assert!(!same(&root, Op::Write(p("/a/b/d"), Bytes::EMPTY), &mut run));
        assert!(!same(&root, Op::Rm(p("/a/b/c")), &mut run));
        assert!(!same(&root, Op::Write(p("/n/m"), Bytes::EMPTY), &mut run));
        assert!(!same(&root, Op::Write(p("/n"), Bytes::EMPTY), &mut run));
        // Below what it removes, anything.
        assert!(!same(&root, Op::Write(p("/r/s/t"), Bytes::from(&b"1"[..])), &mut run));
        assert!(!same(&root, Op::Write(p("/r/s/u"), Bytes::EMPTY), &mut run));
        // The same node by generations, not in memory: a copy of the store
        // whose pages were copied on the paths.
        let mut copy = root.clone();
        run(&mut copy, Op::Write(p("/a/b/c/below"), Bytes::EMPTY));
        run(&mut copy, Op::Rm(p("/a/b/c/below")));
        assert!(
            !f.same(&root, &copy),
            "c lost a child, then got its set back: a new generation"
        );
        let mut copy = root.clone();
        run(&mut copy, Op::Write(p("/a/x"), Bytes::from(&b"2"[..])));
        assert!(f.same(&copy, &root) && f.same(&root, &copy));
        // Not reachable (a node that appears changes its parent's set of
        // children), but a node there in one version only is seen.
        let mut forged = (*root).clone();
        forged
            .children
            .insert(Name::from(&b"n"[..]), Node::new(root.perms.clone(), Bytes::EMPTY, 0));
        assert!(!f.same(&root, &forged) && !f.same(&forged, &root));
    }
}
