// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The access log, as the core sees it: a record per loggable event, handed
//! to a `Sink`. Which events, with what data and
//! transaction id, are oxenstored's (`ox/logging.ml:289-344`, called from
//! `ox/process.ml:426-436, 743, 756`, `ox/connection.ml:228-233, 351, 392-398`,
//! `ox/transaction.ml:259-261`); formatting, time and I/O are the daemon's.
//! A record borrows what it shows, so the core neither copies nor allocates
//! for it; with no sink, each place that could log costs one branch.
//!
//! Where rxenstored differs: a request is recorded before it is handled
//! (oxenstored writes its line after, but replies and events on output, so
//! the order of a request and of its replies and events is the same);
//! replies and events when they are queued, not when they are written; a
//! commit that had to be re-executed and succeeded is a `commit` (oxenstored
//! would log `coalesce` lines, or `conflict` and its replay under
//! `r(<tid>):<con>`, depending on its merge of transactions, which
//! rxenstored does not have); a conflict logs no replay; DIRECTORY_PART,
//! which oxenstored 4.17 does not know (it logs `invalid`), is a read.

use crate::perms::Perms;
use crate::prelude::*;
use crate::{Conn, ConnId, Conns, Core};
use xs_wire::{Message, MsgType};

/// Whose line it is: oxenstored's `get_domstr`, `A<n>` for a socket and
/// `D<domid>` for a domain's ring, domain 0's included
/// (`ox/connection.ml:183-185`). A socket's number is its `ConnId`, as
/// CONTROL `watches` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Socket(u64),
    Domain(u32),
}

impl Who {
    pub(crate) fn of(id: ConnId, c: &Conn) -> Who {
        if c.ring {
            Who::Domain(c.caller.domid)
        } else {
            Who::Socket(id.0)
        }
    }
}

/// What happened (`ox/logging.ml:217-253`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// A request of this wire type, as it came (unknown types included).
    Request(u32),
    /// An ERROR reply was queued.
    Error,
    /// A WATCH_EVENT was queued.
    Event,
    /// A watch did not fire: its watcher may not read the node (`w notfired`).
    NotFired,
    /// A transaction started or ended (`t start`, `t end`).
    Start,
    End,
    /// A transaction was committed, or failed with EAGAIN.
    Commit,
    Conflict,
    /// A connection was created or closed (`newconn`, `endconn`).
    NewConn,
    EndConn,
    /// CONTROL `print <text>`: the text, under the name `=======>`
    /// (`ox/process.ml:228-229`).
    Print,
}

/// The data of a line, unformatted.
#[derive(Debug, Clone, Copy)]
pub enum Data<'a> {
    /// These bytes, one after the other (a payload, as it came or went).
    Parts(&'a [&'a [u8]]),
    /// `EPERM perms=[<perms>] path=<path>`: the permissions the watcher
    /// lacked, each as `n0 r1`, separated by `, ` (`ox/connection.ml:343-351`).
    NotFired { perms: &'a [&'a Perms], path: &'a [u8] },
}

impl Data<'_> {
    /// Appends the bytes of the line's data to `out`, at most `max` of
    /// them; true if that cut them.
    pub fn copy_to(&self, out: &mut Vec<u8>, max: usize) -> bool {
        let mut left = max;
        let mut put = |b: &[u8]| {
            let n = b.len().min(left);
            out.extend_from_slice(b.get(..n).unwrap_or(b));
            left -= n;
            n < b.len()
        };
        match *self {
            Data::Parts(parts) => parts.iter().any(|p| put(p)),
            Data::NotFired { perms, path } => {
                let mut cut = put(b"EPERM perms=[");
                for (i, p) in perms.iter().enumerate() {
                    cut = cut || (i > 0 && put(b", ")) || put(&p.encode_sep(b" ", false));
                }
                cut || put(b"] path=") || put(path)
            }
        }
    }
}

/// One loggable event. `tid` is the transaction id of the line: the
/// request's as it came, the reply's or event's as queued.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    pub who: Who,
    pub tid: u32,
    pub op: Op,
    pub data: Data<'a>,
}

/// Where records go. Called during `process`, for every record the
/// switches let through, in the order of the events.
pub trait Sink: Send {
    fn record(&self, r: &Record<'_>);
}

/// `access-log-read-ops`, `access-log-transactions-ops`,
/// `access-log-special-ops`: all off by default (`ox/logging.ml:270-272`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Switches {
    /// READ, DIRECTORY, GET_PERMS (and DIRECTORY_PART), and ENOENT errors.
    pub read_ops: bool,
    /// `t start` and `t end`.
    pub transaction_ops: bool,
    /// INTRODUCE, RELEASE, GET_DOMAIN_PATH, IS_DOMAIN_INTRODUCED, RESUME.
    pub special_ops: bool,
}

#[derive(Default)]
pub(crate) struct Log {
    sink: Option<Box<dyn Sink>>,
    sw: Switches,
}

impl Core {
    /// Sends the access log's records to `sink` from now on (None: no access log).
    pub fn set_access_log(&mut self, sink: Option<Box<dyn Sink>>, switches: Switches) {
        self.conns.log = Log { sink, sw: switches };
    }
}

impl Conns {
    /// Whose line it is; None for a connection that is not open (none is
    /// logged for: the core logs for the connection it is handling).
    fn who(&self, id: ConnId) -> Option<Who> {
        self.map.get(&id).map(|c| Who::of(id, c))
    }

    /// `xb_op` (`ox/logging.ml:312-320`); transactions are `log_txn`'s.
    pub(crate) fn log_request(&self, id: ConnId, msg: &Message) {
        let Some(sink) = &self.log.sink else { return };
        let sw = self.log.sw;
        let shown = match msg.msg_type() {
            Some(MsgType::Read | MsgType::Directory | MsgType::GetPerms | MsgType::DirectoryPart) => sw.read_ops,
            Some(MsgType::TransactionStart | MsgType::TransactionEnd) => false,
            Some(
                MsgType::Introduce
                | MsgType::Release
                | MsgType::GetDomainPath
                | MsgType::IsDomainIntroduced
                | MsgType::Resume,
            ) => sw.special_ops,
            _ => true,
        };
        if let (true, Some(who)) = (shown, self.who(id)) {
            sink.record(&Record {
                who,
                tid: msg.tx_id,
                op: Op::Request(msg.ty),
                data: Data::Parts(&[&msg.payload]),
            });
        }
    }

    /// `xb_answer` (`ox/logging.ml:333-340`): errors (ENOENT only with
    /// the read switch) and watch events; other replies are not logged.
    pub(crate) fn log_reply(&self, id: ConnId, ty: u32, tid: u32, parts: &[&[u8]]) {
        let Some(sink) = &self.log.sink else { return };
        let (op, who) = match (MsgType::from_u32(ty), self.who(id)) {
            (Some(MsgType::Error), Some(who))
                if self.log.sw.read_ops || !parts.first().is_some_and(|p| p.starts_with(b"ENOENT")) =>
            {
                (Op::Error, who)
            }
            (Some(MsgType::WatchEvent), Some(who)) => (Op::Event, who),
            _ => return,
        };
        sink.record(&Record {
            who,
            tid,
            op,
            data: Data::Parts(parts),
        });
    }

    /// `newconn` and `endconn` (`ox/connection.ml:228, 233`).
    pub(crate) fn log_conn(&self, id: ConnId, c: &Conn, op: Op) {
        let Some(sink) = &self.log.sink else { return };
        sink.record(&Record {
            who: Who::of(id, c),
            tid: 0,
            op,
            data: Data::Parts(&[]),
        });
    }

    /// `t start`, `t end` with the transaction switch
    /// (`ox/logging.ml:322-328`); `commit` and `conflict` always.
    pub(crate) fn log_txn(&self, id: ConnId, tid: u32, op: Op) {
        let Some(sink) = &self.log.sink else { return };
        if let (true, Some(who)) = (
            self.log.sw.transaction_ops || matches!(op, Op::Commit | Op::Conflict),
            self.who(id),
        ) {
            sink.record(&Record {
                who,
                tid,
                op,
                data: Data::Parts(&[]),
            });
        }
    }

    /// `fire`, after logging `w notfired` for the watcher `id` if it is
    /// false (`ox/connection.ml:343-351`). `path`, absolute, is only
    /// computed then.
    pub(crate) fn fires<P: AsRef<[u8]>>(
        &self,
        fire: bool,
        id: ConnId,
        c: &Conn,
        perms: &[&Perms],
        path: impl FnOnce() -> P,
    ) -> bool {
        if let (false, Some(sink)) = (fire, &self.log.sink) {
            sink.record(&Record {
                who: Who::of(id, c),
                tid: 0,
                op: Op::NotFired,
                data: Data::NotFired {
                    perms,
                    path: path().as_ref(),
                },
            });
        }
        fire
    }

    /// CONTROL `print` (`ox/process.ml:228-229`); no reply of its own: OK.
    pub(crate) fn log_print(&self, id: ConnId, text: &[u8]) -> Option<Vec<u8>> {
        if let (Some(sink), Some(who)) = (&self.log.sink, self.who(id)) {
            sink.record(&Record {
                who,
                tid: 0,
                op: Op::Print,
                data: Data::Parts(&[text]),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests;
