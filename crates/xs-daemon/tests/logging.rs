// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The logs, in-process: the line formats against oxenstored's format
//! strings (`ox/` is tools/ocaml/xenstored of Xen 4.17.7), the queue, the
//! destinations, and the log thread behind the core.

// A test crate, not the daemon: it may unwrap, index, print and panic (the
// no-panic rule of Cargo.toml is for code that is not a test).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::get_unwrap,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::exit,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unchecked_time_subtraction
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use xs_core::log::{Data, Op, Record, Switches, Who};
use xs_core::{Config, ConnId, Core};
use xs_daemon::log::dest::{self, FileOut, Out, Outcome, SyslogOut};
use xs_daemon::log::format::{self, Stamp};
use xs_daemon::log::queue::{Batch, Kind, Orders, Queue};
use xs_daemon::log::{self, Dest, Facility, Level, Logger, Output, Settings};
use xs_wire::{write_header, MsgType};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        let d = std::env::temp_dir().join(format!(
            "rxenstored-logging-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn lines(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.path(name))
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 2020-01-23T12:34:56.512345678Z.
const T: Stamp = Stamp {
    secs: 1_579_782_896,
    nanos: 512_345_678,
};

fn access(file: Option<Stamp>, who: Who, tid: u32, op: Op, data: &[u8]) -> String {
    let mut out = Vec::new();
    format::access_line(&mut out, file, who, tid, op, data);
    String::from_utf8(out).unwrap()
}

fn rq(ty: MsgType) -> Op {
    Op::Request(ty as u32)
}

/// Golden lines, each built by hand from the format strings of
/// `ox/logging.ml`: the file prefix `"[%s%s%s] "` with no level nor key
/// (line 44), the date `"%d%.2d%.2dT%.2d:%.2d:%.2d.%.3dZ"` (128), the
/// connection `"%-12s"` of `con` or `con.tid` (213-215), the line
/// `"%s %s %s %s" prefix tid access_type data` (298), the operation
/// names (217-253), the data sanitised (258-263).
#[test]
fn golden_access_lines() {
    let f = Some(T);
    #[rustfmt::skip]
    let cases: &[(Who, u32, Op, &[u8], &str)] = &[
        // xb_op, Write (312-320, 244)
        (Who::Socket(12), 0, rq(MsgType::Write), b"/local/domain/3/foo\0bar", "[20200123T12:34:56.512Z]  A12          write     /local/domain/3/foo bar"),
        // con.tid (215), Mkdir (245): the payload's NUL is a space
        (Who::Domain(3), 5, rq(MsgType::Mkdir), b"/local/domain/3/x\0", "[20200123T12:34:56.512Z]  D3.5         mkdir     /local/domain/3/x "),
        // xb_answer, Watchevent (337, 252); dom0's ring is D0
        (Who::Domain(0), 0, Op::Event, b"@releaseDomain\0tok\0", "[20200123T12:34:56.512Z]  D0           w event   @releaseDomain tok "),
        // xb_answer, Error (336, 251)
        (Who::Socket(12), 0, Op::Error, b"EACCES\0", "[20200123T12:34:56.512Z]  A12          error     EACCES "),
        // Logging.commit, Logging.conflict (309-310, 219-220): no data
        (Who::Domain(3), 5, Op::Commit, b"", "[20200123T12:34:56.512Z]  D3.5         commit    "),
        (Who::Domain(3), 5, Op::Conflict, b"", "[20200123T12:34:56.512Z]  D3.5         conflict  "),
        // new_connection, end_connection (303-304, 221-222)
        (Who::Socket(1), 0, Op::NewConn, b"", "[20200123T12:34:56.512Z]  A1           newconn   "),
        (Who::Domain(7), 0, Op::EndConn, b"", "[20200123T12:34:56.512Z]  D7           endconn   "),
        // start_transaction, end_transaction (322-328, 235-236)
        (Who::Socket(1), 7, Op::Start, b"", "[20200123T12:34:56.512Z]  A1.7         t start   "),
        (Who::Socket(1), 7, Op::End, b"", "[20200123T12:34:56.512Z]  A1.7         t end     "),
        // watch_not_fired (342-344, 223)
        (Who::Domain(3), 0, Op::NotFired, b"EPERM perms=[n0, n0] path=/a", "[20200123T12:34:56.512Z]  D3           w notfired EPERM perms=[n0, n0] path=/a"),
        // CONTROL print (ox/process.ml:228-229): con "=======>", Debug (226)
        (Who::Socket(1), 0, Op::Print, b"hello", "[20200123T12:34:56.512Z]  =======>     debug     hello"),
        // Names longer than 9 (241, 248), and a connection longer than 12
        (Who::Socket(1), 0, rq(MsgType::ResetWatches), b"", "[20200123T12:34:56.512Z]  A1           reset watches "),
        (Who::Socket(1), 0, rq(MsgType::IsDomainIntroduced), b"5\0", "[20200123T12:34:56.512Z]  A1           is introduced 5 "),
        (Who::Socket(123_456_789), 4_000_000_000, rq(MsgType::Rm), b"/x\0", "[20200123T12:34:56.512Z]  A123456789.4000000000 rm        /x "),
        // Watch, Unwatch, Setperms, Debug, Set_target (232-233, 247, 226, 249)
        (Who::Socket(2), 0, rq(MsgType::Watch), b"/w\0t\0", "[20200123T12:34:56.512Z]  A2           watch     /w t "),
        (Who::Socket(2), 0, rq(MsgType::Unwatch), b"/w\0t\0", "[20200123T12:34:56.512Z]  A2           unwatch   /w t "),
        (Who::Socket(2), 0, rq(MsgType::SetPerms), b"/w\0n0\0r3\0", "[20200123T12:34:56.512Z]  A2           setperms  /w n0 r3 "),
        (Who::Socket(2), 0, rq(MsgType::Control), b"watches\0", "[20200123T12:34:56.512Z]  A2           debug     watches "),
        (Who::Socket(2), 0, rq(MsgType::SetTarget), b"3\x004\0", "[20200123T12:34:56.512Z]  A2           settarget 3 4 "),
        // Unknown types (Xb.Op.of_cval, ox/../libs/xb/op.ml:33-36)
        (Who::Socket(2), 0, Op::Request(99), b"x", "[20200123T12:34:56.512Z]  A2           invalid   x"),
    ];
    for (who, tid, op, data, want) in cases {
        assert_eq!(access(f, *who, *tid, *op, data), *want);
    }
    // syslog: the prefix is empty (line 47-48), the line starts with a space.
    assert_eq!(
        access(None, Who::Socket(12), 0, rq(MsgType::Write), b"/a\0b"),
        " A12          write     /a b"
    );
}

#[test]
fn every_operation_name() {
    let names: Vec<&str> = (0..=24).map(|t| format::op_name(Op::Request(t))).collect();
    assert_eq!(
        names,
        [
            "debug    ",
            "directory",
            "read     ",
            "getperms ",
            "watch    ",
            "unwatch  ",
            "t start  ",
            "t end    ",
            "introduce",
            "release  ",
            "getdomain",
            "write    ",
            "mkdir    ",
            "rm       ",
            "setperms ",
            "w event  ",
            "error    ",
            "is introduced",
            "resume   ",
            "settarget",
            "invalid  ",
            "reset watches",
            "directory",
            "invalid  ",
            "invalid  "
        ]
    );
    assert_eq!(format::op_name(Op::Request(u32::MAX)), "invalid  ");
    // The levels of `ox/logging.ml:303-344`, as syslog severities (145-154).
    let sev = |op| format::severity(format::op_level(op));
    assert_eq!(
        [
            sev(rq(MsgType::Write)),
            sev(Op::Event),
            sev(Op::NotFired),
            sev(Op::Print)
        ],
        [6; 4]
    );
    assert_eq!(sev(Op::Error), 4);
    for op in [Op::Start, Op::End, Op::Commit, Op::Conflict, Op::NewConn, Op::EndConn] {
        assert_eq!(sev(op), 7, "{op:?}");
    }
    assert_eq!(
        [Level::Debug, Level::Info, Level::Warn, Level::Error, Level::Null].map(format::severity),
        [7, 6, 4, 3, 7]
    );
}

/// OCaml's `String.escaped` after NUL became a space (`ox/logging.ml:258-263`).
#[test]
fn escaping() {
    let mut out = Vec::new();
    format::escape(&mut out, b"a\0b \"q\" \\ \n\t\r\x08 ~\x7f\x01\xff\xc3\xa9'");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "a b \\\"q\\\" \\\\ \\n\\t\\r\\b ~\\127\\001\\255\\195\\169'"
    );
}

/// `truncate_line` (`ox/logging.ml:60-68`).
#[test]
fn truncation() {
    let cut = |len: usize, nb: i64| {
        let mut l = vec![b'x'; len];
        format::truncate(&mut l, nb);
        String::from_utf8(l).unwrap()
    };
    assert_eq!(cut(179, 180), "x".repeat(179), "nb_chars - 1 fits");
    assert_eq!(cut(180, 180), format!("{}..", "x".repeat(177)));
    assert_eq!(cut(1000, 180).len(), 179);
    assert_eq!(cut(5, 0), "xxxxx", "0: no limit");
    assert_eq!(cut(5, -1), "xxxxx");
    // The smallest limits keep two dots.
    assert_eq!(cut(5, 1), "..");
    assert_eq!(cut(1, 1), "..");
    assert_eq!(cut(0, 1), "");
    assert_eq!(cut(5, 3), "..");
    assert_eq!(cut(5, 4), "x..");
    // A golden line of the default limit: 177 bytes and "..".
    let mut l = Vec::new();
    format::access_line(
        &mut l,
        Some(T),
        Who::Socket(12),
        0,
        rq(MsgType::Write),
        format!("/a\0{}", "v".repeat(300)).as_bytes(),
    );
    format::truncate(&mut l, 180);
    let want = format!(
        "[20200123T12:34:56.512Z]  A12          write     /a {}..",
        "v".repeat(177 - 52)
    );
    assert_eq!(String::from_utf8(l).unwrap(), want);
}

#[test]
fn dates() {
    let d = |secs, nanos| {
        let mut out = Vec::new();
        format::date(&mut out, Stamp { secs, nanos });
        String::from_utf8(out).unwrap()
    };
    assert_eq!(d(0, 0), "19700101T00:00:00.000Z");
    assert_eq!(d(1_709_164_799, 999_999_999), "20240228T23:59:59.999Z");
    assert_eq!(d(1_709_164_800, 1_000_000), "20240229T00:00:00.001Z", "a leap day");
    assert_eq!(d(951_782_400, 0), "20000229T00:00:00.000Z", "a leap century");
    assert_eq!(d(253_402_300_800, 0), "100000101T00:00:00.000Z", "%d: five digits");
    assert_eq!(
        d(-62_198_755_200, 0),
        "-10101T00:00:00.000Z",
        "%d: a year before 0, with its sign"
    );
    assert_eq!(d(-1, 0), "19691231T23:59:59.000Z");
    // The first day of the computation's year (March) a century or more
    // into its 400-year era, where each century day counts.
    assert_eq!(d(920_246_400, 0), "19990301T00:00:00.000Z");
    assert_eq!(d(4_107_542_400, 0), "21000301T00:00:00.000Z");
    let now = Stamp::now();
    assert!(now.secs > 1_700_000_000 && now.nanos < 1_000_000_000);
}

/// `prefix` with a level and a key (`ox/logging.ml:36-49`): the level as
/// `"|%5s"` (39), the key as `"|" ^ x` (42) in a file, `"[" ^ x ^ "] "`
/// (47) for syslog.
#[test]
fn golden_daemon_prefixes() {
    let p = |file, level| {
        let mut out = Vec::new();
        format::daemon_prefix(&mut out, file, level, "xenstored");
        String::from_utf8(out).unwrap()
    };
    assert_eq!(p(Some(T), Level::Warn), "[20200123T12:34:56.512Z| warn|xenstored] ");
    assert_eq!(p(Some(T), Level::Info), "[20200123T12:34:56.512Z| info|xenstored] ");
    assert_eq!(p(Some(T), Level::Debug), "[20200123T12:34:56.512Z|debug|xenstored] ");
    assert_eq!(p(Some(T), Level::Error), "[20200123T12:34:56.512Z|error|xenstored] ");
    assert_eq!(p(Some(T), Level::Null), "[20200123T12:34:56.512Z| null|xenstored] ");
    assert_eq!(p(None, Level::Error), "[xenstored] ");
}

/// glibc's header, misc/syslog.c: `"<%d>"`, `"%h %e %T "`, the tag, `": "`.
#[test]
fn syslog_headers() {
    let h = |pri, local, ident| {
        let mut out = Vec::new();
        format::syslog_header(&mut out, pri, local, ident);
        String::from_utf8(out).unwrap()
    };
    assert_eq!(h(158, T.secs, "oxenstored"), "<158>Jan 23 12:34:56 oxenstored: ");
    assert_eq!(
        h(30, 1_767_225_599 - 86_400 * 30, "rxenstored"),
        "<30>Dec  1 23:59:59 rxenstored: "
    );
    assert_eq!(h(0, 0, "x"), "<0>Jan  1 00:00:00 x: ");
}

#[test]
fn facilities_as_oxenstored_sends_them() {
    use Facility::*;
    let codes: Vec<u8> = [
        Kern,
        User,
        Mail,
        Daemon,
        Auth,
        Syslog,
        Lpr,
        News,
        Uucp,
        Cron,
        Authpriv,
        Ftp,
        Local(0),
        Local(3),
        Local(7),
    ]
    .iter()
    .map(|f| f.code())
    .collect();
    // kern is 0, which syslog(3) makes `user`; lpr is the or of six (ox/syslog_stubs.c:33).
    assert_eq!(codes, [8, 8, 16, 24, 32, 40, 184, 56, 64, 72, 80, 88, 128, 152, 184]);
    assert_eq!(Local(9).code(), 184, "clamped");
}

fn rec<'a>(who: Who, op: Op, parts: &'a [&'a [u8]]) -> Record<'a> {
    Record {
        who,
        tid: 0,
        op,
        data: Data::Parts(parts),
    }
}

fn drain(q: &Queue) -> (Batch, Orders) {
    let mut b = Batch::default();
    let o = q.take(&mut b);
    (b, o)
}

#[test]
fn the_queue_keeps_the_order_and_drops_what_does_not_fit() {
    // Three lines: one for the daemon log (a sixteenth, rounded up), two
    // for the access log.
    let q = Queue::new(3, 1 << 20);
    assert!(q.access(&rec(Who::Socket(1), Op::NewConn, &[]), 10));
    assert!(q.daemon(
        Kind::Daemon {
            level: Level::Warn,
            key: "k"
        },
        b"hello"
    ));
    assert!(q.access(&rec(Who::Domain(2), Op::Event, &[b"/a\0", b"tok\0"]), 4));
    assert!(!q.access(&rec(Who::Socket(1), Op::EndConn, &[]), 10));
    assert!(!q.daemon(Kind::Raw, b"x"));
    assert!(!q.access(&rec(Who::Socket(1), Op::EndConn, &[]), 10));
    let (b, o) = drain(&q);
    assert_eq!(
        o,
        Orders {
            dropped_access: 2,
            dropped_daemon: 1,
            reopen: false,
            stop: false
        }
    );
    let kinds: Vec<Kind> = b.items.iter().map(|i| i.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::Access {
                who: Who::Socket(1),
                tid: 0,
                op: Op::NewConn
            },
            Kind::Daemon {
                level: Level::Warn,
                key: "k"
            },
            Kind::Access {
                who: Who::Domain(2),
                tid: 0,
                op: Op::Event
            }
        ]
    );
    let data: Vec<&[u8]> = b.items.iter().map(|i| b.data(i)).collect();
    assert_eq!(data, [&b""[..], b"hello", b"/a\0t"]);
    assert_eq!(b.items.iter().map(|i| i.cut).collect::<Vec<_>>(), [false, false, true]);
    // In the order they came, stamped when they came.
    assert!(b
        .items
        .windows(2)
        .all(|w| (w[0].time.secs, w[0].time.nanos) <= (w[1].time.secs, w[1].time.nanos)));
    // Empty again, and its counts too.
    assert!(q.access(&rec(Who::Socket(1), Op::EndConn, &[]), 10));
    let (b, o) = drain(&q);
    assert_eq!((b.items.len(), o), (1, Orders::default()));
    // The bytes are bounded too (one line may go past them): 16 bytes,
    // 1 for the daemon log, 15 for the access log.
    let q = Queue::new(100, 16);
    assert!(q.access(&rec(Who::Socket(1), Op::Error, &[b"EACCES\0"]), 99));
    assert!(q.access(&rec(Who::Socket(1), Op::Error, &[b"EACCES\0"]), 99));
    assert!(q.access(&rec(Who::Socket(1), Op::Error, &[b"EACCES\0"]), 99));
    assert!(!q.access(&rec(Who::Socket(1), Op::Error, &[b"EACCES\0"]), 99));
    assert!(q.daemon(Kind::Raw, b"daemon"));
    assert!(!q.daemon(Kind::Raw, b"x"));
    let (mut b, o) = drain(&q);
    assert_eq!((b.items.len(), o.dropped_access, o.dropped_daemon), (4, 1, 1));
    b.clear();
    assert!(b.items.is_empty());
}

/// Each log has its share of the queue, which the other cannot use: a
/// flood of access-log lines (a guest's) leaves the daemon log its room,
/// and the reverse; taking the lines frees both.
#[test]
fn a_flood_of_one_log_leaves_the_other_its_room() {
    let daemon_line = |q: &Queue| q.daemon(Kind::Raw, b"connection marked bad");
    let flood = |q: &Queue| {
        let mut n = 0;
        while q.access(&rec(Who::Domain(5), Op::Error, &[b"EACCES\0"]), 99) {
            n += 1;
        }
        n
    };
    let q = Queue::new(log::QUEUE_LINES, log::QUEUE_BYTES);
    assert_eq!(flood(&q), 61_440);
    assert!(!q.access(&rec(Who::Domain(5), Op::Error, &[]), 99));
    assert_eq!((0..5000).filter(|_| daemon_line(&q)).count(), 4096);
    let (b, o) = drain(&q);
    assert_eq!((b.items.len(), o.dropped_access, o.dropped_daemon), (65_536, 2, 904));
    // Taken: room again, for both.
    assert!(daemon_line(&q));
    assert_eq!(flood(&q), 61_440);
    drain(&q);
    // By bytes: 1,600, 100 of them for the daemon log.
    let q = Queue::new(1000, 1600);
    let big = [b'x'; 100];
    let mut n = 0;
    while q.access(&rec(Who::Domain(5), Op::Error, &[&big]), 1000) {
        n += 1;
    }
    assert_eq!(n, 15);
    assert!(q.daemon(Kind::Raw, &big[..99]));
    assert!(q.daemon(Kind::Raw, b"one may go past"));
    assert!(!q.daemon(Kind::Raw, b"x"));
    drain(&q);
    // A flood of daemon-log lines leaves the access log its room.
    let q = Queue::new(32, 1 << 20);
    assert_eq!((0..10).filter(|_| daemon_line(&q)).count(), 2);
    assert_eq!(flood(&q), 30);
    let (b, o) = drain(&q);
    assert_eq!((b.items.len(), o.dropped_access, o.dropped_daemon), (32, 1, 8));
    // A queue whose access share holds no line: its drops still wake the
    // log thread at the kick.
    let q = std::sync::Arc::new(Queue::new(1, 1 << 20));
    assert!(!q.access(&rec(Who::Domain(5), Op::Error, &[]), 99));
    let q2 = q.clone();
    let t = std::thread::spawn(move || drain(&q2));
    q.kick();
    // Kicked before the thread waits, or while it does: once more until
    // it took the count.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !t.is_finished() {
        assert!(std::time::Instant::now() < deadline, "timed out");
        q.kick();
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(5));
    }
    let (b, o) = t.join().unwrap();
    assert_eq!((b.items.len(), o.dropped_access), (0, 1));
    // `take_within`: nothing came in time.
    let mut b = Batch::default();
    let o = Queue::new(8, 64).take_within(&mut b, Some(Duration::ZERO));
    assert_eq!((b.items.len(), o), (0, Orders::default()));
}

#[test]
fn the_queue_wakes_its_thread_on_a_kick_or_an_order() {
    let q = std::sync::Arc::new(Queue::new(100, 1 << 20));
    let (tx, rx) = std::sync::mpsc::channel();
    let q2 = q.clone();
    let t = std::thread::spawn(move || loop {
        let mut b = Batch::default();
        let o = q2.take(&mut b);
        tx.send((b.items.len(), o)).unwrap();
        if o.stop {
            return;
        }
    });
    let long = Duration::from_secs(30);
    // Lines wait for the kick at the end of the pass (or were taken at
    // once, if the thread had not gone to sleep yet).
    q.access(&rec(Who::Socket(1), Op::NewConn, &[]), 10);
    q.access(&rec(Who::Socket(1), Op::EndConn, &[]), 10);
    q.kick();
    let mut n = 0;
    while n < 2 {
        n += rx.recv_timeout(long).unwrap().0;
    }
    q.kick();
    q.daemon(Kind::Raw, b"x");
    assert_eq!(rx.recv_timeout(long).unwrap(), (1, Orders::default()));
    q.reopen();
    assert_eq!(
        rx.recv_timeout(long).unwrap(),
        (
            0,
            Orders {
                reopen: true,
                ..Orders::default()
            }
        )
    );
    q.stop();
    assert_eq!(
        rx.recv_timeout(long).unwrap(),
        (
            0,
            Orders {
                stop: true,
                ..Orders::default()
            }
        )
    );
    t.join().unwrap();
}

/// Nothing lost, the file rotated as it should: how many lines were
/// written.
fn written(o: Outcome) -> u64 {
    assert!(o.lost.is_none() && o.rotation.is_none(), "{o:?}");
    o.written
}

/// Takes a line: how many were written then.
fn write(f: &mut FileOut, text: &str) -> u64 {
    let mut l = text.as_bytes().to_vec();
    written(f.write(&mut l))
}

fn flush(f: &mut FileOut) -> u64 {
    written(f.flush())
}

/// `log_rotate` (`ox/logging.ml:70-86`) and the counter of
/// `make_file_logger` (88-108).
#[test]
fn files_rotate_by_line_count() {
    let d = Dir::new();
    let p = d.path("access.log");
    fs::write(&p, "old\n").unwrap();
    let mut f = FileOut::open(&p, 3, 2, 0).unwrap();
    // Taken, then written when a line rotates the file, or at the flush.
    let at: Vec<u64> = (1..=10).map(|i| write(&mut f, &format!("{i}"))).collect();
    assert_eq!(at, [0, 0, 3, 0, 0, 3, 0, 0, 3, 0]);
    assert_eq!(flush(&mut f), 1);
    assert_eq!(flush(&mut f), 0);
    // The line after nb_lines rotates: nb_lines + 1 to a file, and
    // nb_files - 1 old files.
    assert_eq!(d.lines("access.log"), ["10"]);
    assert_eq!(d.lines("access.log.1"), ["7", "8", "9"]);
    assert_eq!(d.lines("access.log.2"), ["4", "5", "6"]);
    assert!(!d.path("access.log.3").exists());
    // Created by the rotation: `open_out`'s mode.
    assert_eq!(mode(&p), 0o666 & !umask());
    // One file: truncated in place.
    let q = d.path("one.log");
    let mut f = FileOut::open(&q, 1, 1, 0).unwrap();
    for i in 1..=5 {
        write(&mut f, &format!("{i}"));
    }
    flush(&mut f);
    assert_eq!(d.lines("one.log"), ["5"]);
    assert!(!d.path("one.log.1").exists());
    // The chain stops at the first file missing.
    let r = d.path("gap.log");
    fs::write(d.path("gap.log.2"), "keep\n").unwrap();
    let mut f = FileOut::open(&r, 4, 0, 0).unwrap();
    assert_eq!(write(&mut f, "a"), 1);
    assert_eq!(
        (d.lines("gap.log.1"), d.lines("gap.log.2")),
        (vec!["a".to_string()], vec!["keep".to_string()])
    );
    write(&mut f, "b");
    flush(&mut f);
    assert_eq!(
        (d.lines("gap.log.1"), d.lines("gap.log.2"), d.lines("gap.log.3")),
        (vec!["b".to_string()], vec!["a".to_string()], vec!["keep".to_string()])
    );
    assert_eq!(d.lines("gap.log"), Vec::<String>::new());
    // A file that cannot be rotated: its lines are written, and it stays
    // in use until the next try, nb_lines lines later.
    let e = Dir::new();
    let mut f = FileOut::open(&e.path("gone.log"), 2, 1, 0).unwrap();
    write(&mut f, "1");
    fs::remove_dir_all(&e.0).unwrap();
    let o = f.write(&mut b"2".to_vec());
    assert_eq!(
        (o.written, o.lost.is_none(), o.rotation.map(|e| e.kind())),
        (2, true, Some(std::io::ErrorKind::NotFound))
    );
    assert_eq!(write(&mut f, "3"), 0);
    assert!(f.write(&mut b"4".to_vec()).rotation.is_some());
}

/// Lines are written when `FLUSH_AT` bytes wait, if not before; what a
/// `FileOut` dropped had taken is written.
#[test]
fn files_write_what_waits_past_a_bound_and_at_the_end() {
    let d = Dir::new();
    let p = d.path("big.log");
    let mut f = FileOut::open(&p, 2, 1 << 40, 0).unwrap();
    let line = "x".repeat(999);
    let n = dest::FLUSH_AT / 1000 + 1;
    assert!((0..n - 1).all(|_| write(&mut f, &line) == 0));
    assert_eq!(fs::metadata(&p).unwrap().len(), 0);
    assert_eq!(write(&mut f, &line), n as u64);
    assert_eq!(d.lines("big.log").len(), n);
    write(&mut f, "last");
    drop(f);
    assert_eq!(d.lines("big.log").last().unwrap(), "last");
}

/// A writer that takes `room` bytes, then fails as a full disk does;
/// interrupted once first if `interrupt`; writes nothing, and says so,
/// if `zero`.
#[derive(Default)]
struct Flaky {
    got: Vec<u8>,
    room: usize,
    interrupt: bool,
    zero: bool,
}

impl std::io::Write for Flaky {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if std::mem::take(&mut self.interrupt) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.zero {
            return Ok(0);
        }
        if self.room == 0 {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        let n = b.len().min(self.room);
        self.got.extend_from_slice(&b[..n]);
        self.room -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `put`: a line is written if all of it was; the lines after an error are
/// lost, the one it cut short too, and the next line written starts on a
/// line of its own.
#[test]
fn a_file_write_counts_whole_lines_and_mends_a_torn_one() {
    let lines = b"a\nbb\nccc\n";
    let ends = [2, 5, 9];
    let count = |o: &Outcome| {
        (
            o.written,
            o.lost.as_ref().map(|l| l.0),
            o.lost.as_ref().and_then(|l| l.1.raw_os_error()),
        )
    };
    // All of it, through an interruption.
    let mut w = Flaky {
        room: 100,
        interrupt: true,
        ..Flaky::default()
    };
    let mut torn = false;
    assert_eq!(count(&dest::put(&mut w, lines, &ends, &mut torn)), (3, None, None));
    assert_eq!((w.got.as_slice(), torn), (&lines[..], false));
    // Full at a line's end: the others lost, nothing torn.
    let mut w = Flaky {
        room: 5,
        ..Flaky::default()
    };
    assert_eq!(
        count(&dest::put(&mut w, lines, &ends, &mut torn)),
        (2, Some(1), Some(28))
    );
    assert!(!torn);
    // Full inside one: it is lost too, and torn.
    let mut w = Flaky {
        room: 3,
        ..Flaky::default()
    };
    assert_eq!(
        count(&dest::put(&mut w, lines, &ends, &mut torn)),
        (1, Some(2), Some(28))
    );
    assert_eq!((w.got.as_slice(), torn), (&b"a\nb"[..], true));
    // Nothing to write: nothing written, still torn.
    assert_eq!(count(&dest::put(&mut w, b"", &[], &mut torn)), (0, None, None));
    assert!(torn);
    // Still full: the newline that mends it fails, the lines are lost.
    assert_eq!(
        count(&dest::put(&mut w, b"d\n", &[2], &mut torn)),
        (0, Some(1), Some(28))
    );
    assert!(torn);
    // Room again: the torn line is ended first.
    w.room = 100;
    assert_eq!(count(&dest::put(&mut w, b"e\n", &[2], &mut torn)), (1, None, None));
    assert_eq!((w.got.as_slice(), torn), (&b"a\nb\ne\n"[..], false));
    // A writer that takes nothing: all lost.
    let mut w = Flaky {
        zero: true,
        ..Flaky::default()
    };
    let o = dest::put(&mut w, lines, &ends, &mut torn);
    assert_eq!(
        (o.written, o.lost.map(|(n, e)| (n, e.kind()))),
        (0, Some((3, std::io::ErrorKind::WriteZero)))
    );
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// The process's umask, as Linux shows it.
fn umask() -> u32 {
    let s = fs::read_to_string("/proc/self/status").unwrap();
    let v = s.lines().find_map(|l| l.strip_prefix("Umask:")).unwrap();
    u32::from_str_radix(v.trim(), 8).unwrap()
}

/// Set in the child of `files_are_created_with_oxenstored_modes`.
const MODES_CHILD: &str = "RXS_LOG_MODES_CHILD";

/// oxenstored creates its log file 0o644 at the start and on SIGHUP
/// (`open_out_gen [Open_append; Open_creat] 0o644`, `ox/logging.ml:89,
/// 95`), and 0o666 after a rotation (`open_out`, 86), less the umask.
/// Checked under the umask the tests run with, then in a process of its
/// own under umask 0, where the two differ (the umask is the process's:
/// changed here, it would change the modes other tests see).
#[test]
fn files_are_created_with_oxenstored_modes() {
    let child = std::env::var_os(MODES_CHILD).is_some();
    let um = umask();
    if child {
        assert_eq!(um, 0);
    }
    let d = Dir::new();
    let p = d.path("access.log");
    let mut f = FileOut::open(&p, 2, 1, 0).unwrap();
    assert_eq!(mode(&p), 0o644 & !um, "at the start");
    write(&mut f, "1");
    assert_eq!(write(&mut f, "2"), 2);
    assert_eq!(mode(&p), 0o666 & !um, "after a rotation");
    assert_eq!(mode(&d.path("access.log.1")), 0o644 & !um);
    fs::remove_file(&p).unwrap();
    assert_eq!(written(f.reopen().unwrap()), 0);
    assert_eq!(mode(&p), 0o644 & !um, "on SIGHUP");
    if child {
        return;
    }
    let mut c = std::process::Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "files_are_created_with_oxenstored_modes", "--test-threads=1"])
        .env(MODES_CHILD, "1");
    // SAFETY: umask(2) is async-signal-safe and cannot fail.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut c, || {
            libc::umask(0);
            Ok(())
        });
    }
    let out = c.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("1 passed"), "{text}");
}

#[test]
fn files_cut_lines_and_reopen_by_name() {
    let d = Dir::new();
    let p = d.path("x.log");
    let mut f = FileOut::open(&p, 2, 100, 6).unwrap();
    write(&mut f, "short");
    write(&mut f, "a longer line");
    flush(&mut f);
    assert_eq!(d.lines("x.log"), ["short", "a l.."]);
    // SIGHUP after logrotate renamed it: a new file, the old one keeps its
    // lines, those taken before the SIGHUP too.
    fs::rename(&p, d.path("x.log.old")).unwrap();
    write(&mut f, "1");
    assert_eq!(written(f.reopen().unwrap()), 1);
    write(&mut f, "2");
    flush(&mut f);
    assert_eq!(d.lines("x.log.old"), ["short", "a l..", "1"]);
    assert_eq!(d.lines("x.log"), ["2"]);
    // Reopened, it appends.
    assert_eq!(written(f.reopen().unwrap()), 0);
    write(&mut f, "3");
    flush(&mut f);
    assert_eq!(d.lines("x.log"), ["2", "3"]);
    // A directory that went: the old file stays in use, and the lines
    // taken wait for it.
    write(&mut f, "4");
    fs::remove_dir_all(&d.0).unwrap();
    assert!(f.reopen().is_err());
    assert_eq!(flush(&mut f), 1);
    assert!(FileOut::open(&p, 2, 100, 6).is_err());
}

fn listen(d: &Dir) -> (UnixDatagram, PathBuf) {
    let p = d.path("dev-log");
    let s = UnixDatagram::bind(&p).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    (s, p)
}

fn recv(s: &UnixDatagram) -> String {
    let mut buf = [0u8; 70000];
    let n = s.recv(&mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

fn header(pri: u8, t: Stamp, ident: &str) -> String {
    let mut out = Vec::new();
    format::syslog_header(&mut out, pri, t.secs + xs_sys::log::utc_offset(t.secs), ident);
    String::from_utf8(out).unwrap()
}

/// A syslog header is in local time, as glibc's `syslog(3)` writes it,
/// whatever the zone, summer time included. glibc reads `TZ` once per
/// process: the test runs again in a child with a zone of its own (a
/// POSIX rule: no tzdata needed), UTC+1, UTC+2 in summer.
#[test]
fn syslog_headers_are_in_local_time() {
    const CHILD: &str = "XS_DAEMON_TEST_TZ_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "syslog_headers_are_in_local_time"])
            .env(CHILD, "1")
            .env("TZ", "XST-1XDT,M3.5.0,M10.5.0/3")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
        return;
    }
    let d = Dir::new();
    let (server, path) = listen(&d);
    let mut out = SyslogOut::new(&path, 3 << 3, "rxenstored");
    // 2025-11-15, 2025-07-01 and 2025-11-10 at 00:00:30 UTC (a day of
    // one digit is padded with a space, as syslog(3) does; 10 has two).
    let cases = [
        (1_763_164_830, "Nov 15 01:00:30"),
        (1_751_328_030, "Jul  1 02:00:30"),
        (1_762_732_830, "Nov 10 01:00:30"),
    ];
    for (secs, local) in cases {
        out.send(6, Stamp { secs, nanos: 0 }, b"line").unwrap();
        let got = recv(&server);
        assert!(got.starts_with(&format!("<30>{local} rxenstored: ")), "{got}");
    }
}

/// What rsyslog on the host turns into `/var/log/xenstored-access.log`:
/// the datagram glibc's `syslog(local3|info, "%s", line)` sends.
#[test]
fn syslog_datagrams_byte_for_byte() {
    let d = Dir::new();
    let (server, p) = listen(&d);
    let mut s = SyslogOut::new(&p, Facility::Local(3).code(), "oxenstored");
    let line = access(
        None,
        Who::Socket(12),
        0,
        rq(MsgType::Write),
        b"/local/domain/3/foo\0bar",
    );
    s.send(6, T, line.as_bytes()).unwrap();
    let got = recv(&server);
    assert_eq!(
        got,
        format!(
            "{} A12          write     /local/domain/3/foo bar",
            header(158, T, "oxenstored")
        )
    );
    // Fields 6 and 7 of the file line are the connection and the operation.
    let file_line = format!(
        "Jan 23 12:34:56 xcp-ng-host {}",
        got.split_once(' ')
            .unwrap()
            .1
            .split_once(' ')
            .unwrap()
            .1
            .split_once(' ')
            .unwrap()
            .1
    );
    let fields: Vec<&str> = file_line.split_whitespace().collect();
    assert_eq!((fields[5], fields[6]), ("A12", "write"));
    // One datagram per line, up to a NUL, none for an empty last line
    // (`ox/syslog_stubs.c:47-67`).
    s.send(3, T, b"[xenstored] one\n\ntwo\n").unwrap();
    let h = header(155, T, "oxenstored");
    assert_eq!(
        [recv(&server), recv(&server), recv(&server)],
        [format!("{h}[xenstored] one"), h.clone(), format!("{h}two")]
    );
    s.send(3, T, b"cut\0here\nnot sent").unwrap();
    s.send(3, T, b"").unwrap();
    s.send(3, T, b"last").unwrap();
    assert_eq!([recv(&server), recv(&server)], [format!("{h}cut"), format!("{h}last")]);
    // The daemon restarted: connected again.
    drop(server);
    fs::remove_file(&p).unwrap();
    assert!(s.send(3, T, b"lost").is_err());
    let (server, _) = listen(&d);
    s.send(3, T, b"again").unwrap();
    assert_eq!(recv(&server), format!("{h}again"));
    drop(server);
    fs::remove_file(&p).unwrap();
    let (server, _) = listen(&d);
    s.send(3, T, b"once more").unwrap();
    assert_eq!(recv(&server), format!("{h}once more"));
}

#[test]
fn outputs() {
    let d = Dir::new();
    let mut l = Vec::new();
    let mut out = Out::File(FileOut::open(&d.path("f"), 2, 10, -1).unwrap());
    // A file's line is written at the flush, or at a reopen.
    assert_eq!(
        written(out.write(T, 0, &mut l, |l, file| format::daemon_prefix(l, file, Level::Info, "k"))),
        0
    );
    assert_eq!(written(out.flush()), 1);
    assert_eq!(written(out.reopen().unwrap()), 0);
    assert_eq!(d.lines("f"), ["[20200123T12:34:56.512Z| info|k] "]);
    // The others' at once.
    let mut out = Out::Syslog(SyslogOut::new(&d.path("none"), 8, "x"));
    let o = out.write(T, 0, &mut l, |l, _| l.push(b'a'));
    assert_eq!((o.written, o.lost.map(|l| l.0)), (0, Some(1)));
    assert_eq!(written(out.flush()), 0);
    assert_eq!(written(out.reopen().unwrap()), 0);
    let mut out = Out::Stderr;
    let o = out.write(T, 0, &mut l, |l, file| {
        assert!(file.is_none());
        l.extend_from_slice(b"to stderr, from the tests");
    });
    assert_eq!(written(o), 1);
    assert_eq!(l, b"rxenstored: to stderr, from the tests\n");
    assert_eq!(written(out.flush()), 0);
    assert_eq!(written(out.reopen().unwrap()), 0);
}

fn settings(d: &Dir, daemon: Option<(Dest, Level)>, access: Option<(Dest, Switches)>) -> Settings {
    let out = |dest| Output {
        dest,
        nb_files: 3,
        nb_lines: 1000,
        nb_chars: 180,
    };
    Settings {
        daemon: daemon.map(|(dest, l)| (out(dest), l)),
        access: access.map(|(dest, sw)| (out(dest), sw)),
        ident: "rxenstored".into(),
        syslog_socket: d.path("dev-log"),
        queue_lines: 1000,
        queue_bytes: 1 << 20,
    }
}

/// A request to the core.
fn send(core: &mut Core, c: ConnId, ty: MsgType, tx: u32, payload: &[u8]) {
    let mut bytes = Vec::new();
    write_header(&mut bytes, ty as u32, 1, tx, payload.len() as u32);
    bytes.extend_from_slice(payload);
    core.feed(c, &bytes);
    core.process(c, 100);
}

/// Strips the date of file lines, which the test does not know.
fn undated(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| {
            if l.starts_with("[20") {
                format!("[DATE{}", &l[23..])
            } else {
                l
            }
        })
        .collect()
}

#[test]
fn the_log_thread_behind_the_core() {
    let d = Dir::new();
    let s = settings(
        &d,
        Some((Dest::File(d.path("xenstored.log")), Level::Info)),
        Some((Dest::File(d.path("access.log")), Switches::default())),
    );
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Write, 0, b"/a\0value");
    send(&mut core, a, MsgType::Read, 0, b"/a\0");
    send(&mut core, a, MsgType::Write, 0, b"bad//path\0");
    send(
        &mut core,
        a,
        MsgType::Write,
        0,
        format!("/long\0{}\x01", "v".repeat(500)).as_bytes(),
    );
    log::kick();
    xs_daemon::info!("xenstored", "shown");
    xs_daemon::debug!("xenstored", "not shown");
    xs_daemon::warn!("domains", "domain {}: shown", 3);
    xs_daemon::error!("xenstored", "multi\nline");
    // SIGHUP after the files were renamed: new ones. The five lines are
    // in the old one, written before (however batched).
    wait_for(|| fs::read_to_string(d.path("access.log")).unwrap().lines().count() == 5);
    fs::rename(d.path("access.log"), d.path("access.log.old")).unwrap();
    log::reopen();
    wait_for(|| d.path("access.log").exists());
    core.close(a);
    log::uninstall();
    // Without a logger: stderr, and nothing to kick or reopen.
    xs_daemon::warn!("xenstored", "to stderr, from the tests");
    log::kick();
    log::reopen();
    logger.stop();
    // 177 bytes of the line, and "..": its data was not all queued.
    let long = format!("[DATE]  A1           write     /long {}..", "v".repeat(177 - 55));
    assert_eq!(
        undated(d.lines("access.log.old")),
        [
            "[DATE]  A1           newconn   ",
            "[DATE]  A1           write     /a value",
            "[DATE]  A1           write     bad//path ",
            "[DATE]  A1           error     EINVAL ",
            &long
        ]
    );
    assert_eq!(undated(d.lines("access.log")), ["[DATE]  A1           endconn   "]);
    assert_eq!(
        undated(d.lines("xenstored.log")),
        [
            log::STARTED,
            "[DATE| info|xenstored] shown",
            "[DATE| warn|domains] domain 3: shown",
            "[DATE|error|xenstored] multi",
            "line"
        ]
    );
}

/// Waits until the log thread is past every line queued so far: a
/// daemon-log line queued now comes after them (one queue, taken in
/// order), and the log thread writes the daemon log after it wrote, or
/// lost, the access-log lines before it. Synchronises on what the files
/// show, not on time; the daemon log `log` must show warnings.
fn barrier(d: &Dir, log: &str, name: &str) {
    xs_daemon::warn!("test", "barrier {name}");
    let want = format!("|test] barrier {name}\n");
    wait_for(|| fs::read_to_string(d.path(log)).unwrap().contains(&want));
}

/// The lines of the daemon log `log`, undated, without the barriers.
fn notes(d: &Dir, log: &str) -> Vec<String> {
    undated(d.lines(log))
        .into_iter()
        .filter(|l| !l.contains("|test] barrier "))
        .collect()
}

fn wait_for(mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "timed out");
        // sleep-ok: polls, within the deadline above.
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_full_queue_drops_and_says_how_many() {
    let d = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(d.path("a.log")), Switches::default())),
    );
    s.queue_lines = 4;
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    for i in 0..100 {
        send(&mut core, a, MsgType::Write, 0, format!("/n{i}\0").as_bytes());
    }
    log::uninstall();
    // Written at the stop, without a kick.
    logger.stop();
    let lines = undated(d.lines("a.log"));
    let kept: Vec<&String> = lines.iter().filter(|l| l.contains(" write ")).collect();
    let dropped: u64 = lines
        .iter()
        .filter_map(|l| l.strip_prefix("[DATE]  rxenstored   dropped   "))
        .map(|l| l.split(' ').next().unwrap().parse::<u64>().unwrap())
        .sum();
    assert!(dropped > 0, "{lines:?}");
    // newconn and 100 writes: each kept or counted, in order.
    assert_eq!(kept.len() as u64 + dropped + 1, 101, "{lines:?}");
    let numbers: Vec<u32> = kept
        .iter()
        .map(|l| l.rsplit_once("/n").unwrap().1.trim().parse().unwrap())
        .collect();
    assert!(numbers.windows(2).all(|w| w[0] < w[1]), "{numbers:?}");
    let daemon = undated(d.lines("d.log"));
    assert!(
        daemon.iter().any(|l| l.starts_with("[DATE| warn|logging] ")
            && l.ends_with(" access-log lines dropped: the log thread could not keep up")),
        "{daemon:?}"
    );
}

/// A file line shows at most `nb_chars` bytes of data, so no more is
/// queued: a long value takes no more room in the queue than that. A
/// `nb_chars` of 0 cuts nothing.
#[test]
fn the_queue_holds_what_a_line_shows_and_no_more() {
    for (nb_chars, shown) in [(180, 180 - 55), (0, 400)] {
        let d = Dir::new();
        let mut s = settings(
            &d,
            Some((Dest::File(d.path("d.log")), Level::Warn)),
            Some((Dest::File(d.path("a.log")), Switches::default())),
        );
        if let Some((o, _)) = s.access.as_mut() {
            o.nb_chars = nb_chars;
        }
        // Room for four writes of 180 bytes, not of 400 (but for those
        // when nothing is cut).
        s.queue_bytes = if nb_chars > 0 { 1000 } else { 1 << 20 };
        let logger = Logger::start(&s).unwrap();
        // The log thread wrote its first line and waits: what is queued
        // from now on stays queued until the stop (no kick).
        wait_for(|| fs::read_to_string(d.path("d.log")).is_ok_and(|t| t.contains(log::STARTED)));
        logger.install();
        let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
        log::attach(&mut core);
        let a = core.open();
        for i in 0..4 {
            send(
                &mut core,
                a,
                MsgType::Write,
                0,
                format!("/n{i}\0{}", "v".repeat(396)).as_bytes(),
            );
        }
        log::uninstall();
        logger.stop();
        let lines = undated(d.lines("a.log"));
        let writes: Vec<&String> = lines.iter().filter(|l| l.contains(" write ")).collect();
        assert_eq!(writes.len(), 4, "{nb_chars}: {lines:?}");
        assert!(!lines.iter().any(|l| l.contains(" dropped ")), "{nb_chars}: {lines:?}");
        assert!(
            writes[0].contains(&format!("/n0 {}", "v".repeat(shown - 4))),
            "{writes:?}"
        );
        if nb_chars == 0 {
            assert!(writes[0].ends_with(&format!("/n0 {}", "v".repeat(396))), "{writes:?}");
        }
    }
}

/// The counts of the "dropped" lines of the access log `a`, and of the
/// daemon log's notes of access-log lines dropped in `d`.
fn dropped_and_told(d: &Dir, a: &str, dl: &str) -> (Vec<u64>, Vec<u64>) {
    let count = |l: &str| l.split(' ').next().unwrap().parse::<u64>().unwrap();
    let dropped = undated(d.lines(a))
        .iter()
        .filter_map(|l| l.strip_prefix("[DATE]  rxenstored   dropped   ").map(count))
        .collect();
    let told = undated(d.lines(dl))
        .iter()
        .filter_map(|l| {
            l.strip_prefix("[DATE| warn|logging] ")
                .filter(|l| l.ends_with(" access-log lines dropped: the log thread could not keep up"))
                .map(count)
        })
        .collect();
    (dropped, told)
}

/// A guest floods the access log, in three bursts: the daemon-log lines
/// queued meanwhile are all written (they have their own share of the
/// queue); the access log tells of the lines dropped after each batch,
/// the daemon log once per period (here, an hour: the first at once, the
/// rest at the stop), and the counts agree.
#[test]
fn a_flood_of_the_access_log_drops_no_daemon_line_and_is_told_once_per_period() {
    let d = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(d.path("a.log")), Switches::default())),
    );
    // 3 lines for the daemon log, 45 for the access log. The log thread
    // takes the lines at the kick (or at a daemon-log line): each burst of
    // 300 overflows.
    s.queue_lines = 48;
    let logger = Logger::start_reporting(
        &s,
        log::Echo::new(Duration::ZERO, 0, Box::new(std::io::sink())),
        Duration::from_secs(3600),
    )
    .unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    for round in 0..3 {
        for i in 0..300 {
            send(&mut core, a, MsgType::Write, 0, format!("/n{i}\0").as_bytes());
        }
        xs_daemon::warn!("domains", "domain 5: connection marked bad ({round})");
        log::kick();
        barrier(&d, "d.log", &format!("{round}"));
    }
    let (dropped, told) = dropped_and_told(&d, "a.log", "d.log");
    assert!(dropped.len() >= 3, "{dropped:?}");
    assert_eq!(told.len(), 1, "{told:?}");
    assert_eq!(told[0], dropped[0]);
    log::uninstall();
    logger.stop();
    let (dropped, told) = dropped_and_told(&d, "a.log", "d.log");
    assert_eq!(told.len(), 2, "{told:?}");
    assert_eq!(told.iter().sum::<u64>(), dropped.iter().sum::<u64>());
    let daemon = notes(&d, "d.log");
    for round in 0..3 {
        let want = format!("[DATE| warn|domains] domain 5: connection marked bad ({round})");
        assert!(daemon.contains(&want), "{daemon:?}");
    }
    assert!(
        !daemon.iter().any(|l| l.contains("daemon-log lines dropped")),
        "{daemon:?}"
    );
}

/// Lines dropped that the daemon log has not told of yet are told when
/// the period is over, though no line comes after them.
#[test]
fn drops_not_told_yet_are_told_when_the_period_is_over() {
    let d = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(d.path("a.log")), Switches::default())),
    );
    s.queue_lines = 48;
    let logger = Logger::start_reporting(
        &s,
        log::Echo::new(Duration::ZERO, 0, Box::new(std::io::sink())),
        Duration::from_secs(2),
    )
    .unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    for round in 0..2 {
        for i in 0..300 {
            send(&mut core, a, MsgType::Write, 0, format!("/n{i}\0").as_bytes());
        }
        log::kick();
        barrier(&d, "d.log", &format!("{round}"));
    }
    // Nothing more: the log thread wakes to tell the rest.
    wait_for(|| {
        let (dropped, told) = dropped_and_told(&d, "a.log", "d.log");
        dropped.len() >= 2 && told.iter().sum::<u64>() == dropped.iter().sum::<u64>()
    });
    log::uninstall();
    logger.stop();
}

/// A log that cannot be opened is named in the daemon log.
#[test]
fn an_access_log_that_cannot_be_opened_is_named() {
    let d = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(d.path("no/a.log")), Switches::default())),
    );
    // Whole lines, however long the temporary directory's path.
    if let Some((o, _)) = s.daemon.as_mut() {
        o.nb_chars = 0;
    }
    Logger::start_with(&s, log::Echo::new(Duration::ZERO, 0, Box::new(std::io::sink())))
        .unwrap()
        .stop();
    let want = format!(
        "[DATE|error|logging] access log {}: No such file or directory (os error 2): no access log",
        d.path("no/a.log").display()
    );
    assert!(undated(d.lines("d.log")).contains(&want), "{:?}", d.lines("d.log"));
}

/// A flood of daemon-log lines fills the daemon log's share: the lines
/// dropped are counted and told, and each line is kept or counted.
#[test]
fn a_flood_of_the_daemon_log_is_counted_and_told() {
    let d = Dir::new();
    let mut s = settings(&d, Some((Dest::File(d.path("d.log")), Level::Warn)), None);
    s.daemon.as_mut().unwrap().0.nb_lines = 1 << 20;
    // 3 lines for the daemon log: the log thread, which waits `LINGER`
    // after each batch, cannot take 10,000 lines 3 by 3 as they come.
    s.queue_lines = 48;
    let logger = Logger::start(&s).unwrap();
    logger.install();
    for i in 0..10_000 {
        xs_daemon::warn!("test", "flood {i}");
    }
    log::uninstall();
    logger.stop();
    let lines = notes(&d, "d.log");
    let kept = lines.iter().filter(|l| l.contains("|test] flood ")).count() as u64;
    let told: u64 = lines
        .iter()
        .filter_map(|l| {
            l.strip_prefix("[DATE| warn|logging] ")?
                .strip_suffix(" daemon-log lines dropped: the log thread could not keep up")
        })
        .map(|n| n.parse::<u64>().unwrap())
        .sum();
    assert!(told > 0, "{lines:?}");
    assert_eq!(kept + told, 10_000);
}

#[test]
fn syslog_destinations_and_levels() {
    let d = Dir::new();
    let (server, _) = listen(&d);
    let s = settings(
        &d,
        Some((Dest::Syslog(Facility::Daemon), Level::Null)),
        Some((
            Dest::Syslog(Facility::Local(3)),
            Switches {
                read_ops: true,
                ..Switches::default()
            },
        )),
    );
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Read, 0, b"/missing\0");
    xs_daemon::error!("xenstored", "null shows nothing");
    log::kick();
    log::uninstall();
    logger.stop();
    let got: Vec<String> = (0..4).map(|_| recv(&server)).collect();
    let strip = |s: &str| {
        s.split_once(": ")
            .map(|(h, m)| (h[..h.find('>').unwrap() + 1].to_string(), m.to_string()))
            .unwrap()
    };
    // The first line of every start, whatever the level (`ox/logging.ml:169-172`).
    assert_eq!(strip(&got[0]), ("<30>".into(), log::STARTED.into()));
    assert_eq!(strip(&got[1]), ("<159>".into(), " A1           newconn   ".into()));
    assert_eq!(
        strip(&got[2]),
        ("<158>".into(), " A1           read      /missing ".into())
    );
    assert_eq!(
        strip(&got[3]),
        ("<156>".into(), " A1           error     ENOENT ".into())
    );
    server.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    assert!(server.recv(&mut [0u8; 16]).is_err(), "nothing more");
}

#[test]
fn logs_that_cannot_be_opened() {
    let d = Dir::new();
    // The daemon log goes to stderr; no access log.
    let s = settings(
        &d,
        Some((Dest::File(d.path("no/d.log")), Level::Warn)),
        Some((Dest::File(d.path("no/a.log")), Switches::default())),
    );
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Write, 0, b"/a\0b");
    xs_daemon::warn!("xenstored", "to stderr, from the tests");
    log::uninstall();
    logger.stop();
    assert!(!d.path("no").exists());
    // Neither log: problems on stderr.
    let s = settings(&d, None, Some((Dest::File(d.path("no/a.log")), Switches::default())));
    let logger = Logger::start(&s).unwrap();
    logger.install();
    xs_daemon::error!("xenstored", "no daemon log: not shown");
    log::uninstall();
    drop(logger);
}

#[test]
fn an_access_log_that_fails_is_reported() {
    if !Path::new("/dev/full").exists() {
        return;
    }
    let d = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File("/dev/full".into()), Switches::default())),
    );
    s.access.as_mut().unwrap().0.nb_lines = 1 << 40;
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Write, 0, b"/a\0b");
    log::uninstall();
    logger.stop();
    let daemon = undated(d.lines("d.log"));
    // newconn and the write, both lost (each counted, however they were
    // batched), and never written again: the stop says how many.
    assert_eq!(daemon.len(), 3, "{daemon:?}");
    assert!(
        daemon[1].starts_with("[DATE|error|logging] access log: ")
            && daemon[1].ends_with(": lines are lost until it can be written"),
        "{daemon:?}"
    );
    assert_eq!(
        daemon[2],
        "[DATE|error|logging] access log: not written again by the stop, after 2 lines lost"
    );
}

/// A pipe as the access log: a file the test can make fail (no reader)
/// and come back (a reader again), as a full disk or an NFS server that
/// went would. Each line is written or counted lost, never both, never
/// neither: a line that could not be written is not kept to be written
/// later, and the count is of lines, not of failed writes.
#[test]
fn an_access_log_file_that_fails_and_comes_back_counts_each_line_once() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let d = Dir::new();
    let fifo = d.path("a.fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let reader = || {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap()
    };
    let read = |r: &mut fs::File| {
        let mut buf = vec![0u8; 1 << 16];
        let n = r.read(&mut buf).unwrap_or(0);
        undated(
            String::from_utf8(buf[..n].to_vec())
                .unwrap()
                .lines()
                .map(String::from)
                .collect(),
        )
    };
    let mut r = reader();
    let s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(fifo.clone()), Switches::default())),
    );
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Write, 0, b"/1\0");
    barrier(&d, "d.log", "1");
    assert_eq!(
        read(&mut r),
        ["[DATE]  A1           newconn   ", "[DATE]  A1           write     /1 "]
    );
    assert_eq!(notes(&d, "d.log"), [log::STARTED]);
    // No reader: three lines lost, in two batches or more, said once.
    drop(r);
    send(&mut core, a, MsgType::Write, 0, b"/2\0");
    barrier(&d, "d.log", "2");
    send(&mut core, a, MsgType::Write, 0, b"/3\0");
    send(&mut core, a, MsgType::Write, 0, b"/4\0");
    barrier(&d, "d.log", "3");
    let lost = notes(&d, "d.log");
    assert_eq!(lost.len(), 2, "{lost:?}");
    assert!(
        lost[1].starts_with("[DATE|error|logging] access log: ")
            && lost[1].ends_with(": lines are lost until it can be written"),
        "{lost:?}"
    );
    // A reader again: the next line is written, and only it.
    let mut r = reader();
    send(&mut core, a, MsgType::Write, 0, b"/5\0");
    barrier(&d, "d.log", "4");
    assert_eq!(
        read(&mut r),
        ["[DATE]  A1           write     /5 "],
        "a line counted lost is not written later"
    );
    log::uninstall();
    logger.stop();
    assert_eq!(
        notes(&d, "d.log")[2..],
        ["[DATE| warn|logging] access log: written again, after 3 lines lost"]
    );
}

#[test]
fn an_access_log_that_comes_back_and_one_that_cannot_be_reopened() {
    let d = Dir::new();
    // syslog is not there yet: lines are lost, and that is said once.
    let s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::Syslog(Facility::Local(3)), Switches::default())),
    );
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    let a = core.open();
    send(&mut core, a, MsgType::Write, 0, b"/a\0b");
    // newconn and the write were tried before syslog came, however the log
    // thread took them (one batch or two): it is past them once it wrote
    // what was queued after them.
    barrier(&d, "d.log", "1");
    let daemon = notes(&d, "d.log");
    assert_eq!(
        daemon.len(),
        2,
        "nothing is written again while syslog is not there: {daemon:?}"
    );
    assert!(
        daemon[1].starts_with("[DATE|error|logging] access log: ")
            && daemon[1].ends_with(": lines are lost until it can be written"),
        "{daemon:?}"
    );
    let (server, _) = listen(&d);
    send(&mut core, a, MsgType::Write, 0, b"/c\0d");
    log::kick();
    assert!(recv(&server).ends_with(" A1           write     /c d"));
    log::uninstall();
    logger.stop();
    assert_eq!(
        notes(&d, "d.log")[2..],
        ["[DATE| warn|logging] access log: written again, after 2 lines lost"]
    );

    // A file whose directory went: SIGHUP keeps the old one, and says so;
    // so does a rotation, and the line is not lost.
    let other = Dir::new();
    let mut s = settings(
        &d,
        Some((Dest::File(d.path("d2.log")), Level::Warn)),
        Some((Dest::File(other.path("a.log")), Switches::default())),
    );
    s.access.as_mut().unwrap().0.nb_lines = 0;
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let a = fs::File::open(other.path("a.log")).unwrap();
    fs::remove_dir_all(&other.0).unwrap();
    log::reopen();
    barrier(&d, "d2.log", "1");
    let mut core = Core::new(Config::default(), xs_daemon::reactor::hash_key());
    log::attach(&mut core);
    core.open();
    log::uninstall();
    logger.stop();
    let daemon = notes(&d, "d2.log");
    assert_eq!(daemon.len(), 3, "{daemon:?}");
    assert!(
        daemon[1].starts_with("[DATE|error|logging] access log: cannot open it again: ")
            && daemon[1].ends_with(": still writing to the file it had"),
        "{daemon:?}"
    );
    assert!(
        daemon[2].starts_with("[DATE|error|logging] access log: cannot rotate it: ")
            && daemon[2].ends_with(": still writing to the file it had"),
        "{daemon:?}"
    );
    assert_eq!(
        undated(std::io::read_to_string(a).unwrap().lines().map(String::from).collect()),
        ["[DATE]  A1           newconn   "]
    );
}

/// A daemon log whose directory went: SIGHUP keeps the file it had, which
/// says so; the rotation that line brings about fails, and stderr says
/// that; the line is written all the same.
#[test]
fn a_daemon_log_that_cannot_be_reopened_nor_rotated() {
    let d = Dir::new();
    let gone = Dir::new();
    let mut s = settings(&d, Some((Dest::File(gone.path("d.log")), Level::Warn)), None);
    s.daemon.as_mut().unwrap().0.nb_lines = 1;
    let logger = Logger::start(&s).unwrap();
    logger.install();
    let f = fs::File::open(gone.path("d.log")).unwrap();
    fs::remove_dir_all(&gone.0).unwrap();
    log::reopen();
    log::uninstall();
    logger.stop();
    let daemon = undated(std::io::read_to_string(f).unwrap().lines().map(String::from).collect());
    assert_eq!(daemon.len(), 2, "{daemon:?}");
    assert!(
        daemon[1].starts_with("[DATE|error|logging] daemon log: cannot open it again: ")
            && daemon[1].ends_with(": still writing to the file it had"),
        "{daemon:?}"
    );
}

#[test]
fn a_daemon_log_that_cannot_be_written_goes_to_stderr() {
    // stderr is the process's: the test runs again in a child, whose
    // stderr this one reads.
    const CHILD: &str = "XS_DAEMON_TEST_STDERR_CHILD";
    if !Path::new("/dev/full").exists() {
        return;
    }
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "a_daemon_log_that_cannot_be_written_goes_to_stderr",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{err}");
        // The two lines (the first of every start, then the warning), lost
        // in one batch or in two, however the log thread took them.
        let lost: u64 = err
            .lines()
            .filter_map(|l| l.strip_prefix("rxenstored: daemon log: No space left on device (os error 28): "))
            .map(|l| l.strip_suffix(" lines lost").unwrap().parse::<u64>().unwrap())
            .sum();
        assert_eq!(lost, 2, "{err}");
        assert!(
            err.contains("rxenstored: [xenstored] to stderr, no syslog, from the tests\n"),
            "{err}"
        );
        return;
    }
    let d = Dir::new();
    // Written at the flush: the failure goes to stderr.
    let s = settings(&d, Some((Dest::File("/dev/full".into()), Level::Warn)), None);
    let logger = Logger::start(&s).unwrap();
    logger.install();
    xs_daemon::warn!("xenstored", "to /dev/full, from the tests");
    log::uninstall();
    logger.stop();
    // syslog is not there: each line goes to stderr.
    let s = settings(&d, Some((Dest::Syslog(Facility::Daemon), Level::Warn)), None);
    let logger = Logger::start(&s).unwrap();
    logger.install();
    xs_daemon::warn!("xenstored", "to stderr, no syslog, from the tests");
    log::uninstall();
    logger.stop();
}

/// stderr in a buffer.
#[derive(Clone, Default)]
struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    /// The lines, the date replaced by `DATE`.
    fn lines(&self) -> Vec<String> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| format!("rxenstored: [DATE{}", &l["rxenstored: [20200123T12:34:56.512Z".len()..]))
            .collect()
    }
}

/// The lifecycle messages go to stderr up to the cap, and within the
/// time; the start-up and stop ones always; the daemon log has each at its
/// level. A daemon log that is stderr itself does not get them twice.
#[test]
fn what_goes_to_stderr_besides_the_daemon_log() {
    use log::Echo;
    let d = Dir::new();
    let s = settings(
        &d,
        Some((Dest::File(d.path("d.log")), Level::Warn)),
        Some((Dest::File(d.path("no/a.log")), Switches::default())),
    );
    let out = Buf::default();
    let logger = Logger::start_with(&s, Echo::new(Duration::from_secs(600), 2, Box::new(out.clone()))).unwrap();
    logger.install();
    for domid in 1..=3 {
        xs_daemon::echo!(Lifecycle, Info, "domains", "domain {domid} introduced");
    }
    xs_daemon::echo!(Lifecycle, Error, "domains", "domain 3: marked bad");
    xs_daemon::echo!(Always, Info, "xenstored", "stopped by signal {}", 15);
    log::uninstall();
    logger.stop();
    let lines = out.lines();
    assert_eq!(lines.len(), 5, "{lines:?}");
    assert_eq!(lines[0], format!("rxenstored: [DATE| info|xenstored] {}", log::STARTED));
    assert!(
        lines[1].starts_with("rxenstored: [DATE|error|logging] access log ") && lines[1].ends_with(": no access log"),
        "{lines:?}"
    );
    assert_eq!(
        lines[2..],
        [
            "rxenstored: [DATE| info|domains] domain 1 introduced",
            "rxenstored: [DATE| info|domains] domain 2 introduced",
            "rxenstored: [DATE| info|xenstored] stopped by signal 15"
        ]
    );
    let daemon = undated(d.lines("d.log"));
    assert_eq!(daemon[0], log::STARTED);
    assert!(daemon[1].starts_with("[DATE|error|logging] access log "), "{daemon:?}");
    assert_eq!(daemon[2..], ["[DATE|error|domains] domain 3: marked bad"]);

    // Past the time: the start-up and stop messages only.
    let out = Buf::default();
    let s = settings(&d, Some((Dest::File(d.path("d2.log")), Level::Info)), None);
    let logger = Logger::start_with(&s, Echo::new(Duration::ZERO, 200, Box::new(out.clone()))).unwrap();
    logger.install();
    xs_daemon::echo!(Lifecycle, Info, "domains", "domain 1 introduced");
    xs_daemon::echo!(Always, Warn, "xenstored", "cannot raise the open file limit");
    log::uninstall();
    logger.stop();
    assert_eq!(
        out.lines(),
        [
            format!("rxenstored: [DATE| info|xenstored] {}", log::STARTED),
            "rxenstored: [DATE| warn|xenstored] cannot raise the open file limit".into()
        ]
    );
    assert_eq!(
        undated(d.lines("d2.log"))[1..],
        [
            "[DATE| info|domains] domain 1 introduced",
            "[DATE| warn|xenstored] cannot raise the open file limit"
        ]
    );

    // The daemon log is stderr: what it shows is not echoed again, what
    // it does not show is.
    let out = Buf::default();
    let s = settings(&d, Some((Dest::File(d.path("no/d.log")), Level::Warn)), None);
    let logger = Logger::start_with(&s, Echo::new(Duration::from_secs(600), 200, Box::new(out.clone()))).unwrap();
    logger.install();
    xs_daemon::echo!(
        Always,
        Warn,
        "xenstored",
        "shown by the daemon log, to stderr, from the tests"
    );
    xs_daemon::echo!(Always, Info, "xenstored", "listening on /s");
    log::uninstall();
    // No logger: stderr, as the other messages.
    xs_daemon::echo!(Always, Info, "xenstored", "no logger: to stderr, from the tests");
    logger.stop();
    assert_eq!(out.lines(), ["rxenstored: [DATE| info|xenstored] listening on /s"]);
}
