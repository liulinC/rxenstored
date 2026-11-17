// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! The access log and the daemon log: lines in oxenstored's formats, to
//! the destinations of `oxenstored.conf`, written by one thread so that the
//! event loop never formats a line nor waits on a file or on syslog.
//!
//! The core hands the access log's records to `AccessSink`, which stamps
//! them with the time of the request (to within a clock tick, the time
//! operators correlate with other logs; oxenstored's is when the line is
//! written, which is about the same as it writes at once) and copies their
//! data into the `Queue`, at most as much as a line can show. Daemon-log
//! messages are formatted at the call (`error!`, `warn!`, `info!`,
//! `debug!`), filtered by level, and queued the same way. The log thread
//! formats and writes them, in the order they came, then waits `LINGER`
//! before it takes the next batch, so that a busy daemon wakes it a few
//! hundred times a second rather than at every pass of the event loop
//! (a wake-up per pass would cost more than the rest of the log). A full
//! queue drops lines and counts them (the daemon log has its own share of
//! it, which no flood of access-log lines can fill: `queue`). The count of
//! access-log lines dropped is written to the access log after the lines
//! that were kept, at each batch; the daemon log tells both counts at most
//! once per `REPORT_EVERY`, the first at once and the others summed, so
//! that a long flood cannot rotate its earlier lines away. An access log
//! that cannot be written loses lines, each counted once (not kept to be
//! written later): the daemon log tells when that starts, and when a line
//! is written again or the daemon stops, how many were lost
//! (`Worker::access_outcome`). Before
//! a logger is installed on the calling thread (start-up, and the tests
//! that run the event loop in-process), and when the daemon log cannot be
//! opened, messages go to stderr.
//!
//! stderr is also what tells how a boot went (a launcher may append it
//! to a file): the start-up and stop messages (`echo!(Always, ..)`) are
//! written to it as well as to the daemon log, whatever the level, and
//! the domains' comings and goings (`echo!(Lifecycle, ..)`) during the
//! daemon's first `ECHO_FOR` and at most `ECHO_MAX` of them, so that a
//! host of thousands of domains does not write a line per domain to a file
//! for good. Those writes are the event loop's own (a few per boot, and
//! per domain for a while); the daemon log has every message at its level.

pub mod dest;
pub mod format;
pub mod queue;

use dest::{FileOut, Out, Outcome, SyslogOut};
use format::Stamp;
use queue::{Batch, Kind, Queue};
use std::cell::Cell;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xs_core::log::{Record, Sink, Switches};
use xs_core::Core;

/// A log destination (`ox/logging.ml:27-33`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    File(PathBuf),
    /// `syslog:<facility>`.
    Syslog(Facility),
}

/// syslog facilities oxenstored knows (`ox/syslog.ml:24-46`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Facility {
    Auth,
    Authpriv,
    Cron,
    Daemon,
    Ftp,
    Kern,
    Local(u8),
    Lpr,
    Mail,
    News,
    Syslog,
    User,
    Uucp,
}

impl Facility {
    /// The facility bits of the priority, as oxenstored's lines get them.
    /// Two differ from the name: `kern` is 0, which `syslog(3)` replaces by
    /// its default, `user`; `lpr` is what oxenstored's table has, all of
    /// LPR|MAIL|NEWS|SYSLOG|USER|UUCP or'ed in one entry, which is `local7`
    /// (`ox/syslog_stubs.c:29-34`). The five names after it in oxenstored's
    /// list (`mail` to `uucp`) are what they say here.
    pub fn code(self) -> u8 {
        match self {
            Facility::Kern | Facility::User => 1 << 3,
            Facility::Mail => 2 << 3,
            Facility::Daemon => 3 << 3,
            Facility::Auth => 4 << 3,
            Facility::Syslog => 5 << 3,
            Facility::News => 7 << 3,
            Facility::Uucp => 8 << 3,
            Facility::Cron => 9 << 3,
            Facility::Authpriv => 10 << 3,
            Facility::Ftp => 11 << 3,
            Facility::Local(n) => (16 + n.min(7)) << 3,
            Facility::Lpr => 23 << 3,
        }
    }
}

/// `ox/logging.ml:120-122`, in increasing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
    Null,
}

/// A destination and its `*-nb-files`, `*-nb-lines`, `*-nb-chars`.
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    pub dest: Dest,
    pub nb_files: i64,
    pub nb_lines: i64,
    pub nb_chars: i64,
}

/// The default queue: lines, and bytes of their data.
pub const QUEUE_LINES: usize = 1 << 16;
pub const QUEUE_BYTES: usize = 8 << 20;

/// How long the log thread waits after a batch before it takes the next:
/// the most a line waits for it to be written, once the thread is busy.
pub const LINGER: Duration = Duration::from_millis(2);

/// The daemon log tells of lines dropped at most once in this long: the
/// count since it last did, when the period is over, or at the stop.
pub const REPORT_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// The daemon log and the lowest level it shows; None: none.
    pub daemon: Option<(Output, Level)>,
    /// The access log; None: none.
    pub access: Option<(Output, Switches)>,
    /// The program name in syslog lines.
    pub ident: String,
    /// The local syslog socket.
    pub syslog_socket: PathBuf,
    pub queue_lines: usize,
    pub queue_bytes: usize,
}

/// `Define.xenstored_major`, `xenstored_minor` (`ox/define.ml:17-18`): the
/// line every start writes first (`ox/logging.ml:169-172`).
pub const STARTED: &str = "Xen Storage Daemon, version 1.0";

/// What the event loop's thread shares with the log thread.
struct Shared {
    queue: Queue,
    /// The daemon log's lowest level; None: no daemon log.
    level: Option<Level>,
    /// The access log's switches, and the data a line can show.
    access: Option<(Switches, usize)>,
    echo: Echo,
    /// The daemon log is stderr: what it shows is not echoed again.
    daemon_on_stderr: bool,
}

/// Domain lifecycle messages go to stderr for this long after the start,
/// and at most this many of them.
pub const ECHO_FOR: Duration = Duration::from_secs(600);
pub const ECHO_MAX: u32 = 200;

/// Which messages go to stderr besides the daemon log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stderr {
    /// Start-up and stop: always.
    Always,
    /// A domain introduced, dead, released, reconnected or marked bad:
    /// while the `Echo` allows.
    Lifecycle,
}

/// Where the echoed messages go, and how many lifecycle ones are left.
pub struct Echo {
    /// None: a period longer than an `Instant` can count, which never ends.
    until: Option<Instant>,
    left: AtomicU32,
    out: Mutex<Box<dyn Write + Send>>,
}

impl Echo {
    /// stderr, `ECHO_MAX` lifecycle messages during `ECHO_FOR` from now.
    pub fn stderr() -> Echo {
        Echo::new(ECHO_FOR, ECHO_MAX, Box::new(io::stderr()))
    }

    pub fn new(for_: Duration, max: u32, out: Box<dyn Write + Send>) -> Echo {
        Echo {
            until: Instant::now().checked_add(for_),
            left: AtomicU32::new(max),
            out: Mutex::new(out),
        }
    }

    /// One more lifecycle message may be echoed now.
    fn take(&self) -> bool {
        self.until.is_none_or(|until| Instant::now() < until)
            && self
                .left
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
    }

    /// `rxenstored: ` and the message as a daemon-log file shows it, in
    /// one write.
    fn write(&self, level: Level, key: &str, msg: &[u8]) {
        let mut line = b"rxenstored: ".to_vec();
        format::daemon_prefix(&mut line, Some(Stamp::now()), level, key);
        line.extend_from_slice(msg);
        line.push(b'\n');
        // Nothing to do about a stderr that cannot be written.
        let _ = self.out.lock().unwrap_or_else(|e| e.into_inner()).write_all(&line);
    }
}

/// The logs, written by their own thread until `stop`.
pub struct Logger {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

fn open(o: &Output, s: &Settings) -> io::Result<Out> {
    Ok(match &o.dest {
        Dest::File(p) => Out::File(FileOut::open(p, o.nb_files, o.nb_lines, o.nb_chars)?),
        Dest::Syslog(f) => Out::Syslog(SyslogOut::new(&s.syslog_socket, f.code(), &s.ident)),
    })
}

fn shown(d: &Dest) -> String {
    match d {
        Dest::File(p) => p.display().to_string(),
        Dest::Syslog(f) => format!("syslog ({f:?})"),
    }
}

impl Logger {
    /// Opens the destinations and starts the thread. A daemon log that
    /// cannot be opened is replaced by stderr, an access log that cannot be
    /// is left out (oxenstored would stop on either); both are reported.
    pub fn start(s: &Settings) -> io::Result<Logger> {
        Logger::start_with(s, Echo::stderr())
    }

    /// The same, echoing to `echo` (tests).
    pub fn start_with(s: &Settings, echo: Echo) -> io::Result<Logger> {
        Logger::start_reporting(s, echo, REPORT_EVERY)
    }

    /// The same, the daemon log telling of lines dropped at most once per
    /// `report_every` (tests).
    pub fn start_reporting(s: &Settings, echo: Echo, report_every: Duration) -> io::Result<Logger> {
        let mut problems = Vec::new();
        let daemon = s.daemon.as_ref().map(|(o, _)| {
            open(o, s).unwrap_or_else(|e| {
                problems.push(format!("daemon log {}: {e}: logging to stderr", shown(&o.dest)));
                Out::Stderr
            })
        });
        let access = s.access.as_ref().and_then(|(o, sw)| match open(o, s) {
            Ok(out) => {
                // A file line shows at most `nb_chars` bytes of data, and
                // no payload is longer than a payload.
                let limit = match (&o.dest, o.nb_chars) {
                    (Dest::File(_), n) if n > 0 => n as usize,
                    _ => xs_wire::PAYLOAD_MAX,
                };
                Some((out, (*sw, limit)))
            }
            Err(e) => {
                problems.push(format!("access log {}: {e}: no access log", shown(&o.dest)));
                None
            }
        });
        let (access, switches) = access.unzip();
        let daemon_on_stderr = matches!(daemon, Some(Out::Stderr));
        let shared = Arc::new(Shared {
            queue: Queue::new(s.queue_lines, s.queue_bytes),
            level: s.daemon.as_ref().map(|(_, l)| *l),
            access: switches,
            echo,
            daemon_on_stderr,
        });
        if daemon.is_some() {
            shared.queue.daemon(Kind::Raw, STARTED.as_bytes());
        }
        if !daemon_on_stderr {
            shared.echo.write(Level::Info, "xenstored", STARTED.as_bytes());
        }
        for p in &problems {
            match daemon {
                Some(_) => {
                    shared.queue.daemon(
                        Kind::Daemon {
                            level: Level::Error,
                            key: "logging",
                        },
                        p.as_bytes(),
                    );
                    if !daemon_on_stderr {
                        shared.echo.write(Level::Error, "logging", p.as_bytes());
                    }
                }
                None => stderr(format_args!("{p}")),
            }
        }
        let worker = Worker {
            shared: shared.clone(),
            daemon,
            access,
            lost: 0,
            unreported: (0, 0),
            reported: None,
            report_every,
            line: Vec::new(),
        };
        let thread = xs_sys::log::spawn_masked("rxenstored-log", move || worker.run())?;
        Ok(Logger {
            shared,
            thread: Some(thread),
        })
    }

    /// Writes what is queued, then ends the thread.
    pub fn stop(mut self) {
        self.finish();
    }

    fn finish(&mut self) {
        if let Some(t) = self.thread.take() {
            self.shared.queue.stop();
            let _ = t.join();
        }
    }

    /// The logger of the calling thread from now on: `error!` and the
    /// others, `attach`, `kick`, `reopen` use it.
    pub fn install(&self) {
        let _ = CURRENT.try_with(|c| c.set(Some(self.shared.clone())));
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The calling thread has no logger from now on: messages go to stderr.
pub fn uninstall() {
    let _ = CURRENT.try_with(|c| c.set(None));
}

thread_local! {
    static CURRENT: Cell<Option<Arc<Shared>>> = const { Cell::new(None) };
}

/// The logger of the calling thread; none while the thread ends.
fn current() -> Option<Arc<Shared>> {
    CURRENT
        .try_with(|c| {
            let shared = c.take();
            c.set(shared.clone());
            shared
        })
        .ok()
        .flatten()
}

fn with<R>(f: impl FnOnce(Option<&Shared>) -> R) -> R {
    f(current().as_deref())
}

/// `rxenstored: ` and a message on stderr, for a thread without a logger
/// and before the logs start. Nothing to do about a stderr that cannot be
/// written (`eprintln!` would panic: a full disk under the file it was
/// redirected to, a journal that went away).
pub fn stderr(args: fmt::Arguments) {
    let _ = io::stderr().write_fmt(format_args!("rxenstored: {args}\n"));
}

/// A daemon-log message, if its level is shown; to stderr if the thread
/// has no logger. Use `error!` and the others.
pub fn write(level: Level, key: &'static str, args: fmt::Arguments) {
    with(|s| match s {
        Some(s) => {
            if s.level.is_some_and(|min| level >= min) {
                s.queue.daemon(Kind::Daemon { level, key }, args.to_string().as_bytes());
            }
        }
        None => stderr(args),
    });
}

/// A daemon-log message as `write` does, and to stderr too as `when`
/// says. Use `echo!`.
pub fn echo(when: Stderr, level: Level, key: &'static str, args: fmt::Arguments) {
    with(|s| match s {
        Some(s) => {
            let text = args.to_string();
            let shown = s.level.is_some_and(|min| level >= min);
            if shown {
                s.queue.daemon(Kind::Daemon { level, key }, text.as_bytes());
            }
            let again = shown && s.daemon_on_stderr;
            if !again && (when == Stderr::Always || s.echo.take()) {
                s.echo.write(level, key, text.as_bytes());
            }
        }
        None => stderr(args),
    });
}

/// Gives the core the access log of the thread's logger, if it has one.
pub fn attach(core: &mut Core) {
    if let Some((shared, (sw, limit))) = current().and_then(|s| s.access.map(|a| (s, a))) {
        core.set_access_log(Some(Box::new(AccessSink { shared, limit })), sw);
    }
}

/// End of a pass of the event loop: the log thread writes what it queued.
pub fn kick() {
    with(|s| s.map(|s| s.queue.kick()));
}

/// SIGHUP: the log files are opened again (`ox/xenstored.ml:78-80`).
pub fn reopen() {
    with(|s| s.map(|s| s.queue.reopen()));
}

/// The core's sink: stamps and queues.
struct AccessSink {
    shared: Arc<Shared>,
    limit: usize,
}

impl Sink for AccessSink {
    fn record(&self, r: &Record<'_>) {
        self.shared.queue.access(r, self.limit);
    }
}

#[macro_export]
macro_rules! error {
    ($key:expr, $($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, $key, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($key:expr, $($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, $key, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! info {
    ($key:expr, $($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, $key, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($key:expr, $($arg:tt)*) => { $crate::log::write($crate::log::Level::Debug, $key, format_args!($($arg)*)) };
}

/// `echo!(Always, Info, "xenstored", ...)`: a daemon-log message also
/// written to stderr (`log::Stderr`).
#[macro_export]
macro_rules! echo {
    ($when:ident, $level:ident, $key:expr, $($arg:tt)*) => {
        $crate::log::echo($crate::log::Stderr::$when, $crate::log::Level::$level, $key, format_args!($($arg)*))
    };
}

/// The log thread.
struct Worker {
    shared: Arc<Shared>,
    daemon: Option<Out>,
    access: Option<Out>,
    /// Access-log lines that could not be written since the last that could.
    lost: u64,
    /// Access-log and daemon-log lines dropped that the daemon log has not
    /// told of yet, when it last did, and how often it may.
    unreported: (u64, u64),
    reported: Option<Instant>,
    report_every: Duration,
    line: Vec<u8>,
}

impl Worker {
    fn run(mut self) {
        let mut batch = Batch::default();
        loop {
            // Lines dropped and not told of yet: told when they may be,
            // even if nothing comes meanwhile.
            let wait = (self.unreported != (0, 0)).then(|| {
                self.reported
                    .map_or(Duration::ZERO, |t| self.report_every.saturating_sub(t.elapsed()))
            });
            let orders = self.shared.queue.take_within(&mut batch, wait);
            for it in &batch.items {
                let data = batch.data(it);
                match it.kind {
                    Kind::Access { who, tid, op } => self.access_line(it.time, format::op_level(op), |l, file| {
                        format::access_line(l, file, who, tid, op, data);
                        if it.cut {
                            l.extend_from_slice(b"..");
                        }
                    }),
                    Kind::Daemon { level, key } => self.daemon_line(it.time, Some((level, key)), data),
                    Kind::Raw => self.daemon_line(it.time, None, data),
                }
            }
            let n = orders.dropped_access;
            if n > 0 {
                let text = format!("{n} lines: the log could not keep up");
                self.access_line(Stamp::now(), Level::Warn, |l, file| {
                    format::line(l, file, "rxenstored", "dropped  ", text.as_bytes())
                });
            }
            self.unreported = (
                self.unreported.0.saturating_add(n),
                self.unreported.1.saturating_add(orders.dropped_daemon),
            );
            self.report_dropped(orders.stop);
            // The access log is written before the daemon log, which thus
            // tells about the access-log lines of the batch.
            if let Some(o) = self.access.as_mut().map(Out::flush) {
                self.access_outcome(o);
            }
            if orders.reopen {
                match self.daemon.as_mut().map(Out::reopen) {
                    Some(Ok(o)) => self.daemon_outcome(o),
                    Some(Err(e)) => self.reopen_failed("daemon", e),
                    None => {}
                }
                match self.access.as_mut().map(Out::reopen) {
                    Some(Ok(o)) => self.access_outcome(o),
                    Some(Err(e)) => self.reopen_failed("access", e),
                    None => {}
                }
            }
            if orders.stop && self.lost > 0 {
                self.note(
                    Level::Error,
                    format!(
                        "access log: not written again by the stop, after {} lines lost",
                        self.lost
                    ),
                );
            }
            if let Some(o) = self.daemon.as_mut().map(Out::flush) {
                self.daemon_outcome(o);
            }
            let lines = !batch.items.is_empty();
            batch.clear();
            if orders.stop {
                return;
            }
            if lines {
                // More is likely to come: taken in `LINGER`, as one batch,
                // it costs one wake-up instead of one per pass of the event
                // loop, which does not wake a thread that is not waiting.
                // sleep-ok: batching, by design; no test depends on it.
                std::thread::sleep(LINGER);
            }
        }
    }

    /// Tells in the daemon log of the lines dropped since it last did, if
    /// any, and if `report_every` went by since (or `now`).
    fn report_dropped(&mut self, now: bool) {
        if self.unreported == (0, 0) || !now && self.reported.is_some_and(|t| t.elapsed() < self.report_every) {
            return;
        }
        let (access, daemon) = std::mem::take(&mut self.unreported);
        self.reported = Some(Instant::now());
        if access > 0 {
            self.note(
                Level::Warn,
                format!("{access} access-log lines dropped: the log thread could not keep up"),
            );
        }
        if daemon > 0 {
            self.note(
                Level::Warn,
                format!("{daemon} daemon-log lines dropped: the log thread could not keep up"),
            );
        }
    }

    fn access_line(&mut self, time: Stamp, level: Level, fill: impl FnOnce(&mut Vec<u8>, Option<Stamp>)) {
        if let Some(o) = self
            .access
            .as_mut()
            .map(|out| out.write(time, format::severity(level), &mut self.line, fill))
        {
            self.access_outcome(o);
        }
    }

    /// The access log's lines, as they turn out written or lost (a file's
    /// at its flush, syslog's at once), in order: the first loss of a
    /// streak is told in the daemon log, and its end, at the first line
    /// written after it, with how many lines it lost; a streak the stop
    /// ends, too. Each line is counted once: the lines the daemon log says
    /// lost are those that are not in the access log, whatever the
    /// batches the lines came in (`dest::Outcome`).
    fn access_outcome(&mut self, o: Outcome) {
        if o.written > 0 && self.lost > 0 {
            let m = format!("access log: written again, after {} lines lost", self.lost);
            self.lost = 0;
            self.note(Level::Warn, m);
        }
        if let Some((n, e)) = o.lost {
            if self.lost == 0 {
                self.note(
                    Level::Error,
                    format!("access log: {e}: lines are lost until it can be written"),
                );
            }
            self.lost = self.lost.saturating_add(n);
        }
        if let Some(e) = o.rotation {
            self.note(
                Level::Error,
                format!("access log: cannot rotate it: {e}: still writing to the file it had"),
            );
        }
    }

    /// What became of daemon-log lines written to a file: told on stderr
    /// (the daemon log is what failed).
    fn daemon_outcome(&mut self, o: Outcome) {
        if let Some((n, e)) = o.lost {
            Self::to_stderr(&mut self.line, format!("daemon log: {e}: {n} lines lost").as_bytes());
        }
        if let Some(e) = o.rotation {
            Self::to_stderr(
                &mut self.line,
                format!("daemon log: cannot rotate it: {e}: still writing to the file it had").as_bytes(),
            );
        }
    }

    fn reopen_failed(&mut self, name: &str, e: io::Error) {
        self.note(
            Level::Error,
            format!("{name} log: cannot open it again: {e}: still writing to the file it had"),
        );
    }

    /// The log's own news.
    fn note(&mut self, level: Level, m: String) {
        self.daemon_line(Stamp::now(), Some((level, "logging")), m.as_bytes());
    }

    /// A daemon-log line, with its level and key unless it is raw; to
    /// stderr if it cannot be sent to syslog (a file's lines that cannot
    /// be written are counted on stderr).
    fn daemon_line(&mut self, time: Stamp, head: Option<(Level, &str)>, msg: &[u8]) {
        let Some(out) = &mut self.daemon else { return };
        let fill = |l: &mut Vec<u8>, file: Option<Stamp>| {
            if let Some((level, key)) = head {
                format::daemon_prefix(l, file, level, key);
            }
            l.extend_from_slice(msg);
        };
        let severity = format::severity(head.map_or(Level::Info, |h| h.0));
        let o = out.write(time, severity, &mut self.line, fill);
        let file = matches!(out, Out::File(_));
        if file {
            self.daemon_outcome(o);
        } else if o.lost.is_some() {
            Out::Stderr.write(time, 0, &mut self.line, fill);
        }
    }

    fn to_stderr(line: &mut Vec<u8>, msg: &[u8]) {
        Out::Stderr.write(Stamp::now(), 0, line, |l, _| l.extend_from_slice(msg));
    }
}
