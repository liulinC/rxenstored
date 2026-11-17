// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Where lines go: a file, rotated by line count (`ox/logging.ml:70-108`),
//! syslog (`ox/logging.ml:134-155`), or stderr when the daemon log could
//! not be opened.

use super::format::{self, Stamp};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A syslog daemon that does not read for this long loses the line: the
/// log thread goes on (the queue absorbs the wait meanwhile).
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// `open_out_gen [Open_append; Open_creat] 0o644` at the start and on
/// SIGHUP (`ox/logging.ml:89, 95`), or `open_out` after a rotation (86),
/// which truncates and creates 0o666 (OCaml's `open_out`): both less the
/// umask, and following a symbolic link, as oxenstored's do.
fn open(path: &Path, append: bool) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .mode(if append { 0o644 } else { 0o666 })
        .open(path)
}

/// What became of the lines given to an `Out`, in the order they were
/// given: the first `written` reached it, then the others did not, and are
/// lost. A line is written when all of it, its newline included, reached
/// the destination; one cut short by an error is lost. No line is kept to
/// be tried again: written later, it would have been counted lost too.
#[derive(Debug, Default)]
pub struct Outcome {
    pub written: u64,
    /// How many lines were lost (at least one), and why.
    pub lost: Option<(u64, io::Error)>,
    /// The file could not be rotated: it is still written to, under its
    /// new name if it got one.
    pub rotation: Option<io::Error>,
}

impl Outcome {
    /// One line, written at once.
    fn one(r: io::Result<()>) -> Outcome {
        match r {
            Ok(()) => Outcome {
                written: 1,
                ..Outcome::default()
            },
            Err(e) => Outcome {
                lost: Some((1, e)),
                ..Outcome::default()
            },
        }
    }
}

/// A file's lines are written when this much waits, if not before.
pub const FLUSH_AT: usize = 64 << 10;

/// `make_file_logger` (`ox/logging.ml:88-108`): every line counts; the
/// line after `nb_lines` of them rotates the file. Unlike oxenstored, a
/// rotation does not dump the store (`ox/xenstored.ml:470-473`), and lines
/// are written once per batch (or per `FLUSH_AT`) rather than one by one.
pub struct FileOut {
    path: PathBuf,
    file: File,
    nb_files: i64,
    nb_lines: i64,
    nb_chars: i64,
    count: i64,
    /// The lines taken since the last flush, and where each ends in `buf`.
    buf: Vec<u8>,
    ends: Vec<usize>,
    /// The file ends in a line an error cut short: the next line written
    /// starts on a line of its own.
    torn: bool,
}

impl FileOut {
    pub fn open(path: &Path, nb_files: i64, nb_lines: i64, nb_chars: i64) -> io::Result<FileOut> {
        Ok(FileOut {
            path: path.into(),
            file: open(path, true)?,
            nb_files,
            nb_lines,
            nb_chars,
            count: 0,
            buf: Vec::new(),
            ends: Vec::new(),
            torn: false,
        })
    }

    /// Takes `line`, cut to `nb_chars` if that is positive, then a newline,
    /// to be written at the next `flush`. Returns what became of the lines
    /// written now, if any: when the line rotates the file (the lines
    /// before the rotation, this one included, go to the old file) or
    /// `FLUSH_AT` is reached.
    pub fn write(&mut self, line: &mut Vec<u8>) -> Outcome {
        format::truncate(line, self.nb_chars);
        line.push(b'\n');
        self.buf.extend_from_slice(line);
        self.ends.push(self.buf.len());
        self.count += 1;
        if self.count > self.nb_lines {
            self.rotate()
        } else if self.buf.len() >= FLUSH_AT {
            self.flush()
        } else {
            Outcome::default()
        }
    }

    fn numbered(&self, n: i64) -> PathBuf {
        let mut p = OsString::from(&self.path);
        p.push(format!(".{n}"));
        p.into()
    }

    /// `log_rotate` (`ox/logging.ml:70-86`): the lines taken are written,
    /// then `<file>.<n-1>` becomes `<file>.<n>`, the oldest first, and
    /// `<file>` becomes `<file>.1`, for the files there are, keeping
    /// `nb_files - 1` old ones; then `<file>` starts empty. The chain stops
    /// at the first file missing. If the renames or the new file fail, the
    /// file in use stays in use, and the next try is `nb_lines` lines later.
    fn rotate(&mut self) -> Outcome {
        let mut out = self.flush();
        self.count = 0;
        out.rotation = self.renew().err();
        out
    }

    fn renew(&mut self) -> io::Result<()> {
        let mut moves = Vec::new();
        for n in 1..self.nb_files {
            let from = if n == 1 {
                self.path.clone()
            } else {
                self.numbered(n - 1)
            };
            if !from.exists() {
                break;
            }
            moves.push((from, self.numbered(n)));
        }
        for (from, to) in moves.iter().rev() {
            fs::rename(from, to)?;
        }
        self.file = open(&self.path, false)?;
        self.torn = false;
        Ok(())
    }

    /// SIGHUP (`restart`, `ox/logging.ml:94-96`): the file is opened again
    /// by name, appended to; the count goes on. The lines taken before are
    /// written to the old file, and what became of them is returned. If the
    /// file cannot be opened, the old one stays, and the lines wait.
    pub fn reopen(&mut self) -> io::Result<Outcome> {
        let file = open(&self.path, true)?;
        let out = self.flush();
        self.file = file;
        Ok(out)
    }

    /// Writes the lines taken; at the first error, those not written yet
    /// are dropped and counted (`Outcome`).
    pub fn flush(&mut self) -> Outcome {
        let out = put(&mut self.file, &self.buf, &self.ends, &mut self.torn);
        self.buf.clear();
        self.ends.clear();
        out
    }
}

impl Drop for FileOut {
    /// The log thread flushes before it ends: this is for a `FileOut`
    /// dropped with lines taken.
    fn drop(&mut self) {
        self.flush();
    }
}

/// Writes `buf`, lines that end at `ends`, to `w` (after a newline if
/// `w` ends `torn`), until all of it is written or an error. A line is
/// written if all of it was; `torn` is then whether `w` ends in a line cut
/// short.
pub fn put(w: &mut impl Write, buf: &[u8], ends: &[usize], torn: &mut bool) -> Outcome {
    let mut error = None;
    if *torn && !ends.is_empty() {
        match w.write_all(b"\n") {
            Ok(()) => *torn = false,
            Err(e) => error = Some(e),
        }
    }
    let mut done = 0;
    while error.is_none() && done < buf.len() {
        match w.write(buf.get(done..).unwrap_or_default()) {
            Ok(0) => error = Some(io::ErrorKind::WriteZero.into()),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => error = Some(e),
        }
    }
    let written = ends.iter().take_while(|&&end| end <= done).count();
    let last = written.checked_sub(1).and_then(|i| ends.get(i)).copied().unwrap_or(0);
    *torn |= done > last;
    let lost = ends.len().saturating_sub(written) as u64;
    Outcome {
        written: written as u64,
        lost: error.filter(|_| lost > 0).map(|e| (lost, e)),
        rotation: None,
    }
}

/// `make_syslog_logger` (`ox/logging.ml:134-155`): one datagram per line
/// to the local syslog socket, as glibc's `syslog(3)` sends it (connected
/// at the first line, connected again once if a send fails).
pub struct SyslogOut {
    path: PathBuf,
    sock: Option<UnixDatagram>,
    facility: u8,
    ident: String,
    buf: Vec<u8>,
    /// The minute the offset is for, and the offset from UTC.
    zone: (i64, i64),
    /// The header of the last line, and the priority and local second it
    /// is for: the lines of a second share it.
    header: Vec<u8>,
    header_for: (u8, i64),
}

impl SyslogOut {
    pub fn new(path: &Path, facility: u8, ident: &str) -> SyslogOut {
        SyslogOut {
            path: path.into(),
            sock: None,
            facility,
            ident: ident.into(),
            buf: Vec::new(),
            zone: (i64::MIN, 0),
            header: Vec::new(),
            header_for: (0, i64::MIN),
        }
    }

    /// `stub_syslog` (`ox/syslog_stubs.c:36-71`): the message up to its
    /// first NUL, one datagram per line, none for an empty last line;
    /// `time` stamps the header.
    pub fn send(&mut self, severity: u8, time: Stamp, msg: &[u8]) -> io::Result<()> {
        // Up to the first NUL (`split` gives at least one piece).
        let msg = msg.split(|&c| c == 0).next().unwrap_or_default();
        if msg.is_empty() {
            return Ok(());
        }
        let msg = msg.strip_suffix(b"\n").unwrap_or(msg);
        // The zone can change on a minute only.
        let minute = time.secs.div_euclid(60);
        if self.zone.0 != minute {
            self.zone = (minute, xs_sys::log::utc_offset(time.secs));
        }
        let key = (self.facility | severity, time.secs + self.zone.1);
        if self.header_for != key {
            self.header.clear();
            format::syslog_header(&mut self.header, key.0, key.1, &self.ident);
            self.header_for = key;
        }
        let mut result = Ok(());
        for line in msg.split(|&c| c == b'\n') {
            self.buf.clear();
            self.buf.extend_from_slice(&self.header);
            self.buf.extend_from_slice(line);
            result = result.and(self.send_one());
        }
        result
    }

    /// On the socket kept, if any, else on a new one; if the send fails,
    /// once more on a new one (syslogd went, and came back).
    fn send_one(&mut self) -> io::Result<()> {
        let sock = match self.sock.take() {
            Some(s) => s,
            None => connect(&self.path)?,
        };
        let sock = match sock.send(&self.buf) {
            Ok(_) => sock,
            Err(_) => {
                let again = connect(&self.path)?;
                again.send(&self.buf)?;
                again
            }
        };
        self.sock = Some(sock);
        Ok(())
    }
}

fn connect(path: &Path) -> io::Result<UnixDatagram> {
    let s = UnixDatagram::unbound()?;
    s.connect(path)?;
    s.set_write_timeout(Some(SEND_TIMEOUT))?;
    Ok(s)
}

/// A log's destination, opened.
pub enum Out {
    File(FileOut),
    Syslog(SyslogOut),
    /// The daemon log, when its own could not be opened: `rxenstored: ` and
    /// the syslog form of the line.
    Stderr,
}

impl Out {
    /// Takes one line, which `fill` appends to `line` (cleared first),
    /// given the time if the line is for a file; `severity` for syslog.
    /// syslog and stderr write it at once, a file at its next flush (or
    /// sooner, `FileOut::write`): what became of the lines written now.
    pub fn write(
        &mut self,
        time: Stamp,
        severity: u8,
        line: &mut Vec<u8>,
        fill: impl FnOnce(&mut Vec<u8>, Option<Stamp>),
    ) -> Outcome {
        line.clear();
        match self {
            Out::File(f) => {
                fill(line, Some(time));
                f.write(line)
            }
            Out::Syslog(s) => {
                fill(line, None);
                Outcome::one(s.send(severity, time, line))
            }
            Out::Stderr => {
                line.extend_from_slice(b"rxenstored: ");
                fill(line, None);
                line.push(b'\n');
                Outcome::one(io::stderr().write_all(line))
            }
        }
    }

    /// Writes what a file took; nothing waits in the others.
    pub fn flush(&mut self) -> Outcome {
        match self {
            Out::File(f) => f.flush(),
            _ => Outcome::default(),
        }
    }

    pub fn reopen(&mut self) -> io::Result<Outcome> {
        match self {
            Out::File(f) => f.reopen(),
            _ => Ok(Outcome::default()),
        }
    }
}
