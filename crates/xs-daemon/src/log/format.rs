// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Lines as oxenstored 4.17 writes them (`ox/logging.ml`), and the syslog
//! datagram as glibc's `syslog(3)` sends it, which is what oxenstored's
//! stub calls (`ox/syslog_stubs.c:36-71`).

use super::Level;
use std::io::Write;
use xs_core::log::{Op, Who};

/// A time, from the epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Stamp {
    pub fn now() -> Stamp {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Stamp {
            secs: d.as_secs() as i64,
            nanos: d.subsec_nanos(),
        }
    }
}

/// Year, month (1-12), day (1-31) of a day counted from 1970-01-01
/// (H. Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Date and time of day of `secs`.
fn split(secs: i64) -> ((i64, u32, u32), (i64, i64, i64)) {
    let t = secs.rem_euclid(86_400);
    (civil(secs.div_euclid(86_400)), (t / 3600, t / 60 % 60, t % 60))
}

/// The decimal digits of `n`.
fn number(out: &mut Vec<u8>, n: u64) {
    // u64::MAX has 20 digits: filled from the end.
    let mut digits = [0u8; 20];
    let mut len = 0;
    let mut n = n;
    for d in digits.iter_mut().rev() {
        *d = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(digits.len() - len..).unwrap_or_default());
}

/// `n` (below 100) as two digits.
fn two(out: &mut Vec<u8>, n: i64) {
    out.extend_from_slice(&[b'0' + (n / 10) as u8, b'0' + (n % 10) as u8]);
}

/// `string_of_date` (`ox/logging.ml:124-131`): `20200123T12:34:56.512Z`,
/// UTC, milliseconds truncated. (Written digit by digit: it starts every
/// line of a file.)
pub fn date(out: &mut Vec<u8>, t: Stamp) {
    let ((y, mo, d), (h, mi, s)) = split(t.secs);
    match u64::try_from(y) {
        Ok(y) => number(out, y),
        Err(_) => {
            let _ = write!(out, "{y}");
        }
    }
    two(out, mo.into());
    two(out, d.into());
    out.push(b'T');
    two(out, h);
    out.push(b':');
    two(out, mi);
    out.push(b':');
    two(out, s);
    let ms = t.nanos / 1_000_000;
    out.extend_from_slice(&[
        b'.',
        b'0' + (ms / 100 % 10) as u8,
        b'0' + (ms / 10 % 10) as u8,
        b'0' + (ms % 10) as u8,
        b'Z',
    ]);
}

/// `sanitize_data` (`ox/logging.ml:258-263`): NUL becomes a space, then
/// OCaml's `String.escaped`: `\"`, `\\`, `\n`, `\t`, `\r`, `\b`, printable
/// ASCII as it is, any other byte as `\ddd` in decimal.
pub fn escape(out: &mut Vec<u8>, data: &[u8]) {
    let mut rest = data;
    // Paths and values are mostly bytes kept as they are: copied by runs.
    while let Some((run, [c, tail @ ..])) = rest
        .iter()
        .position(|&c| !matches!(c, b' '..=b'~') || c == b'"' || c == b'\\')
        .and_then(|i| rest.split_at_checked(i))
    {
        out.extend_from_slice(run);
        let c = *c;
        rest = tail;
        match c {
            0 => out.push(b' '),
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', c]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\r' => out.extend_from_slice(b"\\r"),
            8 => out.extend_from_slice(b"\\b"),
            _ => out.extend_from_slice(&[b'\\', b'0' + c / 100, b'0' + c / 10 % 10, b'0' + c % 10]),
        }
    }
    out.extend_from_slice(rest);
}

/// `string_of_access_type` (`ox/logging.ml:212-253`). A request type is
/// read as `Xb.Op.of_cval` reads it (`xb/op.ml:24-36`): 20 and anything
/// past RESET_WATCHES is `invalid`, except DIRECTORY_PART, which rxenstored
/// serves (oxenstored 4.17 does not know it).
pub fn op_name(op: Op) -> &'static str {
    match op {
        Op::Request(ty) => match ty {
            0 => "debug    ",
            1 | 22 => "directory",
            2 => "read     ",
            3 => "getperms ",
            4 => "watch    ",
            5 => "unwatch  ",
            6 => "t start  ",
            7 => "t end    ",
            8 => "introduce",
            9 => "release  ",
            10 => "getdomain",
            11 => "write    ",
            12 => "mkdir    ",
            13 => "rm       ",
            14 => "setperms ",
            15 => "w event  ",
            16 => "error    ",
            17 => "is introduced",
            18 => "resume   ",
            19 => "settarget",
            21 => "reset watches",
            _ => "invalid  ",
        },
        Op::Error => "error    ",
        Op::Event => "w event  ",
        Op::NotFired => "w notfired",
        Op::Start => "t start  ",
        Op::End => "t end    ",
        Op::Commit => "commit   ",
        Op::Conflict => "conflict ",
        Op::NewConn => "newconn  ",
        Op::EndConn => "endconn  ",
        Op::Print => "debug    ",
    }
}

/// The level oxenstored logs each kind of line at: what syslog gets as
/// its severity (`ox/logging.ml:303-344`).
pub fn op_level(op: Op) -> Level {
    match op {
        Op::Request(_) | Op::Event | Op::NotFired | Op::Print => Level::Info,
        Op::Error => Level::Warn,
        _ => Level::Debug,
    }
}

/// The start of every line of a file (`ox/logging.ml:36-44`); a syslog
/// line has none.
fn file_prefix(out: &mut Vec<u8>, file: Option<Stamp>) {
    if let Some(t) = file {
        out.push(b'[');
        date(out, t);
        out.extend_from_slice(b"] ");
    }
}

/// `access_logging` (`ox/logging.ml:212-215, 289-301`): `<prefix> <con> <op> <data>`,
/// the connection, and `.<tid>` if in a transaction, padded to 12
/// (`string_of_tid`). `file`: the time, for a file.
pub fn access_line(out: &mut Vec<u8>, file: Option<Stamp>, who: Who, tid: u32, op: Op, data: &[u8]) {
    file_prefix(out, file);
    out.push(b' ');
    let start = out.len();
    match (op, who) {
        (Op::Print, _) => out.extend_from_slice(b"=======>"),
        (_, Who::Socket(n)) => {
            out.push(b'A');
            number(out, n);
        }
        (_, Who::Domain(d)) => {
            out.push(b'D');
            number(out, d.into());
        }
    }
    if tid != 0 {
        out.push(b'.');
        number(out, tid.into());
    }
    columns(out, start, op_name(op), data);
}

/// After the connection, which started at `start`: its padding to 12, the
/// operation and the data.
fn columns(out: &mut Vec<u8>, start: usize, op: &str, data: &[u8]) {
    let pad = (start + 12).saturating_sub(out.len());
    out.resize(out.len() + pad, b' ');
    out.push(b' ');
    out.extend_from_slice(op.as_bytes());
    out.push(b' ');
    escape(out, data);
}

/// An access line with these columns.
pub fn line(out: &mut Vec<u8>, file: Option<Stamp>, con: &str, op: &str, data: &[u8]) {
    file_prefix(out, file);
    out.push(b' ');
    let start = out.len();
    out.extend_from_slice(con.as_bytes());
    columns(out, start, op, data);
}

/// `truncate_line` (`ox/logging.ml:60-68`), applied by the file logger
/// when the limit is positive: a line of more than `nb_chars - 1` bytes
/// keeps `max(nb_chars - 1, 2) - 2` of them and ends with `..`.
pub fn truncate(line: &mut Vec<u8>, nb_chars: i64) {
    if nb_chars > 0 && line.len() as i64 > nb_chars - 1 {
        let len = (nb_chars - 1).max(2) as usize;
        line.truncate(len - 2);
        line.extend_from_slice(b"..");
    }
}

/// `string_of_level` padded as `%5s` does.
fn level_name(l: Level) -> &'static str {
    match l {
        Level::Debug => "debug",
        Level::Info => " info",
        Level::Warn => " warn",
        Level::Error => "error",
        Level::Null => " null",
    }
}

/// The prefix of a daemon-log message (`ox/logging.ml:36-49, 187-193`):
/// `[<date>|<level>|<key>] ` in a file, `[<key>] ` for syslog.
pub fn daemon_prefix(out: &mut Vec<u8>, file: Option<Stamp>, level: Level, key: &str) {
    match file {
        Some(t) => {
            out.push(b'[');
            date(out, t);
            let _ = write!(out, "|{}|{key}] ", level_name(level));
        }
        None => {
            let _ = write!(out, "[{key}] ");
        }
    }
}

/// The syslog severity of a level (`ox/logging.ml:145-154`).
pub fn severity(l: Level) -> u8 {
    match l {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug | Level::Null => 7,
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// What glibc's `syslog(3)` puts before a message on `/dev/log`
/// (misc/syslog.c): `<PRI>` then the local time as `%h %e %T `, then the
/// program name and `: ` (oxenstored calls no `openlog`: no pid, the
/// default tag). `local` is the local time, as seconds from the epoch.
/// Nothing follows the message on a datagram socket.
pub fn syslog_header(out: &mut Vec<u8>, pri: u8, local: i64, ident: &str) {
    let ((_, mo, d), (h, mi, s)) = split(local);
    out.push(b'<');
    number(out, pri.into());
    out.push(b'>');
    // `split` gives a month from 1 to 12.
    out.extend_from_slice(
        MONTHS
            .get((mo as usize).wrapping_sub(1))
            .copied()
            .unwrap_or_default()
            .as_bytes(),
    );
    out.push(b' ');
    if d < 10 {
        out.extend_from_slice(&[b' ', b'0' + d as u8]);
    } else {
        two(out, d.into());
    }
    out.push(b' ');
    two(out, h);
    out.push(b':');
    two(out, mi);
    out.push(b':');
    two(out, s);
    out.push(b' ');
    out.extend_from_slice(ident.as_bytes());
    out.extend_from_slice(b": ");
}
