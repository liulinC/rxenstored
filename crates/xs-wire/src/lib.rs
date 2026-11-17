// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Xenstore wire format (`xen/include/public/io/xs_wire.h`): a 16-byte
//! little-endian header followed by at most 4096 bytes of payload.
//!
//! `no_std` (`core` and `alloc` only) but in its own test build, so that
//! `xs-core`, which depends on it, can be built for a stub domain
//! (`scripts/nostd.sh` checks it).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// The no-panic lints of Cargo.toml are for code that is not a test; this
// crate's test build (unit tests) may unwrap, index and panic.
#![cfg_attr(
    test,
    allow(
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
    )
)]

// `vec!` and `format!` in every module, as std's prelude gives them: also
// in the code cargo-mutants writes (a `Vec` result replaced by `vec![]`),
// which would otherwise not build in the no_std library and go untested.
#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

pub const HEADER_LEN: usize = 16;
pub const PAYLOAD_MAX: usize = 4096;

/// Message types, with their wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MsgType {
    Control = 0,
    Directory = 1,
    Read = 2,
    GetPerms = 3,
    Watch = 4,
    Unwatch = 5,
    TransactionStart = 6,
    TransactionEnd = 7,
    Introduce = 8,
    Release = 9,
    GetDomainPath = 10,
    Write = 11,
    Mkdir = 12,
    Rm = 13,
    SetPerms = 14,
    WatchEvent = 15,
    Error = 16,
    IsDomainIntroduced = 17,
    Resume = 18,
    SetTarget = 19,
    // 20 was XS_RESTRICT, removed from the protocol.
    ResetWatches = 21,
    DirectoryPart = 22,
    GetFeature = 23,
    SetFeature = 24,
    GetQuota = 25,
    SetQuota = 26,
}

impl MsgType {
    pub const ALL: [MsgType; 26] = [
        MsgType::Control,
        MsgType::Directory,
        MsgType::Read,
        MsgType::GetPerms,
        MsgType::Watch,
        MsgType::Unwatch,
        MsgType::TransactionStart,
        MsgType::TransactionEnd,
        MsgType::Introduce,
        MsgType::Release,
        MsgType::GetDomainPath,
        MsgType::Write,
        MsgType::Mkdir,
        MsgType::Rm,
        MsgType::SetPerms,
        MsgType::WatchEvent,
        MsgType::Error,
        MsgType::IsDomainIntroduced,
        MsgType::Resume,
        MsgType::SetTarget,
        MsgType::ResetWatches,
        MsgType::DirectoryPart,
        MsgType::GetFeature,
        MsgType::SetFeature,
        MsgType::GetQuota,
        MsgType::SetQuota,
    ];

    pub fn from_u32(v: u32) -> Option<MsgType> {
        MsgType::ALL.into_iter().find(|t| *t as u32 == v)
    }
}

/// Error names a daemon puts in an `ERROR` reply (`xs_wire.h:63-78`), plus
/// `EQUOTA`, which oxenstored sends although it is not in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Errno {
    EINVAL,
    EACCES,
    EEXIST,
    EISDIR,
    ENOENT,
    ENOMEM,
    ENOSPC,
    EIO,
    ENOTEMPTY,
    ENOSYS,
    EROFS,
    EBUSY,
    EAGAIN,
    EISCONN,
    E2BIG,
    EPERM,
    EQUOTA,
}

impl Errno {
    pub const ALL: [Errno; 17] = [
        Errno::EINVAL,
        Errno::EACCES,
        Errno::EEXIST,
        Errno::EISDIR,
        Errno::ENOENT,
        Errno::ENOMEM,
        Errno::ENOSPC,
        Errno::EIO,
        Errno::ENOTEMPTY,
        Errno::ENOSYS,
        Errno::EROFS,
        Errno::EBUSY,
        Errno::EAGAIN,
        Errno::EISCONN,
        Errno::E2BIG,
        Errno::EPERM,
        Errno::EQUOTA,
    ];

    /// The name as sent on the wire, without the terminating NUL.
    pub fn name(self) -> &'static str {
        match self {
            Errno::EINVAL => "EINVAL",
            Errno::EACCES => "EACCES",
            Errno::EEXIST => "EEXIST",
            Errno::EISDIR => "EISDIR",
            Errno::ENOENT => "ENOENT",
            Errno::ENOMEM => "ENOMEM",
            Errno::ENOSPC => "ENOSPC",
            Errno::EIO => "EIO",
            Errno::ENOTEMPTY => "ENOTEMPTY",
            Errno::ENOSYS => "ENOSYS",
            Errno::EROFS => "EROFS",
            Errno::EBUSY => "EBUSY",
            Errno::EAGAIN => "EAGAIN",
            Errno::EISCONN => "EISCONN",
            Errno::E2BIG => "E2BIG",
            Errno::EPERM => "EPERM",
            Errno::EQUOTA => "EQUOTA",
        }
    }

    #[cfg(test)]
    pub fn from_name(name: &[u8]) -> Option<Errno> {
        Errno::ALL.into_iter().find(|e| e.name().as_bytes() == name)
    }
}

/// Appends a header to `out`. Unlike [`Message::new`] it does not enforce
/// `PAYLOAD_MAX`: oxenstored sends larger replies on sockets.
pub fn write_header(out: &mut Vec<u8>, ty: u32, req_id: u32, tx_id: u32, len: u32) {
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&req_id.to_le_bytes());
    out.extend_from_slice(&tx_id.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The header announces, or the caller supplied, more than `PAYLOAD_MAX` bytes.
    PayloadTooLarge(usize),
    /// The decoder's position is past the bytes it holds: its own state is
    /// broken, framing is lost.
    Desync,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            WireError::PayloadTooLarge(n) => {
                write!(f, "payload of {n} bytes exceeds the {PAYLOAD_MAX}-byte limit")
            }
            WireError::Desync => write!(f, "decoder position past its buffer"),
        }
    }
}

impl core::error::Error for WireError {}

/// One message. `ty` is kept raw so that an unknown type can still be
/// answered with an error instead of breaking the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub ty: u32,
    pub req_id: u32,
    pub tx_id: u32,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(ty: MsgType, req_id: u32, tx_id: u32, payload: Vec<u8>) -> Result<Message, WireError> {
        if payload.len() > PAYLOAD_MAX {
            return Err(WireError::PayloadTooLarge(payload.len()));
        }
        Ok(Message {
            ty: ty as u32,
            req_id,
            tx_id,
            payload,
        })
    }

    pub fn msg_type(&self) -> Option<MsgType> {
        MsgType::from_u32(self.ty)
    }

    /// Appends header and payload to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.reserve(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.ty.to_le_bytes());
        out.extend_from_slice(&self.req_id.to_le_bytes());
        out.extend_from_slice(&self.tx_id.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
    }

    /// The NUL-separated fields of the payload. One trailing NUL is a
    /// terminator, not an empty last field.
    pub fn fields(&self) -> Vec<&[u8]> {
        if self.payload.is_empty() {
            return vec![];
        }
        let body = self.payload.strip_suffix(&[0]).unwrap_or(&self.payload);
        body.split(|b| *b == 0).collect()
    }
}

/// Builds a payload from fields, each followed by a NUL.
pub fn nul_terminated(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 1).sum());
    for f in fields {
        out.extend_from_slice(f);
        out.push(0);
    }
    out
}

/// Incremental decoder for a byte stream of messages.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    pos: usize,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        match self.buf.get(self.pos..) {
            Some([]) => {
                self.buf.clear();
                self.pos = 0;
            }
            // `get` succeeded, so `pos <= buf.len()`: the drain is in bounds.
            Some(_) if self.pos > 64 * 1024 => {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            // Bytes left to decode below the threshold; or a position past
            // the end, which `next_message` reports.
            _ => {}
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete message, `None` if more bytes are needed.
    /// After an error the stream is unusable: framing is lost.
    pub fn next_message(&mut self) -> Result<Option<Message>, WireError> {
        let avail = self.buf.get(self.pos..).ok_or(WireError::Desync)?;
        let Some((header, rest)) = avail.split_first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let [t0, t1, t2, t3, r0, r1, r2, r3, x0, x1, x2, x3, l0, l1, l2, l3] = *header;
        let len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
        if len > PAYLOAD_MAX {
            return Err(WireError::PayloadTooLarge(len));
        }
        let Some(payload) = rest.get(..len) else {
            return Ok(None);
        };
        let msg = Message {
            ty: u32::from_le_bytes([t0, t1, t2, t3]),
            req_id: u32::from_le_bytes([r0, r1, r2, r3]),
            tx_id: u32::from_le_bytes([x0, x1, x2, x3]),
            payload: payload.to_vec(),
        };
        // At most `avail.len()`: `pos` never passes the end of `buf`.
        self.pos += HEADER_LEN + len;
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_values_match_xs_wire_h() {
        assert_eq!(MsgType::Control as u32, 0);
        assert_eq!(MsgType::Write as u32, 11);
        assert_eq!(MsgType::WatchEvent as u32, 15);
        assert_eq!(MsgType::Error as u32, 16);
        assert_eq!(MsgType::SetTarget as u32, 19);
        assert_eq!(MsgType::ResetWatches as u32, 21);
        assert_eq!(MsgType::SetQuota as u32, 26);
    }

    #[test]
    fn from_u32_round_trips_and_rejects_gaps() {
        for t in MsgType::ALL {
            assert_eq!(MsgType::from_u32(t as u32), Some(t));
        }
        assert_eq!(MsgType::from_u32(20), None);
        assert_eq!(MsgType::from_u32(27), None);
        assert_eq!(MsgType::from_u32(0xffff), None);
    }

    #[test]
    fn encode_layout_is_little_endian() {
        let m = Message::new(MsgType::Write, 0x01020304, 7, b"a\0b".to_vec()).unwrap();
        let mut out = Vec::new();
        m.encode_into(&mut out);
        assert_eq!(out, [11, 0, 0, 0, 4, 3, 2, 1, 7, 0, 0, 0, 3, 0, 0, 0, b'a', 0, b'b']);
    }

    #[test]
    fn new_enforces_payload_limit() {
        assert!(Message::new(MsgType::Write, 0, 0, vec![0; PAYLOAD_MAX]).is_ok());
        assert_eq!(
            Message::new(MsgType::Write, 0, 0, vec![0; PAYLOAD_MAX + 1]),
            Err(WireError::PayloadTooLarge(PAYLOAD_MAX + 1))
        );
        assert!(WireError::PayloadTooLarge(5000).to_string().contains("5000"));
    }

    #[test]
    fn fields_split_on_nul() {
        let f = |p: &[u8]| {
            let m = Message {
                ty: 0,
                req_id: 0,
                tx_id: 0,
                payload: p.to_vec(),
            };
            m.fields().iter().map(|x| x.to_vec()).collect::<Vec<_>>()
        };
        assert!(f(b"").is_empty());
        assert_eq!(f(b"OK\0"), [b"OK".to_vec()]);
        assert_eq!(f(b"/a\0tok\0"), [b"/a".to_vec(), b"tok".to_vec()]);
        assert_eq!(f(b"/a\0\0"), [b"/a".to_vec(), b"".to_vec()]);
        assert_eq!(f(b"/a\0value"), [b"/a".to_vec(), b"value".to_vec()]);
        assert_eq!(f(b"\0"), [b"".to_vec()]);
    }

    #[test]
    fn nul_terminated_joins_fields() {
        assert_eq!(nul_terminated(&[b"/a", b"t"]), b"/a\0t\0");
        assert_eq!(nul_terminated(&[]), b"");
    }

    #[test]
    fn msg_type_of_unknown_is_none() {
        let m = Message {
            ty: 99,
            req_id: 0,
            tx_id: 0,
            payload: vec![],
        };
        assert_eq!(m.msg_type(), None);
        let m = Message::new(MsgType::Read, 0, 0, vec![]).unwrap();
        assert_eq!(m.msg_type(), Some(MsgType::Read));
    }

    #[test]
    fn decoder_handles_any_split() {
        let msgs = [
            Message::new(MsgType::Read, 1, 0, b"/a\0".to_vec()).unwrap(),
            Message::new(MsgType::Watch, 2, 0, vec![]).unwrap(),
            Message::new(MsgType::Write, 3, 9, vec![b'x'; PAYLOAD_MAX]).unwrap(),
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            m.encode_into(&mut stream);
        }
        for chunk in [1, 2, 15, 16, 17, 100, stream.len()] {
            let mut d = Decoder::new();
            let mut got = Vec::new();
            for part in stream.chunks(chunk) {
                d.push(part);
                while let Some(m) = d.next_message().unwrap() {
                    got.push(m);
                    // A decoder that does not advance must fail here, not
                    // fill the memory.
                    assert!(got.len() <= msgs.len(), "chunk size {chunk}: too many messages");
                }
            }
            assert_eq!(got, msgs, "chunk size {chunk}");
            assert_eq!(d.next_message(), Ok(None));
        }
    }

    #[test]
    fn decoder_compacts_a_long_stream() {
        let m = Message::new(MsgType::Write, 1, 0, vec![b'y'; 1000]).unwrap();
        let mut one = Vec::new();
        m.encode_into(&mut one);
        let mut d = Decoder::new();
        // Leave a partial message behind each time so the buffer is never
        // empty at push time, and cross the 64 KiB compaction threshold.
        let mut pending = Vec::new();
        let mut count = 0;
        for _ in 0..200 {
            pending.extend_from_slice(&one);
            let cut = pending.len() - 10;
            d.push(&pending[..cut]);
            pending.drain(..cut);
            while let Some(got) = d.next_message().unwrap() {
                assert_eq!(got, m);
                count += 1;
            }
        }
        assert_eq!(count, 199);
        assert!(d.buf.len() < 80 * 1024);
    }

    #[test]
    fn decoder_compacts_only_past_64k() {
        // 4096 bytes per message: 16 of them end exactly at 64 KiB.
        let m = Message::new(MsgType::Write, 1, 0, vec![b'z'; PAYLOAD_MAX - HEADER_LEN]).unwrap();
        let mut stream = Vec::new();
        for _ in 0..18 {
            m.encode_into(&mut stream);
        }
        let mut d = Decoder::new();
        d.push(&stream);
        let take = |d: &mut Decoder, n: usize| {
            for _ in 0..n {
                assert_eq!(d.next_message(), Ok(Some(m.clone())));
            }
        };
        // Below the threshold the consumed prefix stays.
        take(&mut d, 1);
        d.push(&[]);
        assert_eq!((d.pos, d.buf.len()), (4096, stream.len()));
        // At the threshold exactly, still.
        take(&mut d, 15);
        d.push(&[]);
        assert_eq!((d.pos, d.buf.len()), (64 * 1024, stream.len()));
        // Past it, the prefix goes and the rest is intact.
        take(&mut d, 1);
        d.push(&[]);
        assert_eq!((d.pos, d.buf.len()), (0, 4096));
        take(&mut d, 1);
        assert_eq!(d.next_message(), Ok(None));
    }

    #[test]
    fn encode_reserves_what_it_writes() {
        let m = Message::new(MsgType::Write, 0, 0, vec![0; PAYLOAD_MAX]).unwrap();
        let mut out = Vec::new();
        m.encode_into(&mut out);
        assert_eq!(out.len(), HEADER_LEN + PAYLOAD_MAX);
        // One reservation of the right size: no growth by doubling, no
        // over-reservation.
        assert!(out.capacity() < 2 * out.len(), "capacity {}", out.capacity());
    }

    #[test]
    fn decoder_rejects_oversized_length() {
        let mut d = Decoder::new();
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&2u32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&((PAYLOAD_MAX + 1) as u32).to_le_bytes());
        d.push(&hdr);
        assert_eq!(d.next_message(), Err(WireError::PayloadTooLarge(PAYLOAD_MAX + 1)));
    }

    #[test]
    fn decoder_starts_over_once_everything_is_consumed() {
        let mut one = Vec::new();
        Message::new(MsgType::Read, 1, 0, b"/a\0".to_vec())
            .unwrap()
            .encode_into(&mut one);
        let mut d = Decoder::new();
        d.push(&one);
        assert!(d.next_message().unwrap().is_some());
        d.push(b"x");
        assert_eq!((d.pos, d.buf.len()), (0, 1));
    }

    #[test]
    fn a_decoder_whose_position_is_past_its_bytes_reports_lost_framing() {
        // Not reachable through `push` and `next_message`; were it ever, the
        // stream is reported broken instead of the daemon panicking.
        let mut d = Decoder {
            buf: vec![0; 4],
            pos: 100,
        };
        assert_eq!(d.next_message(), Err(WireError::Desync));
        d.push(b"more");
        assert_eq!(d.next_message(), Err(WireError::Desync));
        assert_eq!(WireError::Desync.to_string(), "decoder position past its buffer");
    }

    #[test]
    fn errno_names_round_trip() {
        for e in Errno::ALL {
            assert_eq!(Errno::from_name(e.name().as_bytes()), Some(e));
        }
        assert_eq!(Errno::ENOENT.name(), "ENOENT");
        assert_eq!(Errno::E2BIG.name(), "E2BIG");
        assert_eq!(Errno::from_name(b"EWHAT"), None);
        let names: std::collections::HashSet<_> = Errno::ALL.iter().map(|e| e.name()).collect();
        assert_eq!(names.len(), Errno::ALL.len());
    }

    #[test]
    fn write_header_matches_encode() {
        let m = Message::new(MsgType::Read, 5, 6, b"/x\0".to_vec()).unwrap();
        let mut a = Vec::new();
        m.encode_into(&mut a);
        let mut b = Vec::new();
        write_header(&mut b, MsgType::Read as u32, 5, 6, 3);
        b.extend_from_slice(b"/x\0");
        assert_eq!(a, b);
        let mut big = Vec::new();
        write_header(&mut big, 1, 0, 0, 10_000);
        assert_eq!(big[12..16], 10_000u32.to_le_bytes());
    }
}
