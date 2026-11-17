// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Raw messages: any type, any length, as the harness needs to send
//! malformed ones and to read replies longer than `PAYLOAD_MAX`.

use xs_wire::{MsgType, HEADER_LEN};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Msg {
    pub ty: u32,
    pub req_id: u32,
    pub tx_id: u32,
    pub payload: Vec<u8>,
}

pub const WATCH_EVENT: u32 = MsgType::WatchEvent as u32;
pub const ERROR: u32 = MsgType::Error as u32;

pub fn encode(ty: u32, req_id: u32, tx_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    xs_wire::write_header(&mut out, ty, req_id, tx_id, len);
    out.extend_from_slice(payload);
    out
}

fn word(buf: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = buf.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Takes the first whole message off the front of `buf`, if there is one.
pub fn decode(buf: &mut Vec<u8>) -> Option<Msg> {
    let len = usize::try_from(word(buf, 12)?).ok()?;
    let total = HEADER_LEN.checked_add(len)?;
    if buf.len() < total {
        return None;
    }
    let msg = Msg {
        ty: word(buf, 0)?,
        req_id: word(buf, 4)?,
        tx_id: word(buf, 8)?,
        payload: buf.get(HEADER_LEN..total)?.to_vec(),
    };
    buf.drain(..total);
    Some(msg)
}

/// A message type's name, or its number.
pub fn type_name(ty: u32) -> String {
    match MsgType::from_u32(ty) {
        Some(MsgType::Control) => "CONTROL".into(),
        Some(MsgType::Directory) => "DIRECTORY".into(),
        Some(MsgType::Read) => "READ".into(),
        Some(MsgType::GetPerms) => "GET_PERMS".into(),
        Some(MsgType::Watch) => "WATCH".into(),
        Some(MsgType::Unwatch) => "UNWATCH".into(),
        Some(MsgType::TransactionStart) => "TRANSACTION_START".into(),
        Some(MsgType::TransactionEnd) => "TRANSACTION_END".into(),
        Some(MsgType::Introduce) => "INTRODUCE".into(),
        Some(MsgType::Release) => "RELEASE".into(),
        Some(MsgType::GetDomainPath) => "GET_DOMAIN_PATH".into(),
        Some(MsgType::Write) => "WRITE".into(),
        Some(MsgType::Mkdir) => "MKDIR".into(),
        Some(MsgType::Rm) => "RM".into(),
        Some(MsgType::SetPerms) => "SET_PERMS".into(),
        Some(MsgType::WatchEvent) => "WATCH_EVENT".into(),
        Some(MsgType::Error) => "ERROR".into(),
        Some(MsgType::IsDomainIntroduced) => "IS_DOMAIN_INTRODUCED".into(),
        Some(MsgType::Resume) => "RESUME".into(),
        Some(MsgType::SetTarget) => "SET_TARGET".into(),
        Some(MsgType::ResetWatches) => "RESET_WATCHES".into(),
        Some(MsgType::DirectoryPart) => "DIRECTORY_PART".into(),
        Some(MsgType::GetFeature) => "GET_FEATURE".into(),
        Some(MsgType::SetFeature) => "SET_FEATURE".into(),
        Some(MsgType::GetQuota) => "GET_QUOTA".into(),
        Some(MsgType::SetQuota) => "SET_QUOTA".into(),
        None => format!("TYPE_{ty}"),
    }
}

/// Bytes as a Rust byte-string literal body: printable ASCII as is, the
/// rest escaped; long runs of one byte shortened.
pub fn show(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let run = bytes.get(i..).map_or(0, |r| r.iter().take_while(|&&c| c == b).count());
        if run > 8 {
            out.push_str(&format!("{{{}×{run}}}", show(&[b])));
            i += run;
            continue;
        }
        match b {
            b'\0' => out.push_str("\\0"),
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode() {
        let mut buf = encode(2, 7, 9, b"/a\0");
        buf.extend_from_slice(&encode(15, 0, 0, b"x")[..10]);
        let m = decode(&mut buf).unwrap();
        assert_eq!((m.ty, m.req_id, m.tx_id, &m.payload[..]), (2, 7, 9, &b"/a\0"[..]));
        assert_eq!(decode(&mut buf), None);
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn show_escapes_and_shortens() {
        assert_eq!(show(b"/a\0\x01"), "/a\\0\\x01");
        assert_eq!(show(&[b'x'; 20]), "{x×20}");
    }
}
