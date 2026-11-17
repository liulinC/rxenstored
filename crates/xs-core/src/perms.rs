// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Node permissions and access checks (`ox/perms.ml`): an owner, the
//! access of everybody else, and an ACL of `(domid, access)` entries.

use crate::prelude::*;
use xs_wire::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    None,
    Read,
    Write,
    Both,
}

impl Access {
    fn letter(self) -> u8 {
        match self {
            Access::None => b'n',
            Access::Read => b'r',
            Access::Write => b'w',
            Access::Both => b'b',
        }
    }

    fn of_letter(c: u8) -> Option<Access> {
        Some(match c {
            b'n' => Access::None,
            b'r' => Access::Read,
            b'w' => Access::Write,
            b'b' => Access::Both,
            _ => return None,
        })
    }

    /// Does this entry grant `want` (`Read` or `Write`)? (`ox/perms.ml:150-163`)
    fn grants(self, want: Access) -> bool {
        matches!(
            (self, want),
            (Access::Both, _) | (Access::Read, Access::Read) | (Access::Write, Access::Write)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Perms {
    /// A domid, which SET_PERMS gives (`parse_domid`), or -1 once the
    /// owner's domain went, which only the root has (`store::NO_OWNER`):
    /// an OCaml int there, so wider than a domid.
    pub owner: i64,
    pub other: Access,
    pub acl: Vec<(u32, Access)>,
}

/// Who asks: the connection's domain and its SET_TARGET domain, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    pub domid: u32,
    pub target: Option<u32>,
}

impl Caller {
    pub const DOM0: Caller = Caller { domid: 0, target: None };

    /// `Perms.Connection.is_owner`.
    pub fn is_owner(&self, id: i64) -> bool {
        i64::from(self.domid) == id || self.target.map(i64::from) == Some(id)
    }

    /// `Perms.Connection.is_dom0`: domain 0, or acting for it.
    pub fn is_dom0(&self) -> bool {
        self.is_owner(0)
    }
}

/// OCaml's `int_of_string` (`nbits` 63) or `Nativeint.of_string` (64), as
/// the runtime's `parse_intnat` reads a number: an optional sign, an
/// optional `0x`/`0o`/`0b`/`0u` prefix, a digit, then digits and `_`
/// separators. Decimal is signed, from -2^(nbits-1) to 2^(nbits-1) - 1; a
/// prefixed number is unsigned, up to 2^nbits - 1, and may be negated.
/// (An OCaml int then wraps prefixed values from 2^62 to negative ones,
/// which `int_of_string` below does; the protocol's callers accept no
/// value that large either way.)
pub fn ocaml_int(s: &[u8], nbits: u32) -> Option<i64> {
    let (neg, s) = match s {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, s),
    };
    let (radix, signed, digits) = match s {
        [b'0', b'x' | b'X', rest @ ..] => (16, false, rest),
        [b'0', b'o' | b'O', rest @ ..] => (8, false, rest),
        [b'0', b'b' | b'B', rest @ ..] => (2, false, rest),
        [b'0', b'u' | b'U', rest @ ..] => (10, false, rest),
        _ => (10, true, s),
    };
    let (first, rest) = digits.split_first()?;
    let mut v = (*first as char).to_digit(radix)? as u64;
    for &c in rest {
        if c != b'_' {
            let d = (c as char).to_digit(radix)? as u64;
            v = v.checked_mul(radix as u64)?.checked_add(d)?;
        }
    }
    let half = 1u64 << (nbits - 1);
    let fits = match (signed, neg) {
        (true, false) => v < half,
        (true, true) => v <= half,
        (false, _) => nbits == 64 || v < half << 1,
    };
    fits.then(|| if neg { (v as i64).wrapping_neg() } else { v as i64 })
}

/// OCaml's `int_of_string` on a 64-bit host, value included: what
/// `ocaml_int(s, 63)` reads, as the 63-bit OCaml int holds it. A prefixed
/// number from 2^62 wraps to a negative one: `0x4000000000000000` is
/// `min_int`, `0x7fffffffffffffff` is -1 (OCaml's runtime, `parse_intnat`
/// then `Val_long`; the manual says so of `0u`: "If the input exceeds
/// max_int it is converted to the signed integer min_int + input - max_int
/// - 1").
pub fn int_of_string(s: &[u8]) -> Option<i64> {
    ocaml_int(s, 63).map(|v| (v << 1) >> 1)
}

/// A domid as oxenstored reads one (`int_of_string`), if it is one: the
/// negative numbers that OCaml accepts (and oxenstored later prints as huge
/// unsigned ones) are refused.
pub fn parse_domid(s: &[u8]) -> Option<u32> {
    ocaml_int(s, 63).and_then(|v| u32::try_from(v).ok())
}

impl Perms {
    /// What a node created by domain 0 at the root gets (`Perms.Node.default0`).
    pub fn default0() -> Perms {
        Perms {
            owner: 0,
            other: Access::None,
            acl: Vec::new(),
        }
    }

    /// Parses the permission part of a SET_PERMS payload: NUL-separated
    /// entries, of which the last piece (normally the empty string after
    /// the final NUL) is dropped, as `Perms.Node.of_string` does.
    pub fn parse(s: &[u8]) -> Result<Perms, Errno> {
        let mut pieces: Vec<&[u8]> = s.split(|c| *c == 0).collect();
        pieces.pop();
        let mut entries = pieces.into_iter().map(|p| {
            let (&letter, id) = p.split_first().ok_or(Errno::EINVAL)?;
            let access = Access::of_letter(letter).ok_or(Errno::EINVAL)?;
            Ok((parse_domid(id).ok_or(Errno::EINVAL)?, access))
        });
        let (owner, other) = entries.next().ok_or(Errno::EINVAL)??;
        let acl = entries.collect::<Result<Vec<_>, Errno>>()?;
        Ok(Perms {
            owner: owner.into(),
            other,
            acl,
        })
    }

    /// Every entry followed by `sep`, except that the GET_PERMS reply
    /// (`sep` = NUL) also ends with one. Each is its letter and its domid
    /// as `%u` prints an OCaml int (`ox/perms.ml:88-93`): the 63 bits of
    /// the int, unsigned, so the lost owner -1 is 9223372036854775807.
    pub fn encode_sep(&self, sep: &[u8], trailing: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let acl = self.acl.iter().map(|(id, a)| (i64::from(*id), *a));
        for (i, (id, a)) in core::iter::once((self.owner, self.other)).chain(acl).enumerate() {
            if i > 0 {
                out.extend_from_slice(sep);
            }
            out.push(a.letter());
            out.extend_from_slice((id & i64::MAX).to_string().as_bytes());
        }
        if trailing {
            out.extend_from_slice(sep);
        }
        out
    }

    /// The GET_PERMS reply: every entry followed by a NUL.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_sep(b"\0", true)
    }

    /// `Perms.lacks`: true if the caller may not `want` (`Read` or `Write`)
    /// this node. `active` is `perms-activate`. Domain 0 and the owner may
    /// do anything; otherwise the first ACL entry of the caller's domain or
    /// of its target decides, falling back to `other` (`ox/perms.ml:140-169`).
    pub fn lacks(&self, active: bool, caller: &Caller, want: Access) -> bool {
        if !active || caller.is_dom0() || caller.is_owner(self.owner) {
            return false;
        }
        let ids = core::iter::once(caller.domid).chain(caller.target);
        !ids.into_iter().any(|d| {
            let access = self
                .acl
                .iter()
                .find(|(id, _)| *id == d)
                .map(|(_, a)| *a)
                .unwrap_or(self.other);
            access.grants(want)
        })
    }

    /// `Perms.check`: EACCES if the caller lacks `want`.
    pub fn check(&self, active: bool, caller: &Caller, want: Access) -> Result<(), Errno> {
        if self.lacks(active, caller, want) {
            Err(Errno::EACCES)
        } else {
            Ok(())
        }
    }

    /// `Perms.check_owner` (`ox/perms.ml:136-139`).
    pub fn check_owner(&self, active: bool, caller: &Caller) -> Result<(), Errno> {
        if active && !caller.is_dom0() && !caller.is_owner(self.owner) {
            Err(Errno::EACCES)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(d: u32) -> Caller {
        Caller { domid: d, target: None }
    }

    #[test]
    fn parse_and_encode() {
        let p = Perms::parse(b"n0\0r4\0b10000\0").unwrap();
        assert_eq!(
            p,
            Perms {
                owner: 0,
                other: Access::None,
                acl: vec![(4, Access::Read), (10000, Access::Both)]
            }
        );
        assert_eq!(p.encode(), b"n0\0r4\0b10000\0");
        assert_eq!(p.encode_sep(b" ", false), b"n0 r4 b10000");
        assert_eq!(Perms::parse(b"w7\0").unwrap().encode(), b"w7\0");
        assert_eq!(Perms::default0().encode(), b"n0\0");
    }

    #[test]
    fn last_piece_is_dropped_even_without_a_final_nul() {
        assert_eq!(Perms::parse(b"n0\0r4").unwrap().encode(), b"n0\0");
        assert_eq!(Perms::parse(b"r4"), Err(Errno::EINVAL));
    }

    #[test]
    fn invalid_permissions() {
        for bad in [
            &b""[..],
            b"\0",
            b"x0\0",
            b"r\0",
            b"rx\0",
            b"n0\0\0",
            b"r-1\0",
            b"r4294967296\0",
            b"r0x\0",
            b"r_1\0",
        ] {
            assert_eq!(Perms::parse(bad), Err(Errno::EINVAL), "{bad:?}");
        }
    }

    #[test]
    fn domid_syntax() {
        assert_eq!(parse_domid(b"42"), Some(42));
        assert_eq!(parse_domid(b"+42"), Some(42));
        assert_eq!(parse_domid(b"0x2a"), Some(42));
        assert_eq!(parse_domid(b"0o52"), Some(42));
        assert_eq!(parse_domid(b"0b101010"), Some(42));
        assert_eq!(parse_domid(b"0u42"), Some(42));
        assert_eq!(parse_domid(b"4_2"), Some(42));
        assert_eq!(parse_domid(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_domid(b""), None);
        assert_eq!(parse_domid(b"0x"), None);
        assert_eq!(parse_domid(b"9a"), None);
        assert_eq!(parse_domid(b"-0"), Some(0), "minus zero is zero");
        assert_eq!(parse_domid(b"-1"), None);
        assert_eq!(parse_domid(b"4294967296"), None);
    }

    #[test]
    fn ocaml_integers() {
        let i = |s: &str| ocaml_int(s.as_bytes(), 63);
        let n = |s: &str| ocaml_int(s.as_bytes(), 64);
        assert_eq!(i("-42"), Some(-42));
        assert_eq!(i("+0x1F"), Some(31));
        assert_eq!(i("-0x10"), Some(-16), "a prefixed number may be negated");
        assert_eq!(i("0O17"), Some(15));
        assert_eq!(i("0B11"), Some(3));
        assert_eq!(i("0U12"), Some(12));
        assert_eq!(i("1__0"), Some(10));
        for bad in [
            "", "-", "+", "_1", "0x_1", "1 ", " 1", "0x", "12a", "0b2", "0o8", "--1", "1.0",
        ] {
            assert_eq!(i(bad), None, "{bad:?}");
        }
        // Decimal is signed, a prefix makes it unsigned, by width.
        assert_eq!(i("4611686018427387903"), Some((1 << 62) - 1));
        assert_eq!(i("4611686018427387904"), None);
        assert_eq!(i("-4611686018427387904"), Some(-(1 << 62)));
        assert_eq!(i("-4611686018427387905"), None);
        assert_eq!(i("0x7fffffffffffffff"), Some(i64::MAX));
        assert_eq!(i("0x8000000000000000"), None);
        assert_eq!(n("9223372036854775807"), Some(i64::MAX));
        assert_eq!(n("9223372036854775808"), None);
        assert_eq!(n("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(n("0xffffffffffffffff"), Some(-1));
        assert_eq!(n("0x10000000000000000"), None, "beyond 64 bits");
        assert_eq!(n("99999999999999999999"), None);
        assert_eq!(n("0u18446744073709551615"), Some(-1));
        assert_eq!(n("0u18446744073709551616"), None, "the addition overflows");
    }

    #[test]
    fn int_of_string_wraps_as_an_ocaml_int() {
        let i = |s: &str| int_of_string(s.as_bytes());
        assert_eq!(i("12"), Some(12));
        assert_eq!(i("-0x10"), Some(-16));
        assert_eq!(i("4611686018427387903"), Some((1 << 62) - 1), "max_int");
        assert_eq!(i("-4611686018427387904"), Some(-(1 << 62)), "min_int");
        assert_eq!(i("4611686018427387904"), None, "decimal is signed");
        assert_eq!(i("0x3fffffffffffffff"), Some((1 << 62) - 1));
        assert_eq!(i("0x4000000000000000"), Some(-(1 << 62)), "wraps to min_int");
        assert_eq!(i("0u4611686018427387905"), Some(-(1 << 62) + 1));
        assert_eq!(i("0x7fffffffffffffff"), Some(-1));
        assert_eq!(i("-0x7fffffffffffffff"), Some(1));
        assert_eq!(i("0x8000000000000000"), None, "beyond 63 bits");
    }

    #[test]
    fn access_rules() {
        use Access::*;
        // Owner 5, others write-only, 6 may read, 7 may not, 8 both.
        let p = Perms::parse(b"w5\0r6\0n7\0b8\0").unwrap();
        for want in [Read, Write] {
            assert!(!p.lacks(true, &Caller::DOM0, want), "domain 0");
            assert!(!p.lacks(true, &dom(5), want), "owner");
            assert!(!p.lacks(true, &dom(8), want), "both");
            assert!(p.lacks(true, &dom(7), want), "none");
            assert!(!p.lacks(false, &dom(7), want), "perms-activate off");
        }
        assert!(!p.lacks(true, &dom(6), Read));
        assert!(p.lacks(true, &dom(6), Write));
        assert!(p.lacks(true, &dom(9), Read), "other is write-only");
        assert!(!p.lacks(true, &dom(9), Write));
        // The first matching entry decides.
        let dup = Perms::parse(b"n0\0r3\0w3\0").unwrap();
        assert!(dup.lacks(true, &dom(3), Write));
        // Through the target domain.
        let t = Caller {
            domid: 9,
            target: Some(6),
        };
        assert!(!p.lacks(true, &t, Read));
        assert!(Caller {
            domid: 3,
            target: Some(0)
        }
        .is_dom0());
        assert!(
            !p.lacks(
                true,
                &Caller {
                    domid: 3,
                    target: Some(5)
                },
                Write
            ),
            "target owns it"
        );
        assert_eq!(p.check(true, &dom(7), Read), Err(Errno::EACCES));
        assert_eq!(p.check(true, &dom(6), Read), Ok(()));
    }

    #[test]
    fn ownership() {
        let p = Perms::parse(b"b5\0").unwrap();
        assert_eq!(p.check_owner(true, &dom(5)), Ok(()));
        assert_eq!(p.check_owner(true, &Caller::DOM0), Ok(()));
        assert_eq!(p.check_owner(true, &dom(6)), Err(Errno::EACCES));
        assert_eq!(p.check_owner(false, &dom(6)), Ok(()));
        assert_eq!(
            p.check_owner(
                true,
                &Caller {
                    domid: 6,
                    target: Some(5)
                }
            ),
            Ok(())
        );
        // The lost owner, -1, is nobody; 4294967295 is a domid.
        let lost = Perms {
            owner: -1,
            ..Perms::default0()
        };
        let largest = Caller {
            domid: u32::MAX,
            target: Some(u32::MAX),
        };
        assert_eq!(lost.check_owner(true, &largest), Err(Errno::EACCES));
        let p = Perms::parse(b"n4294967295\0").unwrap();
        assert_eq!(p.owner, 4294967295);
        assert_eq!(p.check_owner(true, &largest), Ok(()));
    }

    #[test]
    fn the_lost_owner_prints_as_percent_u_prints_an_ocaml_int() {
        // `Printf.sprintf "%c%u"` (`ox/perms.ml:88-89`): -1 is 2^63 - 1.
        let p = Perms {
            owner: -1,
            other: Access::Read,
            acl: vec![(u32::MAX, Access::Write), (0, Access::Both)],
        };
        assert_eq!(p.encode(), b"r9223372036854775807\0w4294967295\0b0\0");
        assert_eq!(p.encode_sep(b" ", false), b"r9223372036854775807 w4294967295 b0");
    }
}
