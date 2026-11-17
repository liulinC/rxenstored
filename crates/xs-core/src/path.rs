// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Path parsing and validation, following oxenstored (`ox/utils.ml:99-123`,
//! `ox/store.ml:117-149`).

use crate::prelude::*;
use xs_wire::Errno;

/// One path component. Bytes, not text: a path starting with `@` is a
/// single component holding anything the client sent.
pub type Name = crate::bytes::Bytes;

/// An absolute path as components; the root is empty.
pub type Path = Vec<Name>;

/// Default limit on the length of a path, or of its part relative to
/// `/local/domain/<domid>/`: oxenstored's built-in `quota-path-max`
/// (`ox/define.ml:42`). The shipped `oxenstored.conf` sets 1024.
pub const PATH_MAX: usize = 2048;

pub fn valid_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'@'
}

/// `home` is `/local/domain/<domid>/`; relative paths are taken from there.
pub fn absolute(raw: &[u8], home: &[u8]) -> Vec<u8> {
    match raw.first() {
        Some(b'/') | Some(b'@') => raw.to_vec(),
        _ => [home, raw].concat(),
    }
}

/// Length of the part of `abs` after `/local/domain/<n>/`, or of all of it.
/// The prefix is matched as OCaml's `"/local/domain/%d/%n"` would
/// (`ox/utils.ml:115-121`): `%d` fails on a number that is no OCaml int.
pub(crate) fn checked_len(abs: &[u8]) -> usize {
    const PREFIX: &[u8] = b"/local/domain/";
    let Some(rest) = abs.strip_prefix(PREFIX) else {
        return abs.len();
    };
    // A sign, then a digit, then digits and `_`, then `/`.
    let sign = usize::from(matches!(rest.first(), Some(b'+') | Some(b'-')));
    let number = sign
        + rest
            .iter()
            .skip(sign)
            .take_while(|c| c.is_ascii_digit() || **c == b'_')
            .count();
    match rest.split_at_checked(number) {
        Some((n, [b'/', after @ ..]))
            if rest.get(sign).is_some_and(u8::is_ascii_digit) && crate::perms::ocaml_int(n, 63).is_some() =>
        {
            after.len()
        }
        _ => abs.len(),
    }
}

/// Splits an absolute path into components (`Store.Path.of_string`).
pub fn components(abs: &[u8]) -> Result<Path, Errno> {
    let rest = match abs {
        [b'@', ..] => return Ok(vec![Name::from(abs)]),
        [b'/', rest @ ..] => rest,
        _ => return Err(Errno::EINVAL),
    };
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    // Sized exactly: collecting through `Result` would start from no size
    // hint and double, to twice what a deep path needs.
    let mut out = Vec::with_capacity(rest.iter().filter(|c| **c == b'/').count() + 1);
    for n in rest.split(|c| *c == b'/') {
        if n.is_empty() || !n.iter().all(|c| valid_char(*c)) {
            return Err(Errno::EINVAL);
        }
        out.push(Name::from(n));
    }
    Ok(out)
}

/// A path kept in little room, as a transaction keeps those of its
/// requests: one byte per byte of the path, where its components take a
/// `Name` (24 bytes) each. `unpack` gives the components back.
pub fn pack(path: &[Name]) -> crate::bytes::Bytes {
    match path {
        // A special path is one component, which may hold a `/`.
        [special] if special.first() == Some(&b'@') => special.clone(),
        _ => crate::bytes::Bytes::from(&to_string(path)[..]),
    }
}

/// The components of a path `pack` made.
pub fn unpack(packed: &[u8]) -> Path {
    if packed.first() == Some(&b'@') {
        return vec![Name::from(packed)];
    }
    let rest = packed.strip_prefix(b"/").unwrap_or(packed);
    if rest.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(rest.iter().filter(|c| **c == b'/').count() + 1);
    out.extend(rest.split(|c| *c == b'/').map(Name::from));
    out
}

/// Parses the path of a store request (READ, WRITE, ...).
pub fn parse(raw: &[u8], home: &[u8], path_max: usize) -> Result<Path, Errno> {
    if raw.is_empty() {
        return Err(Errno::EINVAL);
    }
    let abs = absolute(raw, home);
    if checked_len(&abs) > path_max {
        return Err(Errno::EINVAL);
    }
    components(&abs)
}

/// `/a/b` for `[a, b]`, `/` for the root.
pub fn to_string(path: &[Name]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.iter().map(|n| n.len() + 1).sum::<usize>().max(1));
    for n in path {
        out.push(b'/');
        out.extend_from_slice(n);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// Splits a payload in at most `limit` NUL-separated pieces, the last one
/// holding the rest (`Stdext.String.split ~limit`).
pub fn split(data: &[u8], limit: usize) -> Vec<&[u8]> {
    data.splitn(limit, |c| *c == 0).collect()
}

/// oxenstored's `c_int_of_string`: skips leading non-digits, reads digits,
/// ignores the rest. Arithmetic wraps like a 63-bit OCaml int.
pub fn c_int(s: &[u8]) -> u64 {
    let digits = s
        .iter()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit());
    digits.fold(0u64, |v, c| v.wrapping_mul(10).wrapping_add((c - b'0') as u64)) & ((1 << 63) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &[u8] = b"/local/domain/0/";

    fn p(s: &str) -> Result<Vec<String>, Errno> {
        parse(s.as_bytes(), HOME, PATH_MAX).map(|v| v.iter().map(|n| String::from_utf8(n.to_vec()).unwrap()).collect())
    }

    #[test]
    fn absolute_relative_and_root() {
        assert_eq!(p("/").unwrap(), Vec::<String>::new());
        assert_eq!(p("/a/b-c/D_9").unwrap(), ["a", "b-c", "D_9"]);
        assert_eq!(p("x/y").unwrap(), ["local", "domain", "0", "x", "y"]);
        assert_eq!(p("/a/@b").unwrap(), ["a", "@b"]);
    }

    #[test]
    fn special_paths_are_one_component() {
        assert_eq!(p("@introduceDomain").unwrap(), ["@introduceDomain"]);
        assert_eq!(p("@a/b c").unwrap(), ["@a/b c"]);
    }

    #[test]
    fn invalid_paths() {
        for bad in ["", "/a/", "//a", "/a//b", "/a b", "/a/b\u{e9}", "a/", "/a/./b", "/a:b"] {
            assert_eq!(p(bad), Err(Errno::EINVAL), "{bad:?}");
        }
        assert_eq!(components(b""), Err(Errno::EINVAL));
        assert_eq!(components(b"a"), Err(Errno::EINVAL));
    }

    #[test]
    fn length_limit_counts_the_part_relative_to_a_domain() {
        let long = "a".repeat(PATH_MAX);
        assert!(p(&format!("/{}", &long[1..])).is_ok());
        assert_eq!(p(&format!("/{long}")), Err(Errno::EINVAL));
        // Relative and /local/domain/<n>/ paths: only the part after the prefix counts.
        assert!(p(&long).is_ok());
        assert_eq!(p(&format!("{long}a")), Err(Errno::EINVAL));
        assert!(p(&format!("/local/domain/12345/{long}")).is_ok());
        assert_eq!(p(&format!("/local/domain/12345/{long}a")), Err(Errno::EINVAL));
        assert_eq!(checked_len(b"/local/domain/+1/ab"), 2);
        assert_eq!(checked_len(b"/local/domain/-1_0/ab"), 2);
        assert_eq!(checked_len(b"/local/domain/x/ab"), 18);
        assert_eq!(checked_len(b"/local/domain/_1/ab"), 19);
        assert_eq!(checked_len(b"/local/domain/12"), 16);
        assert_eq!(checked_len(b"/local/domain/"), 14);
        assert_eq!(checked_len(b"/local/domain/-"), 15);
        // A domid `%d` cannot read: the whole path counts.
        assert_eq!(checked_len(b"/local/domain/4611686018427387903/ab"), 2);
        assert_eq!(checked_len(b"/local/domain/4611686018427387904/ab"), 36);
        assert_eq!(checked_len(b"/local/domain/-4611686018427387904/ab"), 2);
        assert_eq!(checked_len(b"/local/domain/-4611686018427387905/ab"), 37);
        assert_eq!(
            checked_len(b"/local/domain/000000000000000000000000000001/ab"),
            2,
            "zeros are no overflow"
        );
    }

    #[test]
    fn components_are_sized_exactly() {
        for s in ["/a", "/a/b", "/a/b/c/d/e", "/@x/b"] {
            let c = components(s.as_bytes()).unwrap();
            assert_eq!(c.capacity(), c.len(), "{s}");
        }
        let deep = format!("/{}", ["a"; 515].join("/"));
        let c = components(deep.as_bytes()).unwrap();
        assert_eq!((c.len(), c.capacity()), (515, 515));
    }

    #[test]
    fn a_packed_path_unpacks_to_its_components() {
        for s in [
            "/",
            "/a",
            "/a/b-c/D_9",
            "/a/@b",
            "/@x",
            "@introduceDomain",
            "@a/b c",
            "@",
        ] {
            let path = components(s.as_bytes()).unwrap();
            let packed = pack(&path);
            let back = unpack(&packed);
            assert_eq!(back, path, "{s}");
            assert_eq!(back.capacity(), back.len(), "{s}");
        }
        // One byte per byte of the path, not a `Name` per component.
        let deep = components(format!("/{}", ["a"; 512].join("/")).as_bytes()).unwrap();
        assert_eq!(pack(&deep).len(), 1024);
        assert_eq!(&*pack(&[Name::from(&b"@a/b"[..])]), b"@a/b");
        // Only a special path is kept as it is: any other is absolute.
        assert_eq!(&*pack(&[Name::from(&b"a"[..])]), b"/a");
        assert_eq!(&*pack(&[Name::from(&b"a"[..]), Name::from(&b"@b"[..])]), b"/a/@b");
        // What `pack` never makes still unpacks to something.
        assert_eq!(unpack(b""), Vec::<Name>::new());
        assert_eq!(unpack(b"a/b"), components(b"/a/b").unwrap());
    }

    #[test]
    fn printing() {
        assert_eq!(to_string(&[]), b"/");
        assert_eq!(to_string(&[Name::from(&b"a"[..]), Name::from(&b"b"[..])]), b"/a/b");
        assert_eq!(to_string(&[Name::from(&b"@x/y"[..])]), b"/@x/y");
    }

    #[test]
    fn splitting_with_a_limit() {
        assert_eq!(split(b"a\0", 2), [&b"a"[..], b""]);
        assert_eq!(split(b"a\0b\0c", 2), [&b"a"[..], b"b\0c"]);
        assert_eq!(split(b"a", 2), [&b"a"[..]]);
        assert_eq!(split(b"", 8), [&b""[..]]);
        assert_eq!(split(b"a\0b\0", 8), [&b"a"[..], b"b", b""]);
    }

    #[test]
    fn c_int_of_string() {
        assert_eq!(c_int(b"12"), 12);
        assert_eq!(c_int(b"abc12x3"), 12);
        assert_eq!(c_int(b""), 0);
        assert_eq!(c_int(b"-7"), 7);
        assert!(c_int(b"99999999999999999999999") < 1 << 63);
    }
}
