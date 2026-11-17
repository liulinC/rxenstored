// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! Immutable byte strings that keep short contents inline (no allocation)
//! and share long ones. Path components and node values are mostly short:
//! `device`, `state`, `4`, the empty string.

use crate::prelude::*;
use alloc::sync::Arc;
use core::borrow::Borrow;

/// Longest content kept inline.
pub const INLINE: usize = 22;

#[derive(Clone)]
pub enum Bytes {
    Inline { len: u8, data: [u8; INLINE] },
    Shared(Arc<[u8]>),
}

impl Bytes {
    pub const EMPTY: Bytes = Bytes::Inline {
        len: 0,
        data: [0; INLINE],
    };

    pub fn as_slice(&self) -> &[u8] {
        match self {
            // `len` is at most `INLINE`: only `from` makes an inline value.
            Bytes::Inline { len, data } => data.get(..usize::from(*len)).unwrap_or_else(|| {
                crate::impossible("an inline value longer than its array");
                data
            }),
            Bytes::Shared(a) => a,
        }
    }

    /// True if no allocation holds the content.
    #[cfg(test)]
    pub fn is_inline(&self) -> bool {
        matches!(self, Bytes::Inline { .. })
    }
}

impl From<&[u8]> for Bytes {
    fn from(s: &[u8]) -> Bytes {
        if s.len() <= INLINE {
            let mut data = [0; INLINE];
            for (d, b) in data.iter_mut().zip(s) {
                *d = *b;
            }
            Bytes::Inline {
                len: s.len() as u8,
                data,
            }
        } else {
            Bytes::Shared(Arc::from(s))
        }
    }
}

impl<const N: usize> From<&[u8; N]> for Bytes {
    fn from(s: &[u8; N]) -> Bytes {
        Bytes::from(&s[..])
    }
}

impl core::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Borrow<[u8]> for Bytes {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Bytes) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl PartialOrd for Bytes {
    fn partial_cmp(&self, other: &Bytes) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bytes {
    fn cmp(&self, other: &Bytes) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl core::hash::Hash for Bytes {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
        self.as_slice().hash(h)
    }
}

impl core::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn short_inline_long_shared() {
        assert_eq!(core::mem::size_of::<Bytes>(), 24);
        let s = Bytes::from(&b"device"[..]);
        assert!(s.is_inline());
        assert_eq!(&*s, b"device");
        let edge = Bytes::from(&[7u8; INLINE][..]);
        assert!(edge.is_inline());
        let long = Bytes::from(&[1u8; INLINE + 1][..]);
        assert!(!long.is_inline());
        assert_eq!(long.len(), INLINE + 1);
        assert!(Bytes::EMPTY.is_empty());
        assert!(Bytes::from(b"").is_inline());
    }

    #[test]
    fn an_inline_length_past_its_array_reads_the_whole_array() {
        // Not reachable: only `from` makes an inline value.
        let _g = crate::tests::expect_impossible();
        let b = Bytes::Inline {
            len: u8::MAX,
            data: [7; INLINE],
        };
        assert_eq!(b.as_slice(), &[7; INLINE]);
    }

    #[test]
    fn equality_order_and_hash_follow_the_content() {
        let a = Bytes::from(&[b'a'; 30][..]);
        let a2 = Bytes::from(&[b'a'; 30][..]);
        let b = Bytes::from(b"b");
        assert_eq!(a, a2);
        assert!(a < b);
        assert_eq!(b.partial_cmp(&a), Some(core::cmp::Ordering::Greater));
        let mut m = HashMap::new();
        m.insert(b.clone(), 1);
        assert_eq!(m.get(&b"b"[..]), Some(&1));
        assert_eq!(format!("{b:?}"), "\"b\"");
    }
}
