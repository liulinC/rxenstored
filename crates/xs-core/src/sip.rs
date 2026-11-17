// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Olivier Lambert <olivier.lambert@vates.tech>
//! SipHash-1-3 with a 128-bit key: the hash function of std's `HashMap`
//! (`RandomState`), which `core` and `alloc` do not provide. The tables
//! whose keys clients choose (the watch index: node names, watch tokens)
//! hash with it, under a key the daemon draws at random at start-up
//! (`Core::new`): a client that cannot know the key cannot make its
//! entries collide.

use core::hash::{BuildHasher, Hasher};

/// The key of a set of tables, and the builder of their hashers.
#[derive(Clone, Copy)]
pub struct SipKey {
    k0: u64,
    k1: u64,
}

impl SipKey {
    pub const fn new(key: [u64; 2]) -> SipKey {
        SipKey { k0: key[0], k1: key[1] }
    }
}

/// The key stays out of debug output, as `RandomState`'s does.
impl core::fmt::Debug for SipKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("SipKey { .. }")
    }
}

impl BuildHasher for SipKey {
    type Hasher = Sip13;

    fn build_hasher(&self) -> Sip13 {
        Sip13::new(self.k0, self.k1)
    }
}

/// No `Debug`, here or in `Sip13`: the state is the key, mixed.
#[derive(Clone, Copy)]
struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    /// One compression round: SipHash-1-3.
    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.v0 ^= m;
    }
}

/// A SipHash-1-3 hasher. Writing bytes in pieces gives the hash of the
/// pieces put together.
pub struct Sip13 {
    v: State,
    /// The bytes written since the last full 8, little-endian.
    tail: u64,
    /// How many: 0 to 7.
    ntail: usize,
    /// All the bytes written (only its low byte counts).
    length: usize,
}

/// Up to 8 bytes as a little-endian number (the first 8 if more).
fn le(bytes: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    for (d, s) in b.iter_mut().zip(bytes) {
        *d = *s;
    }
    u64::from_le_bytes(b)
}

impl Sip13 {
    pub fn new(k0: u64, k1: u64) -> Sip13 {
        let v = State {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
        };
        Sip13 {
            v,
            tail: 0,
            ntail: 0,
            length: 0,
        }
    }
}

impl Hasher for Sip13 {
    fn write(&mut self, msg: &[u8]) {
        self.length = self.length.wrapping_add(msg.len());
        // Complete the tail (`ntail` is below 8, so the shift below 64).
        let need = 8 - self.ntail;
        let (head, rest) = msg.split_at_checked(need.min(msg.len())).unwrap_or((msg, &[]));
        self.tail |= le(head) << (8 * self.ntail);
        self.ntail += head.len();
        if self.ntail < 8 {
            return;
        }
        self.v.compress(self.tail);
        let (blocks, last) = rest.as_chunks::<8>();
        for b in blocks {
            self.v.compress(u64::from_le_bytes(*b));
        }
        self.tail = le(last);
        self.ntail = last.len();
    }

    fn finish(&self) -> u64 {
        let mut v = self.v;
        let mut b = self.tail;
        b |= (self.length as u64) << 56;
        v.compress(b);
        v.v2 ^= 0xff;
        v.round();
        v.round();
        v.round();
        v.v0 ^ v.v1 ^ v.v2 ^ v.v3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{DefaultHasher, Hash};

    /// SipHash-1-3 of the bytes 0, 1, ..., n-1 under the key 00 01 ... 0f,
    /// for n from 0 to 63: the vectors of the Rust project's tests of its
    /// own SipHash-1-3 (`library/coretests/tests/hash/sip.rs`), as
    /// little-endian numbers.
    const VECTORS: [u64; 64] = [
        0xabac0158050fc4dc,
        0xc9f49bf37d57ca93,
        0x82cb9b024dc7d44d,
        0x8bf80ab8e7ddf7fb,
        0xcf75576088d38328,
        0xdef9d52f49533b67,
        0xc50d2b50c59f22a7,
        0xd3927d989bb11140,
        0x369095118d299a8e,
        0x25a48eb36c063de4,
        0x79de85ee92ff097f,
        0x70c118c1f94dc352,
        0x78a384b157b4d9a2,
        0x306f760c1229ffa7,
        0x605aa111c0f95d34,
        0xd320d86d2a519956,
        0xcc4fdd1a7d908b66,
        0x9cf2689063dbd80c,
        0x8ffc389cb473e63e,
        0xf21f9de58d297d1c,
        0xc0dc2f46a6cce040,
        0xb992abfe2b45f844,
        0x7ffe7b9ba320872e,
        0x525a0e7fdae6c123,
        0xf464aeb267349c8c,
        0x45cd5928705b0979,
        0x3a3e35e3ca9913a5,
        0xa91dc74e4ade3b35,
        0xfb0bed02ef6cd00d,
        0x88d93cb44ab1e1f4,
        0x540f11d643c5e663,
        0x2370dd1f8c21d1bc,
        0x81157b6c16a7b60d,
        0x4d54b9e57a8ff9bf,
        0x759f12781f2a753e,
        0xcea1a3bebf186b91,
        0x2cf508d3ada26206,
        0xb6101c2da3c33057,
        0xb3f47496ae3a36a1,
        0x626b57547b108392,
        0xc1d2363299e41531,
        0x667cc1923f1ad944,
        0x65704ffec8138825,
        0x24f280d1c28949a6,
        0xc2ca1cedfaf8876b,
        0xc2164bfc9f042196,
        0xa16e9c9368b1d623,
        0x49fb169c8b5114fd,
        0x9f3143f8df074c46,
        0xc6fdaf2412cc86b3,
        0x7eaf49d10a52098f,
        0x1cf313559d292f9a,
        0xc44a30dda2f41f12,
        0x36fae98943a71ed0,
        0x318fb34c73f0bce6,
        0xa27abf3670a7e980,
        0xb4bcc0db243c6d75,
        0x23f8d852fdb71513,
        0x8f035f4da67d8a08,
        0xd89cd0e5b7e8f148,
        0xf6f4e6bcf7a644ee,
        0xaec59ad80f1837f2,
        0xc3b2f6154b6694e0,
        0x9d199062b7bbb3a8,
    ];

    fn key() -> SipKey {
        SipKey::new([0x0706050403020100, 0x0f0e0d0c0b0a0908])
    }

    #[test]
    fn the_reference_vectors_whole_and_one_byte_at_a_time() {
        let mut bytes = Vec::new();
        let mut inc = key().build_hasher();
        for (n, &want) in VECTORS.iter().enumerate() {
            let mut whole = key().build_hasher();
            whole.write(&bytes);
            assert_eq!(whole.finish(), want, "{n} bytes whole");
            assert_eq!(inc.finish(), want, "{n} bytes one at a time");
            inc.write(&[n as u8]);
            bytes.push(n as u8);
        }
    }

    #[test]
    fn any_split_of_the_input_gives_the_same_hash() {
        let bytes: Vec<u8> = (0..64).collect();
        for n in 0..VECTORS.len() {
            for cut in 0..=n {
                for cut2 in cut..=n {
                    let mut h = key().build_hasher();
                    h.write(&bytes[..cut]);
                    h.write(&bytes[cut..cut2]);
                    h.write(&bytes[cut2..n]);
                    assert_eq!(h.finish(), VECTORS[n], "{n} bytes cut at {cut} and {cut2}");
                }
            }
        }
    }

    /// std's `DefaultHasher::new()` is SipHash-1-3 under the zero key:
    /// what `Hash` writes (integers, length prefixes) hashes the same.
    #[test]
    fn as_std_s_default_hasher_under_the_zero_key() {
        let zero = SipKey::new([0, 0]);
        let values: [(u32, &[u8]); 5] = [
            (0, b""),
            (1, b"a"),
            (7, b"domain"),
            (u32::MAX, b"0123456789abcdef"),
            (42, &[0xff; 100]),
        ];
        for v in values {
            let mut std = DefaultHasher::new();
            v.hash(&mut std);
            assert_eq!(zero.hash_one(v), std.finish(), "{v:?}");
        }
    }

    #[test]
    fn the_key_matters_and_stays_out_of_debug_output() {
        let a = SipKey::new([1, 2]);
        assert_ne!(a.hash_one(b"x"), SipKey::new([1, 3]).hash_one(b"x"));
        assert_ne!(a.hash_one(b"x"), SipKey::new([0, 2]).hash_one(b"x"));
        assert_eq!(format!("{a:?}"), "SipKey { .. }");
    }
}
