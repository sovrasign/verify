//! SHA-256 over one document, computed once and reused by every step that hashes part of it.
//!
//! Signing a document used to hash most of it about seven times: the integrity check that signing
//! runs first hashed the whole file for its report, the signed range of every signature, the
//! preparer's source bytes and each earlier revision; signing hashed the whole file again for the
//! document digest its record carries, and once more for the new signature. All of them are
//! hashes of a prefix of the same bytes, or of a prefix and a short tail (a signature's
//! `ByteRange` leaves out only its own `/Contents`), so one pass can answer them all:
//! [`DocumentDigests`] hashes the document once, keeps the SHA-256 state every [`STRIDE`] bytes
//! and at the end, and answers any prefix from the nearest state before it (at most [`STRIDE`]
//! bytes to hash). The new signature's range starts with the whole input, so its digest continues
//! from the state at the end of the input and hashes only the bytes the signature adds.
//!
//! Hashing goes through one function that is never inlined, [`STRIDE`] bytes per call. A browser
//! runs a new WebAssembly function in its baseline compiler and switches to optimized code only
//! on a later call, so a document hashed in one call ran about 10x slower the first time in Chrome
//! (P0 signer-page spike); in chunks, only the first chunk does.
//!
//! The digests are the same values as hashing the bytes directly (`sha256(bytes[..n])`), which
//! the tests check; what is computed, and what each check compares, does not change.

use std::cell::RefCell;

use sha2::{Digest, Sha256};

/// Bytes hashed between two kept states: a prefix costs at most this much once the document has
/// been hashed. 256 KiB keeps 200 states (about 22 KB) for a 50 MB document.
pub const STRIDE: usize = 256 * 1024;

/// Feed `data` to `state`, [`STRIDE`] bytes per call of a function that is never inlined (see the
/// module documentation).
pub(crate) fn absorb(state: &mut Sha256, data: &[u8]) {
    #[inline(never)]
    fn chunk(state: &mut Sha256, data: &[u8]) {
        state.update(data);
    }
    for part in data.chunks(STRIDE) {
        chunk(state, part);
    }
}

/// SHA-256 of `data`, hashed in chunks ([`absorb`]).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = Sha256::new();
    absorb(&mut state, data);
    state.finalize().into()
}

/// The SHA-256 digests of one document's prefixes, hashing every byte once (module docs).
///
/// Not `Sync`: it fills its states as it is asked, behind a `RefCell`.
pub struct DocumentDigests<'a> {
    bytes: &'a [u8],
    /// `(offset, state after the first offset bytes)`, sorted by offset, starting at 0: one every
    /// [`STRIDE`] bytes as far as the document has been hashed, and one at its end.
    states: RefCell<Vec<(usize, Sha256)>>,
}

impl<'a> DocumentDigests<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        DocumentDigests {
            bytes,
            states: RefCell::new(vec![(0, Sha256::new())]),
        }
    }

    /// The document.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The SHA-256 state after the first `n` bytes (`n` is clamped to the document's length).
    pub fn state_at(&self, n: usize) -> Sha256 {
        let n = n.min(self.bytes.len());
        let mut states = self.states.borrow_mut();
        // The last kept state at or before `n` (the first one is at 0).
        let i = states.partition_point(|(at, _)| *at <= n) - 1;
        let (mut at, mut state) = (states[i].0, states[i].1.clone());
        if at == n {
            return state;
        }
        // Keep a state at every stride boundary passed for the first time, and at the end.
        let known = states.last().map_or(0, |(end, _)| *end);
        while at < n {
            let next = ((at / STRIDE + 1) * STRIDE).min(n);
            absorb(&mut state, &self.bytes[at..next]);
            at = next;
            let boundary = at % STRIDE == 0 || at == self.bytes.len();
            if boundary && at > known {
                states.push((at, state.clone()));
            }
        }
        state
    }

    /// SHA-256 of the first `n` bytes.
    pub fn prefix(&self, n: usize) -> [u8; 32] {
        self.state_at(n).finalize().into()
    }

    /// [`Self::prefix`] as lowercase hex.
    pub fn prefix_hex(&self, n: usize) -> String {
        hex::encode(self.prefix(n))
    }

    /// SHA-256 of the whole document.
    pub fn whole(&self) -> [u8; 32] {
        self.prefix(self.bytes.len())
    }

    /// [`Self::whole`] as lowercase hex.
    pub fn whole_hex(&self) -> String {
        hex::encode(self.whole())
    }

    /// SHA-256 of `bytes[..l1] ‖ bytes[s2..s2 + l2]`: what a signature's `ByteRange`
    /// `[0 l1 s2 l2]` signs. `None` when the second span is out of the document.
    pub fn spans(&self, l1: usize, s2: usize, l2: usize) -> Option<[u8; 32]> {
        let tail = self.bytes.get(s2..s2.checked_add(l2)?)?;
        if l1 > self.bytes.len() {
            return None;
        }
        let mut state = self.state_at(l1);
        absorb(&mut state, tail);
        Some(state.finalize().into())
    }

    /// SHA-256 of the whole document followed by `more`, without copying the document: the
    /// digest of a document that extends this one (an increment appended to it).
    pub fn extended(&self, more: &[&[u8]]) -> [u8; 32] {
        let mut state = self.state_at(self.bytes.len());
        for m in more {
            absorb(&mut state, m);
        }
        state.finalize().into()
    }

    /// How many states are kept (tests).
    #[cfg(test)]
    fn kept(&self) -> usize {
        self.states.borrow().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn doc(len: usize) -> Vec<u8> {
        let mut seed = 0x9e37_79b9u32;
        (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect()
    }

    #[test]
    fn every_prefix_and_span_matches_hashing_directly() {
        let bytes = doc(3 * STRIDE + 12_345);
        let d = DocumentDigests::new(&bytes);
        let len = bytes.len();
        // Out of order, before and after the whole document has been hashed, on and off the
        // stride boundaries.
        let offsets = [
            len,
            0,
            1,
            STRIDE - 1,
            STRIDE,
            STRIDE + 1,
            2 * STRIDE + 77,
            len - 1,
            len,
            63,
            64,
            65,
        ];
        for n in offsets {
            assert_eq!(d.prefix(n), direct(&[&bytes[..n]]), "prefix {n}");
        }
        assert_eq!(d.whole_hex(), hex::encode(direct(&[&bytes])));
        assert_eq!(sha256(&bytes), direct(&[&bytes]));
        for (l1, s2, l2) in [
            (10, 20, len - 20),
            (STRIDE + 5, len - 100, 100),
            (len, len, 0),
        ] {
            assert_eq!(
                d.spans(l1, s2, l2),
                Some(direct(&[&bytes[..l1], &bytes[s2..s2 + l2]])),
                "spans {l1} {s2} {l2}"
            );
        }
        assert_eq!(d.spans(10, len - 5, 6), None);
        assert_eq!(d.spans(len + 1, len, 0), None);
        assert_eq!(d.spans(10, usize::MAX, 2), None);
        assert_eq!(
            d.extended(&[b"one", b"two"]),
            direct(&[&bytes, b"one", b"two"])
        );
        // One state per stride boundary, plus the start and the end.
        assert_eq!(d.kept(), 1 + 3 + 1);
    }

    #[test]
    fn empty_and_short_documents() {
        let d = DocumentDigests::new(b"");
        assert_eq!(d.whole(), direct(&[b""]));
        assert_eq!(d.prefix(5), direct(&[b""]), "clamped to the length");
        let d = DocumentDigests::new(b"%PDF-1.7");
        assert_eq!(d.prefix(4), direct(&[b"%PDF"]));
        assert_eq!(d.whole(), direct(&[b"%PDF-1.7"]));
    }
}
