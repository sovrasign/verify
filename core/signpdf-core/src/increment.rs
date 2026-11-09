//! Increment-only transfer of a document whose head moved.
//!
//! A SignPDF document only ever grows: each revision (a signature, a document timestamp, the
//! validation data before one) is appended to the previous one byte for byte. So a client that
//! holds an earlier revision (its *head*) needs only the bytes after it when someone else has
//! signed since, not the whole document again: on a phone a 50 MB envelope is about a minute of
//! download, a signer's increment well under a second.
//!
//! * The holder of the current document answers with [`increment_after`]: the bytes after the
//!   client's head, once it has checked that the head (its length and SHA-256) is a revision of
//!   this document. A head that is not (another document, a copy that diverged, a revision the
//!   holder never had) is refused, and the client fetches the whole document.
//! * The client checks what it received with [`check_increment`] before it uses it: the head and
//!   the increment together must be the document the holder announced (its length and SHA-256),
//!   so a truncated or altered transfer is never signed. Nothing is copied: the head is hashed
//!   where it is.
//!
//! Neither step judges whether the new revisions are valid; [`crate::verify`] (and signing, which
//! verifies first) does.

use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;
use crate::digest::DocumentDigests;
use crate::error::{Result, SignPdfError};

/// What a client holds of a document, or what a holder announces: its length and SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// Length in bytes.
    pub len: u64,
    /// SHA-256 of those bytes, lowercase hex.
    pub sha256: String,
}

impl Head {
    /// The head of `pdf`.
    pub fn of(pdf: &[u8]) -> Head {
        Head {
            len: pdf.len() as u64,
            sha256: sha256_hex(pdf),
        }
    }
}

/// Whether `bytes` ends a revision: an incremental update (and every SignPDF revision) ends with
/// `%%EOF`, optionally followed by an end of line.
fn ends_a_revision(bytes: &[u8]) -> bool {
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b'\r' | b'\n'))
        .map_or(0, |p| p + 1);
    bytes.len() - end <= 2 && bytes[..end].ends_with(b"%%EOF")
}

fn mismatch(msg: impl Into<String>) -> SignPdfError {
    SignPdfError::Workflow(msg.into())
}

/// The bytes of `pdf` after the client's `head`: `pdf[head.len..]`, empty when the head has not
/// moved. Refused, so the client fetches the whole document instead, when `head` is not a
/// revision of `pdf`: longer than it, of another digest (another document, or a copy that
/// diverged), empty, or not ending where a revision ends.
///
/// Only the first `head.len` bytes are hashed, and nothing is copied.
pub fn increment_after<'a>(pdf: &'a [u8], head: &Head) -> Result<&'a [u8]> {
    let len = usize::try_from(head.len)
        .ok()
        .filter(|n| *n <= pdf.len())
        .ok_or_else(|| {
            mismatch(format!(
                "the head ({} bytes) is longer than this document ({} bytes): fetch the whole \
                 document",
                head.len,
                pdf.len()
            ))
        })?;
    if len == 0 {
        return Err(mismatch(
            "an empty head is not a revision: fetch the whole document",
        ));
    }
    let prefix = &pdf[..len];
    if !ends_a_revision(prefix) {
        return Err(mismatch(format!(
            "the first {len} bytes of this document do not end a revision: fetch the whole \
             document"
        )));
    }
    if !sha256_hex(prefix).eq_ignore_ascii_case(&head.sha256) {
        return Err(mismatch(
            "the head is not a revision of this document (its digest differs): fetch the whole \
             document",
        ));
    }
    Ok(&pdf[len..])
}

/// Check, on the client, that `increment` (what [`increment_after`] sent) extends `head` (the
/// revision the client holds) into the document the holder announced, `expected`: the length
/// adds up, the increment ends a revision, and the SHA-256 of the head followed by the increment
/// is `expected.sha256`. The head is hashed in place; nothing is copied. Returns the new head
/// (`expected`, as checked).
///
/// An empty increment is accepted when `expected` is the head itself (the head did not move).
pub fn check_increment(head: &[u8], increment: &[u8], expected: &Head) -> Result<Head> {
    let total = head.len() as u64 + increment.len() as u64;
    if total != expected.len {
        return Err(mismatch(format!(
            "the head ({} bytes) and the increment ({} bytes) do not add up to the announced \
             document ({} bytes): fetch the whole document",
            head.len(),
            increment.len(),
            expected.len
        )));
    }
    if !increment.is_empty() && !ends_a_revision(increment) {
        return Err(mismatch(
            "the increment does not end a revision (the transfer was cut short): fetch it again",
        ));
    }
    let digest = hex::encode(DocumentDigests::new(head).extended(&[increment]));
    if !digest.eq_ignore_ascii_case(&expected.sha256) {
        return Err(mismatch(
            "the head and the increment are not the announced document (its digest differs): \
             fetch the whole document",
        ));
    }
    Ok(Head {
        len: total,
        sha256: digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV0: &[u8] = b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF\n";
    const INC1: &[u8] = b"2 0 obj\n<< >>\nendobj\ntrailer\n<< /Prev 0 >>\n%%EOF\n";
    const INC2: &[u8] = b"3 0 obj\n<< >>\nendobj\ntrailer\n<< /Prev 1 >>\n%%EOF\r\n";

    fn doc(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn the_holder_sends_only_what_follows_a_known_revision() {
        let full = doc(&[REV0, INC1, INC2]);
        let head = Head::of(REV0);
        assert_eq!(increment_after(&full, &head).unwrap(), doc(&[INC1, INC2]));
        let head = Head::of(&doc(&[REV0, INC1]));
        assert_eq!(increment_after(&full, &head).unwrap(), INC2);
        // The head did not move.
        assert!(increment_after(&full, &Head::of(&full)).unwrap().is_empty());
        // Upper-case hex is the same digest.
        let mut upper = Head::of(REV0);
        upper.sha256 = upper.sha256.to_uppercase();
        assert_eq!(
            increment_after(&full, &upper).unwrap().len(),
            full.len() - REV0.len()
        );
    }

    #[test]
    fn a_head_that_is_not_a_revision_gets_the_whole_document() {
        let full = doc(&[REV0, INC1]);
        let refused = |head: Head| {
            let e = increment_after(&full, &head).unwrap_err().to_string();
            assert!(e.contains("fetch the whole document"), "{e}");
        };
        // Another document of the same length.
        let mut other = REV0.to_vec();
        other[10] ^= 1;
        refused(Head::of(&other));
        // Longer than the document, empty, mid-revision.
        refused(Head {
            len: full.len() as u64 + 1,
            sha256: Head::of(&full).sha256,
        });
        refused(Head::of(b""));
        refused(Head::of(&full[..20]));
        refused(Head {
            len: u64::MAX,
            sha256: String::new(),
        });
    }

    #[test]
    fn the_client_checks_the_increment_against_the_announced_head() {
        let new = doc(&[REV0, INC1, INC2]);
        let announced = Head::of(&new);
        let inc = increment_after(&new, &Head::of(REV0)).unwrap();
        assert_eq!(check_increment(REV0, inc, &announced).unwrap(), announced);
        // Nothing moved.
        assert_eq!(
            check_increment(&new, b"", &announced).unwrap(),
            announced,
            "an empty increment for an unmoved head"
        );

        let refused = |head: &[u8], inc: &[u8], what: &str| {
            let e = check_increment(head, inc, &announced)
                .unwrap_err()
                .to_string();
            assert!(e.contains(what), "{e}");
        };
        // Cut short (the length no longer adds up), or cut and padded to length.
        refused(REV0, &inc[..inc.len() - 10], "do not add up");
        let mut cut = inc[..inc.len() - 10].to_vec();
        cut.extend_from_slice(b"          ");
        refused(REV0, &cut, "does not end a revision");
        // Altered in transit, or applied to another head.
        let mut altered = inc.to_vec();
        altered[3] ^= 1;
        refused(REV0, &altered, "digest differs");
        let mut other_head = REV0.to_vec();
        other_head[10] ^= 1;
        refused(&other_head, inc, "digest differs");
    }

    #[test]
    fn revision_ends() {
        assert!(ends_a_revision(b"x\n%%EOF"));
        assert!(ends_a_revision(b"x\n%%EOF\n"));
        assert!(ends_a_revision(b"x\n%%EOF\r\n"));
        assert!(!ends_a_revision(b"x\n%%EOF\n\n\n"));
        assert!(!ends_a_revision(b"x\n%%EOF x"));
        assert!(!ends_a_revision(b"\n"));
        assert!(!ends_a_revision(b""));
    }
}
