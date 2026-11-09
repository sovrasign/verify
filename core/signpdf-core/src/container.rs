//! On-disk signing container (**legacy / superseded**).
//!
//! > **Status:** this append-log container is no longer the production signing path. The
//! > shipping workflow embeds the envelope as a PDF attachment and signs with real PAdES
//! > incremental updates + CMS (see [`crate::pades`] and [`crate::workflow`]). This module is
//! > retained for [`make_sample_pdf`] / [`is_pdf`] and for reference, and its signing
//! > semantics below describe the model the PAdES path now realises with standard PDF bytes.
//!
//! The container is the original PDF bytes followed by an append-only log of workflow
//! events. Each event ("section") is written as a marker line, a single base64 line
//! holding the section JSON, and a newline:
//!
//! ```text
//! <original PDF bytes>
//! \n%%SIGNPDF-V1\n<base64 section payload>\n
//! \n%%SIGNPDF-V1\n<base64 section payload>\n
//! ...
//! ```
//!
//! The crucial property: every section's signature is computed over the **byte prefix**
//! that existed when the section was appended (`prefix_len` = the offset of its marker).
//! This is exactly the trust model of a PAdES `ByteRange` — signer *N* signs over
//! everything signer *N-1* produced — so altering any earlier byte invalidates every
//! later signature. The base64 alphabet excludes `%` and newlines, so the marker can
//! never occur inside a payload.

use serde::{Deserialize, Serialize};

use crate::crypto::{b64_decode, b64_encode};
use crate::error::{Result, SignPdfError};
use crate::model::Envelope;

/// Marker that delimits each appended section.
pub const MARKER: &[u8] = b"\n%%SIGNPDF-V1\n";

/// One appended workflow event plus the post-event envelope snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionPayload {
    /// "prepared" | "signed" | "declined".
    pub kind: String,
    pub actor_fingerprint: String,
    pub actor_public_key: String,
    pub signed_at: String,
    /// Hex SHA-256 of the signed byte prefix.
    pub doc_digest: String,
    pub signed_prefix_len: u64,
    /// Hex SHA-256 of the envelope's intent core (see [`Envelope::core_digest`]).
    pub core_digest: String,
    /// Base64 DER ECDSA signature over [`signing_payload`].
    pub signature: String,
    /// Full envelope state after this event.
    pub envelope: Envelope,
}

/// A parsed section together with the prefix length it was signed over.
#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub prefix_len: usize,
    pub payload: SectionPayload,
}

/// Result of parsing a container's append-log.
#[derive(Debug, Clone)]
pub struct ParsedContainer {
    pub original_len: usize,
    pub sections: Vec<ParsedSection>,
}

impl ParsedContainer {
    /// The latest (authoritative) envelope snapshot, if any sections exist.
    pub fn latest_envelope(&self) -> Option<&Envelope> {
        self.sections.last().map(|s| &s.payload.envelope)
    }
}

/// Deterministic byte string that a section's signature is computed over.
pub fn signing_payload(
    kind: &str,
    doc_digest: &str,
    actor_fingerprint: &str,
    signed_at: &str,
    core_digest: &str,
) -> Vec<u8> {
    format!("signpdf-v1|{kind}|{doc_digest}|{actor_fingerprint}|{signed_at}|{core_digest}")
        .into_bytes()
}

/// Append a section to `current`, returning the new container bytes.
pub fn append_section(current: &[u8], payload: &SectionPayload) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload)?;
    let b64 = b64_encode(&json);
    let mut out = Vec::with_capacity(current.len() + MARKER.len() + b64.len() + 1);
    out.extend_from_slice(current);
    out.extend_from_slice(MARKER);
    out.extend_from_slice(b64.as_bytes());
    out.push(b'\n');
    Ok(out)
}

/// Parse the original bytes and every appended section out of a container.
pub fn parse(bytes: &[u8]) -> Result<ParsedContainer> {
    let positions = find_all(bytes, MARKER);
    let original_len = positions.first().copied().unwrap_or(bytes.len());
    let mut sections = Vec::with_capacity(positions.len());
    for &pos in &positions {
        let start = pos + MARKER.len();
        let rel_end = bytes[start..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| SignPdfError::Container("section missing terminator".into()))?;
        let end = start + rel_end;
        let b64 = std::str::from_utf8(&bytes[start..end])
            .map_err(|e| SignPdfError::Container(e.to_string()))?;
        let json = b64_decode(b64)?;
        let payload: SectionPayload = serde_json::from_slice(&json)?;
        sections.push(ParsedSection {
            prefix_len: pos,
            payload,
        });
    }
    Ok(ParsedContainer {
        original_len,
        sections,
    })
}

/// True when `bytes` begins with a PDF header.
pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
}

/// Generate a small but structurally valid single-page PDF (used for tests and the demo;
/// real input PDFs come from the user). Cross-reference offsets are computed correctly.
pub fn make_sample_pdf(text: &str) -> Vec<u8> {
    let safe: String = text
        .chars()
        .flat_map(|c| match c {
            '(' => vec!['\\', '('],
            ')' => vec!['\\', ')'],
            '\\' => vec!['\\', '\\'],
            _ => vec![c],
        })
        .collect();
    let content = format!("BT /F1 24 Tf 72 700 Td ({safe}) Tj ET\n");

    let objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.len(),
            content
        ),
    ];

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, body).as_bytes());
    }
    let xref_start = buf.len();
    let size = objects.len() + 1;
    buf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n")
            .as_bytes(),
    );
    buf
}

/// All start indices at which `needle` occurs in `haystack`.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_pdf_is_pdf() {
        let pdf = make_sample_pdf("Hello");
        assert!(is_pdf(&pdf));
        assert!(pdf.windows(5).any(|w| w == b"%%EOF"));
    }

    #[test]
    fn find_all_non_overlapping() {
        assert_eq!(find_all(b"axaxax", b"ax"), vec![0, 2, 4]);
        assert_eq!(find_all(b"abc", b"x"), Vec::<usize>::new());
    }
}
