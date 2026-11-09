//! Certificate of completion: a human-readable PDF summary of a verified SignPDF document —
//! the verdict, who prepared and signed it (with verified identities, trust status, times and
//! verification codes), and the full audit trail.
//!
//! The certificate is a *derived report*, generated from [`crate::workflow::verify`]. It is not
//! itself signed: anyone relying on it should re-verify the signed PDF (whose SHA-256 the
//! certificate names). It is a separate file because appending a page to the signed PDF would
//! break the "last signature covers the whole file" rule.

use crate::error::Result;
use crate::pades::winansi_literal;
use crate::trust::TrustStore;
use crate::workflow::{self, human_time, SignatureStatus, VerificationReport};

const PAGE_W: f32 = 612.0;
const PAGE_H: f32 = 792.0;
const MARGIN: f32 = 54.0;
const LINE: f32 = 13.0;
const WRAP: usize = 96;

/// A styled line of the report.
enum Line {
    Title(String),
    Heading(String),
    Text(String),
    Blank,
}

/// Verify `pdf` against `trust` and render a certificate of completion for it.
pub fn completion_certificate(pdf: &[u8], trust: &TrustStore) -> Result<Vec<u8>> {
    let report = workflow::verify(pdf, trust)?;
    Ok(render(&report))
}

/// Render a certificate from an existing verification report.
pub fn render(report: &VerificationReport) -> Vec<u8> {
    let mut lines: Vec<Line> = Vec::new();
    let env = report.envelope.as_ref();
    lines.push(Line::Title("SignPDF Certificate of Completion".into()));
    // Said first, not in the small print: this page carries no signature of its own.
    lines.push(Line::Text(
        "A summary, not proof: anyone can produce a page like this one. What proves the \
         signatures is the signed PDF itself, checked with SignPDF."
            .into(),
    ));
    lines.push(Line::Blank);
    if let Some(env) = env {
        lines.push(Line::Text(format!("Document: {}", env.title)));
        lines.push(Line::Text(format!("Envelope id: {}", env.envelope_id)));
        // An envelope of several documents: each one, with its pages in the combined PDF and the
        // SHA-256 of the file it was made from (a prepared term, checked by the verifier).
        let count = env.documents.len();
        if count > 0 {
            lines.push(Line::Text(format!(
                "Documents: {count}, signed together as one PDF"
            )));
        }
        for (i, d) in env.documents.iter().enumerate() {
            let pages = match d.page_count {
                1 => format!("page {}", d.first_page + 1),
                n => format!("pages {}-{}", d.first_page + 1, d.first_page + n),
            };
            lines.push(Line::Text(format!(
                "  {}. {} ({pages}; original file SHA-256 {})",
                i + 1,
                d.name,
                d.source_digest
            )));
        }
    }
    if let Some(link) = &report.service_link {
        // The preparer's link back to the service that sent the envelope (never part of the
        // verdict).
        lines.push(Line::Text(format!("Open in the sending service: {link}")));
    }
    lines.push(Line::Text(format!(
        "Signed PDF SHA-256: {}",
        report.document_sha256
    )));
    lines.push(Line::Text(format!(
        "Signed PDF size: {} bytes",
        report.original_len
    )));
    lines.push(Line::Blank);

    let verdict = if report.valid {
        "VALID - intact, and every identity is anchored in the verifier's trust store"
    } else if report.trusted_time_pending {
        "NOT YET VERIFIED - intact, but some identities count only once a trusted timestamp \
         covers their signature, and none does yet"
    } else if report.integrity_ok {
        "NOT FULLY VERIFIED - intact, but some identities are not trusted by this verifier"
    } else {
        "INVALID - the document or its signing history failed verification"
    };
    lines.push(Line::Heading("Verdict".into()));
    lines.push(Line::Text(verdict.into()));
    let state = if report.declined {
        "declined (void)"
    } else if report.complete {
        "completed - all signers signed"
    } else {
        "in progress - signatures outstanding"
    };
    lines.push(Line::Text(format!("Status: {state}")));
    // The trusted upper bound on every signing time: the earliest trusted timestamp covering the
    // last revision covers every earlier one too.
    if let Some(last) = report.signatures.last().or(report.preparer.as_ref()) {
        lines.push(Line::Text(match &last.existed_before {
            Some(e) => format!(
                "Signing times: all signatures in this document existed before {} (trusted \
                 timestamp, {})",
                human_time(&e.time),
                tsa_label(&e.tsa_name)
            ),
            None => "Signing times: no trusted timestamp yet; the times below are the signers' \
                     device clocks, not independently confirmed"
                .into(),
        }));
    }
    lines.push(Line::Text(format!(
        "Audit log: {}   Signing order: {}",
        if report.audit_ok { "intact" } else { "BROKEN" },
        if report.order_ok {
            "respected"
        } else {
            "VIOLATED"
        }
    )));
    lines.push(Line::Blank);

    if let Some(p) = &report.preparer {
        lines.push(Line::Heading("Prepared by".into()));
        push_status(&mut lines, p, None);
        lines.push(Line::Blank);
    }

    lines.push(Line::Heading("Signers".into()));
    if let Some(env) = env {
        for (i, s) in env.signers.iter().enumerate() {
            lines.push(Line::Text(format!(
                "{}. {} <{}>{} - order {} - {:?}",
                i + 1,
                s.name,
                s.handle,
                if s.role.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", s.role)
                },
                s.order,
                s.status
            )));
            if let Some(st) = report.signatures.iter().find(|x| x.signer_id == s.id) {
                push_status(&mut lines, st, Some("   "));
            }
        }
    }
    lines.push(Line::Blank);

    let any_timestamp = report
        .preparer
        .iter()
        .chain(&report.signatures)
        .any(|s| s.timestamp.is_some());
    if any_timestamp || !report.document_timestamps.is_empty() {
        lines.push(Line::Heading("Timestamps and long-term validation".into()));
        if !report.pades_level.is_empty() {
            lines.push(Line::Text(format!(
                "PAdES level: {} - {}",
                report.pades_level,
                pades_level_meaning(&report.pades_level)
            )));
        }
        for d in &report.document_timestamps {
            let t = &d.timestamp;
            lines.push(Line::Text(format!(
                "Document timestamp {}: {} by {} ({}), covering every revision up to {}{}",
                d.index,
                human_time(&t.time),
                if t.tsa_name.is_empty() {
                    "?"
                } else {
                    &t.tsa_name
                },
                if t.is_trusted() {
                    "trusted"
                } else {
                    "NOT trusted"
                },
                d.after_revision,
                if d.added_validation_data {
                    ", with validation data"
                } else {
                    ""
                }
            )));
        }
        if let Some(v) = &report.validation_data {
            lines.push(Line::Text(format!(
                "Validation data in the document: {} certificate(s), {} OCSP response(s), {} \
                 CRL(s)",
                v.certificates, v.ocsp_responses, v.crls
            )));
        }
        lines.push(Line::Blank);
    }

    if let Some(env) = env {
        let filled: Vec<_> = env.fields.iter().filter(|f| f.value.is_some()).collect();
        if !filled.is_empty() {
            lines.push(Line::Heading("Field values".into()));
            for f in filled {
                lines.push(Line::Text(format!(
                    "{} ({:?}, signer {}): {}",
                    f.id,
                    f.field_type,
                    f.assigned_signer,
                    f.value.as_deref().unwrap_or("")
                )));
            }
            lines.push(Line::Blank);
        }

        lines.push(Line::Heading("Audit trail".into()));
        for e in &env.audit_log {
            lines.push(Line::Text(format!(
                "#{} {} {:?} by {} [{}]",
                e.seq,
                human_time(&e.at),
                e.action,
                e.actor_name,
                e.actor_fingerprint.get(..8).unwrap_or(&e.actor_fingerprint)
            )));
            lines.push(Line::Text(format!("    {}", e.details)));
        }
        lines.push(Line::Blank);
    }

    if !report.messages.is_empty() {
        lines.push(Line::Heading("Problems".into()));
        for m in &report.messages {
            lines.push(Line::Text(format!("- {m}")));
        }
        lines.push(Line::Blank);
    }
    if !report.warnings.is_empty() {
        lines.push(Line::Heading("Warnings".into()));
        for w in &report.warnings {
            lines.push(Line::Text(format!("- {w}")));
        }
        lines.push(Line::Blank);
    }
    lines.push(Line::Text(
        "This certificate summarizes one verification of the signed PDF named above by its \
         SHA-256, with the trust settings of the computer that produced it. It is not itself \
         signed: to rely on it, verify that signed PDF with SignPDF. Other PDF software can \
         check that the file is intact, but not who signed it."
            .into(),
    ));

    layout_pdf(&lines)
}

/// A time-stamp authority's name, or `?`.
fn tsa_label(name: &str) -> &str {
    if name.is_empty() {
        "?"
    } else {
        name
    }
}

/// What a PAdES level means for the reader.
fn pades_level_meaning(level: &str) -> &'static str {
    match level {
        "B-T" => "every signature has trusted time evidence",
        "B-LT" => {
            "every signature has trusted time evidence, and the document holds what is needed to \
             check it without the authorities"
        }
        "B-LTA" => {
            "every signature has trusted time evidence, the document holds what is needed to \
             check it without the authorities, and a document timestamp seals that"
        }
        _ => "no signature has trusted time evidence",
    }
}

fn push_status(lines: &mut Vec<Line>, s: &SignatureStatus, indent: Option<&str>) {
    let ind = indent.unwrap_or("");
    let who = if s.idp_email.is_empty() {
        "(identity not verified)".to_string()
    } else {
        format!(
            "{} via {} ({})",
            s.idp_email,
            s.idp_issuer,
            if s.identity_trust.is_empty() {
                "untrusted"
            } else {
                &s.identity_trust
            }
        )
    };
    lines.push(Line::Text(format!(
        "{ind}{}: {} - {}",
        s.kind,
        if s.valid { "VALID" } else { "NOT VALID" },
        who
    )));
    // The level the verifier computed, and the evidence it rests on in plain words.
    if let Some(level) = s.level {
        let basis: Vec<String> = s.basis.iter().map(|b| b.describe()).collect();
        lines.push(Line::Text(format!(
            "{ind}Assurance: {level} {} ({})",
            level.name(),
            basis.join("; ")
        )));
    }
    let clock = match (&s.timestamp, s.time_source.as_str()) {
        (Some(t), "tsa") => format!("trusted timestamp, {}", tsa_label(&t.tsa_name)),
        _ => "signer's device clock, not independently confirmed".into(),
    };
    lines.push(Line::Text(format!(
        "{ind}Time: {} ({clock})   Verification code: {}",
        human_time(&s.signed_at),
        s.signature_code
    )));
    // A device time is bounded by the identity token's issue time and the first trusted
    // timestamp after the signature.
    if s.time_source != "tsa" {
        let after = if s.token_issued_at.is_empty() {
            String::new()
        } else {
            format!(
                "after {} (identity token issued) and ",
                human_time(&s.token_issued_at)
            )
        };
        let before = match &s.existed_before {
            Some(e) => format!(
                "before {} (trusted timestamp, {})",
                human_time(&e.time),
                tsa_label(&e.tsa_name)
            ),
            None => "before: no trusted timestamp yet".into(),
        };
        lines.push(Line::Text(format!("{ind}Made {after}{before}")));
    }
    if let (Some(date), Some(time)) = (s.local_signed_at.get(..10), s.local_signed_at.get(11..16)) {
        lines.push(Line::Text(format!(
            "{ind}Signer's local time: {date} {time} (UTC{})",
            s.utc_offset
        )));
    }
    if let Some(c) = &s.esign_consent {
        lines.push(Line::Text(format!(
            "{ind}Agreed to electronic records and signatures: disclosure {} ({}) at {}",
            c.version,
            c.lang,
            human_time(&c.at)
        )));
        lines.push(Line::Text(format!(
            "{ind}  Disclosure SHA-256: {}",
            c.sha256
        )));
        if let Some(r) = &c.ref_sha256 {
            lines.push(Line::Text(format!("{ind}  Reference text SHA-256: {r}")));
        }
    }
    if let Some(ts) = &s.timestamp {
        lines.push(Line::Text(format!(
            "{ind}RFC 3161 signature timestamp: {} by {} ({})",
            human_time(&ts.time),
            if ts.tsa_name.is_empty() {
                "?"
            } else {
                &ts.tsa_name
            },
            if ts.is_trusted() {
                "trusted"
            } else {
                "NOT trusted"
            }
        )));
    }
    if !s.valid && !s.detail.is_empty() {
        lines.push(Line::Text(format!("{ind}Detail: {}", s.detail)));
    }
}

/// Greedy word wrap at `width` characters.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let indent: String = s.chars().take_while(|c| *c == ' ').collect();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let mut word = word.to_string();
        while word.chars().count() > width {
            let head: String = word.chars().take(width).collect();
            let tail: String = word.chars().skip(width).collect();
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            out.push(format!("{indent}{head}"));
            word = tail;
        }
        if cur.chars().count() + word.chars().count() + 1 > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if cur.is_empty() {
            cur = format!("{indent}{word}");
        } else {
            cur.push(' ');
            cur.push_str(&word);
        }
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Lay out `lines` on US-Letter pages and serialize a complete PDF.
fn layout_pdf(lines: &[Line]) -> Vec<u8> {
    // (font resource, size, text) per physical line, then paginate.
    let mut phys: Vec<(&str, f32, String)> = Vec::new();
    for l in lines {
        match l {
            Line::Title(t) => phys.push(("F2", 16.0, t.clone())),
            Line::Heading(t) => phys.push(("F2", 11.0, t.clone())),
            Line::Text(t) => {
                for w in wrap(t, WRAP) {
                    phys.push(("F1", 9.0, w));
                }
            }
            Line::Blank => phys.push(("F1", 9.0, String::new())),
        }
    }
    let per_page = ((PAGE_H - 2.0 * MARGIN) / LINE) as usize;
    let pages: Vec<&[(&str, f32, String)]> = phys.chunks(per_page.max(1)).collect();
    let n_pages = pages.len().max(1);

    // Object layout: 1 catalog, 2 pages, 3 F1, 4 F2, then (page, content) pairs.
    let mut objects: Vec<Vec<u8>> = Vec::new();
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    let kids: Vec<String> = (0..n_pages).map(|i| format!("{} 0 R", 5 + 2 * i)).collect();
    objects.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            n_pages
        )
        .into_bytes(),
    );
    objects.push(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_vec(),
    );
    objects.push(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_vec(),
    );
    for (i, page_lines) in pages.iter().enumerate() {
        let mut cs = String::new();
        let mut y = PAGE_H - MARGIN;
        for (font, size, text) in page_lines.iter() {
            if !text.is_empty() {
                cs.push_str(&format!(
                    "BT /{font} {size} Tf {MARGIN} {y:.1} Td ({}) Tj ET\n",
                    // Names and titles keep their accents; a character the font lacks is `?`.
                    winansi_literal(text)
                ));
            }
            y -= LINE;
        }
        cs.push_str(&format!(
            "BT /F1 8 Tf {MARGIN} 30 Td (SignPDF certificate of completion - page {} of {}) Tj ET\n",
            i + 1,
            n_pages
        ));
        let content_id = 6 + 2 * i;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
        let mut stream = format!("<< /Length {} >>\nstream\n", cs.len()).into_bytes();
        stream.extend_from_slice(cs.as_bytes());
        stream.extend_from_slice(b"\nendstream");
        objects.push(stream);
    }

    let mut buf: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\nendobj\n");
    }
    let xref = buf.len();
    let size = objects.len() + 1;
    buf.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for off in offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_long_lines_and_words() {
        let w = wrap(&"word ".repeat(50), 20);
        assert!(w.iter().all(|l| l.chars().count() <= 20));
        let w = wrap(&"x".repeat(45), 20);
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn renders_a_parseable_multi_page_pdf() {
        let mut report = VerificationReport {
            document_sha256: "ab".repeat(32),
            ..Default::default()
        };
        for i in 0..200 {
            report
                .messages
                .push(format!("message {i} (with parens) and \\ backslash"));
        }
        let pdf = render(&report);
        let doc = lopdf::Document::load_mem(&pdf).expect("certificate must parse");
        assert!(doc.get_pages().len() >= 3);
    }
}
