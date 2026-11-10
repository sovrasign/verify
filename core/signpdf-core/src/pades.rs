//! PAdES signing: real PDF **incremental updates** + detached **CMS/PKCS#7**.
//!
//! This is the production signing path. Unlike the
//! [`crate::container`] append-log, output here is a standards-compliant signed PDF:
//! every signature is added as an incremental update that
//!
//! 1. adds an AcroForm signature field + `Widget` annotation,
//! 2. adds a signature dictionary with `/SubFilter /ETSI.CAdES.detached` (PAdES baseline), a
//!    correct `/ByteRange`, and a `/Contents` placeholder, and
//! 3. fills `/Contents` with a detached CMS `SignedData` (ECDSA-P256-SHA256) whose signed
//!    attributes carry the `messageDigest` of the two `ByteRange` spans and an ESS
//!    `signing-certificate-v2` binding the signer certificate (PAdES B-B). When a
//!    [`Timestamper`] is supplied, an RFC 3161 `signature-time-stamp` over the signature value is
//!    added as an unsigned attribute (PAdES B-T). A host whose TSA client is asynchronous (a
//!    browser `fetch`) signs with [`SignOptions::reserve_timestamp`] instead, asks the TSA for
//!    [`signature_timestamp_digest`], and adds the token with [`embed_signature_timestamp`].
//!
//! Verification ([`pades_verify`]) is hardened against the "PDF Insecurity" attack classes: the
//! `ByteRange` is bounds-checked, must start at 0, and its gap must be exactly the `/Contents`
//! hex string; [`audit_increment`] diffs consecutive revisions so callers can reject incremental
//! updates that modify content outside a narrow allow-list.
//!
//! Because each signature is an incremental update, the original bytes are never
//! rewritten, so earlier signatures stay valid when later signers add their own — the
//! property a multi-signer workflow needs. The whole stack is pure Rust (no OpenSSL / C
//! toolchain): `x509-cert` for the self-signed certificate and `cms` for the SignedData.

use std::time::Duration;

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode, SliceReader};
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::digest::{absorb, DocumentDigests};
use crate::ink::{drawing_ops, is_filled_paths, is_ink, SignatureDrawing};
// The hand-drawn signature's types and limits, which `pades` has always exported.
pub use crate::ink::{validate_ink, InkStrokes, MAX_INK_POINTS, MAX_INK_STROKES};
use spki::AlgorithmIdentifierOwned;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::crypto::KeyPair;
use crate::error::{Result, SignPdfError};
use crate::util::{now_pdf_date, now_unix};

/// Hex characters reserved for the `/Contents` placeholder of a signature without a timestamp,
/// above the size of its CMS ([`reserved_contents_hex`]). The CMS is measured on a trial built over a
/// dummy digest; the real one differs only in its ECDSA signature, whose DER encoding varies by a
/// few bytes.
const CONTENTS_HEADROOM_HEX: usize = 256;
/// The placeholder is a multiple of this.
const CONTENTS_ROUND_HEX: usize = 1024;
/// Placeholder size when an RFC 3161 token (often 5–7 KB with its chain) is embedded.
const CONTENTS_HEX_LEN_TIMESTAMPED: usize = 49152;

const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// id-aa-signingCertificateV2 (RFC 5035).
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// id-aa-signatureTimeStampToken (RFC 3161 Appendix A).
const OID_SIGNATURE_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Obtains an RFC 3161 timestamp token for a SHA-256 digest. The core stays transport-agnostic:
/// hosts implement this with whatever HTTP stack they have (the CLI uses `ureq`).
pub trait Timestamper {
    /// Return the DER `TimeStampToken` (a CMS `ContentInfo`) whose message imprint is `digest`.
    fn timestamp(&self, digest: &[u8; 32]) -> Result<Vec<u8>>;
}

/// A text value drawn onto a page inside the signer's increment (field values are visible on the
/// page and covered by that signer's signature).
#[derive(Debug, Clone)]
pub struct FieldText {
    /// Stable name recorded as the annotation `/NM` (e.g. the field id).
    pub name: String,
    /// 0-based page index.
    pub page_index: u32,
    /// `[x1, y1, x2, y2]` rectangle in default user space.
    pub rect: [f32; 4],
    /// The text to draw (single line; a character the built-in font lacks is drawn as `?`).
    /// With a [`FieldMark`], the caption drawn beside the mark.
    pub text: String,
    /// The mark drawn at the left of the rectangle, for checkbox and radio fields.
    pub mark: FieldMark,
    /// Wrap the text over several lines (it may contain line breaks) instead of drawing one line.
    pub multiline: bool,
}

/// The box or circle drawn before a checkbox or radio caption, and whether it is selected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FieldMark {
    /// Plain text (text, date, stamp).
    #[default]
    None,
    Checkbox {
        checked: bool,
    },
    Radio {
        selected: bool,
    },
}

/// The `/Contents` of a field annotation: the text itself or, for a marked field, a plain-text
/// rendition of the mark followed by the caption (`[X] I agree`, `( ) By post`). The verifier
/// recomputes this from the envelope, so the annotation cannot claim a different answer.
pub fn field_contents(text: &str, mark: FieldMark, multiline: bool) -> String {
    contents_with(text, mark, multiline, drawable)
}

/// [`field_contents`] as it was written before the engine drew the whole WinAnsi range, when
/// every character outside printable ASCII became `?`. The verifier accepts this rendition too,
/// so that documents signed by those versions still verify.
pub fn legacy_field_contents(text: &str, mark: FieldMark, multiline: bool) -> String {
    contents_with(text, mark, multiline, |c| {
        if (' '..='~').contains(&c) {
            c
        } else {
            '?'
        }
    })
}

/// The annotation text of a field, each character of it passed through `draw`.
fn contents_with(text: &str, mark: FieldMark, multiline: bool, draw: fn(char) -> char) -> String {
    let full = match mark {
        FieldMark::None => text.to_string(),
        FieldMark::Checkbox { checked } => format!("[{}] {text}", if checked { 'X' } else { ' ' }),
        FieldMark::Radio { selected } => format!("({}) {text}", if selected { 'o' } else { ' ' }),
    };
    if multiline {
        multiline_with(&full, draw)
    } else {
        full.chars().take(120).map(draw).collect()
    }
}

/// Longest text a multi-line field holds, in characters.
pub const MAX_MULTILINE_CHARS: usize = 2000;

/// Multi-line text as it is drawn and recorded: line breaks kept (`\n` only), tabs as spaces,
/// every other character as the built-in font draws it (`?` for one it lacks), capped at
/// [`MAX_MULTILINE_CHARS`].
pub fn multiline_text(s: &str) -> String {
    multiline_with(s, drawable)
}

fn multiline_with(s: &str, draw: fn(char) -> char) -> String {
    s.replace("\r\n", "\n")
        .chars()
        .map(|c| match c {
            '\n' => '\n',
            '\r' => '\n',
            '\t' => ' ',
            c => draw(c),
        })
        .take(MAX_MULTILINE_CHARS)
        .collect()
}

/// The characters of WinAnsiEncoding codes `0x80..=0x9F` (the part where Windows-1252 departs
/// from Latin-1), `'\0'` where the encoding defines none:
/// `€ ‚ ƒ „ … † ‡ ˆ ‰ Š ‹ Œ Ž`, then `‘ ’ “ ” • – — ˜ ™ š › œ ž Ÿ`.
const WINANSI_80_9F: [char; 32] = [
    '\u{20AC}', '\0', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\0', '\u{017D}', '\0', '\0',
    '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}',
    '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\0', '\u{017E}', '\u{0178}',
];

/// The code of `c` in WinAnsiEncoding, the encoding of the Helvetica font that all engine text
/// is drawn with: printable ASCII, the Latin-1 letters and signs (`é`, `ü`, `ñ`, `ß`, `¿`…) and
/// the Windows-1252 additions (`€`, `Š`, `œ`, curly quotes, dashes). `None` for every other
/// character: other scripts need an embedded font, which the engine does not have.
pub(crate) fn winansi_code(c: char) -> Option<u8> {
    match c as u32 {
        0x20..=0x7E | 0xA0..=0xFF => Some(c as u32 as u8),
        0 => None,
        _ => WINANSI_80_9F
            .iter()
            .position(|&w| w == c)
            .map(|i| 0x80 + i as u8),
    }
}

/// `c` as the font draws it: itself when the encoding has it; a space for the typographic spaces
/// it lacks (thin, em, ideographic…), a no-break space for the two of them that do not break
/// (figure and narrow no-break, as French puts before `;` `:` `!` `?` and inside numbers);
/// `?` for anything else.
pub(crate) fn drawable(c: char) -> char {
    match c {
        '\u{2007}' | '\u{202F}' => '\u{A0}',
        '\u{2000}'..='\u{200A}' | '\u{205F}' | '\u{3000}' => ' ',
        c if winansi_code(c).is_some() => c,
        _ => '?',
    }
}

/// `s` as it is drawn on one line: cut to `max` characters, each as [`drawable`] gives it.
fn drawable_caption(s: &str, max: usize) -> String {
    s.chars().take(max).map(drawable).collect()
}

/// Helvetica advance widths, in 1/1000 em, by WinAnsiEncoding code from `0x20` to `0xFF`, one
/// row per 16 codes (from Adobe's metrics for the standard-14 font; `0` where the encoding has
/// no character). Used to wrap and fit text exactly.
#[rustfmt::skip]
const HELVETICA_WIDTHS: [u16; 224] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // sp ! " # $ % & ' ( ) * + , - . /
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, // 0-9 : ; < = > ?
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, // @ A-O
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, // P-Z [ \ ] ^ _
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, // ` a-o
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0, // p-z { | } ~
    556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0, // 0x80: € ‚ ƒ „ … † ‡ ˆ ‰ Š ‹ Œ Ž
    0, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667, // 0x90: ‘ ’ “ ” • – — ˜ ™ š › œ ž Ÿ
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, // 0xA0: nbsp ¡ ¢ £ ¤ ¥ ¦ § ¨ © ª « ¬ shy ® ¯
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, // 0xB0: ° ± ² ³ ´ µ ¶ · ¸ ¹ º » ¼ ½ ¾ ¿
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, // 0xC0: À Á Â Ã Ä Å Æ Ç È É Ê Ë Ì Í Î Ï
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, // 0xD0: Ð Ñ Ò Ó Ô Õ Ö × Ø Ù Ú Û Ü Ý Þ ß
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, // 0xE0: à á â ã ä å æ ç è é ê ë ì í î ï
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500, // 0xF0: ð ñ ò ó ô õ ö ÷ ø ù ú û ü ý þ ÿ
];

/// Width of `s` set in Helvetica at `size` points.
fn text_width(s: &str, size: f32) -> f32 {
    let units: u32 = s
        .chars()
        .map(|c| match winansi_code(c) {
            Some(code) => HELVETICA_WIDTHS[code as usize - 0x20] as u32,
            // Drawn as `?`.
            None => 556,
        })
        .sum();
    units as f32 * size / 1000.0
}

/// The largest size, at most `size`, at which `s` is no wider than `width` (never below 4 pt).
pub(crate) fn fit_size(s: &str, size: f32, width: f32) -> f32 {
    let natural = text_width(s, size);
    if natural <= width || natural <= 0.0 {
        size
    } else {
        (size * width / natural).max(4.0)
    }
}

/// Break `text` into lines no wider than `width` at `size` points: at its own line breaks, then
/// between words, and inside a word only when the word alone is too wide.
fn wrap_lines(text: &str, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split(' ') {
            let candidate = if line.is_empty() {
                word.to_string()
            } else {
                format!("{line} {word}")
            };
            if text_width(&candidate, size) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            // The word starts a line; split it by characters if it is wider than the field.
            for c in word.chars() {
                let mut grown = line.clone();
                grown.push(c);
                if !line.is_empty() && text_width(&grown, size) > width {
                    lines.push(std::mem::replace(&mut line, c.to_string()));
                } else {
                    line = grown;
                }
            }
        }
        lines.push(line);
    }
    lines
}

/// Padding between a text field's edge and its text, in points.
const FIELD_PAD: f32 = 2.0;
/// Line height as a multiple of the font size.
const LEADING: f32 = 1.2;

/// Lay `text` out in a `w`×`h` multi-line field: the font size (10 pt, reduced in half-point
/// steps down to 5 pt until everything fits) and the wrapped lines. `None` when the text does
/// not fit even at the smallest size, so it is never silently cut off.
pub fn layout_multiline(text: &str, w: f32, h: f32) -> Option<(f32, Vec<String>)> {
    let text = multiline_text(text);
    let (inner_w, inner_h) = (w - 2.0 * FIELD_PAD, h - 2.0 * FIELD_PAD);
    if inner_w <= 0.0 || inner_h <= 0.0 {
        return None;
    }
    let mut size = 10.0_f32;
    while size >= 5.0 {
        let lines = wrap_lines(&text, size, inner_w);
        if lines.len() as f32 * size * LEADING <= inner_h + 0.01 {
            return Some((size, lines));
        }
        size -= 0.5;
    }
    None
}

/// Everything [`pades_sign_with`] needs beyond the input PDF and key.
#[derive(Default)]
pub struct SignOptions<'a> {
    pub appearance: SignAppearance,
    /// Attachment written into the same increment (covered by the signature).
    pub embed: Option<EmbeddedFile>,
    /// Field values to draw as read-only annotations in the same increment.
    pub field_texts: Vec<FieldText>,
    /// When set, a PAdES B-T signature timestamp is embedded.
    pub timestamper: Option<&'a dyn Timestamper>,
    /// Reserve room in `/Contents` for a signature timestamp that the host adds afterwards with
    /// [`embed_signature_timestamp`]: the two-step B-T signing of hosts whose TSA client is
    /// asynchronous (a browser's `fetch`), while [`Timestamper`] is synchronous. The output is a
    /// complete B-B signature until then. Implied by `timestamper`.
    pub reserve_timestamp: bool,
}

/// A standard-14 Helvetica font object body, reused by every visible appearance stream.
const HELV_FONT_BODY: &[u8] =
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";

fn pades(msg: impl Into<String>) -> SignPdfError {
    SignPdfError::Pades(msg.into())
}

/// Image streams larger than this are not kept in full when the engine parses a document.
const LARGE_IMAGE: usize = 64 * 1024;

/// What a [`ImageBytes::Drop`] parse keeps of a large image's bytes.
const IMAGE_PLACEHOLDER: &[u8] = b"image bytes not loaded";

/// What a parse keeps of a large image's bytes (see [`load_for_inspection`]).
#[derive(Clone, Copy)]
enum ImageBytes {
    /// A fixed placeholder: for parses that never look at image content.
    Drop,
    /// The SHA-256 of the bytes: for parses whose objects are compared ([`audit_increment`]),
    /// where comparing digests is as strict as comparing bytes.
    Digest,
}

/// Whether a stream dictionary describes an image XObject: `/Subtype /Image`, with no `/Type` or
/// `/Type /XObject`. These are the only streams [`load_for_inspection`] filters.
///
/// The `/Type` condition keeps every stream whose bytes lopdf or the engine interprets out of
/// the filter's reach, whatever else its dictionary claims: an object stream (`/Type /ObjStm`,
/// which lopdf unpacks after the filter has run: filtered, every object in it would vanish from
/// the engine's view while other readers still see them), a cross-reference stream, and an
/// embedded file (`/Type /EmbeddedFile`, whose `/Subtype` is a MIME type and may well read
/// `/Image`). An entry that is not a direct name never matches, so the bytes are kept. See
/// `docs/SECURITY_REVIEW_LOAD_FILTER.md`.
fn is_image_xobject(dict: &Dictionary) -> bool {
    let subtype_is_image = matches!(dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Image");
    let type_allows_image = match dict.get(b"Type") {
        Err(_) => true,
        Ok(Object::Name(n)) => n == b"XObject",
        Ok(_) => false,
    };
    subtype_is_image && type_allows_image
}

/// A document parsed by [`load_for_inspection`]. Its large images hold a placeholder or a digest
/// instead of their bytes, so it is read-only: it dereferences to the parsed [`Document`] but
/// never gives out `&mut Document`, so it can be neither changed nor saved (every lopdf writer
/// takes `&mut self`). The engine builds its output from the input bytes and from dictionaries
/// copied out of the parse, which never contain streams.
struct Inspected(Document);

impl std::ops::Deref for Inspected {
    type Target = Document;

    fn deref(&self) -> &Document {
        &self.0
    }
}

/// Parse `pdf` for the engine's own use (signing, verification, reading the envelope, page
/// geometry): like `Document::load_mem`, except that the bytes of every image XObject larger
/// than [`LARGE_IMAGE`] are dropped or replaced by their digest as they are read.
///
/// The engine never reads image bytes and never writes a parsed document back; it only compares
/// objects between revisions. Images are most of a large document (scans, photos), and before
/// this a 50 MB document cost about 50 MB per parse, two at once when an increment was audited,
/// which made signing peak at 5x the document in WebAssembly (P0 signer-page spike).
///
/// Only image XObjects are touched ([`is_image_xobject`]): object streams, cross-reference
/// streams and embedded files keep their bytes, and appearance streams, whose bytes
/// [`audit_increment`] reads, must be form XObjects (an appearance stream that claims to be an
/// image is reported by [`annotation_shape`]). lopdf resolves an indirect `/Length` while it
/// parses when it can; a stream whose length it cannot resolve then is read after the filter
/// has run, so it keeps its bytes (a missed saving, not a difference in behaviour).
///
/// What this changes for the increment audit, and why it is as strict as comparing bytes, is in
/// the security review `docs/SECURITY_REVIEW_LOAD_FILTER.md`.
fn load_for_inspection(pdf: &[u8], images: ImageBytes) -> lopdf::Result<Inspected> {
    // lopdf 0.42 calls the filter on every top-level object as it is read, before it unpacks
    // object streams, and keeps the object as the filter left it (only a `None` return, which
    // drops the object, matters there). It then calls the filter on every object unpacked from
    // an object stream and keeps the returned copy; those are never streams (lopdf parses them
    // as direct objects), so a stream returns a placeholder instead of a copy. The filter never
    // returns `None`: it removes no object. `filter_keeps_every_object_lopdf_loads` pins this.
    fn filter(id: ObjectId, obj: &mut Object, images: ImageBytes) -> Option<(ObjectId, Object)> {
        if matches!(obj, Object::Stream(_)) {
            shrink_large_image(obj, images);
            return Some((id, Object::Null));
        }
        Some((id, obj.clone()))
    }
    fn drop_images(id: ObjectId, obj: &mut Object) -> Option<(ObjectId, Object)> {
        filter(id, obj, ImageBytes::Drop)
    }
    fn digest_images(id: ObjectId, obj: &mut Object) -> Option<(ObjectId, Object)> {
        filter(id, obj, ImageBytes::Digest)
    }
    let f: lopdf::FilterFunc = match images {
        ImageBytes::Drop => drop_images,
        ImageBytes::Digest => digest_images,
    };
    Document::load_mem_with_options(pdf, lopdf::LoadOptions::with_filter(f)).map(Inspected)
}

#[cfg(any(test, feature = "test-issuer"))]
thread_local! {
    /// Objects a modified signing client writes into its own revision, under the signature
    /// ([`crate::workflow::testing::sign_with_extra_objects`]). Empty except in that call.
    pub(crate) static EXTRA_OBJECTS: std::cell::RefCell<Vec<(u32, Vec<u8>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// What [`load_for_inspection`] does to each object lopdf reads: the bytes of an image XObject
/// larger than [`LARGE_IMAGE`] are dropped or replaced by their digest.
fn shrink_large_image(obj: &mut Object, images: ImageBytes) {
    if let Object::Stream(s) = obj {
        if is_image_xobject(&s.dict) && s.content.len() > LARGE_IMAGE {
            let length = i64::try_from(s.content.len()).unwrap_or(i64::MAX);
            s.content = match images {
                // Not empty: lopdf re-reads empty streams from the file.
                ImageBytes::Drop => IMAGE_PLACEHOLDER.to_vec(),
                ImageBytes::Digest => Sha256::digest(&s.content).to_vec(),
            };
            // The dictionary keeps the real length. lopdf already sets `/Length` to the number
            // of bytes it read; setting it here makes it the engine's rule: a filtered stream
            // (`/Length` over 64 KiB, 22 or 32 bytes of content) can never equal a stream read in
            // full, whose `/Length` is its content's length.
            s.dict.set("Length", Object::Integer(length));
        }
    }
}

/// Text rendered into a visible signature appearance: a `Signed by:` label above the signer's
/// name, and a footer line carrying the verification `code`, signing time, and provider.
#[derive(Debug, Clone)]
pub struct SignatureCaption {
    /// Verified signer name (or email) shown beneath the `Signed by:` label.
    pub signer_name: String,
    /// Short, human-comparable verification code (e.g. the first 8 hex of the signer fingerprint).
    pub code: String,
    /// Human-readable signing time, e.g. `2026-06-24 18:00 UTC`.
    pub signed_at: String,
    /// Identity-provider label, e.g. `google`.
    pub issuer: String,
}

/// Where and how a signature is shown in the page.
#[derive(Debug, Clone)]
pub struct SignAppearance {
    /// Human name recorded in the signature dictionary `/Name` and the certificate CN.
    pub name: String,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// 0-based page index the signature field lives on.
    pub page_index: u32,
    /// `[x1, y1, x2, y2]` field rectangle; `None` makes the signature invisible.
    pub rect: Option<[f32; 4]>,
    /// When set (and `rect` is a non-degenerate box), a visible `/AP` appearance stream is drawn
    /// inside the field showing who signed and the verification code. Covered by the signer's
    /// `ByteRange`, so the visible chrome is as tamper-evident as the signature itself.
    pub caption: Option<SignatureCaption>,
    /// The signer's drawing (hand-drawn strokes or a typed signature's filled paths), drawn at
    /// the left of the visible appearance, which keeps the verified caption. Ignored without a
    /// `caption`, and when it cannot be drawn ([`SignatureDrawing::validate`]).
    pub ink: Option<SignatureDrawing>,
}

impl Default for SignAppearance {
    fn default() -> Self {
        Self {
            name: "SignPDF Signer".to_string(),
            reason: None,
            location: None,
            page_index: 0,
            rect: None,
            caption: None,
            ink: None,
        }
    }
}

/// A file to embed as a PDF attachment (an `EmbeddedFile` stream + `Filespec`) inside a
/// signing or preparation increment, so workflow metadata travels within the signed bytes.
///
/// When embedded during [`pades_sign`], the attachment is covered by that signer's
/// `ByteRange`, so tampering with the workflow metadata breaks the PAdES signature.
#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    /// File name recorded in the name tree and the `Filespec` (`/F`, `/UF`).
    pub name: String,
    pub data: Vec<u8>,
    /// MIME type, e.g. `application/json`.
    pub mime: String,
    /// PDF 2.0 `/AFRelationship` value, e.g. `Data`.
    pub relationship: String,
    pub description: String,
}

/// Outcome of verifying a single embedded PAdES signature with our own reader.
#[derive(Debug, Clone, Default)]
pub struct PadesValidation {
    pub field_name: String,
    pub signer_cn: String,
    pub byte_range: [i64; 4],
    /// Uncompressed SEC1 bytes of the signer certificate's public key, so a caller can link
    /// the standards signature back to a workflow signer identity (fingerprint).
    pub signer_pubkey_sec1: Vec<u8>,
    /// True when the signature's `ByteRange` reaches the end of the file (i.e. nothing was
    /// appended after it). A non-final signer in a multi-signature file reports `false`.
    pub covers_to_eof: bool,
    /// The `messageDigest` signed attribute equals the SHA-256 of the signed spans.
    pub digest_matches: bool,
    /// The CMS signature verifies against the embedded certificate's public key.
    pub signature_valid: bool,
    /// End offset of the signed range (`ByteRange[2] + ByteRange[3]`): the length of the revision
    /// this signature covers.
    pub covered_end: usize,
    /// `/SubFilter` of the signature dictionary.
    pub sub_filter: String,
    /// Raw CMS signature value (what a signature timestamp's imprint covers).
    pub signature_value: Vec<u8>,
    /// DER `TimeStampToken` from the `signature-time-stamp` unsigned attribute (PAdES B-T).
    pub signature_timestamp: Option<Vec<u8>>,
    /// Set when the signature is structurally malformed (it is then never valid).
    pub structure_error: Option<String>,
    /// The CMS is byte-for-byte the canonical structure SignPDF emits (no unsigned field can be
    /// altered without detection). Third-party signatures are usually not canonical; the SignPDF
    /// workflow requires it of every revision.
    pub canonical: bool,
}

impl PadesValidation {
    pub fn is_valid(&self) -> bool {
        self.structure_error.is_none() && self.digest_matches && self.signature_valid
    }
}

// --- signing -----------------------------------------------------------------------------

/// Sign `pdf` as `signer`, returning a new PDF with one more PAdES signature appended.
///
/// When `embed` is `Some`, the attachment is written into the same incremental update and
/// is therefore covered by this signature's `ByteRange` — the mechanism the SignPDF
/// workflow uses to carry its (tamper-evident) envelope inside the signed document.
pub fn pades_sign(
    pdf: &[u8],
    signer: &KeyPair,
    app: &SignAppearance,
    embed: Option<&EmbeddedFile>,
) -> Result<Vec<u8>> {
    pades_sign_with(
        pdf,
        signer,
        &SignOptions {
            appearance: app.clone(),
            embed: embed.cloned(),
            ..Default::default()
        },
    )
}

/// Resolve a 0-based page index to its object id.
fn page_id_at(doc: &Document, page_index: u32) -> Result<ObjectId> {
    doc.get_pages()
        .get(&(page_index + 1))
        .copied()
        .ok_or_else(|| pades(format!("page index {page_index} is out of range")))
}

/// The page's current `/Annots` list (resolving an indirect array).
fn page_annots(doc: &Document, page: &Dictionary) -> Vec<Object> {
    match page.get(b"Annots") {
        Ok(Object::Array(a)) => a.clone(),
        Ok(Object::Reference(r)) => doc
            .get_object(*r)
            .and_then(|o| o.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Sign `pdf` with full control over the increment (see [`SignOptions`]).
pub fn pades_sign_with(pdf: &[u8], signer: &KeyPair, opts: &SignOptions<'_>) -> Result<Vec<u8>> {
    let increment = pades_sign_increment(&DocumentDigests::new(pdf), signer, opts)?;
    Ok(appended(pdf, &increment))
}

/// [`pades_sign_with`], returning only the increment: the bytes the signature appends to the
/// document `digests` hashes. The signed document is that document followed by the increment
/// ([`appended`]); a host that only uploads the increment never holds a second copy of the
/// document. The new signature's digest continues from the document's hash in `digests`, so the
/// document is not hashed again.
pub fn pades_sign_increment(
    digests: &DocumentDigests<'_>,
    signer: &KeyPair,
    opts: &SignOptions<'_>,
) -> Result<Vec<u8>> {
    let pdf = digests.bytes();
    let app = &opts.appearance;
    let embed = opts.embed.as_ref();
    if !pdf.starts_with(b"%PDF-") {
        return Err(pades("input is not a PDF"));
    }
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;

    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .map_err(|e| pades(format!("trailer has no /Root: {e}")))?;
    let mut catalog = doc
        .get_object(root_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad catalog: {e}")))?
        .clone();

    // An invisible signature may sit on any page; a visible one must name an existing page.
    let page_id = if app.rect.is_some() {
        page_id_at(&doc, app.page_index)?
    } else {
        page_id_at(&doc, app.page_index).or_else(|_| page_id_at(&doc, 0))?
    };

    let mut next_id = first_free_number(&doc);
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        (id, 0u16)
    };

    let widget_id = alloc();
    let sig_id = alloc();
    let embed_ids: Option<(ObjectId, ObjectId)> = embed.map(|_| (alloc(), alloc()));
    // Visible appearance (form XObject) when a caption and a non-degenerate rectangle are
    // supplied; otherwise the field stays invisible (no `/AP`).
    let appearance_id: Option<ObjectId> = match (&app.caption, app.rect) {
        (Some(_), Some(r)) if (r[2] - r[0]) > 1.0 && (r[3] - r[1]) > 1.0 => Some(alloc()),
        _ => None,
    };
    // Field-value annotations: (annotation id, appearance id, page id, field).
    let mut field_ids: Vec<(ObjectId, ObjectId, ObjectId, &FieldText)> = Vec::new();
    for ft in &opts.field_texts {
        let pid = page_id_at(&doc, ft.page_index)?;
        field_ids.push((alloc(), alloc(), pid, ft));
    }
    let font_id: Option<ObjectId> = if appearance_id.is_some() || !field_ids.is_empty() {
        Some(alloc())
    } else {
        None
    };

    // Reuse an existing AcroForm (multi-signature) or create one.
    let mut need_catalog_rewrite = false;
    let acroform_id;
    let mut acroform: Dictionary;
    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(r)) => {
            let r = *r;
            acroform = doc
                .get_object(r)
                .and_then(|o| o.as_dict())
                .map_err(|e| pades(format!("bad AcroForm: {e}")))?
                .clone();
            acroform_id = r;
        }
        Ok(Object::Dictionary(d)) => {
            acroform = d.clone();
            acroform_id = alloc();
            need_catalog_rewrite = true;
        }
        _ => {
            acroform = Dictionary::new();
            acroform_id = alloc();
            need_catalog_rewrite = true;
        }
    }

    // /Fields may be a direct array or — commonly, in real-world PDFs — an
    // indirect reference to one. Resolve before reading; otherwise `as_array`
    // fails on the Reference and we silently drop every pre-existing form field.
    let mut fields = acroform
        .get(b"Fields")
        .ok()
        .and_then(|o| resolve(&doc, o))
        .and_then(|o| o.as_array().ok())
        .cloned()
        .unwrap_or_default();
    let field_no = fields.len() + 1;
    fields.push(Object::Reference(widget_id));
    acroform.set("Fields".as_bytes().to_vec(), Object::Array(fields));
    acroform.set("SigFlags".as_bytes().to_vec(), Object::Integer(3));

    // Collect every page this increment touches, appending the new annotations to each.
    let mut pages: std::collections::BTreeMap<ObjectId, (Dictionary, Vec<Object>)> =
        std::collections::BTreeMap::new();
    let mut touch = |pid: ObjectId, annot: ObjectId| -> Result<()> {
        let entry = match pages.entry(pid) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(v) => {
                let dict = doc
                    .get_object(pid)
                    .and_then(|o| o.as_dict())
                    .map_err(|e| pades(format!("bad page object: {e}")))?
                    .clone();
                let annots = page_annots(&doc, &dict);
                v.insert((dict, annots))
            }
        };
        entry.1.push(Object::Reference(annot));
        Ok(())
    };
    touch(page_id, widget_id)?;
    for (annot_id, _, pid, _) in &field_ids {
        touch(*pid, *annot_id)?;
    }

    if need_catalog_rewrite {
        catalog.set(
            "AcroForm".as_bytes().to_vec(),
            Object::Reference(acroform_id),
        );
    }
    // (The embedded envelope is written as standalone objects below; it is intentionally
    // not referenced from the catalog /Names or /AF so that re-embedding it in later
    // increments does not alter the catalog of an already-signed revision. The latest
    // envelope is located by scanning the embedded Filespecs — see `read_attachment`.)

    // Self-signed certificate for this signer.
    let cert = self_signed_cert(signer, &app.name)?;

    // Everything needed from the parsed document has been copied out (only the trailer is used
    // below). Free it before building the output, so the parse and the output copy of a large
    // document are never in memory together.
    let trailer = doc.trailer.clone();
    drop(doc);

    // Build the incremental update.
    let contents_hex_len = if opts.timestamper.is_some() || opts.reserve_timestamp {
        CONTENTS_HEX_LEN_TIMESTAMPED
    } else {
        reserved_contents_hex(build_cms(signer, &cert, &[0; 32])?.len())
    };
    let mut out = Increment::after(pdf, contents_hex_len + embed.map_or(0, |e| e.data.len()));
    let mut xref: Vec<(ObjectId, usize)> = Vec::new();

    let rect = app.rect.unwrap_or([0.0, 0.0, 0.0, 0.0]);
    let ap_frag = match appearance_id {
        Some(ap_id) => format!(" /AP << /N {} 0 R >>", ap_id.0),
        None => String::new(),
    };
    let widget_body = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature{field_no}) \
         /Rect [{} {} {} {}] /V {} 0 R /P {} 0 R /F 132{} >>",
        fmt_num(rect[0]),
        fmt_num(rect[1]),
        fmt_num(rect[2]),
        fmt_num(rect[3]),
        sig_id.0,
        page_id.0,
        ap_frag,
    );
    write_indirect(&mut out, &mut xref, widget_id, widget_body.as_bytes());

    let mut acroform_body = Vec::new();
    write_object(&mut acroform_body, &Object::Dictionary(acroform));
    write_indirect(&mut out, &mut xref, acroform_id, &acroform_body);

    for (pid, (mut dict, annots)) in pages {
        dict.set("Annots".as_bytes().to_vec(), Object::Array(annots));
        let mut page_body = Vec::new();
        write_object(&mut page_body, &Object::Dictionary(dict));
        write_indirect(&mut out, &mut xref, pid, &page_body);
    }

    if need_catalog_rewrite {
        let mut cat_body = Vec::new();
        write_object(&mut cat_body, &Object::Dictionary(catalog));
        write_indirect(&mut out, &mut xref, root_id, &cat_body);
    }

    if let (Some(e), Some((ef_id, fs_id))) = (embed, embed_ids) {
        write_embedded_file(&mut out, &mut xref, ef_id, fs_id, e);
    }

    if let Some(font_id) = font_id {
        write_indirect(&mut out, &mut xref, font_id, HELV_FONT_BODY);
    }
    if let (Some(caption), Some(ap_id), Some(font_id)) = (&app.caption, appearance_id, font_id) {
        let w = rect[2] - rect[0];
        let h = rect[3] - rect[1];
        let ink = app.ink.as_ref().filter(|ink| ink.validate().is_ok());
        write_signature_appearance(&mut out, &mut xref, ap_id, font_id, w, h, caption, ink);
    }
    for (annot_id, ap_id, pid, ft) in &field_ids {
        let font_id = font_id.expect("allocated when field texts exist");
        write_field_text(&mut out, &mut xref, *annot_id, *ap_id, font_id, *pid, ft);
    }
    #[cfg(any(test, feature = "test-issuer"))]
    EXTRA_OBJECTS.with(|extra| {
        for (num, body) in extra.borrow().iter() {
            write_indirect(&mut out, &mut xref, (*num, 0), body);
        }
    });

    // Signature object, written by hand so we can capture inner byte offsets.
    let sig_offset = out.pos();
    xref.push((sig_id, sig_offset));
    out.extend_from_slice(format!("{} 0 obj\n", sig_id.0).as_bytes());
    out.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
    out.extend_from_slice(format!(" /Name {}", pdf_text_string(&app.name)).as_bytes());
    out.extend_from_slice(format!(" /M ({})", now_pdf_date()).as_bytes());
    if let Some(r) = &app.reason {
        out.extend_from_slice(format!(" /Reason {}", pdf_text_string(r)).as_bytes());
    }
    if let Some(l) = &app.location {
        out.extend_from_slice(format!(" /Location {}", pdf_text_string(l)).as_bytes());
    }
    out.extend_from_slice(b" /ByteRange [");
    let br_off = out.pos();
    out.extend_from_slice(b"0000000000 0000000000 0000000000 0000000000");
    out.extend_from_slice(b"] /Contents ");
    let contents_lt = out.pos();
    out.push(b'<');
    out.fill(contents_hex_len, b'0');
    out.push(b'>');
    out.extend_from_slice(b" >>\nendobj\n");

    // Cross-reference table + trailer for the increment.
    let prev_startxref = find_last_startxref(pdf)?;
    let size = next_id;
    finish_increment(&mut out, &mut xref, size, root_id, prev_startxref, &trailer);

    // Patch ByteRange now that the file length is final.
    let file_len = out.pos();
    let a = contents_lt; // first signed span: [0, a)
    let start2 = contents_lt + 1 + contents_hex_len + 1; // first byte after '>'
    let len2 = file_len - start2;
    out.put10(br_off, 0);
    out.put10(br_off + 11, a as u64);
    out.put10(br_off + 22, start2 as u64);
    out.put10(br_off + 33, len2 as u64);

    // Digest the two signed spans, continuing from the input's hash ([0, a) is the input followed
    // by the increment's first bytes), and embed the CMS.
    let digest = digests.extended(&[out.range(pdf.len(), a), out.range(start2, file_len)]);

    let mut cms_der = build_cms(signer, &cert, &digest)?;
    if let Some(ts) = opts.timestamper {
        cms_der = add_signature_timestamp(&cms_der, ts)?;
    }
    let cms_hex = hex::encode(&cms_der);
    if cms_hex.len() > contents_hex_len {
        return Err(pades("CMS signature exceeds reserved /Contents space"));
    }
    out.write_at(contents_lt + 1, cms_hex.as_bytes());

    Ok(out.into_bytes())
}

/// The `/Contents` placeholder for a CMS of `der_len` bytes without a timestamp: its hex, the
/// headroom, rounded up. A SignPDF CMS is about 850 bytes, so 2048 characters, where a fixed
/// 16384 used to be reserved: 14 KB of zeros in every revision.
fn reserved_contents_hex(der_len: usize) -> usize {
    (der_len * 2 + CONTENTS_HEADROOM_HEX).div_ceil(CONTENTS_ROUND_HEX) * CONTENTS_ROUND_HEX
}

/// Add a PAdES B-T `signature-time-stamp` (over the SHA-256 of the signature value) to a built
/// detached CMS, as an unsigned attribute of its single signerInfo.
fn add_signature_timestamp(cms_der: &[u8], ts: &dyn Timestamper) -> Result<Vec<u8>> {
    let digest = cms_signature_digest(cms_der)?;
    let token = ts.timestamp(&digest)?;
    cms_with_signature_timestamp(cms_der, &token)
}

/// The SHA-256 of a detached CMS's (single) signature value: the imprint its signature
/// timestamp must carry.
fn cms_signature_digest(cms_der: &[u8]) -> Result<[u8; 32]> {
    let ci = ContentInfo::from_der(cms_der).map_err(|e| pades(format!("re-read cms: {e}")))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| pades(format!("signed data: {e}")))?;
    let si = sd
        .signer_infos
        .0
        .as_ref()
        .first()
        .ok_or_else(|| pades("CMS has no signerInfo"))?;
    Ok(Sha256::digest(si.signature.as_bytes()).into())
}

/// `cms_der` with `token` (a DER `TimeStampToken`) as its signerInfo's only unsigned attribute.
/// Refuses a token whose imprint is not the SHA-256 of this signature value.
fn cms_with_signature_timestamp(cms_der: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    use cms::signed_data::{SignerInfo, SignerInfos, UnsignedAttributes};
    use der::asn1::SetOfVec;
    use der::Any;

    let mut ci = ContentInfo::from_der(cms_der).map_err(|e| pades(format!("re-read cms: {e}")))?;
    let mut sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| pades(format!("signed data: {e}")))?;
    // Adding the attribute rebuilds the SignedData, so it must re-encode to the bytes it was read
    // from. x509-cert rewrites some certificate fields when it re-encodes (validity dates before
    // 2050 written as GeneralizedTime), and a changed certificate breaks the signature's
    // signing-certificate hash for other validators: refuse rather than alter it.
    if !Any::encode_from(&sd).is_ok_and(|a| a == ci.content) {
        return Err(pades(
            "this signature's CMS cannot be rebuilt without changing its bytes \
             (a certificate in it uses an encoding the CMS library rewrites), \
             so it cannot take a signature timestamp",
        ));
    }
    let mut infos: Vec<SignerInfo> = sd.signer_infos.0.iter().cloned().collect();
    if infos.len() != 1 {
        return Err(pades("CMS must have exactly one signerInfo"));
    }
    let si = &mut infos[0];
    let digest: [u8; 32] = Sha256::digest(si.signature.as_bytes()).into();
    // Refuse a token that does not bind this signature value.
    crate::timestamp::verify_token(token, &digest)?;
    let value = Any::from_der(token).map_err(|e| pades(format!("timestamp token: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| pades(format!("timestamp attr: {e}")))?;
    let attr = x509_cert::attr::Attribute {
        oid: OID_SIGNATURE_TIMESTAMP,
        values,
    };
    si.unsigned_attrs = Some(
        UnsignedAttributes::try_from(vec![attr])
            .map_err(|e| pades(format!("unsigned attrs: {e}")))?,
    );
    sd.signer_infos =
        SignerInfos(SetOfVec::try_from(infos).map_err(|e| pades(format!("signer infos: {e}")))?);
    ci.content = Any::encode_from(&sd).map_err(|e| pades(format!("encode sd: {e}")))?;
    ci.to_der().map_err(|e| pades(format!("encode cms: {e}")))
}

/// The last signature of `pdf` and the `/Contents` hex range it occupies, if it can still take a
/// signature timestamp: it must be valid, cover the whole file and have no timestamp yet.
fn last_signature_awaiting_timestamp(
    pdf: &[u8],
) -> Result<(PadesValidation, std::ops::Range<usize>)> {
    let last = pades_verify(pdf)?
        .pop()
        .ok_or_else(|| pades("the document has no signature to timestamp"))?;
    if let Some(e) = &last.structure_error {
        return Err(pades(format!("the last signature is malformed: {e}")));
    }
    if !last.is_valid() {
        return Err(pades("the last signature is not valid"));
    }
    // The verifier also requires the CMS in exactly the form SignPDF writes; a timestamp added
    // to any other would give a document it refuses.
    if !last.canonical {
        return Err(pades(
            "the last signature's CMS is not in SignPDF's canonical form",
        ));
    }
    if !last.covers_to_eof {
        return Err(pades(
            "the last signature does not cover the whole file (something was added after it)",
        ));
    }
    if last.signature_timestamp.is_some() {
        return Err(pades(
            "the last signature already has a signature timestamp",
        ));
    }
    let (l1, s2, _) = checked_byte_range(&last.byte_range, pdf.len())?;
    // `verify_one` checked that the gap is exactly `<hex>`.
    Ok((last, l1 + 1..s2 - 1))
}

/// The SHA-256 imprint a PAdES B-T signature timestamp of `pdf`'s last signature must carry
/// (the hash of its signature value). Build the TSA request with
/// [`crate::timestamp::build_request`], then add the token with [`embed_signature_timestamp`].
pub fn signature_timestamp_digest(pdf: &[u8]) -> Result<[u8; 32]> {
    let (last, _) = last_signature_awaiting_timestamp(pdf)?;
    Ok(Sha256::digest(&last.signature_value).into())
}

/// Add an RFC 3161 signature timestamp (`token`, a DER `TimeStampToken`) to the last signature
/// of `pdf`, which must have been made with room for one ([`SignOptions::reserve_timestamp`]).
///
/// The timestamp is an unsigned attribute of the CMS inside `/Contents`, outside the signed
/// byte range, so the output has the same length and every signature stays valid; only the
/// last signature changes from B-B to B-T. The key that made the signature is not needed. A
/// token whose imprint is not the hash of that signature value is refused.
pub fn embed_signature_timestamp(pdf: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    let (_, gap) = last_signature_awaiting_timestamp(pdf)?;
    let mut out = pdf.to_vec();
    with_signature_timestamp(&mut out[gap], token)?;
    Ok(out)
}

/// Rewrite `gap`, the `/Contents` hex of a signature with no timestamp yet, to hold its CMS with
/// `token` added as its signature timestamp, padded with zeros to the same length.
fn with_signature_timestamp(gap: &mut [u8], token: &[u8]) -> Result<()> {
    let contents = hex::decode(&*gap).map_err(|_| pades("/Contents is not hex"))?;
    let mut reader = SliceReader::new(&contents).map_err(|e| pades(format!("cms reader: {e}")))?;
    let ci = ContentInfo::decode(&mut reader).map_err(|e| pades(format!("cms decode: {e}")))?;
    let cms_der = ci.to_der().map_err(|e| pades(format!("encode cms: {e}")))?;
    let cms_hex = hex::encode(cms_with_signature_timestamp(&cms_der, token)?);
    if cms_hex.len() > gap.len() {
        return Err(pades(
            "the signature has no room for a timestamp: sign with room reserved for one",
        ));
    }
    gap[..cms_hex.len()].copy_from_slice(cms_hex.as_bytes());
    gap[cms_hex.len()..].fill(b'0');
    Ok(())
}

/// The signature dictionary SignPDF writes, up to its `/ByteRange` ([`pades_sign_increment`]).
const SIGNATURE_DICT_START: &[u8] =
    b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached";

/// The signature at the end of `increment`, appended to the document `head` hashes, if it can
/// still take a signature timestamp ([`last_signature_awaiting_timestamp`] for a document held
/// apart), with its `/Contents` hex range in `increment`.
///
/// The increment is not parsed as a PDF (that would need the whole document in one buffer): its
/// last `/ByteRange` must be a SignPDF signature dictionary's, in the form the engine writes, with
/// `/Contents` right after it. Then the same checks as for a whole document: the range starts at
/// 0, covers `head` and the increment to the end and leaves out exactly that `/Contents`, whose
/// CMS verifies over the signed bytes and has no timestamp yet.
fn increment_signature_awaiting_timestamp(
    head: &DocumentDigests<'_>,
    increment: &[u8],
) -> Result<(PadesValidation, std::ops::Range<usize>)> {
    const BYTE_RANGE: &[u8] = b"/ByteRange [";
    const CONTENTS: &[u8] = b"] /Contents ";
    let not_signed =
        || pades("the increment does not end with a SignPDF signature (a signer's revision)");
    let base = head.bytes().len();
    let file_len = base + increment.len();
    let at = increment
        .windows(BYTE_RANGE.len())
        .rposition(|w| w == BYTE_RANGE)
        .ok_or_else(not_signed)?;
    // The dictionary the range belongs to: the last object header before it.
    let dict_start = increment[..at]
        .windows(5)
        .rposition(|w| w == b" obj\n")
        .map(|p| p + 5)
        .ok_or_else(not_signed)?;
    if !increment[dict_start..at].starts_with(SIGNATURE_DICT_START) {
        return Err(not_signed());
    }
    let numbers_at = at + BYTE_RANGE.len();
    let close = increment[numbers_at..]
        .iter()
        .position(|b| *b == b']')
        .map(|p| numbers_at + p)
        .ok_or_else(not_signed)?;
    let br: Vec<i64> = std::str::from_utf8(&increment[numbers_at..close])
        .map_err(|_| not_signed())?
        .split(' ')
        .map(|n| n.parse::<i64>().unwrap_or(-1))
        .collect();
    let (l1, s2, l2) = checked_byte_range(&br, file_len)?;
    // `/Contents` follows the range, and the range's gap is exactly its `<hex>`.
    if !increment[close..].starts_with(CONTENTS) || base + close + CONTENTS.len() != l1 {
        return Err(pades("the signature's ByteRange gap is not its /Contents"));
    }
    if s2 + l2 != file_len {
        return Err(pades(
            "the last signature does not cover the whole file (something was added after it)",
        ));
    }
    if increment[l1 - base] != b'<' || increment[s2 - base - 1] != b'>' {
        return Err(pades("ByteRange gap is not the /Contents hex string"));
    }
    let gap_range = l1 - base + 1..s2 - base - 1;
    let gap = &increment[gap_range.clone()];
    if !gap.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(pades("ByteRange gap contains non-hex bytes"));
    }
    let contents = hex::decode(gap).map_err(|_| pades("ByteRange gap is not valid hex"))?;
    let computed = head.extended(&[&increment[..l1 - base], &increment[s2 - base..]]);
    let last = validated_cms(SignedSpans {
        byte_range: [br[0], br[1], br[2], br[3]],
        covered_end: s2 + l2,
        file_len,
        contents: &contents,
        gap,
        computed: &computed,
        sub_filter: "ETSI.CAdES.detached".into(),
    })?;
    if !last.is_valid() {
        return Err(pades("the last signature is not valid"));
    }
    // The verifier also requires the CMS in exactly the form SignPDF writes; a timestamp added
    // to any other would give a document it refuses.
    if !last.canonical {
        return Err(pades(
            "the last signature's CMS is not in SignPDF's canonical form",
        ));
    }
    if last.signature_timestamp.is_some() {
        return Err(pades(
            "the last signature already has a signature timestamp",
        ));
    }
    Ok((last, gap_range))
}

/// [`signature_timestamp_digest`] for a document held apart: `increment`, which ends with a
/// signature, appended to the document `head` hashes. Neither is copied into a whole document.
pub fn increment_signature_timestamp_digest(
    head: &DocumentDigests<'_>,
    increment: &[u8],
) -> Result<[u8; 32]> {
    let (last, _) = increment_signature_awaiting_timestamp(head, increment)?;
    Ok(Sha256::digest(&last.signature_value).into())
}

/// [`embed_signature_timestamp`] for a document held apart, as
/// [`increment_signature_timestamp_digest`]: the new increment, the same length, whose last
/// signature carries `token`.
pub fn embed_increment_signature_timestamp(
    head: &DocumentDigests<'_>,
    increment: &[u8],
    token: &[u8],
) -> Result<Vec<u8>> {
    let (_, gap) = increment_signature_awaiting_timestamp(head, increment)?;
    let mut out = increment.to_vec();
    with_signature_timestamp(&mut out[gap], token)?;
    Ok(out)
}

/// Embed `embed` as a PDF attachment via a plain incremental update (no signature).
///
/// Used at preparation time and for declines, where the workflow envelope must travel with
/// the document but no cryptographic PDF signature is applied in that step. The attachment is
/// written as standalone objects (an `EmbeddedFile` stream + a `Filespec`) and is deliberately
/// **not** referenced from the catalog `/Names` or `/AF`. Keeping the catalog untouched means
/// embedding a newer envelope in a later increment never modifies an already-signed revision's
/// catalog, so earlier PAdES signatures stay cleanly valid. The latest envelope is found by
/// scanning the embedded `Filespec`s (see [`read_attachment`]).
pub fn embed_attachment(pdf: &[u8], embed: &EmbeddedFile) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(pades("input is not a PDF"));
    }
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .map_err(|e| pades(format!("trailer has no /Root: {e}")))?;

    let mut next_id = first_free_number(&doc);
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        (id, 0u16)
    };
    let ef_id = alloc();
    let fs_id = alloc();

    let mut out = Increment::after(pdf, embed.data.len());
    let mut xref: Vec<(ObjectId, usize)> = Vec::new();
    write_embedded_file(&mut out, &mut xref, ef_id, fs_id, embed);

    let prev_startxref = find_last_startxref(pdf)?;
    finish_increment(
        &mut out,
        &mut xref,
        next_id,
        root_id,
        prev_startxref,
        &doc.trailer,
    );
    drop(doc);
    Ok(out.appended_to(pdf))
}

/// Stamp a visible, read-only "document id" label onto the lower-left of the first page via a
/// self-contained [`/Subtype /Stamp`] annotation that carries **its own** `/AP` appearance and
/// font. Nothing in the page's inherited resources is rewritten, so the stamp can never corrupt
/// the page content. The annotation is flagged Print + ReadOnly + Locked (`/F 196`).
///
/// Applied at preparation time as a plain incremental update (no signature). Before any signature
/// it is, like the rest of the prepared document, not yet cryptographically protected; once a
/// signer's `ByteRange` covers it, the visible document id is as tamper-evident as the signature.
pub fn stamp_document_id(pdf: &[u8], label: &str) -> Result<Vec<u8>> {
    stamp_document_id_lines(pdf, &[label.to_string()])
}

/// [`stamp_document_id`] with one line of text per entry of `lines` (the document id, then, from
/// envelope schema version 7, the 'verify at' address: [`crate::workflow::document_id_lines`]).
/// One line draws exactly what [`stamp_document_id`] draws.
pub fn stamp_document_id_lines(pdf: &[u8], lines: &[String]) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(pades("input is not a PDF"));
    }
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .map_err(|e| pades(format!("trailer has no /Root: {e}")))?;

    let pages = doc.get_pages();
    let page_id = pages
        .values()
        .next()
        .copied()
        .ok_or_else(|| pades("document has no pages"))?;
    let media = page_media_box(&doc, page_id);
    let mut page = doc
        .get_object(page_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad page object: {e}")))?
        .clone();

    let mut next_id = first_free_number(&doc);
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        (id, 0u16)
    };
    let annot_id = alloc();
    let ap_id = alloc();
    let font_id = alloc();

    let stamp = document_id_stamp(lines);
    let (text, box_w, box_h) = (&stamp.text, stamp.w, stamp.h);
    let x0 = media[0] + 18.0;
    let y0 = media[1] + 18.0;
    let x1 = x0 + box_w;
    let y1 = y0 + box_h;

    let mut out = Increment::after(pdf, 0);
    let mut xref: Vec<(ObjectId, usize)> = Vec::new();

    let annot_body = format!(
        "<< /Type /Annot /Subtype /Stamp /Rect [{} {} {} {}] /F 196 /P {} 0 R \
         /Name /SignPDFDocID /T (SignPDF Document ID) /Contents ({}) /AP << /N {} 0 R >> >>",
        fmt_num(x0),
        fmt_num(y0),
        fmt_num(x1),
        fmt_num(y1),
        page_id.0,
        esc_pdf_str(text),
        ap_id.0,
    );
    write_indirect(&mut out, &mut xref, annot_id, annot_body.as_bytes());

    write_form_xobject(
        &mut out,
        &mut xref,
        ap_id,
        font_id,
        box_w,
        box_h,
        &stamp.content,
    );

    write_indirect(&mut out, &mut xref, font_id, HELV_FONT_BODY);

    let mut annots: Vec<Object> = match page.get(b"Annots") {
        Ok(Object::Array(a)) => a.clone(),
        Ok(Object::Reference(r)) => doc
            .get_object(*r)
            .and_then(|o| o.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    annots.push(Object::Reference(annot_id));
    page.set("Annots".as_bytes().to_vec(), Object::Array(annots));

    let mut page_body = Vec::new();
    write_object(&mut page_body, &Object::Dictionary(page));
    write_indirect(&mut out, &mut xref, page_id, &page_body);

    let prev_startxref = find_last_startxref(pdf)?;
    finish_increment(
        &mut out,
        &mut xref,
        next_id,
        root_id,
        prev_startxref,
        &doc.trailer,
    );
    drop(doc);
    Ok(out.appended_to(pdf))
}

/// The document-id stamp: its text, its natural size and its content stream.
struct DocumentIdStamp {
    text: String,
    w: f32,
    h: f32,
    content: String,
}

/// What the engine draws for the document-id stamp of `lines`. The single definition of the
/// stamp: the preparer writes it and the verifier compares against it. One line is the stamp of
/// every envelope before schema version 7 (and of later ones without a 'verify at' address), and
/// must keep drawing byte for byte what it always drew; more lines stack from the top, and the
/// annotation's text joins them with " - ".
fn document_id_stamp(lines: &[String]) -> DocumentIdStamp {
    let font_size = 8.0_f32;
    let pad = 4.0_f32;
    let rows: Vec<String> = lines.iter().map(|l| ascii_caption(l, 64)).collect();
    let longest = rows.iter().map(String::len).max().unwrap_or(0);
    let box_w = (longest as f32) * (font_size * 0.5) + 2.0 * pad;
    if rows.len() <= 1 {
        let text = rows.into_iter().next().unwrap_or_default();
        let box_h = font_size + 2.0 * pad;
        let content = format!(
            "q
0.96 0.96 0.86 rg
0 0 {bw} {bh} re
f
0.55 0.5 0.2 RG
0.8 w
0.5 0.5 {bwi} {bhi} re
S
BT
/Helv {fs} Tf
0.15 0.15 0.15 rg
{pad} {ty} Td
({txt}) Tj
ET
Q
",
            bw = fmt_num(box_w),
            bh = fmt_num(box_h),
            bwi = fmt_num(box_w - 1.0),
            bhi = fmt_num(box_h - 1.0),
            fs = fmt_num(font_size),
            pad = fmt_num(pad),
            ty = fmt_num(pad + 1.0),
            txt = esc_pdf_str(&text),
        );
        return DocumentIdStamp {
            text,
            w: box_w,
            h: box_h,
            content,
        };
    }
    let leading = font_size + 2.0;
    let box_h = font_size + 2.0 * pad + leading * (rows.len() - 1) as f32;
    let mut text_ops = String::new();
    for (i, row) in rows.iter().enumerate() {
        if i == 0 {
            let ty = pad + 1.0 + leading * (rows.len() - 1) as f32;
            text_ops.push_str(&format!(
                "{} {} Td
",
                fmt_num(pad),
                fmt_num(ty)
            ));
        } else {
            text_ops.push_str(&format!(
                "0 {} Td
",
                fmt_num(-leading)
            ));
        }
        text_ops.push_str(&format!(
            "({}) Tj
",
            esc_pdf_str(row)
        ));
    }
    let content = format!(
        "q
0.96 0.96 0.86 rg
0 0 {bw} {bh} re
f
0.55 0.5 0.2 RG
0.8 w
0.5 0.5 {bwi} {bhi} re
S
BT
/Helv {fs} Tf
0.15 0.15 0.15 rg
{text_ops}ET
Q
",
        bw = fmt_num(box_w),
        bh = fmt_num(box_h),
        bwi = fmt_num(box_w - 1.0),
        bhi = fmt_num(box_h - 1.0),
        fs = fmt_num(font_size),
    );
    DocumentIdStamp {
        text: rows.join(" - "),
        w: box_w,
        h: box_h,
        content,
    }
}

/// Read the bytes of the most recently embedded attachment named `name`.
///
/// The envelope is not referenced from the catalog (so signing it again later does not perturb
/// earlier signatures), so we scan every `Filespec` object whose name matches and return the
/// one with the highest object id — i.e. the one added in the latest incremental update.
pub fn read_attachment(pdf: &[u8], name: &str) -> Result<Vec<u8>> {
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    attachment_in(&doc, name)
}

/// [`read_attachment`] of a parsed document.
fn attachment_in(doc: &Document, name: &str) -> Result<Vec<u8>> {
    let mut best: Option<(ObjectId, ObjectId)> = None; // (filespec id, embedded-file id)
    for (id, obj) in &doc.objects {
        let Ok(dict) = obj.as_dict() else { continue };
        let is_filespec = matches!(dict.get(b"Type"), Ok(Object::Name(n)) if n == b"Filespec");
        if !is_filespec {
            continue;
        }
        let matches_name = match dict.get(b"F") {
            Ok(Object::String(s, _)) => s.as_slice() == name.as_bytes(),
            _ => false,
        };
        if !matches_name {
            continue;
        }
        let Some(ef) = resolved_dict(doc, dict.get(b"EF").ok()) else {
            continue;
        };
        let Ok(ef_ref) = ef.get(b"F").and_then(|o| o.as_reference()) else {
            continue;
        };
        if best.map(|(fid, _)| id.0 > fid.0).unwrap_or(true) {
            best = Some((*id, ef_ref));
        }
    }

    let (_, ef_ref) = best.ok_or_else(|| pades(format!("attachment '{name}' not found")))?;
    let stream = doc
        .get_object(ef_ref)
        .and_then(|o| o.as_stream())
        .map_err(|e| pades(format!("embedded file stream: {e}")))?;
    // The parse does not keep a large image's bytes: a stream that claims to be an image
    // XObject is refused, never returned as its placeholder. (The engine writes its attachments
    // with `/Type /EmbeddedFile`, which the filter never touches, whatever their MIME type.)
    if is_image_xobject(&stream.dict) {
        return Err(pades(format!(
            "attachment '{name}' is an image stream, not an embedded file"
        )));
    }
    attachment_bytes(stream)
}

fn self_signed_cert(signer: &KeyPair, common_name: &str) -> Result<Certificate> {
    let signing: &SigningKey = signer.signing_key();
    let spki = SubjectPublicKeyInfoOwned::from_key(signing.verifying_key())
        .map_err(|e| pades(format!("spki: {e}")))?;
    let serial = SerialNumber::from(rand_serial());
    // From the engine's clock rather than `Validity::from_now`, which reads `SystemTime` (absent
    // on wasm32-unknown-unknown). Whole seconds; the certificate profile picks the encoding when
    // it is written, as it does for `from_now`.
    let now = Duration::from_secs(u64::try_from(now_unix()).unwrap_or(0));
    let time = |d: Duration| {
        der::asn1::GeneralizedTime::from_unix_duration(d)
            .map(x509_cert::time::Time::from)
            .map_err(|e| pades(format!("validity: {e}")))
    };
    let validity = Validity::new(
        time(now)?,
        time(now + Duration::from_secs(60 * 60 * 24 * 3650))?,
    );
    let dn = format!("CN={},O=SignPDF Self-Signed", sanitize_dn(common_name));
    let subject: Name = dn.parse().map_err(|e| pades(format!("dn: {e}")))?;
    let builder = CertificateBuilder::new(SelfSignedLeaf(subject), serial, validity, spki)
        .map_err(|e| pades(format!("cert builder: {e}")))?;
    builder
        .build::<_, DerSignature>(signing)
        .map_err(|e| pades(format!("cert sign: {e}")))
}

/// Certificate profile for a self-signed end-entity certificate: issuer = subject, and the
/// extensions x509-cert 0.2's `Profile::Leaf` added (subject and authority key identifiers,
/// `cA: false`, key usage digitalSignature + nonRepudiation). x509-cert 0.3 replaced that enum
/// with this trait; keeping the same extensions keeps certificates as they were.
pub(crate) struct SelfSignedLeaf(pub(crate) Name);

impl BuilderProfile for SelfSignedLeaf {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.0.clone()
    }

    // Each extension is built against the ones before it (to_extension sees the list), so they
    // are pushed one at a time.
    #[allow(clippy::vec_init_then_push)]
    fn build_extensions(
        &self,
        spk: spki::SubjectPublicKeyInfoRef<'_>,
        issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        use x509_cert::ext::pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        };
        use x509_cert::ext::ToExtension;
        let subject = tbs.subject();
        let mut extensions = Vec::new();
        extensions.push(SubjectKeyIdentifier::try_from(spk)?.to_extension(subject, &extensions)?);
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk)?.to_extension(subject, &extensions)?,
        );
        extensions.push(
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(subject, &extensions)?,
        );
        extensions.push(
            KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation)
                .to_extension(subject, &extensions)?,
        );
        Ok(extensions)
    }
}

/// DER-encode a short TLV (lengths < 128 only, enough for the ESS attribute).
fn short_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    debug_assert!(value.len() < 128);
    let mut v = vec![tag, value.len() as u8];
    v.extend_from_slice(value);
    v
}

/// The ESS `signing-certificate-v2` attribute (RFC 5035) binding `cert` by its SHA-256 hash, as
/// PAdES baseline signatures require: `SEQUENCE { SEQUENCE OF { SEQUENCE { OCTET STRING hash } } }`
/// (hashAlgorithm defaults to SHA-256 and is omitted).
pub(crate) fn signing_certificate_v2(cert: &Certificate) -> Result<x509_cert::attr::Attribute> {
    use der::asn1::SetOfVec;
    let cert_der = cert
        .to_der()
        .map_err(|e| pades(format!("encode cert: {e}")))?;
    let hash = Sha256::digest(&cert_der);
    let ess_cert_id = short_tlv(0x30, &short_tlv(0x04, &hash));
    let certs = short_tlv(0x30, &ess_cert_id);
    let value = short_tlv(0x30, &certs);
    let any = der::Any::from_der(&value).map_err(|e| pades(format!("ess attr: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(any)
        .map_err(|e| pades(format!("ess attr: {e}")))?;
    Ok(x509_cert::attr::Attribute {
        oid: OID_SIGNING_CERTIFICATE_V2,
        values,
    })
}

fn build_cms(signer: &KeyPair, cert: &Certificate, digest: &[u8]) -> Result<Vec<u8>> {
    let signing: &SigningKey = signer.signing_key();
    let sha256_alg = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let econtent = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate().issuer().clone(),
        serial_number: cert.tbs_certificate().serial_number().clone(),
    });
    let mut signer_info = SignerInfoBuilder::new(sid, sha256_alg.clone(), &econtent, Some(digest))
        .map_err(|e| pades(format!("signer info: {e}")))?;
    signer_info
        .add_signed_attribute(signing_certificate_v2(cert)?)
        .map_err(|e| pades(format!("signed attr: {e}")))?;
    let ci: ContentInfo = SignedDataBuilder::new(&econtent)
        .add_digest_algorithm(sha256_alg)
        .map_err(|e| pades(format!("digest alg: {e}")))?
        .add_certificate(CertificateChoices::Certificate(cert.clone()))
        .map_err(|e| pades(format!("add cert: {e}")))?
        .add_signer_info::<SigningKey, DerSignature>(signer_info, signing)
        .map_err(|e| pades(format!("add signer: {e}")))?
        .build()
        .map_err(|e| pades(format!("build signed data: {e}")))?;
    ci.to_der().map_err(|e| pades(format!("encode cms: {e}")))
}

// --- verification ------------------------------------------------------------------------

/// Validate every embedded PAdES signature in `pdf` with our own reader, ordered by the length of
/// the revision each one covers (oldest first).
///
/// A structurally malformed signature (bad `ByteRange`, `/Contents` not exactly filling the
/// `ByteRange` gap, undecodable CMS) does not abort verification: it is reported as an invalid
/// [`PadesValidation`] with [`PadesValidation::structure_error`] set.
pub fn pades_verify(pdf: &[u8]) -> Result<Vec<PadesValidation>> {
    Ok(pades_verify_all(pdf)?.signatures)
}

/// Everything [`pades_verify_all`] reads from a document in one parse.
#[derive(Debug, Clone, Default)]
pub struct PadesScan {
    /// Every signature (`/Type /Sig`), as [`pades_verify`] reports them.
    pub signatures: Vec<PadesValidation>,
    /// Every document timestamp (`/Type /DocTimeStamp`), ordered by the length of the revision
    /// each covers.
    pub document_timestamps: Vec<DocumentTimestampValidation>,
    /// The document's validation data (the catalog's `/DSS`), when it has some.
    pub dss: Option<Dss>,
}

/// [`pades_verify`], plus every document timestamp and the validation data (DSS), from one parse.
pub fn pades_verify_all(pdf: &[u8]) -> Result<PadesScan> {
    pades_verify_all_with(&DocumentDigests::new(pdf))
}

/// [`pades_verify_all`] of the document `digests` hashes, taking every signed range's digest from
/// it: the document is hashed once, however many signatures it carries, and the caller can reuse
/// the same digests afterwards.
pub fn pades_verify_all_with(digests: &DocumentDigests<'_>) -> Result<PadesScan> {
    let pdf = digests.bytes();
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let mut scan = PadesScan::default();

    for (id, obj) in &doc.objects {
        let Ok(dict) = obj.as_dict() else { continue };
        let kind = match dict.get(b"Type") {
            Ok(Object::Name(n)) => n.as_slice(),
            _ => continue,
        };
        if dict.get(b"ByteRange").is_err() {
            continue;
        }
        let field_name = field_name_for(&doc, *id).unwrap_or_else(|| "<unnamed>".to_string());
        match kind {
            b"Sig" => {
                let v = match verify_one(digests, dict) {
                    Ok(mut v) => {
                        v.field_name = field_name;
                        v
                    }
                    Err(e) => PadesValidation {
                        field_name,
                        structure_error: Some(e.to_string()),
                        ..PadesValidation::default()
                    },
                };
                scan.signatures.push(v);
            }
            b"DocTimeStamp" => {
                let v = match verify_document_timestamp(digests, dict) {
                    Ok(mut v) => {
                        v.field_name = field_name;
                        v
                    }
                    Err(e) => DocumentTimestampValidation {
                        field_name,
                        // Still placed by its range, when that much is readable, so the revision
                        // it claims to end is known.
                        covered_end: signed_gap(pdf, dict).map_or(0, |g| g.s2 + g.l2),
                        structure_error: Some(e.to_string()),
                        ..DocumentTimestampValidation::default()
                    },
                };
                scan.document_timestamps.push(DocumentTimestampValidation {
                    object_id: *id,
                    ..v
                });
            }
            _ => {}
        }
    }
    scan.signatures.sort_by_key(|v| v.covered_end);
    scan.document_timestamps.sort_by_key(|v| v.covered_end);
    scan.dss = read_dss_of(&doc).map(|(_, refs)| refs.data);
    Ok(scan)
}

/// Parse and bounds-check a `/ByteRange`, returning `(len1, start2, len2)` (start1 is always 0).
fn checked_byte_range(br: &[i64], file_len: usize) -> Result<(usize, usize, usize)> {
    if br.len() != 4 || br.iter().any(|&v| v < 0) {
        return Err(pades("malformed ByteRange"));
    }
    let to_usize = |v: i64| usize::try_from(v).map_err(|_| pades("ByteRange value too large"));
    let (s1, l1, s2, l2) = (
        to_usize(br[0])?,
        to_usize(br[1])?,
        to_usize(br[2])?,
        to_usize(br[3])?,
    );
    if s1 != 0 {
        return Err(pades("ByteRange must start at offset 0"));
    }
    let end = s2
        .checked_add(l2)
        .ok_or_else(|| pades("ByteRange overflows"))?;
    if l1 < 1 || s2 < l1 + 2 || end > file_len {
        return Err(pades("ByteRange is out of bounds or overlapping"));
    }
    Ok((l1, s2, l2))
}

/// The signed spans and unsigned gap of a signature or document-timestamp dictionary.
struct SignedGap<'a> {
    byte_range: [i64; 4],
    /// Length of the first signed span (`[0, l1)`), which ends at the gap's `<`.
    l1: usize,
    /// Start and length of the second signed span, which begins after the gap's `>`.
    s2: usize,
    l2: usize,
    /// The `/Contents` bytes (decoded from the gap's hex).
    contents: Vec<u8>,
    /// The gap's hex digits.
    gap: &'a [u8],
}

/// Read and check `dict`'s `/ByteRange` and `/Contents`: the range is in bounds and starts at 0,
/// and its gap is exactly `<hex>` holding this dictionary's `/Contents`, so no unsigned byte can
/// hide content (signature-wrapping attacks).
fn signed_gap<'a>(pdf: &'a [u8], dict: &Dictionary) -> Result<SignedGap<'a>> {
    let br: Vec<i64> = dict
        .get(b"ByteRange")
        .and_then(|o| o.as_array())
        .map_err(|e| pades(format!("ByteRange: {e}")))?
        .iter()
        .map(|o| o.as_i64().unwrap_or(-1))
        .collect();
    let (l1, s2, l2) = checked_byte_range(&br, pdf.len())?;
    let byte_range = [br[0], br[1], br[2], br[3]];

    let contents = match dict.get(b"Contents") {
        Ok(Object::String(bytes, _)) => bytes.clone(),
        _ => return Err(pades("signature has no /Contents")),
    };

    if pdf[l1] != b'<' || pdf[s2 - 1] != b'>' {
        return Err(pades("ByteRange gap is not the /Contents hex string"));
    }
    let gap = &pdf[l1 + 1..s2 - 1];
    if !gap.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(pades("ByteRange gap contains non-hex bytes"));
    }
    let gap_bytes = hex::decode(gap).map_err(|_| pades("ByteRange gap is not valid hex"))?;
    if gap_bytes != contents {
        return Err(pades(
            "ByteRange gap does not hold this signature's /Contents",
        ));
    }
    Ok(SignedGap {
        byte_range,
        l1,
        s2,
        l2,
        contents,
        gap,
    })
}

fn verify_one(digests: &DocumentDigests<'_>, sig: &Dictionary) -> Result<PadesValidation> {
    let pdf = digests.bytes();
    let SignedGap {
        byte_range,
        l1,
        s2,
        l2,
        contents,
        gap,
    } = signed_gap(pdf, sig)?;

    // Recompute the digest over the two signed spans.
    let computed = digests
        .spans(l1, s2, l2)
        .ok_or_else(|| pades("ByteRange is out of bounds or overlapping"))?;
    let sub_filter = match sig.get(b"SubFilter") {
        Ok(Object::Name(n)) => String::from_utf8_lossy(n).to_string(),
        _ => String::new(),
    };
    validated_cms(SignedSpans {
        byte_range,
        covered_end: s2 + l2,
        file_len: pdf.len(),
        contents: &contents,
        gap,
        computed: &computed,
        sub_filter,
    })
}

/// A signature's signed spans and `/Contents`, read from the file, with the digest of the spans.
struct SignedSpans<'a> {
    byte_range: [i64; 4],
    /// `ByteRange[2] + ByteRange[3]`.
    covered_end: usize,
    file_len: usize,
    /// The `/Contents` bytes (the decoded gap).
    contents: &'a [u8],
    /// The gap's hex digits.
    gap: &'a [u8],
    /// SHA-256 of the signed spans.
    computed: &'a [u8; 32],
    sub_filter: String,
}

/// Check the detached CMS in a signature's `/Contents` against the digest of its signed spans:
/// what [`verify_one`] reports, once it has read the signature from the file.
fn validated_cms(signed: SignedSpans<'_>) -> Result<PadesValidation> {
    let SignedSpans {
        byte_range,
        covered_end,
        file_len,
        contents,
        gap,
        computed,
        sub_filter,
    } = signed;
    // Parse the detached CMS (tolerating the trailing zero padding in /Contents).
    let mut reader = SliceReader::new(contents).map_err(|e| pades(format!("cms reader: {e}")))?;
    let ci = ContentInfo::decode(&mut reader).map_err(|e| pades(format!("cms decode: {e}")))?;
    // Everything after the CMS structure is unsigned padding; it must be canonical zeros so the
    // gap cannot carry hidden data and the signed file is not malleable.
    let cms_len = usize::try_from(
        ci.encoded_len()
            .map_err(|e| pades(format!("cms length: {e}")))?,
    )
    .map_err(|_| pades("cms length overflow"))?;
    if contents
        .get(cms_len..)
        .is_some_and(|pad| pad.iter().any(|b| *b != 0))
    {
        return Err(pades(
            "/Contents padding after the CMS signature is not zero",
        ));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| pades(format!("signed data: {e}")))?;

    let cert = sd
        .certificates
        .as_ref()
        .and_then(|set| {
            set.0.iter().find_map(|c| match c {
                CertificateChoices::Certificate(cert) => Some(cert.clone()),
                _ => None,
            })
        })
        .ok_or_else(|| pades("CMS has no certificate"))?;
    let signer_cn = first_cn(&cert).unwrap_or_else(|| "<unknown>".to_string());

    let si = sd
        .signer_infos
        .0
        .as_ref()
        .first()
        .ok_or_else(|| pades("CMS has no signerInfo"))?;

    // messageDigest signed attribute must equal the recomputed digest.
    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| pades("signerInfo has no signed attributes"))?;
    let mut digest_matches = false;
    for attr in signed_attrs.iter() {
        if attr.oid == OID_MESSAGE_DIGEST {
            if let Some(val) = attr.values.iter().next() {
                if let Ok(os) = val.decode_as::<OctetString>() {
                    digest_matches = os.as_bytes() == &computed[..];
                }
            }
        }
    }

    // Signature is over the DER SET OF the signed attributes.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| pades(format!("encode signed attrs: {e}")))?;
    let vk = verifying_key_from_cert(&cert)?;
    let sig_bytes = si.signature.as_bytes();
    let signature_valid = DerSignature::from_bytes(sig_bytes)
        .ok()
        .map(|s| vk.verify(&signed_attrs_der, &s).is_ok())
        .unwrap_or(false);

    let signature_timestamp = si.unsigned_attrs.as_ref().and_then(|attrs| {
        attrs
            .iter()
            .find(|a| a.oid == OID_SIGNATURE_TIMESTAMP)
            .and_then(|a| a.values.iter().next())
            .and_then(|v| v.to_der().ok())
    });

    // SignPDF writes lowercase hex; mixed case decodes to the same bytes, so accepting it would
    // leave the unsigned gap malleable.
    let lowercase_gap = gap
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
    let canonical = signature_valid && lowercase_gap && is_canonical_signpdf_cms(&ci, &sd, &cert);

    Ok(PadesValidation {
        field_name: String::new(),
        signer_cn,
        byte_range,
        signer_pubkey_sec1: vk.to_sec1_point(false).as_bytes().to_vec(),
        covers_to_eof: covered_end == file_len,
        digest_matches,
        signature_valid,
        covered_end,
        sub_filter,
        signature_value: sig_bytes.to_vec(),
        signature_timestamp,
        structure_error: None,
        canonical,
    })
}

/// Whether a (signature-verified) CMS is exactly the structure [`build_cms`] emits: SignedData v1
/// over detached `id-data` with SHA-256, one certificate, one signerInfo identified by that
/// certificate's issuer/serial, ECDSA-with-SHA256, and signed attributes of exactly
/// content-type(id-data), message-digest and an ESS signing-certificate-v2 binding the embedded
/// certificate. Only the optional signature-timestamp unsigned attribute may be added.
///
/// Every field outside the signed attributes is otherwise unsigned in CMS, so without this check
/// a third party could alter e.g. the `eContentType`, algorithm identifiers, or the embedded
/// certificate's non-key fields of a signed document without invalidating the signature.
fn is_canonical_signpdf_cms(ci: &ContentInfo, sd: &SignedData, cert: &Certificate) -> bool {
    use cms::content_info::CmsVersion;
    use cms::signed_data::{CertificateSet, DigestAlgorithmIdentifiers};
    use der::asn1::SetOfVec;

    let sha256 = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let Some(si) = sd.signer_infos.0.iter().next() else {
        return false;
    };
    if sd.signer_infos.0.len() != 1
        || ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA
        || si.version != CmsVersion::V1
        || si.digest_alg != sha256
        || si.signature_algorithm.oid != const_oid::db::rfc5912::ECDSA_WITH_SHA_256
        || si.signature_algorithm.parameters.is_some()
        || si.sid
            != SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: cert.tbs_certificate().issuer().clone(),
                serial_number: cert.tbs_certificate().serial_number().clone(),
            })
    {
        return false;
    }
    // Signed attributes: exactly content-type, message-digest, and the ESS binding of `cert`.
    let Some(attrs) = si.signed_attrs.as_ref() else {
        return false;
    };
    let Ok(ess) = signing_certificate_v2(cert) else {
        return false;
    };
    let content_type_ok = attrs.iter().any(|a| {
        a.oid == const_oid::db::rfc5911::ID_CONTENT_TYPE
            && a.values.len() == 1
            && a.values
                .iter()
                .next()
                .and_then(|v| v.decode_as::<ObjectIdentifier>().ok())
                == Some(const_oid::db::rfc5911::ID_DATA)
    });
    if attrs.len() != 3
        || !content_type_ok
        || !attrs
            .iter()
            .any(|a| a.oid == OID_MESSAGE_DIGEST && a.values.len() == 1)
        || !attrs.iter().any(|a| *a == ess)
    {
        return false;
    }
    if let Some(unsigned) = si.unsigned_attrs.as_ref() {
        if unsigned.len() != 1 || unsigned.iter().any(|a| a.oid != OID_SIGNATURE_TIMESTAMP) {
            return false;
        }
    }
    // Rebuild the SignedData around the verified parts and require identical encoding.
    let (Ok(digests), Ok(certs)) = (
        SetOfVec::try_from(vec![sha256]),
        SetOfVec::try_from(vec![CertificateChoices::Certificate(cert.clone())]),
    ) else {
        return false;
    };
    let rebuilt = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::from(digests),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(certs)),
        crls: None,
        signer_infos: sd.signer_infos.clone(),
    };
    match (rebuilt.to_der(), ci.content.to_der()) {
        (Ok(a), Ok(b)) => {
            // `ci.content` is the [0] EXPLICIT wrapper's inner value (the SignedData itself).
            a == b
                || der::Any::encode_from(&rebuilt)
                    .map(|x| x == ci.content)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

// --- document timestamps and validation data (PAdES B-LT / B-LTA) ----------------------------

/// Bytes reserved for a document timestamp's `/Contents` (hex chars): an RFC 3161 token with its
/// TSA chain is usually 5–8 KB; 16 KB leaves room for long chains.
const DOC_TIMESTAMP_HEX_LEN: usize = 32768;

/// Outcome of checking one document timestamp (`/Type /DocTimeStamp`, `/SubFilter
/// /ETSI.RFC3161`) with our own reader: an RFC 3161 token over everything before its `/Contents`
/// (PAdES B-LTA, ETSI EN 319 142-1).
#[derive(Debug, Clone, Default)]
pub struct DocumentTimestampValidation {
    pub field_name: String,
    /// The object holding the timestamp dictionary.
    pub object_id: ObjectId,
    pub byte_range: [i64; 4],
    /// End offset of the signed range: the length of the revision this timestamp covers.
    pub covered_end: usize,
    /// Nothing was appended after it.
    pub covers_to_eof: bool,
    /// The token's message imprint is the hash of the signed spans (with the token's own digest
    /// algorithm: SHA-256, SHA-384 or SHA-512).
    pub digest_matches: bool,
    /// The DER `TimeStampToken`, exactly as embedded.
    pub token: Vec<u8>,
    /// Set when the timestamp is structurally malformed (it then proves nothing).
    pub structure_error: Option<String>,
}

impl DocumentTimestampValidation {
    pub fn is_valid(&self) -> bool {
        self.structure_error.is_none() && self.digest_matches
    }
}

fn verify_document_timestamp(
    digests: &DocumentDigests<'_>,
    dict: &Dictionary,
) -> Result<DocumentTimestampValidation> {
    let pdf = digests.bytes();
    if !matches!(dict.get(b"SubFilter"), Ok(Object::Name(n)) if n == b"ETSI.RFC3161") {
        return Err(pades(
            "a document timestamp must have /SubFilter /ETSI.RFC3161",
        ));
    }
    let g = signed_gap(pdf, dict)?;
    // Like a signature's: one spelling only, so the unsigned gap is not malleable.
    if !g
        .gap
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(pades(
            "the document timestamp's /Contents is not lowercase hex",
        ));
    }
    if g.contents.iter().all(|b| *b == 0) {
        return Err(pades(
            "the document timestamp is empty: its token was never added",
        ));
    }
    let token_len = crate::timestamp::read_tlv(&g.contents)
        .map_err(|e| pades(format!("document timestamp token: {e}")))?
        .der
        .len();
    if g.contents[token_len..].iter().any(|b| *b != 0) {
        return Err(pades(
            "/Contents padding after the timestamp token is not zero",
        ));
    }
    let token = g.contents[..token_len].to_vec();
    let (alg, imprint) = crate::timestamp::token_imprint(&token)
        .map_err(|e| pades(format!("document timestamp token: {e}")))?;
    // SHA-256 tokens reuse the document's hash; other algorithms hash the spans.
    let digest = if alg == const_oid::db::rfc5912::ID_SHA_256 {
        digests.spans(g.l1, g.s2, g.l2).map(|d| d.to_vec())
    } else {
        crate::timestamp::digest_spans(&alg, &[&pdf[..g.l1], &pdf[g.s2..g.s2 + g.l2]])
    }
    .ok_or_else(|| pades("the document timestamp uses an unsupported digest algorithm"))?;
    let covered_end = g.s2 + g.l2;
    Ok(DocumentTimestampValidation {
        field_name: String::new(),
        object_id: (0, 0),
        byte_range: g.byte_range,
        covered_end,
        covers_to_eof: covered_end == pdf.len(),
        digest_matches: digest == imprint,
        token,
        structure_error: None,
    })
}

/// Append a document timestamp's increment to `pdf`, with room for the token, and return it
/// with the SHA-256 the token must carry: the first step of adding a PAdES document timestamp.
/// Ask a time-stamp authority for that digest ([`crate::timestamp::build_request`]), then add its
/// token with [`embed_document_timestamp`] ([`add_document_timestamp`] does both with a
/// synchronous [`Timestamper`]).
///
/// The increment adds one invisible signature field on the first page, whose value is the
/// `/DocTimeStamp` dictionary, and nothing else. It holds no date (the time is the token's), so
/// the same input always gives the same output. The document must already carry a signature
/// (its form). [`crate::workflow::prepare_document_timestamp`] adds the envelope's checks.
pub fn prepare_document_timestamp(pdf: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(pades("input is not a PDF"));
    }
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .map_err(|e| pades(format!("trailer has no /Root: {e}")))?;
    let catalog = doc
        .get_object(root_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad catalog: {e}")))?;
    let Ok(Object::Reference(acroform_id)) = catalog.get(b"AcroForm") else {
        return Err(pades(
            "the document has no signature form: a document timestamp follows a signature",
        ));
    };
    let acroform_id = *acroform_id;
    let mut acroform = doc
        .get_object(acroform_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad AcroForm: {e}")))?
        .clone();
    let page_id = page_id_at(&doc, 0)?;
    let mut page = doc
        .get_object(page_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad page object: {e}")))?
        .clone();

    let first = first_free_number(&doc);
    let widget_id = (first, 0u16);
    let ts_id = (first + 1, 0u16);
    let next_id = first + 2;

    let mut fields = acroform
        .get(b"Fields")
        .ok()
        .and_then(|o| resolve(&doc, o))
        .and_then(|o| o.as_array().ok())
        .cloned()
        .unwrap_or_default();
    let field_no = fields.len() + 1;
    fields.push(Object::Reference(widget_id));
    acroform.set("Fields".as_bytes().to_vec(), Object::Array(fields));
    acroform.set("SigFlags".as_bytes().to_vec(), Object::Integer(3));
    let mut annots = page_annots(&doc, &page);
    annots.push(Object::Reference(widget_id));
    page.set("Annots".as_bytes().to_vec(), Object::Array(annots));
    let trailer = doc.trailer.clone();
    drop(doc);

    let mut out = Increment::after(pdf, DOC_TIMESTAMP_HEX_LEN);
    let mut xref: Vec<(ObjectId, usize)> = Vec::new();
    let widget_body = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (DocumentTimestamp{field_no}) \
         /Rect [0 0 0 0] /V {} 0 R /P {} 0 R /F 132 >>",
        ts_id.0, page_id.0,
    );
    write_indirect(&mut out, &mut xref, widget_id, widget_body.as_bytes());
    let mut body = Vec::new();
    write_object(&mut body, &Object::Dictionary(acroform));
    write_indirect(&mut out, &mut xref, acroform_id, &body);
    let mut body = Vec::new();
    write_object(&mut body, &Object::Dictionary(page));
    write_indirect(&mut out, &mut xref, page_id, &body);

    xref.push((ts_id, out.pos()));
    out.extend_from_slice(format!("{} 0 obj\n", ts_id.0).as_bytes());
    out.extend_from_slice(
        b"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange [",
    );
    let br_off = out.pos();
    out.extend_from_slice(b"0000000000 0000000000 0000000000 0000000000");
    out.extend_from_slice(b"] /Contents ");
    let contents_lt = out.pos();
    out.push(b'<');
    out.fill(DOC_TIMESTAMP_HEX_LEN, b'0');
    out.push(b'>');
    out.extend_from_slice(b" >>\nendobj\n");

    let prev_startxref = find_last_startxref(pdf)?;
    finish_increment(
        &mut out,
        &mut xref,
        next_id,
        root_id,
        prev_startxref,
        &trailer,
    );
    let file_len = out.pos();
    let start2 = contents_lt + 1 + DOC_TIMESTAMP_HEX_LEN + 1;
    out.put10(br_off, 0);
    out.put10(br_off + 11, contents_lt as u64);
    out.put10(br_off + 22, start2 as u64);
    out.put10(br_off + 33, (file_len - start2) as u64);
    let mut hasher = Sha256::new();
    absorb(&mut hasher, pdf);
    absorb(&mut hasher, out.range(pdf.len(), contents_lt));
    absorb(&mut hasher, out.range(start2, file_len));
    Ok((out.appended_to(pdf), hasher.finalize().into()))
}

/// Add an RFC 3161 token (`token`, a DER `TimeStampToken`) to the document timestamp that
/// [`prepare_document_timestamp`] left at the end of `pdf`. The output has the same length. A
/// token whose message imprint is not the hash of the document's signed bytes is refused, and so
/// is a document that does not end with an empty document timestamp.
pub fn embed_document_timestamp(pdf: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let mut waiting = None;
    for obj in doc.objects.values() {
        let Ok(dict) = obj.as_dict() else { continue };
        if !matches!(dict.get(b"Type"), Ok(Object::Name(n)) if n == b"DocTimeStamp") {
            continue;
        }
        let Ok(g) = signed_gap(pdf, dict) else {
            continue;
        };
        if g.s2 + g.l2 == pdf.len() && g.contents.iter().all(|b| *b == 0) {
            waiting = Some((g.l1, g.s2, g.l2));
        }
    }
    drop(doc);
    let (l1, s2, l2) = waiting.ok_or_else(|| {
        pades(
            "the document does not end with a document timestamp waiting for its token \
             (prepare one first)",
        )
    })?;
    if crate::timestamp::read_tlv(token).map(|t| t.der.len()).ok() != Some(token.len()) {
        return Err(pades("the timestamp token is not one DER element"));
    }
    let (alg, imprint) = crate::timestamp::token_imprint(token)
        .map_err(|e| pades(format!("timestamp token: {e}")))?;
    let digest = crate::timestamp::digest_spans(&alg, &[&pdf[..l1], &pdf[s2..s2 + l2]])
        .ok_or_else(|| pades("the timestamp token uses an unsupported digest algorithm"))?;
    if digest != imprint {
        return Err(pades(
            "the timestamp token is not for this document (its message imprint is another hash)",
        ));
    }
    let token_hex = hex::encode(token);
    let gap = l1 + 1..s2 - 1;
    if token_hex.len() > gap.len() {
        return Err(pades(
            "the timestamp token is larger than the room reserved for it",
        ));
    }
    let mut out = pdf.to_vec();
    out[gap.start..gap.start + token_hex.len()].copy_from_slice(token_hex.as_bytes());
    Ok(out)
}

/// Add a PAdES document timestamp to `pdf` with a synchronous time-stamp authority:
/// [`prepare_document_timestamp`], then [`embed_document_timestamp`].
pub fn add_document_timestamp(pdf: &[u8], ts: &dyn Timestamper) -> Result<Vec<u8>> {
    let (prepared, digest) = prepare_document_timestamp(pdf)?;
    let token = ts.timestamp(&digest)?;
    embed_document_timestamp(&prepared, &token)
}

/// A document's validation data: the PAdES document security store (the catalog's `/DSS`), as
/// the DER items it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dss {
    /// X.509 certificates (`/Certs`).
    pub certs: Vec<Vec<u8>>,
    /// OCSP responses (`/OCSPs`).
    pub ocsps: Vec<Vec<u8>>,
    /// CRLs (`/CRLs`).
    pub crls: Vec<Vec<u8>>,
}

impl Dss {
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty() && self.ocsps.is_empty() && self.crls.is_empty()
    }
}

/// A check that a DSS entry holds the right kind of item.
type DssItemCheck = fn(&[u8]) -> bool;

/// The three DSS arrays: key, what each entry must be, and the check that it is.
const DSS_LISTS: [(&[u8], &str, DssItemCheck); 3] = [
    (b"Certs", "a certificate", crate::ltv::is_certificate),
    (b"OCSPs", "an OCSP response", crate::ltv::is_ocsp_response),
    (b"CRLs", "a CRL", crate::ltv::is_crl),
];

/// The DSS of a parsed document, with the objects that hold it.
struct DssRefs {
    /// The DSS dictionary.
    dict: Dictionary,
    /// The entries of `/Certs`, `/OCSPs` and `/CRLs`, as stored (normally references).
    entries: [Vec<Object>; 3],
    /// The bytes of the entries that are unfiltered streams.
    data: Dss,
}

/// The catalog's DSS: the object holding it (when it is indirect) and its content.
fn read_dss_of(doc: &Document) -> Option<(Option<ObjectId>, DssRefs)> {
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .ok()?;
    let catalog = doc.get_object(root).ok()?.as_dict().ok()?;
    let entry = catalog.get(b"DSS").ok()?;
    let id = entry.as_reference().ok();
    let dict = resolve(doc, entry)?.as_dict().ok()?.clone();
    let mut entries: [Vec<Object>; 3] = Default::default();
    let mut lists: [Vec<Vec<u8>>; 3] = Default::default();
    for (k, (key, _, _)) in DSS_LISTS.iter().enumerate() {
        entries[k] = resolved_vec(doc, dict.get(key).ok());
        lists[k] = entries[k]
            .iter()
            .filter_map(|e| resolve(doc, e)?.as_stream().ok())
            .filter(|s| s.dict.get(b"Filter").is_err())
            .map(|s| s.content.clone())
            .collect();
    }
    let [certs, ocsps, crls] = lists;
    Some((
        id,
        DssRefs {
            dict,
            entries,
            data: Dss { certs, ocsps, crls },
        },
    ))
}

/// The validation data (DSS) of `pdf`, if it has some.
pub fn read_dss(pdf: &[u8]) -> Result<Option<Dss>> {
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    Ok(read_dss_of(&doc).map(|(_, refs)| refs.data))
}

/// Append an increment that adds `add`'s items to the document's validation data (its DSS),
/// keeping what it already holds; items already there are not repeated. Returns `pdf` unchanged
/// when there is nothing new. The items are not checked here:
/// [`crate::workflow::add_validation_data`] checks them against the document's timestamps.
///
/// Each item is an unfiltered stream; the DSS dictionary is rewritten in place when the catalog
/// already references one, and the catalog gains `/DSS` otherwise. Nothing else changes. A
/// document timestamp should follow ([`prepare_document_timestamp`]): until one does, the new
/// data is an unsigned addition, which SignPDF's verifier refuses.
pub fn add_validation_data(pdf: &[u8], add: &Dss) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(pades("input is not a PDF"));
    }
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(|o| o.as_reference())
        .map_err(|e| pades(format!("trailer has no /Root: {e}")))?;
    let mut catalog = doc
        .get_object(root_id)
        .and_then(|o| o.as_dict())
        .map_err(|e| pades(format!("bad catalog: {e}")))?
        .clone();
    let existing = read_dss_of(&doc);
    let mut next_id = first_free_number(&doc);
    let trailer = doc.trailer.clone();
    drop(doc);

    let (dss_id, mut dict, mut entries, have) = match existing {
        Some((id, refs)) => (id, refs.dict, refs.entries, refs.data),
        None => (None, Dictionary::new(), Default::default(), Dss::default()),
    };
    let have = [have.certs, have.ocsps, have.crls];
    let add = [&add.certs, &add.ocsps, &add.crls];
    let mut new_items: Vec<(ObjectId, &[u8])> = Vec::new();
    for k in 0..3 {
        let mut seen: Vec<&[u8]> = have[k].iter().map(Vec::as_slice).collect();
        for item in add[k] {
            if seen.contains(&item.as_slice()) {
                continue;
            }
            seen.push(item);
            let id = (next_id, 0u16);
            next_id += 1;
            entries[k].push(Object::Reference(id));
            new_items.push((id, item));
        }
    }
    if new_items.is_empty() {
        return Ok(pdf.to_vec());
    }
    dict.set("Type".as_bytes().to_vec(), Object::Name(b"DSS".to_vec()));
    for (k, (key, _, _)) in DSS_LISTS.iter().enumerate() {
        if !entries[k].is_empty() {
            dict.set(key.to_vec(), Object::Array(entries[k].clone()));
        }
    }
    let rewrite_catalog = dss_id.is_none();
    let dss_id = dss_id.unwrap_or_else(|| {
        let id = (next_id, 0u16);
        next_id += 1;
        id
    });

    let extra: usize = new_items.iter().map(|(_, d)| d.len() + 64).sum();
    let mut out = Increment::after(pdf, extra);
    let mut xref: Vec<(ObjectId, usize)> = Vec::new();
    for (id, data) in &new_items {
        let mut body = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        write_indirect(&mut out, &mut xref, *id, &body);
    }
    let mut body = Vec::new();
    write_object(&mut body, &Object::Dictionary(dict));
    write_indirect(&mut out, &mut xref, dss_id, &body);
    if rewrite_catalog {
        catalog.set("DSS".as_bytes().to_vec(), Object::Reference(dss_id));
        let mut body = Vec::new();
        write_object(&mut body, &Object::Dictionary(catalog));
        write_indirect(&mut out, &mut xref, root_id, &body);
    }
    let prev_startxref = find_last_startxref(pdf)?;
    finish_increment(
        &mut out,
        &mut xref,
        next_id,
        root_id,
        prev_startxref,
        &trailer,
    );
    Ok(out.appended_to(pdf))
}

/// What the increments between a signature (or document timestamp) and the document timestamp
/// that ends them changed, when they may only add validation data and that one document
/// timestamp ([`audit_ltv_increment`]).
#[derive(Debug, Clone, Default)]
pub struct LtvIncrementAudit {
    /// Changes outside the allow-list (each a human-readable reason).
    pub violations: Vec<String>,
    /// The validation data (DSS) changed.
    pub dss_changed: bool,
    /// The document timestamp dictionary the increments added, when they added exactly one.
    pub document_timestamp: Option<ObjectId>,
}

/// Compare revision `before` (which ends with a signature or a document timestamp) with
/// `after`, which ends with a document timestamp, and report every change outside what may
/// follow a signature (PAdES B-LT and B-LTA):
///
/// * **validation data**: the catalog may gain or change `/DSS` (and nothing else); the DSS
///   dictionary may only gain entries in `/Certs`, `/OCSPs` and `/CRLs`, keeping every entry it
///   had; each new entry is a new, unfiltered stream holding a certificate, a successful OCSP
///   response or a CRL respectively;
/// * **one document timestamp**: one new invisible signature widget on a page (the page may only
///   gain it), added as the form's one new field, whose value is a new `/DocTimeStamp`
///   dictionary carrying only `/Type`, `/Filter`, `/SubFilter`, `/ByteRange` and `/Contents`.
///
/// Every other change, and every other new object (cross-reference and object streams apart),
/// is a violation: a document timestamp can be added by anyone who can reach a time-stamp
/// authority, so what it covers must never be able to show or change anything.
pub fn audit_ltv_increment(before: &[u8], after: &[u8]) -> Result<LtvIncrementAudit> {
    let mut audit = LtvIncrementAudit::default();
    if !after.starts_with(before) {
        audit
            .violations
            .push("revision does not extend the previous one byte-for-byte".into());
        return Ok(audit);
    }
    let old = load_for_inspection(before, ImageBytes::Digest)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let new = load_for_inspection(after, ImageBytes::Digest)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let root = |d: &Document| d.trailer.get(b"Root").and_then(|o| o.as_reference()).ok();
    let old_root = root(&old);
    if old_root.is_none() || old_root != root(&new) {
        audit
            .violations
            .push("document catalog was replaced".into());
        return Ok(audit);
    }
    if old.get_pages() != new.get_pages() {
        audit
            .violations
            .push("the page tree was changed (pages added, removed or reordered)".into());
    }
    let page_index: std::collections::HashMap<ObjectId, u32> =
        new.get_pages().iter().map(|(n, id)| (*id, n - 1)).collect();
    let catalog_of = |d: &Document| -> Dictionary {
        old_root
            .and_then(|r| d.get_object(r).ok())
            .and_then(|o| o.as_dict().ok())
            .cloned()
            .unwrap_or_default()
    };
    let (old_catalog, new_catalog) = (catalog_of(&old), catalog_of(&new));
    let acroform_id = old_catalog
        .get(b"AcroForm")
        .and_then(|o| o.as_reference())
        .ok();
    let old_dss = read_dss_of(&old);
    let new_dss = read_dss_of(&new);
    // The DSS dictionary may be rewritten in place only while the catalog still points at it.
    let old_dss_id = old_dss
        .as_ref()
        .and_then(|(id, _)| *id)
        .filter(|id| new_dss.as_ref().and_then(|(n, _)| *n) == Some(*id));

    // What the increments define, read from their own cross-reference. The objects compared
    // below are the only ones of the previous revision they may rewrite.
    let mut may_change: std::collections::HashSet<ObjectId> =
        old.get_pages().values().copied().collect();
    may_change.extend(old_root);
    may_change.extend(acroform_id);
    may_change.extend(old_dss.as_ref().and_then(|(id, _)| *id));
    audit.violations.extend(increment_xref_problems(
        before,
        after,
        &old,
        &new,
        &may_change,
    ));

    // Objects of the previous revision.
    let mut added_annots: Vec<(u32, Object)> = Vec::new();
    for (id, old_obj) in &old.objects {
        let Some(new_obj) = new.objects.get(id) else {
            audit
                .violations
                .push(format!("object {} {} was removed", id.0, id.1));
            continue;
        };
        if new_obj == old_obj {
            continue;
        }
        let (Ok(od), Ok(nd)) = (old_obj.as_dict(), new_obj.as_dict()) else {
            audit
                .violations
                .push(format!("object {} {} was modified", id.0, id.1));
            continue;
        };
        if Some(*id) == old_root {
            if dict_without(od, &[b"DSS"]) != dict_without(nd, &[b"DSS"]) {
                audit.violations.push(
                    "the document catalog was modified beyond its validation data (/DSS)".into(),
                );
            }
        } else if Some(*id) == old_dss_id || Some(*id) == acroform_id {
            // The DSS and the form are checked below.
        } else if matches!(od.get(b"Type"), Ok(Object::Name(n)) if n == b"Page") {
            let oa = resolved_vec(&old, od.get(b"Annots").ok());
            let na = resolved_vec(&new, nd.get(b"Annots").ok());
            if !na.starts_with(&oa) {
                audit.violations.push(format!(
                    "existing annotations on page object {} were removed or reordered",
                    id.0
                ));
            }
            if dict_without(od, &[b"Annots"]) != dict_without(nd, &[b"Annots"]) {
                audit.violations.push(format!(
                    "page object {} was modified beyond adding annotations",
                    id.0
                ));
            }
            let pidx = page_index.get(id).copied().unwrap_or(u32::MAX);
            for extra in na.iter().skip(oa.len()) {
                added_annots.push((pidx, extra.clone()));
            }
        } else {
            audit
                .violations
                .push(format!("object {} {} was modified", id.0, id.1));
        }
    }
    audit
        .violations
        .extend(redefined_unreadable_objects(&old, &new));

    // New objects these increments may add, as they are found.
    let mut explained: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();

    // The validation data.
    match (&old_dss, &new_dss) {
        (Some(_), None) => audit
            .violations
            .push("the validation data (DSS) was removed".into()),
        (_, Some((new_id, refs))) => {
            if let Some(id) = new_id {
                if !old.objects.contains_key(id) {
                    explained.insert(*id);
                }
            }
            if !matches!(new_catalog.get(b"DSS"), Ok(Object::Reference(_)))
                && old_catalog.get(b"DSS").ok() != new_catalog.get(b"DSS").ok()
            {
                audit
                    .violations
                    .push("the DSS is not an indirect dictionary".into());
            }
            let old_refs = old_dss.as_ref().map(|(_, r)| r);
            for (key, value) in refs.dict.iter() {
                let known = matches!(key.as_slice(), b"Certs" | b"OCSPs" | b"CRLs")
                    || (key.as_slice() == b"Type"
                        && matches!(value, Object::Name(n) if n == b"DSS"));
                let unchanged = old_refs.is_some_and(|r| r.dict.get(key).ok() == Some(value));
                if !known && !unchanged {
                    audit.violations.push(format!(
                        "the DSS holds /{}, which is not validation data SignPDF accepts",
                        String::from_utf8_lossy(key)
                    ));
                }
            }
            for (k, (key, what, is_kind)) in DSS_LISTS.iter().enumerate() {
                let before = old_refs.map(|r| r.entries[k].clone()).unwrap_or_default();
                let after = &refs.entries[k];
                if before.iter().any(|e| !after.contains(e)) {
                    audit.violations.push(format!(
                        "the DSS lost entries of /{}",
                        String::from_utf8_lossy(key)
                    ));
                }
                if refs.dict.get(key).is_ok_and(|o| o.as_array().is_err()) {
                    audit.violations.push(format!(
                        "the DSS's /{} is not a direct array",
                        String::from_utf8_lossy(key)
                    ));
                }
                for e in after.iter().filter(|e| !before.contains(e)) {
                    let stream = match e {
                        Object::Reference(r) if !old.objects.contains_key(r) => {
                            explained.insert(*r);
                            new.get_object(*r).ok().and_then(|o| o.as_stream().ok())
                        }
                        _ => None,
                    };
                    let ok = stream.is_some_and(|s| {
                        s.dict.iter().all(|(k, _)| k.as_slice() == b"Length") && is_kind(&s.content)
                    });
                    if !ok {
                        audit.violations.push(format!(
                            "an entry added to the DSS's /{} is not {what} in a new, unfiltered \
                             stream",
                            String::from_utf8_lossy(key)
                        ));
                    }
                }
            }
            audit.dss_changed = old_refs.map(|r| &r.entries) != Some(&refs.entries);
        }
        (None, None) => {}
    }

    // The document timestamp.
    let mut widget_ref = None;
    if added_annots.len() != 1 {
        audit.violations.push(format!(
            "exactly one document timestamp field must follow a signature ({} annotations were \
             added)",
            added_annots.len()
        ));
    }
    for (pidx, extra) in &added_annots {
        let Ok(aref) = extra.as_reference() else {
            audit
                .violations
                .push("an inline (direct) annotation was added".into());
            continue;
        };
        let Some(ad) = new.get_object(aref).ok().and_then(|o| o.as_dict().ok()) else {
            audit
                .violations
                .push("an added annotation is not a dictionary".into());
            continue;
        };
        let is_new = !old.objects.contains_key(&aref);
        let a = added_annotation(&new, ad, *pidx, is_new);
        if a.subtype != "Widget" || a.field_type.as_deref() != Some("Sig") || !is_new {
            audit.violations.push(format!(
                "an increment after a signature added an unexpected '{}' annotation",
                a.subtype
            ));
            continue;
        }
        audit.violations.extend(a.shape_problems.iter().cloned());
        if a.rect.iter().any(|v| *v != 0.0) {
            audit
                .violations
                .push("the document timestamp's field is not invisible".into());
        }
        audit.violations.extend(check_signature_widget(
            &a,
            a.rect,
            None,
            InkRule::Recorded(None),
        ));
        explained.insert(aref);
        widget_ref = Some(aref);
        let ts = match ad.get(b"V") {
            Ok(Object::Reference(r)) if !old.objects.contains_key(r) => Some(*r),
            _ => None,
        };
        let ts_dict = ts.and_then(|r| new.get_object(r).ok().and_then(|o| o.as_dict().ok()));
        match (ts, ts_dict) {
            (Some(id), Some(d)) if matches!(d.get(b"Type"), Ok(Object::Name(n)) if n == b"DocTimeStamp") =>
            {
                explained.insert(id);
                audit.document_timestamp = Some(id);
                if let Some((k, _)) = d.iter().find(|(k, _)| {
                    !matches!(
                        k.as_slice(),
                        b"Type" | b"Filter" | b"SubFilter" | b"ByteRange" | b"Contents"
                    )
                }) {
                    audit.violations.push(format!(
                        "the document timestamp carries an unexpected /{} entry",
                        String::from_utf8_lossy(k)
                    ));
                }
            }
            _ => audit
                .violations
                .push("the field added after a signature is not a new document timestamp".into()),
        }
    }

    // The form: it may only have gained the document timestamp's field.
    let form = |d: &Document| -> Dictionary {
        acroform_id
            .and_then(|r| d.get_object(r).ok())
            .and_then(|o| o.as_dict().ok())
            .cloned()
            .unwrap_or_default()
    };
    let (old_form, new_form) = (form(&old), form(&new));
    let mut expected_fields = resolved_vec(&old, old_form.get(b"Fields").ok());
    expected_fields.extend(widget_ref.map(Object::Reference));
    if acroform_id.is_none()
        || new_catalog.get(b"AcroForm").ok() != old_catalog.get(b"AcroForm").ok()
        || resolved_vec(&new, new_form.get(b"Fields").ok()) != expected_fields
        || dict_without(&old_form, &[b"Fields", b"SigFlags"])
            != dict_without(&new_form, &[b"Fields", b"SigFlags"])
    {
        audit.violations.push(
            "the form must gain exactly one field, the document timestamp's, and nothing else"
                .into(),
        );
    }

    // Every other new object is unexplained (cross-reference and object streams apart, which
    // only carry the file's structure).
    for (id, obj) in &new.objects {
        if old.objects.contains_key(id) || explained.contains(id) {
            continue;
        }
        let structural = obj.as_stream().is_ok_and(|s| {
            matches!(s.dict.get(b"Type"), Ok(Object::Name(n)) if n == b"XRef" || n == b"ObjStm")
        });
        if !structural {
            audit.violations.push(format!(
                "object {} {} is neither validation data nor the document timestamp",
                id.0, id.1
            ));
        }
    }
    Ok(audit)
}

// --- revision auditing --------------------------------------------------------------------

/// An annotation that an incremental update added to a page.
#[derive(Debug, Clone, PartialEq)]
pub struct AddedAnnotation {
    /// 0-based page index.
    pub page_index: u32,
    /// `/Subtype` (e.g. `Widget`, `FreeText`, `Stamp`).
    pub subtype: String,
    /// `/FT` for widgets (e.g. `Sig`).
    pub field_type: Option<String>,
    /// `/Rect` as `[x1, y1, x2, y2]`.
    pub rect: [f32; 4],
    /// `/Contents` text.
    pub contents: Option<String>,
    /// `/NM` (unique name) or `/Name`.
    pub name: Option<String>,
    /// True when the annotation object itself is new in this increment (not a re-reference).
    pub is_new_object: bool,
    /// `/F` annotation flags.
    pub flags: Option<i64>,
    /// `/DA` default-appearance string.
    pub default_appearance: Option<String>,
    /// The normal appearance stream (`/AP /N`), when the annotation has one.
    pub appearance: Option<AddedAppearance>,
    /// Ways in which the annotation or its appearance stream is built differently from what
    /// SignPDF writes: an entry it never writes (an action, a transform, a filter), a font other
    /// than the standard one. Any of these could make a viewer show or do something the
    /// verifier did not check.
    pub shape_problems: Vec<String>,
}

/// The appearance stream of an added annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct AddedAppearance {
    /// `/BBox`.
    pub bbox: [f32; 4],
    /// The content stream (the stream carries no filter).
    pub content: Vec<u8>,
}

/// What one incremental update changed, relative to the previous revision.
#[derive(Debug, Clone, Default)]
pub struct IncrementAudit {
    /// Changes outside the allow-list for a signing increment (each is a human-readable reason).
    pub violations: Vec<String>,
    /// Annotations appended to page `/Annots` arrays.
    pub added_annotations: Vec<AddedAnnotation>,
    /// How many pages the later revision has (the page tree may not change, so the earlier one
    /// has as many unless a violation says otherwise); 0 when the audit stopped before reading
    /// it.
    pub pages: u32,
}

fn dict_without(d: &Dictionary, keys: &[&[u8]]) -> Dictionary {
    let mut c = d.clone();
    for k in keys {
        c.remove(k);
    }
    c
}

fn resolved_vec(doc: &Document, o: Option<&Object>) -> Vec<Object> {
    o.and_then(|o| resolve(doc, o))
        .and_then(|o| o.as_array().ok())
        .cloned()
        .unwrap_or_default()
}

fn obj_text(doc: &Document, o: Option<&Object>) -> Option<String> {
    match o.and_then(|o| resolve(doc, o)) {
        Some(Object::String(s, _)) => Some(decode_text_string(s)),
        Some(Object::Name(n)) => Some(String::from_utf8_lossy(n).to_string()),
        _ => None,
    }
}

/// Compare revision `before` with its successor `after` (which must extend it byte-for-byte) and
/// report every object-level change.
///
/// The allow-list for a signing increment: the catalog may only gain an `/AcroForm` reference;
/// the AcroForm may only grow `/Fields` (keeping the existing entries) and set `/SigFlags`; page
/// dictionaries may only grow `/Annots` (keeping the existing entries). Everything else — content
/// streams, resources, the page tree, existing annotations or signatures — must be untouched.
/// New objects are allowed (the caller inspects [`IncrementAudit::added_annotations`] to decide
/// whether the new annotations are legitimate).
pub fn audit_increment(before: &[u8], after: &[u8]) -> Result<IncrementAudit> {
    if !after.starts_with(before) {
        return Ok(not_extended());
    }
    audit_revisions(
        &ParsedRevision::parse(before)?,
        &ParsedRevision::parse(after)?,
    )
}

fn not_extended() -> IncrementAudit {
    IncrementAudit {
        violations: vec!["revision does not extend the previous one byte-for-byte".into()],
        ..IncrementAudit::default()
    }
}

/// One revision of a document (a prefix of it that ends where a revision ends), parsed once
/// for everything the verifier asks of it: the envelope it carries ([`ParsedRevision::attachment`])
/// and the audit of the increments before and after it ([`audit_revisions`]).
///
/// Verifying a document used to parse every revision three times (once to read its envelope,
/// and once on each side of the two increment audits it takes part in); with many signers,
/// these parses were most of the time a verification took. The parse is the one
/// [`audit_increment`] makes ([`load_for_inspection`] keeping the digest of a large image), so
/// an audit of two parsed revisions is the audit of their bytes, and an attachment read from it
/// is the one [`read_attachment`] reads (only image XObjects differ between the two parses, and
/// an attachment is never one).
pub struct ParsedRevision<'a> {
    bytes: &'a [u8],
    doc: Inspected,
}

impl<'a> ParsedRevision<'a> {
    /// Parse `bytes`, a revision of a document.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let doc = load_for_inspection(bytes, ImageBytes::Digest)
            .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
        Ok(ParsedRevision { bytes, doc })
    }

    /// Its length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether it is empty (never, for a revision that parsed).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// [`read_attachment`] of this revision.
    pub fn attachment(&self, name: &str) -> Result<Vec<u8>> {
        attachment_in(&self.doc, name)
    }
}

/// [`audit_increment`] of two revisions already parsed: `new` must be `old` followed by the
/// increments audited.
pub fn audit_revisions(
    old: &ParsedRevision<'_>,
    new: &ParsedRevision<'_>,
) -> Result<IncrementAudit> {
    let mut audit = IncrementAudit::default();
    if !new.bytes.starts_with(old.bytes) {
        return Ok(not_extended());
    }
    let (before, after) = (old.bytes, new.bytes);
    let (old, new) = (&old.doc, &new.doc);

    let root = |d: &Document| d.trailer.get(b"Root").and_then(|o| o.as_reference()).ok();
    let old_root = root(old);
    if old_root != root(new) {
        audit
            .violations
            .push("document catalog was replaced".into());
        return Ok(audit);
    }
    let new_acroform_id = old_root
        .and_then(|r| new.get_object(r).ok())
        .and_then(|o| o.as_dict().ok())
        .and_then(|c| c.get(b"AcroForm").ok())
        .and_then(|o| o.as_reference().ok());

    let old_pages = old.get_pages();
    let new_pages = new.get_pages();
    audit.pages = u32::try_from(new_pages.len()).unwrap_or(u32::MAX);
    if old_pages != new_pages {
        audit
            .violations
            .push("the page tree was changed (pages added, removed or reordered)".into());
    }

    // What the increments define, read from their own cross-reference. The objects compared
    // below are the only ones of the previous revision they may rewrite.
    let mut may_change: std::collections::HashSet<ObjectId> = old_pages.values().copied().collect();
    may_change.extend(old_root);
    may_change.extend(
        old_root
            .and_then(|r| old.get_object(r).ok())
            .and_then(|o| o.as_dict().ok())
            .and_then(|c| c.get(b"AcroForm").ok())
            .and_then(|o| o.as_reference().ok()),
    );
    audit.violations.extend(increment_xref_problems(
        before,
        after,
        old,
        new,
        &may_change,
    ));
    let page_index: std::collections::HashMap<ObjectId, u32> =
        new_pages.iter().map(|(n, id)| (*id, n - 1)).collect();
    // New signature widgets this revision adds to pages: the form's new field must be one.
    let mut added_signature_widgets: Vec<ObjectId> = Vec::new();

    for (id, old_obj) in &old.objects {
        let Some(new_obj) = new.objects.get(id) else {
            audit
                .violations
                .push(format!("object {} {} was removed", id.0, id.1));
            continue;
        };
        if new_obj == old_obj {
            continue;
        }
        let (Ok(od), Ok(nd)) = (old_obj.as_dict(), new_obj.as_dict()) else {
            audit
                .violations
                .push(format!("object {} {} was modified", id.0, id.1));
            continue;
        };
        if Some(*id) == old_root {
            let old_af = od.get(b"AcroForm").ok();
            let af_ok = match old_af {
                Some(Object::Reference(r)) => {
                    nd.get(b"AcroForm").ok() == Some(&Object::Reference(*r))
                }
                _ => true,
            };
            if !af_ok || dict_without(od, &[b"AcroForm"]) != dict_without(nd, &[b"AcroForm"]) {
                audit
                    .violations
                    .push("the document catalog was modified beyond adding an AcroForm".into());
            }
        } else if Some(*id) == new_acroform_id {
            let of = resolved_vec(old, od.get(b"Fields").ok());
            let nf = resolved_vec(new, nd.get(b"Fields").ok());
            if !nf.starts_with(&of)
                || dict_without(od, &[b"Fields", b"SigFlags"])
                    != dict_without(nd, &[b"Fields", b"SigFlags"])
            {
                audit
                    .violations
                    .push("existing form fields were modified".into());
            }
        } else if matches!(od.get(b"Type"), Ok(Object::Name(n)) if n == b"Page") {
            let oa = resolved_vec(old, od.get(b"Annots").ok());
            let na = resolved_vec(new, nd.get(b"Annots").ok());
            if !na.starts_with(&oa) {
                audit.violations.push(format!(
                    "existing annotations on page object {} were removed or reordered",
                    id.0
                ));
            }
            if dict_without(od, &[b"Annots"]) != dict_without(nd, &[b"Annots"]) {
                audit.violations.push(format!(
                    "page object {} was modified beyond adding annotations",
                    id.0
                ));
            }
            let pidx = page_index.get(id).copied().unwrap_or(u32::MAX);
            for extra in na.iter().skip(oa.len()) {
                let Ok(aref) = extra.as_reference() else {
                    audit
                        .violations
                        .push("an inline (direct) annotation was added".into());
                    continue;
                };
                let Some(ad) = new.get_object(aref).ok().and_then(|o| o.as_dict().ok()) else {
                    audit
                        .violations
                        .push("an added annotation is not a dictionary".into());
                    continue;
                };
                let added = added_annotation(new, ad, pidx, !old.objects.contains_key(&aref));
                if added.is_new_object
                    && added.subtype == "Widget"
                    && added.field_type.as_deref() == Some("Sig")
                {
                    added_signature_widgets.push(aref);
                }
                audit.added_annotations.push(added);
            }
        } else {
            audit
                .violations
                .push(format!("object {} {} was modified", id.0, id.1));
        }
    }

    // An object the previous revision's cross-reference lists, but which lopdf could not read
    // there (a damaged object, an object stream it could not unpack), is missing from `old`: if
    // this revision defines it, the loop above never compares it and it would pass as a new
    // object, although other PDF readers may have shown the old one. Refuse it. The engine
    // numbers the objects it adds above every number of the previous revision, so it never
    // does this (docs/SECURITY_REVIEW_LOAD_FILTER.md, finding 1).
    audit
        .violations
        .extend(redefined_unreadable_objects(old, new));

    // The form: whether its dictionary is the old object or a new one, it may only have gained
    // one field (the signature being added) and `/SigFlags`.
    let acroform = |d: &Document| -> Dictionary {
        root(d)
            .and_then(|r| d.get_object(r).ok())
            .and_then(|o| o.as_dict().ok())
            .and_then(|c| resolved_dict(d, c.get(b"AcroForm").ok()))
            .cloned()
            .unwrap_or_default()
    };
    let (old_form, new_form) = (acroform(old), acroform(new));
    let old_fields = resolved_vec(old, old_form.get(b"Fields").ok());
    let new_fields = resolved_vec(new, new_form.get(b"Fields").ok());
    if !new_fields.starts_with(&old_fields) || new_fields.len() != old_fields.len() + 1 {
        audit
            .violations
            .push("the form must gain exactly one field, the new signature".into());
    } else if !matches!(
        new_fields.last(),
        Some(Object::Reference(r)) if added_signature_widgets.contains(r)
    ) {
        // The field must be the widget this revision put on a page, not any other new field
        // object, which could carry entries (actions, say) no audit looks at
        // (docs/SECURITY_REVIEW_2026-10-27.md, finding 4).
        audit.violations.push(
            "the form's new field is not the signature widget this revision added to a page".into(),
        );
    }
    if dict_without(&old_form, &[b"Fields", b"SigFlags"])
        != dict_without(&new_form, &[b"Fields", b"SigFlags"])
    {
        audit
            .violations
            .push("the form's settings were changed".into());
    }
    Ok(audit)
}

/// The cross-reference of every increment between `before` and `after`, read from the bytes
/// (docs/SECURITY_REVIEW_2026-10-27.md, finding 1). The audits compare lopdf's parses of the two
/// revisions, and lopdf reads a cross-reference differently from viewers (it ignores free
/// entries, keeps the last of two entries for one number where viewers keep the first, and
/// orders hybrid sections differently), so what lopdf sees an increment define is only what
/// viewers see when the increment leaves no room for a difference. Problems:
///
/// * an increment not in the form SignPDF writes ([`crate::xref::read_increments`]: one classic
///   table, in-use entries only, each number once, each pointing at its own object inside the
///   increment, nothing else in it);
/// * a trailer whose `/Root`, `/Info` or `/ID` differs from the previous revision's;
/// * an entry for an object the previous revision already had (for lopdf or for a viewer) other
///   than those in `may_change`, which the caller compares;
/// * an entry for one of those whose previous definition viewers and lopdf read differently
///   (another entry, a free one, an object stream that does not hold it), so that comparing
///   lopdf's two parses would not compare what viewers showed;
/// * an entry for one of those, or for any object the increments list, whose lopdf copy did not
///   come from that entry: lopdf files an object under the header it finds, so another entry
///   leading to a second `N G obj` overrides it, and an object it cannot read at its entry is
///   filled from any object stream that lists it ([`EntryReader`]). The audit would then compare
///   a copy viewers never show (review of PR #51, defect 1);
/// * a new object with a generation other than 0;
/// * a new object whose number the previous revision refers to without defining it (finding 2):
///   viewers treat such a reference as `null`, so defining it later would add to what they show
///   without changing any object the audit compares. The engine numbers its own objects above
///   every referenced number ([`first_free_number`]).
fn increment_xref_problems(
    before: &[u8],
    after: &[u8],
    old: &Document,
    new: &Document,
    may_change: &std::collections::HashSet<ObjectId>,
) -> Vec<String> {
    use crate::xref::ViewerEntry;
    let increments = match crate::xref::read_increments(before, after) {
        Ok(i) => i,
        Err(e) => {
            return vec![format!(
                "the revision's cross-reference is not in the form SignPDF writes: {e}"
            )]
        }
    };
    let mut problems = Vec::new();
    for inc in &increments {
        for key in [&b"Root"[..], b"Info", b"ID"] {
            let same = match (inc.trailer.get(key).ok(), old.trailer.get(key).ok()) {
                (None, None) => true,
                (Some(a), Some(b)) => same_object(a, b),
                _ => false,
            };
            if !same {
                problems.push(format!(
                    "an increment's trailer changes /{} of the previous revision",
                    String::from_utf8_lossy(key)
                ));
            }
        }
    }
    let mut listed: std::collections::BTreeMap<u32, u16> = std::collections::BTreeMap::new();
    for e in increments.iter().flat_map(|i| &i.entries) {
        if listed.insert(e.num, e.gen).is_some_and(|g| g != e.gen) {
            problems.push(format!("object {} is written with two generations", e.num));
        }
    }
    let Some(prev_start) = crate::xref::last_startxref(before) else {
        problems.push("the previous revision has no startxref".into());
        return problems;
    };
    let length_of = |id: ObjectId| old.objects.get(&id).and_then(|o| o.as_i64().ok());
    let viewer = crate::xref::viewer_xref(before, prev_start, &length_of);
    let old_entries = EntryReader::new(before, old);
    let new_entries = EntryReader::new(after, new);
    let lopdf_nums: std::collections::HashSet<u32> = old
        .objects
        .keys()
        .map(|id| id.0)
        .chain(old.reference_table.entries.keys().copied())
        .collect();
    let referenced = referenced_numbers(old);
    for (&num, &gen) in &listed {
        // What the revision defines must be what the audit compares: lopdf's copy of every
        // object the increments list comes from the increment's own entry.
        if !new_entries.own_copy(new, (num, gen)) {
            problems.push(format!(
                "object {num} {gen} of the revision is not read from its own cross-reference \
                 entry (another entry or an object stream gives the verifier a different copy)"
            ));
        }
        let viewer_has = matches!(
            viewer.get(num),
            Some(ViewerEntry::InUse { .. } | ViewerEntry::Compressed { .. })
        );
        if !lopdf_nums.contains(&num) && !viewer_has {
            if gen != 0 {
                problems.push(format!("new object {num} has generation {gen}"));
            }
            if referenced.contains(&num) {
                problems.push(format!(
                    "the revision defines object {num}, which the previous revision refers to \
                     without defining it"
                ));
            }
            continue;
        }
        if !may_change.contains(&(num, gen)) {
            problems.push(format!(
                "the revision rewrites object {num} {gen}, which existed before and may not change"
            ));
        } else if !defined_alike(before, old, &viewer, &old_entries, (num, gen)) {
            problems.push(format!(
                "object {num} {gen} was defined ambiguously in the previous revision (viewers \
                 and the verifier may read different versions of it), so its change cannot be \
                 checked"
            ));
        }
    }
    problems
}

/// Every object number `doc` refers to (`N G R`), in its objects (stream dictionaries included)
/// and its trailer.
fn referenced_numbers(doc: &Document) -> std::collections::HashSet<u32> {
    fn walk(o: &Object, out: &mut std::collections::HashSet<u32>) {
        match o {
            Object::Reference((n, _)) => {
                out.insert(*n);
            }
            Object::Array(a) => a.iter().for_each(|v| walk(v, out)),
            Object::Dictionary(d) => d.iter().for_each(|(_, v)| walk(v, out)),
            Object::Stream(s) => s.dict.iter().for_each(|(_, v)| walk(v, out)),
            _ => {}
        }
    }
    let mut out = std::collections::HashSet::new();
    doc.objects.values().for_each(|o| walk(o, &mut out));
    doc.trailer.iter().for_each(|(_, v)| walk(v, &mut out));
    out
}

/// The number of the first object the engine adds to `doc`: above every number its
/// cross-reference lists and every number it refers to, so that an increment never defines an
/// object an earlier revision refers to without defining (which the audits refuse).
fn first_free_number(doc: &Document) -> u32 {
    referenced_numbers(doc)
        .into_iter()
        .chain(doc.objects.keys().map(|id| id.0))
        .chain(std::iter::once(doc.max_id))
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

/// Whether viewers (`viewer`) and lopdf (`old`) read object `id` of revision `pdf` from the same
/// place: the same in-use entry at an `N G obj` of that number (after the whitespace and comments
/// every reader skips there, see [`crate::xref::object_header_at`]) that no other entry leads to a
/// copy of, or the same position in the same object stream, whose own entry they read alike and
/// whose header lists the object there and only there. And whether lopdf's copy of the object,
/// the one the audit compares, is the one that place holds ([`EntryReader::own_copy`]).
fn defined_alike(
    pdf: &[u8],
    old: &Document,
    viewer: &crate::xref::ViewerXref,
    entries: &EntryReader<'_>,
    id: ObjectId,
) -> bool {
    use crate::xref::ViewerEntry;
    use lopdf::xref::XrefEntry;
    if !viewer.complete || !old.objects.contains_key(&id) {
        return false;
    }
    let in_use_alike = |id: ObjectId| match (viewer.get(id.0), old.reference_table.get(id.0)) {
        (
            Some(ViewerEntry::InUse { offset, gen }),
            Some(XrefEntry::Normal {
                offset: o,
                generation: g,
            }),
        ) => {
            usize::try_from(*o).is_ok_and(|o| o == offset)
                && gen == *g
                && gen == id.1
                && crate::xref::object_header_at(pdf, offset, id.0, gen)
                && entries.sole_entry_for(id.0)
        }
        _ => false,
    };
    let place_alike = match (viewer.get(id.0), old.reference_table.get(id.0)) {
        (Some(ViewerEntry::InUse { .. }), _) => in_use_alike(id),
        (
            Some(ViewerEntry::Compressed { stream, index }),
            Some(XrefEntry::Compressed {
                container,
                index: i,
            }),
        ) => {
            id.1 == 0
                && stream == *container
                && index == u32::from(*i)
                && in_use_alike((stream, 0))
                && old
                    .objects
                    .get(&(stream, 0))
                    .and_then(|o| o.as_stream().ok())
                    .filter(|s| s.dict.has_type(b"ObjStm"))
                    .and_then(|s| {
                        let n = s.dict.get(b"N").and_then(Object::as_i64).ok()?;
                        let first = s.dict.get(b"First").and_then(Object::as_i64).ok()?;
                        let decoded = s.decompressed_content().ok()?;
                        let numbers = crate::xref::object_stream_numbers(
                            decoded.get(..usize::try_from(first).ok()?)?,
                            usize::try_from(n).ok()?,
                        )?;
                        // Listed once: lopdf keeps one copy per number, viewers read by index.
                        if numbers.iter().filter(|&&m| m == id.0).count() != 1 {
                            return None;
                        }
                        numbers.get(usize::try_from(index).ok()?).copied()
                    })
                    == Some(id.0)
        }
        _ => false,
    };
    place_alike && entries.own_copy(old, id)
}

/// lopdf's reading of one revision object by object, each through the object's own
/// cross-reference entry (lopdf's merged reading of the chain, which [`defined_alike`] checks
/// against the viewers').
///
/// lopdf 0.42 loads a document by reading the object at every in-use entry's offset and filing
/// it under the number of the header it finds there, not the entry's number (the later entry
/// wins); then it adds the objects of every object stream it read for numbers it has no object
/// for yet. So its copy of object `N` can come from another entry that leads to a second
/// `N G obj`, or from an object stream no entry names, when what `N`'s own entry leads to is
/// something lopdf cannot parse and viewers can. Viewers read `N` from its own entry only. The
/// audits compare lopdf's copies, so they check with this that each copy they rely on is the one
/// `N`'s entry leads to (review of PR #51, defect 1).
struct EntryReader<'a> {
    /// lopdf's reader over the bytes it parsed, holding the revision's cross-reference: its
    /// `get_object` reads one object through that object's own entry, the way the load did.
    reader: lopdf::Reader<'a>,
    /// For each object number, the in-use entries whose offset leads to an `N G obj` of it.
    headers: std::collections::HashMap<u32, Vec<u32>>,
}

impl<'a> EntryReader<'a> {
    /// `doc` is lopdf's load of `pdf`.
    fn new(pdf: &'a [u8], doc: &Document) -> Self {
        // lopdf reads from the first `%PDF-` on, and its offsets count from there.
        let start = pdf.windows(5).position(|w| w == b"%PDF-").unwrap_or(0);
        let buffer = &pdf[start..];
        let mut headers: std::collections::HashMap<u32, Vec<u32>> = Default::default();
        for (&m, entry) in &doc.reference_table.entries {
            if let lopdf::xref::XrefEntry::Normal { offset, .. } = entry {
                if let Some(n) = usize::try_from(*offset)
                    .ok()
                    .and_then(|o| crate::xref::object_header_number_at(buffer, o))
                {
                    headers.entry(n).or_default().push(m);
                }
            }
        }
        let mut document = Document::new();
        document.reference_table = doc.reference_table.clone();
        let reader = lopdf::Reader {
            buffer,
            document,
            encryption_state: None,
            raw_objects: Default::default(),
            password: None,
            strict: false,
        };
        EntryReader { reader, headers }
    }

    /// No in-use entry other than `num`'s own leads to an object numbered `num`.
    fn sole_entry_for(&self, num: u32) -> bool {
        self.headers
            .get(&num)
            .is_none_or(|entries| entries.iter().all(|&m| m == num))
    }

    /// Whether `doc`'s copy of `id` (lopdf's load of these bytes through
    /// [`load_for_inspection`]) is the object `id`'s own entry leads to: no other entry leads to
    /// an object of that number (or to the object stream its entry names), and reading `id`
    /// through its entry, or from the object stream its entry names, gives the same object.
    fn own_copy(&self, doc: &Document, id: ObjectId) -> bool {
        let Some(have) = doc.objects.get(&id) else {
            return false;
        };
        if !self.sole_entry_for(id.0) {
            return false;
        }
        if let Some(lopdf::xref::XrefEntry::Compressed { container, .. }) =
            doc.reference_table.get(id.0)
        {
            if !self.sole_entry_for(*container) {
                return false;
            }
        }
        let Ok(mut read) = self
            .reader
            .get_object(id, &mut std::collections::HashSet::new())
        else {
            return false;
        };
        shrink_large_image(&mut read, ImageBytes::Digest);
        read == *have
    }
}

/// Whether two objects are equal, ignoring how strings were written (literal or hexadecimal).
fn same_object(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::String(x, _), Object::String(y, _)) => x == y,
        (Object::Array(x), Object::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_object(p, q))
        }
        (Object::Dictionary(x), Object::Dictionary(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_ok_and(|w| same_object(v, w)))
        }
        _ => a == b,
    }
}

/// Objects the previous revision's cross-reference lists but lopdf could not read there, which
/// `new` defines: they would pass as new objects although other readers may have shown the old
/// ones (docs/SECURITY_REVIEW_LOAD_FILTER.md, finding 1).
fn redefined_unreadable_objects(old: &Document, new: &Document) -> Vec<String> {
    new.objects
        .keys()
        .filter(|id| {
            matches!(
                old.reference_table.get(id.0),
                Some(
                    lopdf::xref::XrefEntry::Normal { .. }
                        | lopdf::xref::XrefEntry::Compressed { .. }
                )
            ) && !old.objects.contains_key(id)
        })
        .map(|id| {
            format!(
                "object {} {} could not be read in the previous revision and was redefined",
                id.0, id.1
            )
        })
        .collect()
}

/// Describe the annotation `ad` that an increment added to page `page_index` of `doc`.
fn added_annotation(
    doc: &Document,
    ad: &Dictionary,
    page_index: u32,
    is_new_object: bool,
) -> AddedAnnotation {
    let (appearance, shape_problems) = annotation_shape(doc, ad);
    let rect_vals = resolved_vec(doc, ad.get(b"Rect").ok());
    let mut rect = [0.0f32; 4];
    for (i, v) in rect_vals.iter().take(4).enumerate() {
        rect[i] = num_as_f32(v).unwrap_or(0.0);
    }
    AddedAnnotation {
        page_index,
        subtype: obj_text(doc, ad.get(b"Subtype").ok()).unwrap_or_default(),
        field_type: obj_text(doc, ad.get(b"FT").ok()),
        rect,
        contents: obj_text(doc, ad.get(b"Contents").ok()),
        name: obj_text(doc, ad.get(b"NM").ok()).or_else(|| obj_text(doc, ad.get(b"Name").ok())),
        is_new_object,
        flags: ad.get(b"F").ok().and_then(|o| o.as_i64().ok()),
        default_appearance: obj_text(doc, ad.get(b"DA").ok()),
        appearance,
        shape_problems,
    }
}

/// The font object every SignPDF appearance stream uses, as a parsed dictionary.
fn standard_font() -> Dictionary {
    let mut d = Dictionary::new();
    for (key, name) in [
        ("Type", "Font"),
        ("Subtype", "Type1"),
        ("BaseFont", "Helvetica"),
        ("Encoding", "WinAnsiEncoding"),
    ] {
        d.set(
            key.as_bytes().to_vec(),
            Object::Name(name.as_bytes().to_vec()),
        );
    }
    d
}

/// Read an added annotation's appearance stream and list every way the annotation is built
/// differently from what SignPDF writes (see [`AddedAnnotation::shape_problems`]).
fn annotation_shape(doc: &Document, ad: &Dictionary) -> (Option<AddedAppearance>, Vec<String>) {
    let mut problems = Vec::new();
    let show = |key: &[u8]| String::from_utf8_lossy(key).to_string();
    let subtype = obj_text(doc, ad.get(b"Subtype").ok()).unwrap_or_default();
    let allowed: &[&[u8]] = match subtype.as_str() {
        "Widget" => &[
            b"Type", b"Subtype", b"FT", b"T", b"Rect", b"V", b"P", b"F", b"AP",
        ],
        "FreeText" => &[
            b"Type",
            b"Subtype",
            b"Rect",
            b"F",
            b"P",
            b"NM",
            b"Contents",
            b"DA",
            b"AP",
        ],
        "Stamp" => &[
            b"Type",
            b"Subtype",
            b"Rect",
            b"F",
            b"P",
            b"Name",
            b"T",
            b"Contents",
            b"AP",
        ],
        // Any other kind of annotation is refused outright by the caller.
        _ => return (None, problems),
    };
    for (key, _) in ad.iter() {
        if !allowed.contains(&key.as_slice()) {
            problems.push(format!(
                "a {subtype} annotation carries an unexpected /{} entry",
                show(key)
            ));
        }
    }
    let Ok(ap) = ad.get(b"AP") else {
        return (None, problems);
    };
    let normal = resolve(doc, ap)
        .and_then(|o| o.as_dict().ok())
        .filter(|apd| apd.len() == 1)
        .and_then(|apd| apd.get(b"N").ok())
        .and_then(|o| resolve(doc, o))
        .and_then(|o| o.as_stream().ok());
    let Some(stream) = normal else {
        problems.push(format!(
            "a {subtype} annotation's appearance is not a single normal appearance stream"
        ));
        return (None, problems);
    };
    let sd = &stream.dict;
    for (key, _) in sd.iter() {
        if ![
            &b"Type"[..],
            b"Subtype",
            b"FormType",
            b"BBox",
            b"Resources",
            b"Length",
        ]
        .contains(&key.as_slice())
        {
            problems.push(format!(
                "an appearance stream carries an unexpected /{} entry",
                show(key)
            ));
        }
    }
    let is_name = |key: &[u8], want: &[u8]| matches!(sd.get(key), Ok(Object::Name(n)) if n == want);
    if !is_name(b"Type", b"XObject") || !is_name(b"Subtype", b"Form") {
        problems.push("an appearance stream is not a form XObject".into());
    }
    // Resources: the standard font under /Helv, and nothing else that could draw.
    let resources = resolved_dict(doc, sd.get(b"Resources").ok());
    let fonts = resources.and_then(|r| resolved_dict(doc, r.get(b"Font").ok()));
    let font = fonts
        .filter(|f| f.len() == 1)
        .and_then(|f| resolved_dict(doc, f.get(b"Helv").ok()));
    let proc_set = resources.map(|r| resolved_vec(doc, r.get(b"ProcSet").ok()));
    let expected_proc_set = vec![
        Object::Name(b"PDF".to_vec()),
        Object::Name(b"Text".to_vec()),
    ];
    if resources.map(Dictionary::len) != Some(2)
        || font != Some(&standard_font())
        || proc_set != Some(expected_proc_set)
    {
        problems.push("an appearance stream does not use the standard font and resources".into());
    }
    let mut bbox = [f32::NAN; 4];
    let values = resolved_vec(doc, sd.get(b"BBox").ok());
    if values.len() == 4 {
        for (slot, value) in bbox.iter_mut().zip(&values) {
            *slot = num_as_f32(value).unwrap_or(f32::NAN);
        }
    }
    (
        Some(AddedAppearance {
            bbox,
            content: stream.content.clone(),
        }),
        problems,
    )
}

fn same_box(bbox: [f32; 4], w: f32, h: f32) -> bool {
    [0.0, 0.0, w, h]
        .iter()
        .zip(bbox.iter())
        .all(|(want, got)| (want - got).abs() < 0.001)
}

/// Check that an added field-value annotation draws exactly what the engine draws for `ft`.
/// The annotation's `/Rect`, name and `/Contents` are the caller's to check; this covers what a
/// reader sees.
pub fn check_field_annotation(a: &AddedAnnotation, ft: &FieldText) -> Vec<String> {
    let drawn = field_appearance(ft);
    let expected_da = format!("/Helv {} Tf 0 0 0.35 rg", fmt_num(drawn.size));
    let ok = a.flags == Some(196)
        && a.default_appearance.as_deref() == Some(expected_da.as_str())
        && a.appearance.as_ref().is_some_and(|ap| {
            same_box(ap.bbox, drawn.w, drawn.h) && ap.content == drawn.content.as_bytes()
        });
    if ok {
        Vec::new()
    } else {
        vec![format!(
            "what is drawn in '{}' is not what the engine draws for the recorded value",
            ft.name
        )]
    }
}

/// What the drawing area of a signature box may hold.
#[derive(Debug, Clone, Copy)]
pub enum InkRule<'a> {
    /// Envelope schema versions before 6, whose signature records keep no drawing: nothing, or
    /// pen strokes confined to the area ([`is_ink`]).
    Strokes,
    /// Version 6 and later: exactly what the engine draws for the drawing the signer's record
    /// keeps (nothing when it keeps none), which must also be pen strokes or filled paths
    /// confined to the area ([`is_ink`], [`is_filled_paths`]).
    Recorded(Option<&'a SignatureDrawing>),
}

/// Check the signature widget an increment added, whose `/Rect` is `rect`: with a `caption`
/// and a real rectangle it must draw exactly the engine's signature box for that caption, with
/// what `ink` allows in its drawing area; otherwise it must draw nothing.
pub fn check_signature_widget(
    a: &AddedAnnotation,
    rect: [f32; 4],
    caption: Option<&SignatureCaption>,
    ink: InkRule<'_>,
) -> Vec<String> {
    let mut problems = Vec::new();
    if a.flags != Some(132) {
        problems.push("the signature field has unexpected flags".to_string());
    }
    let (w, h) = (rect[2] - rect[0], rect[3] - rect[1]);
    let caption = caption.filter(|_| w > 1.0 && h > 1.0);
    match (caption, &a.appearance) {
        (None, None) => {}
        (None, Some(_)) => problems.push("an invisible signature draws something".to_string()),
        (Some(_), None) => problems.push("the signature box is not drawn".to_string()),
        (Some(caption), Some(ap)) => {
            let plain = signature_box(w, h, caption, false);
            let inked = signature_box(w, h, caption, true);
            let content = String::from_utf8_lossy(&ap.content);
            let drawn = || {
                content
                    .strip_prefix(inked.head.as_str())
                    .and_then(|rest| rest.strip_suffix(inked.tail.as_str()))
            };
            let shows = match ink {
                InkRule::Strokes => {
                    content == format!("{}{}", plain.head, plain.tail)
                        || drawn().is_some_and(|strokes| is_ink(strokes, inked.ink_box))
                }
                InkRule::Recorded(None) => content == format!("{}{}", plain.head, plain.tail),
                InkRule::Recorded(Some(drawing)) => drawn().is_some_and(|ops| {
                    let area = inked.ink_box;
                    let follows_the_rule = match drawing {
                        SignatureDrawing::Drawn { .. } => !ops.is_empty() && is_ink(ops, area),
                        SignatureDrawing::Typed { .. } => is_filled_paths(ops, area),
                    };
                    ops == drawing_ops(drawing, area) && follows_the_rule
                }),
            };
            let ok = same_box(ap.bbox, w, h) && shows;
            if !ok {
                problems.push(
                    "the signature box does not show what the engine draws for the verified signer"
                        .to_string(),
                );
            }
        }
    }
    problems
}

/// Check the document-id stamp a preparer's increment added: it shows `label`, as the engine
/// draws it, at its natural size.
pub fn check_document_id_stamp(a: &AddedAnnotation, label: &str) -> Vec<String> {
    check_document_id_stamp_lines(a, &[label.to_string()])
}

/// [`check_document_id_stamp`] for a stamp of several lines
/// ([`crate::workflow::document_id_lines`]).
pub fn check_document_id_stamp_lines(a: &AddedAnnotation, lines: &[String]) -> Vec<String> {
    let stamp = document_id_stamp(lines);
    let (w, h) = (a.rect[2] - a.rect[0], a.rect[3] - a.rect[1]);
    let ok = a.flags == Some(196)
        && a.contents.as_deref() == Some(stamp.text.as_str())
        && (w - stamp.w).abs() < 0.01
        && (h - stamp.h).abs() < 0.01
        && a.appearance.as_ref().is_some_and(|ap| {
            same_box(ap.bbox, stamp.w, stamp.h) && ap.content == stamp.content.as_bytes()
        });
    if ok {
        Vec::new()
    } else {
        vec!["the document-id stamp is not the one the engine draws".to_string()]
    }
}

fn verifying_key_from_cert(cert: &Certificate) -> Result<VerifyingKey> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| pades("public key not byte-aligned"))?;
    VerifyingKey::from_sec1_bytes(point).map_err(|e| pades(format!("public key: {e}")))
}

fn first_cn(cert: &Certificate) -> Option<String> {
    // CN OID 2.5.4.3
    let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3");
    for rdn in cert.tbs_certificate().subject().iter_rdn() {
        for atv in rdn.iter() {
            if atv.oid == cn_oid {
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef>() {
                    return Some(s.as_str().to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef>() {
                    return Some(s.as_str().to_string());
                }
            }
        }
    }
    None
}

fn field_name_for(doc: &Document, sig_id: ObjectId) -> Option<String> {
    for obj in doc.objects.values() {
        let Ok(dict) = obj.as_dict() else { continue };
        if matches!(dict.get(b"V"), Ok(Object::Reference(r)) if *r == sig_id) {
            if let Ok(Object::String(t, _)) = dict.get(b"T") {
                return Some(String::from_utf8_lossy(t).to_string());
            }
        }
    }
    None
}

// --- low-level PDF helpers ---------------------------------------------------------------

/// A copy of `pdf`, ending in a line break, with room for an increment of about `extra` bytes
/// plus slack for the small objects every increment writes.
///
/// Sized once on purpose: growing a copy of a large document by pushing to it reallocates at
/// twice its size while the old buffer is still alive, so a 50 MB document briefly needed
/// 150 MB for its output alone (measured in WebAssembly, where memory never shrinks).
#[cfg(test)]
fn increment_buffer(pdf: &[u8], extra: usize) -> Vec<u8> {
    const SLACK: usize = 256 * 1024;
    let mut out = Vec::with_capacity(pdf.len() + 1 + extra + SLACK);
    out.extend_from_slice(pdf);
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

/// An incremental update being written after a document: offsets (cross-reference entries, a
/// signature's `ByteRange`) are positions in the whole file, but only the appended bytes are held,
/// so writing one never copies the document.
struct Increment {
    /// The length of the document it follows: the file offset of its first byte.
    base: usize,
    buf: Vec<u8>,
}

impl Increment {
    /// The increment after `pdf`, starting on a new line, with room for `extra` bytes plus the
    /// small objects every increment writes.
    fn after(pdf: &[u8], extra: usize) -> Self {
        const SLACK: usize = 16 * 1024;
        let mut buf = Vec::with_capacity(1 + extra + SLACK);
        if !pdf.ends_with(b"\n") {
            buf.push(b'\n');
        }
        Increment {
            base: pdf.len(),
            buf,
        }
    }

    /// The file offset of the next byte written.
    fn pos(&self) -> usize {
        self.base + self.buf.len()
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn push(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    /// Append `n` copies of `byte`.
    fn fill(&mut self, n: usize, byte: u8) {
        self.buf.resize(self.buf.len() + n, byte);
    }

    /// Overwrite the bytes at file offset `at`, which this increment wrote.
    fn write_at(&mut self, at: usize, bytes: &[u8]) {
        let i = at - self.base;
        self.buf[i..i + bytes.len()].copy_from_slice(bytes);
    }

    /// Overwrite a ten-digit placeholder at file offset `at` with `val`.
    fn put10(&mut self, at: usize, val: u64) {
        self.write_at(at, format!("{val:010}").as_bytes());
    }

    /// The bytes between file offsets `from` and `to`, both within this increment.
    fn range(&self, from: usize, to: usize) -> &[u8] {
        &self.buf[from - self.base..to - self.base]
    }

    /// Only the appended bytes.
    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// The new document: `pdf` (the document it follows) and this increment.
    fn appended_to(self, pdf: &[u8]) -> Vec<u8> {
        debug_assert_eq!(pdf.len(), self.base);
        appended(pdf, &self.buf)
    }
}

/// `pdf` followed by `increment`, allocated once at its final size: growing a copy of a large
/// document by pushing to it reallocates at twice its size while the old buffer is still alive.
pub fn appended(pdf: &[u8], increment: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pdf.len() + increment.len());
    out.extend_from_slice(pdf);
    out.extend_from_slice(increment);
    out
}

fn write_indirect(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    id: ObjectId,
    body: &[u8],
) {
    let off = out.pos();
    out.extend_from_slice(format!("{} {} obj\n", id.0, id.1).as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendobj\n");
    xref.push((id, off));
}

/// Append the classic `xref` table, `trailer`, `startxref`, and `%%EOF` for an increment.
fn finish_increment(
    out: &mut Increment,
    xref: &mut [(ObjectId, usize)],
    size: u32,
    root_id: ObjectId,
    prev_startxref: u64,
    trailer: &Dictionary,
) {
    let xref_off = out.pos();
    out.extend_from_slice(b"xref\n");
    out.extend_from_slice(build_xref_sections(xref).as_bytes());
    out.extend_from_slice(b"trailer\n<< /Size ");
    out.extend_from_slice(size.to_string().as_bytes());
    out.extend_from_slice(
        format!(
            " /Root {} {} R /Prev {}",
            root_id.0, root_id.1, prev_startxref
        )
        .as_bytes(),
    );
    if let Ok(id_obj) = trailer.get(b"ID") {
        out.extend_from_slice(b" /ID ");
        let mut body = Vec::new();
        write_object(&mut body, id_obj);
        out.extend_from_slice(&body);
    }
    if let Ok(info) = trailer.get(b"Info") {
        out.extend_from_slice(b" /Info ");
        let mut body = Vec::new();
        write_object(&mut body, info);
        out.extend_from_slice(&body);
    }
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(xref_off.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
}

/// Write the `EmbeddedFile` stream object and its `Filespec` object for an attachment.
fn write_embedded_file(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    ef_id: ObjectId,
    fs_id: ObjectId,
    embed: &EmbeddedFile,
) {
    let compressed = compressed_attachment(&embed.data);
    let (filter, stored) = match &compressed {
        Some(c) => (" /Filter /FlateDecode", c.as_slice()),
        None => ("", embed.data.as_slice()),
    };
    let mut ef_body = Vec::new();
    ef_body.extend_from_slice(
        format!(
            "<< /Type /EmbeddedFile /Subtype /{}{filter} /Length {} /Params << /Size {} >> >>\nstream\n",
            name_token(&embed.mime),
            stored.len(),
            embed.data.len(),
        )
        .as_bytes(),
    );
    ef_body.extend_from_slice(stored);
    ef_body.extend_from_slice(b"\nendstream");
    write_indirect(out, xref, ef_id, &ef_body);

    let fs_body = format!(
        "<< /Type /Filespec /F ({name}) /UF ({name}) /EF << /F {ef} 0 R >> \
         /AFRelationship /{rel} /Desc ({desc}) >>",
        name = esc_pdf_str(&embed.name),
        ef = ef_id.0,
        rel = name_token(&embed.relationship),
        desc = esc_pdf_str(&embed.description),
    );
    write_indirect(out, xref, fs_id, fs_body.as_bytes());
}

/// Attachments shorter than this are stored as they are: compressing them saves next to nothing.
const COMPRESS_FROM: usize = 1024;

/// The largest attachment [`read_attachment`] inflates: far above any envelope (200 signers with
/// drawings are a few megabytes), and a bound on what a hostile document can make it allocate.
pub const MAX_ATTACHMENT_INFLATED: usize = 32 * 1024 * 1024;

/// `data` compressed for a `/FlateDecode` attachment (zlib, level 6), or `None` when it is short or
/// would not shrink.
///
/// The workflow re-embeds the whole envelope in every revision, and with many signers most of a
/// revision was its JSON: about 316 KB a revision at 200 signers, two thirds of it the records
/// and audit entries of the earlier signers. JSON compresses about 3x.
fn compressed_attachment(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < COMPRESS_FROM {
        return None;
    }
    let packed = miniz_oxide::deflate::compress_to_vec_zlib(data, 6);
    (packed.len() < data.len()).then_some(packed)
}

/// The bytes of an embedded-file stream: its content, inflated when its `/Filter` is
/// `/FlateDecode` (what [`write_embedded_file`] writes). Any other filter, or decode parameters,
/// is refused rather than returned undecoded. Either refusal is a [`SignPdfError::Encoding`]: the
/// attachment is there but cannot be read (its bytes were damaged, say).
fn attachment_bytes(stream: &lopdf::Stream) -> Result<Vec<u8>> {
    let filter = match stream.dict.get(b"Filter") {
        Err(_) => return Ok(stream.content.clone()),
        Ok(Object::Name(n)) => n.as_slice(),
        Ok(Object::Array(a)) if a.len() == 1 => match &a[0] {
            Object::Name(n) => n.as_slice(),
            _ => b"",
        },
        Ok(_) => b"",
    };
    if filter != b"FlateDecode" || stream.dict.get(b"DecodeParms").is_ok() {
        return Err(SignPdfError::Encoding(
            "the attachment is encoded with a filter other than /FlateDecode".into(),
        ));
    }
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
        &stream.content,
        MAX_ATTACHMENT_INFLATED,
    )
    .map_err(|e| SignPdfError::Encoding(format!("the attachment does not inflate: {e:?}")))
}

/// Encode a string as the body of a PDF name (escaping non-regular bytes as `#XX`).
fn name_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+') {
            out.push(b as char);
        } else {
            out.push_str(&format!("#{b:02X}"));
        }
    }
    out
}

/// Resolve one level of indirection, returning the pointed-to object.
fn resolve<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Object> {
    match obj {
        Object::Reference(r) => doc.get_object(*r).ok(),
        other => Some(other),
    }
}

fn resolved_dict<'a>(doc: &'a Document, obj: Option<&'a Object>) -> Option<&'a Dictionary> {
    resolve(doc, obj?)?.as_dict().ok()
}

fn resolved_array<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Vec<Object>> {
    resolve(doc, obj)?.as_array().ok()
}

fn num_as_f32(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

/// Resolve the effective `/MediaBox` for `page`, walking the `/Parent` chain for an inherited
/// value and falling back to US Letter (`[0 0 612 792]`) when none is present.
fn page_media_box(doc: &Document, page: ObjectId) -> [f32; 4] {
    let mut current = Some(page);
    let mut guard = 0;
    while let (Some(id), true) = (current, guard < 32) {
        guard += 1;
        let Ok(dict) = doc.get_object(id).and_then(|o| o.as_dict()) else {
            break;
        };
        if let Some(arr) = dict
            .get(b"MediaBox")
            .ok()
            .and_then(|o| resolved_array(doc, o))
        {
            if arr.len() == 4 {
                let mut mb = [0.0f32; 4];
                for (i, v) in arr.iter().enumerate() {
                    mb[i] = num_as_f32(v).unwrap_or(0.0);
                }
                return mb;
            }
        }
        current = dict.get(b"Parent").ok().and_then(|o| o.as_reference().ok());
    }
    [0.0, 0.0, 612.0, 792.0]
}

// --- page geometry ------------------------------------------------------------------------

/// An annotation already present on a page (e.g. an existing form field), for overlap checks.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExistingAnnotation {
    /// `/Subtype`, e.g. `Widget`, `Link`, `FreeText`.
    pub subtype: String,
    /// `/FT` for widgets (e.g. `Tx`, `Sig`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
    /// Normalised `[x1, y1, x2, y2]` in default user space.
    pub rect: [f32; 4],
}

/// The geometry of one page, with inherited attributes resolved. All boxes are normalised
/// `[x1, y1, x2, y2]` (x1 < x2, y1 < y2) in **default user space** (points, origin bottom-left,
/// unrotated) — the space field rectangles use.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PageGeometry {
    /// 0-based page index.
    pub index: u32,
    pub media_box: [f32; 4],
    /// The visible region: `/CropBox` (default: the MediaBox), intersected with the MediaBox.
    pub crop_box: [f32; 4],
    /// Clockwise display rotation: 0, 90, 180 or 270.
    pub rotate: u32,
    pub annotations: Vec<ExistingAnnotation>,
}

/// Look up an inheritable page attribute (`MediaBox`, `CropBox`, `Rotate`) through `/Parent`.
fn inherited<'a>(doc: &'a Document, page: ObjectId, key: &[u8]) -> Option<&'a Object> {
    let mut current = Some(page);
    let mut guard = 0;
    while let (Some(id), true) = (current, guard < 32) {
        guard += 1;
        let dict = doc.get_object(id).and_then(|o| o.as_dict()).ok()?;
        if let Ok(v) = dict.get(key) {
            return resolve(doc, v);
        }
        current = dict.get(b"Parent").ok().and_then(|o| o.as_reference().ok());
    }
    None
}

/// A normalised rectangle from a 4-number array.
fn normalized_box(doc: &Document, obj: Option<&Object>) -> Option<[f32; 4]> {
    let arr = obj.and_then(|o| resolved_array(doc, o))?;
    if arr.len() != 4 {
        return None;
    }
    let v: Vec<f32> = arr.iter().map(num_as_f32).collect::<Option<_>>()?;
    if v.iter().any(|n| !n.is_finite()) {
        return None;
    }
    Some([
        v[0].min(v[2]),
        v[1].min(v[3]),
        v[0].max(v[2]),
        v[1].max(v[3]),
    ])
}

/// Geometry of every page of `pdf` (MediaBox, effective CropBox, rotation, annotations).
pub fn page_geometry(pdf: &[u8]) -> Result<Vec<PageGeometry>> {
    let doc = load_for_inspection(pdf, ImageBytes::Drop)
        .map_err(|e| pades(format!("cannot parse PDF: {e}")))?;
    let mut out = Vec::new();
    for (number, page_id) in doc.get_pages() {
        let media = normalized_box(&doc, inherited(&doc, page_id, b"MediaBox"))
            .unwrap_or([0.0, 0.0, 612.0, 792.0]);
        let crop = normalized_box(&doc, inherited(&doc, page_id, b"CropBox"))
            .map(|c| {
                [
                    c[0].max(media[0]),
                    c[1].max(media[1]),
                    c[2].min(media[2]),
                    c[3].min(media[3]),
                ]
            })
            .filter(|c| c[0] < c[2] && c[1] < c[3])
            .unwrap_or(media);
        let rotate = match inherited(&doc, page_id, b"Rotate") {
            Some(Object::Integer(r)) if r % 90 == 0 => r.rem_euclid(360) as u32,
            _ => 0,
        };
        let mut annotations = Vec::new();
        if let Ok(page) = doc.get_object(page_id).and_then(|o| o.as_dict()) {
            for a in resolved_vec(&doc, page.get(b"Annots").ok()) {
                let Some(ad) = resolve(&doc, &a).and_then(|o| o.as_dict().ok()) else {
                    continue;
                };
                let Some(rect) = normalized_box(&doc, ad.get(b"Rect").ok()) else {
                    continue;
                };
                annotations.push(ExistingAnnotation {
                    subtype: obj_text(&doc, ad.get(b"Subtype").ok()).unwrap_or_default(),
                    field_type: obj_text(&doc, ad.get(b"FT").ok()),
                    rect,
                });
            }
        }
        out.push(PageGeometry {
            index: number - 1,
            media_box: media,
            crop_box: crop,
            rotate,
            annotations,
        });
    }
    Ok(out)
}

/// Keep only printable ASCII (`0x20..=0x7E`), replacing anything else with `?`, and cap the
/// result at `max` characters. For identifiers the engine writes and matches again (annotation
/// names, the document-ID stamp); text typed by people goes through [`drawable_caption`].
fn ascii_caption(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() >= max {
            break;
        }
        let b = c as u32;
        if (0x20..=0x7E).contains(&b) {
            out.push(c);
        } else {
            out.push('?');
        }
    }
    out
}

/// Write a visible signature appearance: a form XObject (`ap_id`) drawing a framed three-row
/// caption — `Signed by:` / signer name / `Sig <code>  <time>  via <issuer>` — using the shared
/// Helvetica font object `font_id`. Referenced from the signature widget's `/AP /N`, so it is
/// covered by the signer's `ByteRange`.
///
/// With `ink`, the signer's drawing (pen strokes, or a typed signature's filled paths) takes the
/// left part of the box and the caption the rest. The caption always stays: the drawing says
/// nothing about who signed.
#[allow(clippy::too_many_arguments)]
fn write_signature_appearance(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    ap_id: ObjectId,
    font_id: ObjectId,
    w: f32,
    h: f32,
    caption: &SignatureCaption,
    ink: Option<&SignatureDrawing>,
) {
    let parts = signature_box(w, h, caption, ink.is_some());
    let drawing = ink.map(|ink| drawing_ops(ink, parts.ink_box));
    let cs = format!(
        "{}{}{}",
        parts.head,
        drawing.unwrap_or_default(),
        parts.tail
    );
    write_form_xobject(out, xref, ap_id, font_id, w, h, &cs);
}

/// The content of a signature box, split around the optional drawing.
struct SignatureBox {
    /// Background and frame.
    head: String,
    /// The three caption rows.
    tail: String,
    /// Where the drawing goes, as `[x, y, w, h]` (empty without a drawing).
    ink_box: [f32; 4],
}

/// What a `w`×`h` signature box shows for `caption`, laid out with or without room for the
/// signer's drawing at its left. The single definition of the box: the signer writes it and
/// the verifier compares against it.
fn signature_box(w: f32, h: f32, caption: &SignatureCaption, with_ink: bool) -> SignatureBox {
    let pad = 4.0_f32;
    // The drawing gets 40% of the width; the caption starts after it.
    let ink_w = if with_ink {
        (w * 0.40 - pad).max(0.0)
    } else {
        0.0
    };
    let text_x = if with_ink { pad + ink_w + pad } else { pad };
    let text_w = (w - text_x - pad).max(1.0);

    let name = drawable_caption(&caption.signer_name, 48);
    let footer = drawable_caption(
        &format!(
            "Sig {}  {}  via {}",
            caption.code, caption.signed_at, caption.issuer
        ),
        72,
    );
    // Shrink a row rather than let it run out of the box.
    let name_size = fit_size(&name, (h * 0.30).clamp(9.0, 14.0), text_w);
    let label_size = (h * 0.18).clamp(6.0, 9.0);
    let foot_size = fit_size(&footer, (h * 0.16).clamp(5.0, 8.0), text_w);

    let label_y = (h - 3.0 - label_size).max(0.0);
    let name_y = (h * 0.40).max(foot_size + 2.0);
    let foot_y = 4.0_f32;

    let head = format!(
        "q\n0.96 0.96 0.98 rg\n0 0 {w} {h} re\nf\n0.45 0.45 0.55 RG\n0.7 w\n0.5 0.5 {wi} {hi} re\nS\n",
        w = fmt_num(w),
        h = fmt_num(h),
        wi = fmt_num(w - 1.0),
        hi = fmt_num(h - 1.0),
    );
    let tail = format!(
        "BT\n/Helv {ls} Tf\n0.30 0.30 0.40 rg\n{tx} {ly} Td\n(Signed by:) Tj\nET\n\
         BT\n/Helv {ns} Tf\n0 0 0 rg\n{tx} {ny} Td\n({name}) Tj\nET\n\
         BT\n/Helv {fs} Tf\n0.30 0.30 0.40 rg\n{tx} {fy} Td\n({footer}) Tj\nET\nQ\n",
        ls = fmt_num(label_size),
        ns = fmt_num(name_size),
        fs = fmt_num(foot_size),
        tx = fmt_num(text_x),
        ly = fmt_num(label_y),
        ny = fmt_num(name_y),
        fy = fmt_num(foot_y),
        name = winansi_literal(&name),
        footer = winansi_literal(&footer),
    );
    SignatureBox {
        head,
        tail,
        ink_box: [pad, 3.0, ink_w, (h - 6.0).max(0.0)],
    }
}

/// Write a form XObject `id` with bounding box `w`×`h` drawing `content` with `/Helv` = `font_id`.
fn write_form_xobject(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    id: ObjectId,
    font_id: ObjectId,
    w: f32,
    h: f32,
    content: &str,
) {
    let mut form = Vec::new();
    form.extend_from_slice(
        format!(
            "<< /Type /XObject /Subtype /Form /FormType 1 /BBox [0 0 {} {}] \
             /Resources << /Font << /Helv {} 0 R >> /ProcSet [/PDF /Text] >> /Length {} >>\nstream\n",
            fmt_num(w),
            fmt_num(h),
            font_id.0,
            content.len(),
        )
        .as_bytes(),
    );
    form.extend_from_slice(content.as_bytes());
    form.extend_from_slice(b"\nendstream");
    write_indirect(out, xref, id, &form);
}

/// Content-stream operators drawing a checkbox or radio mark in the `side`-sized square whose
/// bottom-left corner is at `(0, y0)`: the outline, plus a tick or a filled dot when selected.
fn mark_ops(mark: FieldMark, side: f32, y0: f32) -> String {
    let n = |v: f32| fmt_num((v * 100.0).round() / 100.0);
    let inset = (side * 0.12).max(1.0);
    let (x1, y1, d) = (inset, y0 + inset, (side - 2.0 * inset).max(1.0));
    let circle = |cx: f32, cy: f32, r: f32| {
        let k = 0.5523 * r;
        format!(
            "{} {} m\n{} {} {} {} {} {} c\n{} {} {} {} {} {} c\n{} {} {} {} {} {} c\n{} {} {} {} {} {} c\n",
            n(cx + r), n(cy),
            n(cx + r), n(cy + k), n(cx + k), n(cy + r), n(cx), n(cy + r),
            n(cx - k), n(cy + r), n(cx - r), n(cy + k), n(cx - r), n(cy),
            n(cx - r), n(cy - k), n(cx - k), n(cy - r), n(cx), n(cy - r),
            n(cx + k), n(cy - r), n(cx + r), n(cy - k), n(cx + r), n(cy),
        )
    };
    let stroke = "0 0 0.35 RG\n0.8 w\n";
    match mark {
        FieldMark::None => String::new(),
        FieldMark::Checkbox { checked } => {
            let mut s = format!("{stroke}{} {} {} {} re\nS\n", n(x1), n(y1), n(d), n(d));
            if checked {
                s.push_str(&format!(
                    "{} w\n1 J\n1 j\n{} {} m\n{} {} l\n{} {} l\nS\n",
                    n((d * 0.14).max(1.0)),
                    n(x1 + d * 0.2),
                    n(y1 + d * 0.52),
                    n(x1 + d * 0.42),
                    n(y1 + d * 0.26),
                    n(x1 + d * 0.8),
                    n(y1 + d * 0.76),
                ));
            }
            s
        }
        FieldMark::Radio { selected } => {
            let (cx, cy, r) = (x1 + d / 2.0, y1 + d / 2.0, d / 2.0);
            let mut s = format!("{stroke}{}S\n", circle(cx, cy, r));
            if selected {
                s.push_str(&format!("0 0 0.35 rg\n{}f\n", circle(cx, cy, r * 0.5)));
            }
            s
        }
    }
}

/// Write a read-only `FreeText` annotation (`annot_id`) drawing a field value inside its field
/// rectangle, with its own appearance stream (`ap_id`) so every viewer renders it identically.
/// Flags: Print + ReadOnly + Locked (`/F 196`).
fn write_field_text(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    annot_id: ObjectId,
    ap_id: ObjectId,
    font_id: ObjectId,
    page_id: ObjectId,
    ft: &FieldText,
) {
    let drawn = field_appearance(ft);
    write_field_annotation(
        out,
        xref,
        annot_id,
        ap_id,
        font_id,
        page_id,
        ft,
        drawn.size,
        drawn.w,
        drawn.h,
        &drawn.content,
    );
}

/// How a field value is drawn: the font size (also recorded in `/DA`), the form's size and its
/// content stream.
struct DrawnField {
    size: f32,
    w: f32,
    h: f32,
    content: String,
}

/// What the engine draws for `ft`. The single definition of a field value's look: the signer
/// writes it and the verifier compares against it.
fn field_appearance(ft: &FieldText) -> DrawnField {
    let r = ft.rect;
    let w = (r[2] - r[0]).max(1.0);
    let h = (r[3] - r[1]).max(1.0);
    if ft.multiline {
        // Wrapped lines from the top; text that fits at no size is clipped (signing refuses it
        // beforehand, see `layout_multiline`).
        let (size, lines) = layout_multiline(&ft.text, w, h).unwrap_or_else(|| {
            (
                5.0,
                wrap_lines(&multiline_text(&ft.text), 5.0, w - 2.0 * FIELD_PAD),
            )
        });
        let mut cs = format!(
            "q\n0 0 {} {} re\nW\nn\nBT\n/Helv {s} Tf\n0 0 0.35 rg\n{l} TL\n{x} {y} Td\n",
            fmt_num(w),
            fmt_num(h),
            s = fmt_num(size),
            l = fmt_num(size * LEADING),
            x = fmt_num(FIELD_PAD),
            // Baseline of the first line: one line down from the top padding, less the descent.
            y = fmt_num(h - FIELD_PAD - size * 0.95),
        );
        for line in &lines {
            cs.push_str(&format!("({}) Tj\nT*\n", winansi_literal(line)));
        }
        cs.push_str("ET\nQ\n");
        return DrawnField {
            size,
            w,
            h,
            content: cs,
        };
    }
    // A marked field draws its box or circle in a square at the left, then the caption.
    let side = if ft.mark == FieldMark::None {
        0.0
    } else {
        h.min(w)
    };
    let text = drawable_caption(&ft.text, 120);
    let left = if side > 0.0 { side + 3.0 } else { 2.0 };
    // Shrink long text to fit the field width rather than clipping it.
    let room = w - left - FIELD_PAD;
    let size = fit_size(&text, (h * 0.6).clamp(6.0, 14.0), room.max(1.0));
    let ty = ((h - size) / 2.0).max(1.0) + 1.0;
    let mut cs = format!("q\n0 0 {} {} re\nW\nn\n", fmt_num(w), fmt_num(h));
    cs.push_str(&mark_ops(ft.mark, side, (h - side) / 2.0));
    if !text.is_empty() && room > 0.0 {
        cs.push_str(&format!(
            "BT\n/Helv {s} Tf\n0 0 0.35 rg\n{x} {ty} Td\n({t}) Tj\nET\n",
            s = fmt_num(size),
            x = fmt_num(left),
            ty = fmt_num(ty),
            t = winansi_literal(&text),
        ));
    }
    cs.push_str("Q\n");
    DrawnField {
        size,
        w,
        h,
        content: cs,
    }
}

/// Write the `FreeText` annotation of a field value and its appearance stream `cs`.
#[allow(clippy::too_many_arguments)]
fn write_field_annotation(
    out: &mut Increment,
    xref: &mut Vec<(ObjectId, usize)>,
    annot_id: ObjectId,
    ap_id: ObjectId,
    font_id: ObjectId,
    page_id: ObjectId,
    ft: &FieldText,
    size: f32,
    w: f32,
    h: f32,
    cs: &str,
) {
    let r = ft.rect;
    let annot_body = format!(
        "<< /Type /Annot /Subtype /FreeText /Rect [{} {} {} {}] /F 196 /P {} 0 R \
         /NM ({}) /Contents {} /DA (/Helv {} Tf 0 0 0.35 rg) /AP << /N {} 0 R >> >>",
        fmt_num(r[0]),
        fmt_num(r[1]),
        fmt_num(r[2]),
        fmt_num(r[3]),
        page_id.0,
        esc_pdf_str(&ascii_caption(&ft.name, 64)),
        pdf_text_string(&field_contents(&ft.text, ft.mark, ft.multiline)),
        fmt_num(size),
        ap_id.0,
    );
    write_indirect(out, xref, annot_id, annot_body.as_bytes());
    write_form_xobject(out, xref, ap_id, font_id, w, h, cs);
}

/// The subsections of an increment's table: one in-use entry per object, with the object's own
/// generation (a viewer refuses an entry whose generation differs from the `N G obj` it points
/// at, and then reads the whole file another way).
fn build_xref_sections(xref: &mut [(ObjectId, usize)]) -> String {
    xref.sort_by_key(|e| e.0 .0);
    let mut s = String::new();
    let mut i = 0;
    while i < xref.len() {
        let start = xref[i].0 .0;
        let mut run = vec![xref[i]];
        let mut last = start;
        let mut j = i + 1;
        while j < xref.len() && xref[j].0 .0 == last + 1 {
            last = xref[j].0 .0;
            run.push(xref[j]);
            j += 1;
        }
        s.push_str(&format!("{} {}\n", start, run.len()));
        for ((_, gen), off) in run {
            s.push_str(&format!("{off:010} {gen:05} n \n"));
        }
        i = j;
    }
    s
}

fn find_last_startxref(bytes: &[u8]) -> Result<u64> {
    let needle = b"startxref";
    let pos = bytes
        .windows(needle.len())
        .rposition(|w| w == needle)
        .ok_or_else(|| pades("original PDF has no startxref"))?;
    let mut i = pos + needle.len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut j = i;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    std::str::from_utf8(&bytes[i..j])
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| pades("could not read startxref offset"))
}

/// Write `obj` so that it reads back as the same object: the engine rewrites objects of the
/// previous revision (a page, the catalog, the form), and the audits compare the two readings.
fn write_object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(fmt_real(*r).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, fmt) => write_pdf_string(out, s, *fmt),
        Object::Reference(id) => out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes()),
        Object::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, e);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => {
            write_dict(out, &s.dict);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&s.content);
            out.extend_from_slice(b"\nendstream");
        }
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        out.push(b' ');
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
    }
    out.extend_from_slice(b" >>");
}

fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{b:02X}").as_bytes());
        }
    }
}

fn write_pdf_string(out: &mut Vec<u8>, s: &[u8], fmt: StringFormat) {
    match fmt {
        StringFormat::Hexadecimal => {
            out.push(b'<');
            out.extend_from_slice(hex::encode_upper(s).as_bytes());
            out.push(b'>');
        }
        StringFormat::Literal => {
            out.push(b'(');
            for &b in s {
                match b {
                    b'(' | b')' | b'\\' => {
                        out.push(b'\\');
                        out.push(b);
                    }
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    _ => out.push(b),
                }
            }
            out.push(b')');
        }
    }
}

pub(crate) fn fmt_num(r: f32) -> String {
    if r.is_finite() && r == r.trunc() && r.abs() < 1e15 {
        format!("{}", r as i64)
    } else {
        format!("{r}")
    }
}

/// A real number of a rewritten object, written so that it reads back as a real: [`fmt_num`]
/// writes `612.0` as `612`, which reads back as the integer 612, and the audits would then see the
/// rewritten object differ from the one it replaces (Microsoft Print to PDF writes its page boxes
/// as `[ 0.0 0.0 612.0 792.0 ]`). Drawn content keeps [`fmt_num`]: it is compared byte for byte.
fn fmt_real(r: f32) -> String {
    let s = fmt_num(r);
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        format!("{s}.0")
    } else {
        s
    }
}

/// `s` as the body of a PDF literal string. Only for ASCII: text that may hold anything else
/// goes through [`pdf_text_string`] (dictionary values) or [`winansi_literal`] (drawn text).
fn esc_pdf_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// `s` as a PDF text string object (ISO 32000-1 §7.9.2.2), for dictionary values that a viewer
/// shows in its own fonts (`/Contents`, `/Name`, `/Reason`…) and that may therefore hold any
/// character: a literal string while `s` is plain ASCII, otherwise UTF-16BE with its byte-order
/// mark, in hexadecimal.
fn pdf_text_string(s: &str) -> String {
    if s.chars().all(|c| c == '\n' || (' '..='~').contains(&c)) {
        return format!("({})", esc_pdf_str(s));
    }
    let mut out = String::from("<FEFF");
    for unit in s.encode_utf16() {
        out.push_str(&format!("{unit:04X}"));
    }
    out.push('>');
    out
}

/// The text of a PDF string object: UTF-16BE when it starts with that byte-order mark (see
/// [`pdf_text_string`]), otherwise its bytes as UTF-8, which is how ASCII strings read. Bytes
/// that do not decode become U+FFFD, so a malformed string never equals an expected text.
fn decode_text_string(bytes: &[u8]) -> String {
    let Some(utf16) = bytes.strip_prefix(&[0xFE, 0xFF]) else {
        return String::from_utf8_lossy(bytes).to_string();
    };
    let (pairs, dangling) = utf16.as_chunks::<2>();
    let units = pairs.iter().map(|pair| u16::from_be_bytes(*pair));
    let mut text: String = char::decode_utf16(units)
        .map(|u| u.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !dangling.is_empty() {
        text.push(char::REPLACEMENT_CHARACTER);
    }
    text
}

/// `s` as the body of a literal string in a content stream, for text shown in the
/// WinAnsi-encoded Helvetica: one byte per character, written as an octal escape above ASCII so
/// that the stream stays ASCII. A character the font lacks becomes `?` (callers have already
/// replaced them; this keeps the function total).
pub(crate) fn winansi_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match winansi_code(c) {
            Some(b @ (b'(' | b')' | b'\\')) => {
                out.push('\\');
                out.push(b as char);
            }
            Some(b) if b.is_ascii() => out.push(b as char),
            Some(b) => out.push_str(&format!("\\{b:03o}")),
            None => out.push('?'),
        }
    }
    out
}

fn sanitize_dn(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '@' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "SignPDF Signer".to_string()
    } else {
        trimmed.to_string()
    }
}

fn rand_serial() -> u64 {
    let mut bytes = [0u8; 8];
    crate::crypto::fill_random(&mut bytes);
    // Keep it positive and modest so the DER INTEGER stays small.
    (u64::from_le_bytes(bytes) >> 1) | 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cms_that_would_change_when_rebuilt_takes_no_signature_timestamp() {
        use crate::timestamp::testing::{replace_element, TestTsa};
        let tsa = TestTsa::new();
        let now = "2030-01-01T00:00:00Z";
        // A timestamp token is a one-signer CMS SignedData, so it stands in for a signature here.
        let cms = tsa.stamp(&[1u8; 32], now);
        let token = tsa.stamp(&cms_signature_digest(&cms).unwrap(), now);
        // In its usual encoding it takes the timestamp.
        cms_with_signature_timestamp(&cms, &token).unwrap();
        // With its certificate dates written as GeneralizedTime it would be rewritten: refused.
        let gt_cms = replace_element(&cms, &tsa.cert_der(), &tsa.cert_der_with_generalized_time());
        assert_ne!(gt_cms, cms);
        let token = tsa.stamp(&cms_signature_digest(&gt_cms).unwrap(), now);
        let err = cms_with_signature_timestamp(&gt_cms, &token).unwrap_err();
        assert!(err.to_string().contains("cannot be rebuilt"), "{err}");
    }

    #[test]
    fn helvetica_widths_match_the_font_metrics() {
        // H 722 + e 556 + l 222 + l 222 + o 556 = 2278 units.
        assert!((text_width("Hello", 10.0) - 22.78).abs() < 1e-4);
        assert!((text_width(" ", 1000.0) - 278.0).abs() < 1e-3);
        assert!((text_width("~", 1000.0) - 584.0).abs() < 1e-3);
        // A long row is shrunk to the width it has; a short one keeps its size.
        assert_eq!(fit_size("Hello", 10.0, 100.0), 10.0);
        assert!((fit_size("Hello", 10.0, 11.39) - 5.0).abs() < 1e-3);
        assert_eq!(
            fit_size(&"W".repeat(200), 10.0, 20.0),
            4.0,
            "never below 4 pt"
        );
    }

    #[test]
    fn wrapping_keeps_line_breaks_and_splits_only_oversized_words() {
        // "aaa bbb" is 34.5 pt wide at 10 pt.
        assert_eq!(wrap_lines("aaa bbb ccc", 10.0, 40.0), ["aaa bbb", "ccc"]);
        assert_eq!(wrap_lines("one\n\ntwo", 10.0, 100.0), ["one", "", "two"]);
        // A word wider than the field is split by characters, never dropped.
        let lines = wrap_lines("ab WWWWWWWW cd", 10.0, 30.0);
        assert_eq!(lines.concat().replace(' ', ""), "abWWWWWWWWcd");
        assert!(
            lines.iter().all(|l| text_width(l, 10.0) <= 30.0),
            "{lines:?}"
        );
    }

    #[test]
    fn multiline_layout_shrinks_then_gives_up() {
        // Three lines fit a 40 pt field at 10 pt (3 x 12 = 36 <= 36); four need a smaller size.
        assert_eq!(layout_multiline("a\nb\nc", 200.0, 40.0).unwrap().0, 10.0);
        let (size, lines) = layout_multiline("a\nb\nc\nd", 200.0, 40.0).unwrap();
        assert_eq!((size, lines.len()), (7.5, 4));
        assert!(layout_multiline(&"x\n".repeat(20), 200.0, 40.0).is_none());
        assert!(
            layout_multiline("text", 3.0, 40.0).is_none(),
            "no room at all"
        );
        // Line ends and tabs are normalized; what the font can draw is kept, the rest is `?`.
        assert_eq!(multiline_text("a\r\nb\tc\u{e9}"), "a\nb c\u{e9}");
        assert_eq!(multiline_text("Grüße\r山田"), "Grüße\n??");
    }

    #[test]
    fn winansi_covers_latin_1_and_the_windows_1252_additions() {
        // ASCII and Latin-1 are their own codes.
        assert_eq!(winansi_code('A'), Some(0x41));
        assert_eq!(winansi_code('é'), Some(0xE9));
        assert_eq!(winansi_code('ß'), Some(0xDF));
        assert_eq!(winansi_code('ÿ'), Some(0xFF));
        assert_eq!(winansi_code('\u{a0}'), Some(0xA0));
        // The 0x80..=0x9F block is Windows-1252's own.
        assert_eq!(winansi_code('€'), Some(0x80));
        assert_eq!(winansi_code('’'), Some(0x92));
        assert_eq!(winansi_code('–'), Some(0x96));
        assert_eq!(winansi_code('œ'), Some(0x9C));
        assert_eq!(winansi_code('Ÿ'), Some(0x9F));
        // Controls, the codes the encoding leaves undefined, and other scripts have none.
        for c in [
            '\0', '\n', '\t', '\u{7f}', '\u{81}', '\u{9d}', 'Ł', 'Ж', '山', '한', '😀',
        ] {
            assert_eq!(winansi_code(c), None, "{c:?}");
        }
        // Every code maps back to exactly one character, and every character it draws has a width.
        let mut drawn = 0;
        for c in (0..=0x2122_u32).filter_map(char::from_u32) {
            if let Some(code) = winansi_code(c) {
                drawn += 1;
                assert!(HELVETICA_WIDTHS[code as usize - 0x20] > 0, "{c:?}");
            }
        }
        assert_eq!(drawn, 95 + 96 + 27);
        assert_eq!(
            HELVETICA_WIDTHS.iter().filter(|w| **w > 0).count(),
            drawn,
            "no width without a character"
        );
    }

    #[test]
    fn accented_text_is_measured_with_its_own_widths() {
        // J 500 + ü 556 + r 333 + g 556 + e 556 + n 556 = 3057 units.
        assert!((text_width("Jürgen", 10.0) - 30.57).abs() < 1e-4);
        // É is as wide as E, œ and — are not ASCII widths.
        assert_eq!(text_width("É", 1000.0), text_width("E", 1000.0));
        assert!((text_width("œ", 1000.0) - 944.0).abs() < 1e-3);
        assert!((text_width("—", 1000.0) - 1000.0).abs() < 1e-3);
        // What cannot be drawn is measured as the `?` that replaces it.
        assert_eq!(text_width("山", 1000.0), text_width("?", 1000.0));
        assert_eq!(drawable_caption("Zoë 山田 Müller", 9), "Zoë ?? Mü");
    }

    #[test]
    fn drawn_text_is_one_winansi_byte_per_character_in_an_ascii_stream() {
        assert_eq!(
            winansi_literal("Jürgen (Müller) \\ 5 €"),
            "J\\374rgen \\(M\\374ller\\) \\\\ 5 \\200"
        );
        assert_eq!(
            winansi_literal("naïve café — “déjà vu”"),
            "na\\357ve caf\\351 \\227 \\223d\\351j\\340 vu\\224"
        );
        assert_eq!(winansi_literal("山田\n"), "???");
        assert!(winansi_literal("Ærøskøbing ÅÄÖ ñ ß ¿¡").is_ascii());
    }

    #[test]
    fn text_strings_are_ascii_literals_or_utf16_and_read_back() {
        // Plain ASCII is written exactly as before.
        assert_eq!(
            pdf_text_string("[X] I agree (yes)\nline 2"),
            "([X] I agree \\(yes\\)\\nline 2)"
        );
        // Anything else is UTF-16BE with its byte-order mark, so any viewer reads it.
        assert_eq!(pdf_text_string("Zoë"), "<FEFF005A006F00EB>");
        assert_eq!(
            pdf_text_string("山田 😀"),
            "<FEFF5C717530 0020 D83DDE00>".replace(' ', "")
        );
        for text in [
            "",
            "plain",
            "Jürgen Müller",
            "山田太郎",
            "a\tb",
            "x 😀 y",
            "naïve\ncafé",
        ] {
            let written = pdf_text_string(text);
            let bytes = match written.strip_prefix('<') {
                Some(hex) => hex::decode(hex.trim_end_matches('>')).unwrap(),
                None => text.as_bytes().to_vec(),
            };
            assert_eq!(decode_text_string(&bytes), text);
        }
        // Malformed UTF-16 never reads as valid text: an odd byte and a lone surrogate.
        assert_eq!(
            decode_text_string(&[0xFE, 0xFF, 0x00, 0x41, 0x00]),
            "A\u{fffd}"
        );
        assert_eq!(
            decode_text_string(&[0xFE, 0xFF, 0xD8, 0x3D, 0x00, 0x41]),
            "\u{fffd}A"
        );
        // Without the mark the bytes are read as before.
        assert_eq!(decode_text_string(b"J?rgen"), "J?rgen");
    }

    #[test]
    fn field_contents_keep_accents_and_the_legacy_form_replaces_them() {
        let mark = FieldMark::Checkbox { checked: true };
        assert_eq!(
            field_contents("Geprüft – ja", mark, false),
            "[X] Geprüft – ja"
        );
        assert_eq!(
            legacy_field_contents("Geprüft – ja", mark, false),
            "[X] Gepr?ft ? ja"
        );
        assert_eq!(
            field_contents("Zeile 1\r\nÜber 山", FieldMark::None, true),
            "Zeile 1\nÜber ?"
        );
        assert_eq!(
            legacy_field_contents("Zeile 1\r\nÜber 山", FieldMark::None, true),
            "Zeile 1\n?ber ?"
        );
        // ASCII text has a single form.
        assert_eq!(
            field_contents("By post", FieldMark::Radio { selected: true }, false),
            legacy_field_contents("By post", FieldMark::Radio { selected: true }, false)
        );
    }

    #[test]
    fn typographic_spaces_are_drawn_as_spaces() {
        // The narrow no-break space of French typography, and the figure space, stay unbreakable.
        assert_eq!(drawable('\u{202f}'), '\u{a0}');
        assert_eq!(drawable('\u{2007}'), '\u{a0}');
        // Thin, em and ideographic spaces are plain spaces.
        for c in [
            '\u{2002}', '\u{2003}', '\u{2009}', '\u{200a}', '\u{205f}', '\u{3000}',
        ] {
            assert_eq!(drawable(c), ' ', "{c:?}");
        }
        // A zero-width space is not a space to draw.
        assert_eq!(drawable('\u{200b}'), '?');
        assert_eq!(
            field_contents("Prix\u{202f}: 1\u{202f}250\u{a0}€", FieldMark::None, false),
            "Prix\u{a0}: 1\u{a0}250\u{a0}€"
        );
        assert_eq!(
            winansi_literal(&multiline_text("1\u{202f}250\u{2009}€")),
            "1\\240250 \\200"
        );
        // A no-break space does not offer a line break; a plain one does.
        assert_eq!(
            wrap_lines("aaa\u{a0}bbb ccc", 10.0, 40.0),
            ["aaa\u{a0}bbb", "ccc"]
        );
        // The rendition of older versions had `?` for all of them.
        assert_eq!(
            legacy_field_contents("Prix\u{202f}: 1\u{a0}250 €", FieldMark::None, false),
            "Prix?: 1?250 ?"
        );
    }
}

/// What a signer's revision draws is checked against what the engine draws, byte for byte.
#[cfg(test)]
mod appearance_tests {
    use super::*;
    use crate::ink::{stroke_ops, INK_PEN};

    fn field(text: &str, mark: FieldMark, multiline: bool, rect: [f32; 4]) -> FieldText {
        FieldText {
            name: "signpdf-field-x".into(),
            page_index: 0,
            rect,
            text: text.into(),
            mark,
            multiline,
        }
    }

    fn caption() -> SignatureCaption {
        SignatureCaption {
            signer_name: "bob@example.com".into(),
            code: "9f1629a7".into(),
            signed_at: "2026-10-10 13:27 UTC".into(),
            issuer: "google".into(),
        }
    }

    /// The exact bytes the engine draws. The verifier accepts a document only if its boxes
    /// match the current rendering, so **a change here makes every document signed before it
    /// fail verification**. To change how something is drawn, keep the old rendering and let the
    /// verifier accept either; do not just update these strings.
    #[test]
    fn the_rendering_is_pinned() {
        let text = field(
            "Bob Builder Ltd",
            FieldMark::None,
            false,
            [72.0, 320.0, 292.0, 360.0],
        );
        assert_eq!(
            field_appearance(&text).content,
            "q\n0 0 220 40 re\nW\nn\nBT\n/Helv 14 Tf\n0 0 0.35 rg\n2 14 Td\n(Bob Builder Ltd) Tj\nET\nQ\n"
        );
        let ticked = field(
            "I agree",
            FieldMark::Checkbox { checked: true },
            false,
            [72.0, 380.0, 312.0, 396.0],
        );
        assert_eq!(
            field_appearance(&ticked).content,
            "q\n0 0 240 16 re\nW\nn\n0 0 0.35 RG\n0.8 w\n1.92 1.92 12.16 12.16 re\nS\n1.7 w\n1 J\n1 j\n4.35 8.24 m\n7.03 5.08 l\n11.65 11.16 l\nS\nBT\n/Helv 9.6 Tf\n0 0 0.35 rg\n19 4.2 Td\n(I agree) Tj\nET\nQ\n"
        );
        let radio = field(
            "By post",
            FieldMark::Radio { selected: false },
            false,
            [72.0, 408.0, 312.0, 424.0],
        );
        assert_eq!(
            field_appearance(&radio).content,
            "q\n0 0 240 16 re\nW\nn\n0 0 0.35 RG\n0.8 w\n14.08 8 m\n14.08 11.36 11.36 14.08 8 14.08 c\n4.64 14.08 1.92 11.36 1.92 8 c\n1.92 4.64 4.64 1.92 8 1.92 c\n11.36 1.92 14.08 4.64 14.08 8 c\nS\nBT\n/Helv 9.6 Tf\n0 0 0.35 rg\n19 4.2 Td\n(By post) Tj\nET\nQ\n"
        );
        let notes = field(
            "Line one\nLine two",
            FieldMark::None,
            true,
            [72.0, 470.0, 312.0, 514.0],
        );
        assert_eq!(
            field_appearance(&notes).content,
            "q\n0 0 240 44 re\nW\nn\nBT\n/Helv 10 Tf\n0 0 0.35 rg\n12 TL\n2 32.5 Td\n(Line one) Tj\nT*\n(Line two) Tj\nT*\nET\nQ\n"
        );

        let plain = signature_box(220.0, 40.0, &caption(), false);
        assert_eq!(
            plain.head,
            "q\n0.96 0.96 0.98 rg\n0 0 220 40 re\nf\n0.45 0.45 0.55 RG\n0.7 w\n0.5 0.5 219 39 re\nS\n"
        );
        assert_eq!(
            plain.tail,
            "BT\n/Helv 7.2000003 Tf\n0.30 0.30 0.40 rg\n4 29.8 Td\n(Signed by:) Tj\nET\nBT\n/Helv 12 Tf\n0 0 0 rg\n4 16 Td\n(bob@example.com) Tj\nET\nBT\n/Helv 6.3999996 Tf\n0.30 0.30 0.40 rg\n4 4 Td\n(Sig 9f1629a7  2026-10-10 13:27 UTC  via google) Tj\nET\nQ\n"
        );
        let inked = signature_box(220.0, 40.0, &caption(), true);
        assert_eq!(inked.ink_box, [4.0, 3.0, 84.0, 34.0]);
        assert_eq!(inked.head, plain.head);
        assert_eq!(
            inked.tail,
            "BT\n/Helv 7.2000003 Tf\n0.30 0.30 0.40 rg\n92 29.8 Td\n(Signed by:) Tj\nET\nBT\n/Helv 12 Tf\n0 0 0 rg\n92 16 Td\n(bob@example.com) Tj\nET\nBT\n/Helv 5.6906843 Tf\n0.30 0.30 0.40 rg\n92 4 Td\n(Sig 9f1629a7  2026-10-10 13:27 UTC  via google) Tj\nET\nQ\n"
        );

        let stamp =
            document_id_stamp(&["SignPDF Document 0123456789abcdef0123456789abcdef".into()]);
        assert_eq!((stamp.w, stamp.h), (204.0, 16.0));
        assert_eq!(
            stamp.content,
            "q\n0.96 0.96 0.86 rg\n0 0 204 16 re\nf\n0.55 0.5 0.2 RG\n0.8 w\n0.5 0.5 203 15 re\nS\nBT\n/Helv 8 Tf\n0.15 0.15 0.15 rg\n4 5 Td\n(SignPDF Document 0123456789abcdef0123456789abcdef) Tj\nET\nQ\n"
        );
        // From envelope schema version 7: a second line with the 'verify at' address.
        let stamp = document_id_stamp(&[
            "SignPDF Document 0123456789abcdef0123456789abcdef".into(),
            "Verify at verify.example.com".into(),
        ]);
        assert_eq!((stamp.w, stamp.h), (204.0, 26.0));
        assert_eq!(
            stamp.text,
            "SignPDF Document 0123456789abcdef0123456789abcdef - Verify at verify.example.com"
        );
        assert_eq!(
            stamp.content,
            "q\n0.96 0.96 0.86 rg\n0 0 204 26 re\nf\n0.55 0.5 0.2 RG\n0.8 w\n0.5 0.5 203 25 re\nS\nBT\n/Helv 8 Tf\n0.15 0.15 0.15 rg\n4 15 Td\n(SignPDF Document 0123456789abcdef0123456789abcdef) Tj\n0 -10 Td\n(Verify at verify.example.com) Tj\nET\nQ\n"
        );
        assert_eq!(INK_PEN, "0.05 0.05 0.30 RG\n0.9 w\n1 J\n1 j\n");
        let strokes: InkStrokes = vec![
            vec![[0.0, 40.0], [30.0, 0.0], [60.0, 40.0]],
            vec![[70.0, 10.0]],
        ];
        assert_eq!(
            stroke_ops(&strokes, inked.ink_box),
            "0.05 0.05 0.30 RG\n0.9 w\n1 J\n1 j\n17.04 3.45 m\n41.86 36.55 l\n66.69 3.45 l\nS\n\
             74.96 28.28 m\n74.96 28.28 l\nS\n"
        );
        assert_eq!(
            drawing_ops(&SignatureDrawing::Typed { paths: ring() }, inked.ink_box),
            "q\n4 3 84 34 re\nW\nn\n0.05 0.05 0.30 rg\n29 20 m\n29 37 63 37 63 20 c\n\
             63 3 29 3 29 20 c\nh\n39.2 20 m\n46 13.2 l\n52.8 20 l\nh\nf\nQ\n"
        );
    }

    /// An annotation as the audit reports it, drawing `content` in a `w`×`h` form.
    fn added(
        subtype: &str,
        flags: i64,
        da: Option<&str>,
        w: f32,
        h: f32,
        content: &str,
    ) -> AddedAnnotation {
        AddedAnnotation {
            page_index: 0,
            subtype: subtype.into(),
            field_type: (subtype == "Widget").then(|| "Sig".to_string()),
            rect: [72.0, 320.0, 72.0 + w, 320.0 + h],
            contents: None,
            name: None,
            is_new_object: true,
            flags: Some(flags),
            default_appearance: da.map(str::to_string),
            appearance: Some(AddedAppearance {
                bbox: [0.0, 0.0, w, h],
                content: content.as_bytes().to_vec(),
            }),
            shape_problems: Vec::new(),
        }
    }

    #[test]
    fn a_field_must_be_drawn_as_the_engine_draws_its_value() {
        let ft = field(
            "EUR 12,500",
            FieldMark::None,
            false,
            [72.0, 320.0, 292.0, 360.0],
        );
        let drawn = field_appearance(&ft);
        let da = format!("/Helv {} Tf 0 0 0.35 rg", fmt_num(drawn.size));
        let honest = added("FreeText", 196, Some(&da), 220.0, 40.0, &drawn.content);
        assert!(check_field_annotation(&honest, &ft).is_empty());

        // The page shows another amount than the one recorded.
        let other = drawn.content.replace("EUR 12,500", "EUR 99,500");
        let forged = added("FreeText", 196, Some(&da), 220.0, 40.0, &other);
        assert_eq!(check_field_annotation(&forged, &ft).len(), 1);

        // A box drawn ticked for a value recorded as unticked.
        let unticked = field(
            "I agree",
            FieldMark::Checkbox { checked: false },
            false,
            [72.0, 380.0, 312.0, 396.0],
        );
        let ticked = FieldText {
            mark: FieldMark::Checkbox { checked: true },
            ..unticked.clone()
        };
        let d = field_appearance(&ticked);
        let da = format!("/Helv {} Tf 0 0 0.35 rg", fmt_num(d.size));
        let forged = added("FreeText", 196, Some(&da), 240.0, 16.0, &d.content);
        assert_eq!(check_field_annotation(&forged, &unticked).len(), 1);
        assert!(check_field_annotation(&forged, &ticked).is_empty());

        // Hidden, non-printing or unlocked annotations (other flags), or a stretched form.
        let mut odd = honest.clone();
        odd.flags = Some(2);
        assert_eq!(check_field_annotation(&odd, &ft).len(), 1);
        let mut stretched = honest.clone();
        stretched.appearance.as_mut().unwrap().bbox = [0.0, 0.0, 22.0, 4.0];
        assert_eq!(check_field_annotation(&stretched, &ft).len(), 1);
        let mut blank = honest;
        blank.appearance = None;
        assert_eq!(check_field_annotation(&blank, &ft).len(), 1);
    }

    #[test]
    fn a_signature_box_shows_the_verified_caption_and_at_most_a_scribble() {
        let rect = [72.0, 320.0, 292.0, 360.0];
        let plain = signature_box(220.0, 40.0, &caption(), false);
        let inked = signature_box(220.0, 40.0, &caption(), true);
        let check = |content: &str| {
            check_signature_widget(
                &added("Widget", 132, None, 220.0, 40.0, content),
                rect,
                Some(&caption()),
                InkRule::Strokes,
            )
        };
        assert!(check(&format!("{}{}", plain.head, plain.tail)).is_empty());

        let strokes: InkStrokes = vec![
            vec![[0.0, 40.0], [30.0, 0.0], [60.0, 40.0]],
            vec![[70.0, 10.0]],
        ];
        let area = inked.ink_box;
        let honest = format!("{}{}{}", inked.head, stroke_ops(&strokes, area), inked.tail);
        assert!(check(&honest).is_empty());

        // Another name in the box.
        let forged = honest.replace("bob@example.com", "ceo@bigcorp.example");
        assert_eq!(check(&forged).len(), 1);
        // The honest caption, but text smuggled into the drawing area.
        let smuggled = format!(
            "{}{}BT\n/Helv 12 Tf\n4 16 Td\n(Signed by the CEO) Tj\nET\n{}",
            inked.head,
            stroke_ops(&strokes, area),
            inked.tail
        );
        assert_eq!(check(&smuggled).len(), 1);
        // Strokes that leave the drawing area to scratch out the caption.
        let escaped = honest.replacen("\n1 j\n", "\n1 j\n150 20 m\n210 20 l\nS\n", 1);
        assert_eq!(check(&escaped).len(), 1);
        // Before version 6, a box holds no filled paths.
        let typed = SignatureDrawing::Typed { paths: ring() };
        let filled = format!("{}{}{}", inked.head, drawing_ops(&typed, area), inked.tail);
        assert_eq!(check(&filled).len(), 1);

        // Without a box to fill, a signature draws nothing.
        let invisible = AddedAnnotation {
            rect: [0.0; 4],
            appearance: None,
            ..added("Widget", 132, None, 0.0, 0.0, "")
        };
        for rule in [InkRule::Strokes, InkRule::Recorded(None)] {
            assert!(check_signature_widget(&invisible, [0.0; 4], None, rule).is_empty());
            let drawing = added("Widget", 132, None, 220.0, 40.0, &honest);
            assert_eq!(
                check_signature_widget(&drawing, [0.0; 4], None, rule).len(),
                1
            );
            // And with one, it must be drawn.
            assert_eq!(
                check_signature_widget(&invisible, rect, Some(&caption()), rule).len(),
                1
            );
        }
    }

    /// A ring: an outline and its counter, as a typed signature's paths.
    fn ring() -> crate::ink::InkPaths {
        use crate::ink::PathSegment::{Curve, Line};
        vec![
            vec![
                Line([0.0, 50.0]),
                Curve([0.0, 0.0, 100.0, 0.0, 100.0, 50.0]),
                Curve([100.0, 100.0, 0.0, 100.0, 0.0, 50.0]),
            ],
            vec![Line([30.0, 50.0]), Line([50.0, 70.0]), Line([70.0, 50.0])],
        ]
    }

    #[test]
    fn from_version_6_a_box_shows_exactly_the_recorded_drawing() {
        let rect = [72.0, 320.0, 292.0, 360.0];
        let plain = signature_box(220.0, 40.0, &caption(), false);
        let inked = signature_box(220.0, 40.0, &caption(), true);
        let area = inked.ink_box;
        let check = |content: &str, drawing: Option<&SignatureDrawing>| {
            check_signature_widget(
                &added("Widget", 132, None, 220.0, 40.0, content),
                rect,
                Some(&caption()),
                InkRule::Recorded(drawing),
            )
        };
        let boxed = |ops: &str| format!("{}{}{}", inked.head, ops, inked.tail);
        let typed = SignatureDrawing::Typed { paths: ring() };
        let drawn = SignatureDrawing::Drawn {
            strokes: vec![vec![[0.0, 40.0], [30.0, 0.0], [60.0, 40.0]]],
        };

        // No drawing recorded: the plain box, nothing else (not even a scribble).
        let bare = format!("{}{}", plain.head, plain.tail);
        assert!(check(&bare, None).is_empty());
        assert_eq!(check(&boxed(&drawing_ops(&drawn, area)), None).len(), 1);
        assert_eq!(check(&boxed(""), None).len(), 1);

        // A drawing recorded: exactly the engine's rendering of it.
        for drawing in [&typed, &drawn] {
            let honest = boxed(&drawing_ops(drawing, area));
            assert!(check(&honest, Some(drawing)).is_empty(), "{honest}");
            assert_eq!(
                check(&bare, Some(drawing)).len(),
                1,
                "the drawing is missing"
            );
        }
        // Not the other kind, nor another drawing of the same kind.
        assert_eq!(
            check(&boxed(&drawing_ops(&drawn, area)), Some(&typed)).len(),
            1
        );
        assert_eq!(
            check(&boxed(&drawing_ops(&typed, area)), Some(&drawn)).len(),
            1
        );
        let other = SignatureDrawing::Typed {
            paths: vec![ring()[1].clone()],
        };
        assert_eq!(
            check(&boxed(&drawing_ops(&other, area)), Some(&typed)).len(),
            1
        );
        // The recorded paths, filled in another colour, or with text after them.
        let honest = drawing_ops(&typed, area);
        let red = honest.replace("0.05 0.05 0.30 rg", "1 0 0 rg");
        assert_eq!(check(&boxed(&red), Some(&typed)).len(), 1);
        let text = format!("{honest}BT\n/Helv 12 Tf\n4 16 Td\n(Signed by the CEO) Tj\nET\n");
        assert_eq!(check(&boxed(&text), Some(&typed)).len(), 1);
        // A recorded drawing the engine cannot draw is never shown.
        let empty = SignatureDrawing::Typed { paths: vec![] };
        assert_eq!(check(&boxed(""), Some(&empty)).len(), 1);
        assert_eq!(check(&bare, Some(&empty)).len(), 1);
    }

    #[test]
    fn annotations_built_differently_from_the_engine_s_are_reported() {
        let mut doc = Document::with_version("1.7");
        let font = doc.add_object(Object::Dictionary(standard_font()));
        let form = |font: ObjectId, extra: Option<(&str, Object)>| {
            let mut fonts = Dictionary::new();
            fonts.set("Helv", Object::Reference(font));
            let mut resources = Dictionary::new();
            resources.set("Font", Object::Dictionary(fonts));
            resources.set(
                "ProcSet",
                Object::Array(vec![
                    Object::Name(b"PDF".to_vec()),
                    Object::Name(b"Text".to_vec()),
                ]),
            );
            let mut d = Dictionary::new();
            d.set("Type", Object::Name(b"XObject".to_vec()));
            d.set("Subtype", Object::Name(b"Form".to_vec()));
            d.set("FormType", Object::Integer(1));
            d.set(
                "BBox",
                Object::Array(vec![0.into(), 0.into(), 220.into(), 40.into()]),
            );
            d.set("Resources", Object::Dictionary(resources));
            if let Some((key, value)) = extra {
                d.set(key, value);
            }
            lopdf::Stream::new(d, b"q\nQ\n".to_vec())
        };
        let annotation = |ap: ObjectId, extra: Option<(&str, Object)>| {
            let mut n = Dictionary::new();
            n.set("N", Object::Reference(ap));
            let mut d = Dictionary::new();
            d.set("Type", Object::Name(b"Annot".to_vec()));
            d.set("Subtype", Object::Name(b"FreeText".to_vec()));
            d.set("F", Object::Integer(196));
            d.set("AP", Object::Dictionary(n));
            if let Some((key, value)) = extra {
                d.set(key, value);
            }
            d
        };

        // As the engine writes it: nothing to report, and the stream is read.
        let ap = doc.add_object(form(font, None));
        let (appearance, problems) = annotation_shape(&doc, &annotation(ap, None));
        assert!(problems.is_empty(), "{problems:?}");
        let appearance = appearance.unwrap();
        assert_eq!(appearance.bbox, [0.0, 0.0, 220.0, 40.0]);
        assert_eq!(appearance.content, b"q\nQ\n");

        // An action on the annotation (JavaScript, a link).
        let mut action = Dictionary::new();
        action.set("S", Object::Name(b"JavaScript".to_vec()));
        let (_, problems) = annotation_shape(
            &doc,
            &annotation(ap, Some(("A", Object::Dictionary(action)))),
        );
        assert!(
            problems.iter().any(|p| p.contains("unexpected /A entry")),
            "{problems:?}"
        );

        // A transform on the form, which would move or scale what is drawn.
        let matrix = Object::Array(vec![
            2.into(),
            0.into(),
            0.into(),
            2.into(),
            0.into(),
            0.into(),
        ]);
        let moved = doc.add_object(form(font, Some(("Matrix", matrix))));
        let (_, problems) = annotation_shape(&doc, &annotation(moved, None));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("unexpected /Matrix entry")),
            "{problems:?}"
        );

        // Another font under the same name: the same bytes would show other glyphs.
        let mut other = standard_font();
        other.set("BaseFont", Object::Name(b"Courier".to_vec()));
        let other_font = doc.add_object(Object::Dictionary(other));
        let disguised = doc.add_object(form(other_font, None));
        let (_, problems) = annotation_shape(&doc, &annotation(disguised, None));
        assert!(
            problems.iter().any(|p| p.contains("standard font")),
            "{problems:?}"
        );
    }
}

#[cfg(test)]
mod large_image_tests {
    use super::*;

    /// A one-page PDF whose page draws one large image XObject. Returns (bytes, image id, root id).
    fn pdf_with_large_image(pixels: &[u8]) -> (Vec<u8>, ObjectId, ObjectId) {
        let mut doc = Document::with_version("1.7");
        let mut img = Dictionary::new();
        for (k, v) in [
            ("Type", "XObject"),
            ("Subtype", "Image"),
            ("ColorSpace", "DeviceGray"),
        ] {
            img.set(k, Object::Name(v.as_bytes().to_vec()));
        }
        img.set("Width", Object::Integer(pixels.len() as i64));
        img.set("Height", Object::Integer(1));
        img.set("BitsPerComponent", Object::Integer(8));
        let image_id = doc.add_object(lopdf::Stream::new(img, pixels.to_vec()));
        let content = doc.add_object(lopdf::Stream::new(
            Dictionary::new(),
            b"q 100 0 0 1 0 0 cm /Im0 Do Q".to_vec(),
        ));
        let pages_id = doc.new_object_id();
        let mut xobjects = Dictionary::new();
        xobjects.set("Im0", Object::Reference(image_id));
        let mut resources = Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobjects));
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Parent", Object::Reference(pages_id));
        page.set(
            "MediaBox",
            Object::Array(vec![0.into(), 0.into(), 612.into(), 792.into()]),
        );
        page.set("Resources", Object::Dictionary(resources));
        page.set("Contents", Object::Reference(content));
        let page_id = doc.add_object(page);
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        let root_id = doc.add_object(catalog);
        doc.trailer.set("Root", Object::Reference(root_id));
        let mut out = Vec::new();
        doc.save_to(&mut out).expect("save");
        (out, image_id, root_id)
    }

    /// `before` plus an increment that redefines the image object with `pixels`.
    fn redefine_image(
        before: &[u8],
        image_id: ObjectId,
        root_id: ObjectId,
        pixels: &[u8],
    ) -> Vec<u8> {
        let mut out = increment_buffer(before, pixels.len() + 1024);
        let off = out.len();
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Type /XObject /Subtype /Image /ColorSpace /DeviceGray /Width {} \
                 /Height 1 /BitsPerComponent 8 /Length {} >>\nstream\n",
                image_id.0,
                pixels.len(),
                pixels.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(pixels);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        let xref = out.len();
        let prev = find_last_startxref(before).expect("startxref");
        out.extend_from_slice(
            format!(
                "xref\n{} 1\n{off:010} 00000 n \ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev} >>\n\
                 startxref\n{xref}\n%%EOF\n",
                image_id.0,
                root_id.0 + 1,
                root_id.0
            )
            .as_bytes(),
        );
        out
    }

    #[test]
    fn large_images_are_compared_by_digest_and_never_kept() {
        let pixels: Vec<u8> = (0..LARGE_IMAGE * 2).map(|i| (i % 251) as u8).collect();
        let (before, image_id, root_id) = pdf_with_large_image(&pixels);

        // Parses keep a placeholder or a digest, not the bytes.
        let dropped = load_for_inspection(&before, ImageBytes::Drop).expect("parse");
        let digested = load_for_inspection(&before, ImageBytes::Digest).expect("parse");
        let content = |d: &Document| {
            d.get_object(image_id)
                .unwrap()
                .as_stream()
                .unwrap()
                .content
                .clone()
        };
        assert!(content(&dropped).len() < 64);
        assert_eq!(content(&digested), Sha256::digest(&pixels).to_vec());
        assert_eq!(page_geometry(&before).expect("geometry").len(), 1);

        // These increments add no signature, so the audit always reports the missing field;
        // what matters here is whether it sees the image object as modified.
        let modified = format!("object {} 0 was modified", image_id.0);

        // The same bytes written again in an increment are not a change...
        let same = redefine_image(&before, image_id, root_id, &pixels);
        let audit = audit_increment(&before, &same).expect("audit");
        assert!(
            !audit.violations.iter().any(|v| v.contains(&modified)),
            "{:?}",
            audit.violations
        );

        // ...but one changed byte in a large image is.
        let mut swapped = pixels.clone();
        swapped[LARGE_IMAGE + 7] ^= 1;
        let changed = redefine_image(&before, image_id, root_id, &swapped);
        let audit = audit_increment(&before, &changed).expect("audit");
        assert!(
            audit.violations.iter().any(|v| v.contains(&modified)),
            "{:?}",
            audit.violations
        );
    }

    /// `before` plus an increment that redefines the image object with `content`, declaring
    /// `/Length declared` (which may be wrong on purpose).
    fn redefine_image_raw(
        before: &[u8],
        image_id: ObjectId,
        root_id: ObjectId,
        width: usize,
        declared: usize,
        content: &[u8],
    ) -> Vec<u8> {
        let mut out = increment_buffer(before, content.len() + 1024);
        let off = out.len();
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Type /XObject /Subtype /Image /ColorSpace /DeviceGray /Width {width} \
                 /Height 1 /BitsPerComponent 8 /Length {declared} >>\nstream\n",
                image_id.0
            )
            .as_bytes(),
        );
        out.extend_from_slice(content);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        let xref = out.len();
        let prev = find_last_startxref(before).expect("startxref");
        out.extend_from_slice(
            format!(
                "xref\n{} 1\n{off:010} 00000 n \ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev} >>\n\
                 startxref\n{xref}\n%%EOF\n",
                image_id.0,
                root_id.0 + 1,
                root_id.0
            )
            .as_bytes(),
        );
        out
    }

    /// Review of the digest comparison: a later revision must not be able to replace a large
    /// image with a small stream whose raw bytes equal the digest the audit keeps for the
    /// original, with or without a misleading `/Length`.
    #[test]
    fn a_small_stream_equal_to_the_digest_is_still_a_modification() {
        let pixels: Vec<u8> = (0..LARGE_IMAGE * 2).map(|i| (i % 251) as u8).collect();
        let (before, image_id, root_id) = pdf_with_large_image(&pixels);
        let digest = Sha256::digest(&pixels).to_vec();
        let modified = format!("object {} 0 was modified", image_id.0);
        for declared in [digest.len(), pixels.len()] {
            let forged =
                redefine_image_raw(&before, image_id, root_id, pixels.len(), declared, &digest);
            let audit = audit_increment(&before, &forged).expect("audit");
            assert!(
                audit.violations.iter().any(|v| v.contains(&modified)),
                "declared /Length {declared}: {:?}",
                audit.violations
            );
        }
    }

    // ---- security review of the load filter (docs/SECURITY_REVIEW_LOAD_FILTER.md) ----------

    /// Pixels for a large image: more than [`LARGE_IMAGE`] bytes, not all alike.
    fn large_pixels() -> Vec<u8> {
        (0..LARGE_IMAGE * 2).map(|i| (i % 251) as u8).collect()
    }

    /// `before` plus an increment holding `objects` (object number, body between `obj` and
    /// `endobj`), with `/Size size`.
    fn append_increment(
        before: &[u8],
        root_id: ObjectId,
        size: u32,
        objects: &[(u32, Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = Increment {
            base: before.len(),
            buf: Vec::new(),
        };
        let mut xref = Vec::new();
        for (id, body) in objects {
            write_indirect(&mut out, &mut xref, (*id, 0), body);
        }
        let prev = find_last_startxref(before).expect("startxref");
        finish_increment(&mut out, &mut xref, size, root_id, prev, &Dictionary::new());
        out.appended_to(before)
    }

    /// A stream object body: `dict` (without `/Length`) and `content`.
    fn stream_body(dict: &str, content: &[u8]) -> Vec<u8> {
        let mut body = format!("<< {dict} /Length {} >>\nstream\n", content.len()).into_bytes();
        body.extend_from_slice(content);
        body.extend_from_slice(b"\nendstream");
        body
    }

    /// A PDF with a cross-reference stream: `objects` (number, body) stored as ordinary objects,
    /// and `members` in the object stream `container`, whose dictionary also claims to be an
    /// image (`/Subtype /Image`) and which is padded past [`LARGE_IMAGE`]. Other PDF readers
    /// unpack it like any object stream. Object 1 is the catalog.
    fn pdf_with_object_stream(
        container: u32,
        members: &[(u32, &str)],
        objects: &[(u32, Vec<u8>)],
    ) -> Vec<u8> {
        let (mut index, mut packed) = (String::new(), String::new());
        for (number, member) in members {
            index.push_str(&format!("{number} {} ", packed.len()));
            packed.push_str(member);
            packed.push('\n');
        }
        let first = index.len();
        let mut content = format!("{index}{packed}").into_bytes();
        content.resize(LARGE_IMAGE + 1000, b' ');

        // Cross-reference rows: type, then offset or container, then generation or index.
        let mut rows = std::collections::BTreeMap::<u32, (u8, usize, u16)>::new();
        let mut out = b"%PDF-1.7\n".to_vec();
        for (number, body) in objects {
            rows.insert(*number, (1, out.len(), 0));
            out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        rows.insert(container, (1, out.len(), 0));
        out.extend_from_slice(format!("{container} 0 obj\n").as_bytes());
        out.extend_from_slice(&stream_body(
            &format!(
                "/Type /ObjStm /Subtype /Image /N {} /First {first}",
                members.len()
            ),
            &content,
        ));
        out.extend_from_slice(b"\nendobj\n");
        for (i, (number, _)) in members.iter().enumerate() {
            rows.insert(*number, (2, container as usize, u16::try_from(i).unwrap()));
        }
        let xref_id = rows.keys().max().unwrap() + 1;
        let xref_offset = out.len();
        rows.insert(xref_id, (1, xref_offset, 0));
        let mut entries = Vec::new();
        for number in 0..=xref_id {
            let (kind, field2, field3) = rows.get(&number).copied().unwrap_or((0, 0, 0xFFFF));
            entries.push(kind);
            entries.extend_from_slice(&u32::try_from(field2).unwrap().to_be_bytes());
            entries.extend_from_slice(&field3.to_be_bytes());
        }
        out.extend_from_slice(format!("{xref_id} 0 obj\n").as_bytes());
        out.extend_from_slice(&stream_body(
            &format!("/Type /XRef /Size {} /W [1 4 2] /Root 1 0 R", xref_id + 1),
            &entries,
        ));
        out.extend_from_slice(format!("\nendobj\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes());
        out
    }

    /// A PDF whose catalog, page tree and page sit in an object stream that claims to be an
    /// image.
    fn pdf_with_image_like_object_stream() -> Vec<u8> {
        pdf_with_object_stream(
            4,
            &[
                (1, "<< /Type /Catalog /Pages 2 0 R >>"),
                (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
                (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"),
            ],
            &[],
        )
    }

    /// `pdf_with_large_image`'s document plus an increment with an attachment `name` whose
    /// embedded-file stream has the dictionary entries `dict`.
    fn pdf_with_attachment(name: &str, dict: &str, data: &[u8]) -> Vec<u8> {
        let (before, _, root_id) = pdf_with_large_image(&[7u8; 16]);
        let filespec = format!("<< /Type /Filespec /F ({name}) /EF << /F 6 0 R >> >>");
        append_increment(
            &before,
            root_id,
            8,
            &[(6, stream_body(dict, data)), (7, filespec.into_bytes())],
        )
    }

    /// `before` (from `pdf_with_large_image`) plus an increment that adds a signature widget
    /// whose normal appearance is a stream with the dictionary entries `ap_dict` and `content`.
    fn with_added_widget(
        before: &[u8],
        root_id: ObjectId,
        ap_dict: &str,
        content: &[u8],
    ) -> Vec<u8> {
        let doc = Document::load_mem(before).expect("parse");
        let page_id = doc.get_pages()[&1];
        let mut page = doc.get_object(page_id).unwrap().as_dict().unwrap().clone();
        page.set("Annots", Object::Array(vec![Object::Reference((6, 0))]));
        let mut page_body = Vec::new();
        write_object(&mut page_body, &Object::Dictionary(page));
        let widget = b"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 100 50] /F 132 \
                       /AP << /N 7 0 R >> >>"
            .to_vec();
        append_increment(
            before,
            root_id,
            8,
            &[
                (page_id.0, page_body),
                (6, widget),
                (7, stream_body(ap_dict, content)),
            ],
        )
    }

    /// Every document the tests have: the compatibility corpus, the fixtures, and the documents
    /// built here to probe the filter.
    fn documents() -> Vec<(String, Vec<u8>)> {
        let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut dirs = vec![tests.join("corpus"), tests.join("fixtures")];
        let mut docs = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("read test directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "pdf") {
                    let bytes = std::fs::read(&path).expect("read test PDF");
                    docs.push((path.display().to_string(), bytes));
                }
            }
        }
        assert!(docs.len() >= 10, "the corpus was not found: {docs:?}");

        let pixels = large_pixels();
        let (large, image_id, root_id) = pdf_with_large_image(&pixels);
        let signed = pades_sign(
            &large,
            &KeyPair::generate(),
            &SignAppearance::default(),
            None,
        )
        .expect("sign the large-image document");
        // The image again, its /Length an indirect reference to a new object.
        let mut indirect = format!(
            "<< /Type /XObject /Subtype /Image /ColorSpace /DeviceGray /Width {} /Height 1 \
             /BitsPerComponent 8 /Length 6 0 R >>\nstream\n",
            pixels.len()
        )
        .into_bytes();
        indirect.extend_from_slice(&pixels);
        indirect.extend_from_slice(b"\nendstream");
        let indirect_length = append_increment(
            &large,
            root_id,
            7,
            &[
                (image_id.0, indirect),
                (6, pixels.len().to_string().into_bytes()),
            ],
        );
        let pad = vec![b' '; LARGE_IMAGE + 1];
        docs.extend([
            ("large image".to_string(), large.clone()),
            ("large image, signed".to_string(), signed),
            ("large image, indirect /Length".to_string(), indirect_length),
            (
                "object stream claiming /Subtype /Image".to_string(),
                pdf_with_image_like_object_stream(),
            ),
            (
                "embedded file with /Subtype /Image".to_string(),
                pdf_with_attachment("a.bin", "/Type /EmbeddedFile /Subtype /Image", &pixels),
            ),
            (
                "untyped stream with /Subtype /Image as an attachment".to_string(),
                pdf_with_attachment("a.bin", "/Subtype /Image", &pixels),
            ),
            (
                "appearance stream claiming /Subtype /Image".to_string(),
                with_added_widget(&large, root_id, "/Type /XObject /Subtype /Image", &pad),
            ),
        ]);
        docs
    }

    /// The filter's whole effect, for every document the tests have, in both modes: the parse
    /// has exactly the objects and trailer a plain lopdf parse has, all equal, except that each
    /// image XObject over 64 KiB keeps its dictionary (with its real `/Length`) and holds the
    /// placeholder or its SHA-256 instead of its bytes, which never equals the original. This
    /// also pins lopdf's filter contract, which a lopdf upgrade could change.
    #[test]
    fn filter_keeps_every_object_lopdf_loads() {
        let mut filtered_somewhere = false;
        for (name, pdf) in documents() {
            let full = Document::load_mem(&pdf).unwrap_or_else(|e| panic!("{name}: {e}"));
            for mode in [ImageBytes::Drop, ImageBytes::Digest] {
                let parsed = load_for_inspection(&pdf, mode).expect("filtered parse");
                assert_eq!(parsed.trailer, full.trailer, "{name}: trailer");
                assert_eq!(parsed.max_id, full.max_id, "{name}: max id");
                assert!(
                    parsed.objects.keys().eq(full.objects.keys()),
                    "{name}: the filter changed which objects exist"
                );
                for (id, original) in &full.objects {
                    let got = &parsed.objects[id];
                    match original {
                        Object::Stream(s)
                            if is_image_xobject(&s.dict) && s.content.len() > LARGE_IMAGE =>
                        {
                            filtered_somewhere = true;
                            let g = got.as_stream().expect("still a stream");
                            assert_eq!(g.dict, s.dict, "{name}: dictionary of {id:?}");
                            let expected = match mode {
                                ImageBytes::Drop => IMAGE_PLACEHOLDER.to_vec(),
                                ImageBytes::Digest => Sha256::digest(&s.content).to_vec(),
                            };
                            assert_eq!(g.content, expected, "{name}: content of {id:?}");
                            assert_ne!(got, original, "{name}: {id:?} compares equal to its bytes");
                        }
                        _ => assert_eq!(got, original, "{name}: object {id:?} differs"),
                    }
                }
            }
        }
        assert!(filtered_somewhere, "no document exercised the filter");
    }

    /// Review finding 1: an object stream that also claims `/Subtype /Image` is still unpacked.
    /// Filtered, its objects (here the catalog and the only page) would vanish from the engine's
    /// view while every other reader still sees them.
    #[test]
    fn an_object_stream_claiming_to_be_an_image_is_still_unpacked() {
        let pdf = pdf_with_image_like_object_stream();
        assert_eq!(
            Document::load_mem(&pdf).expect("lopdf").get_pages().len(),
            1
        );
        for mode in [ImageBytes::Drop, ImageBytes::Digest] {
            let doc = load_for_inspection(&pdf, mode).expect("parse");
            assert_eq!(doc.get_pages().len(), 1);
            assert!(doc.get_object((1, 0)).is_ok_and(|o| o.as_dict().is_ok()));
        }
        assert_eq!(page_geometry(&pdf).expect("geometry").len(), 1);
    }

    /// Review finding 1, as an attack: a sender's source document keeps its page's `/Contents`
    /// array in an object stream that claims to be an image. A later revision (a signer's, made
    /// with a modified engine) points that array at new page content. Every viewer shows the
    /// new content; the audit must report the change. With the filter unpacking no such object
    /// stream, the array did not exist in the audit's view of the earlier revision, so its
    /// redefinition passed as a new object and the shadow attack went unseen.
    #[test]
    fn page_content_hidden_in_an_image_like_object_stream_cannot_be_swapped() {
        let original = b"BT /F1 24 Tf 72 700 Td (Price: 100) Tj ET".to_vec();
        let before = pdf_with_object_stream(
            4,
            &[(5, "[6 0 R]")],
            &[
                (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
                (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
                (
                    3,
                    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R \
                      /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 \
                      /BaseFont /Helvetica >> >> >> >>"
                        .to_vec(),
                ),
                (6, stream_body("", &original)),
            ],
        );
        let full = Document::load_mem(&before).expect("lopdf");
        assert_eq!(
            full.get_page_content(full.get_pages()[&1])
                .unwrap()
                .trim_ascii_end(),
            original
        );

        let swapped = b"BT /F1 24 Tf 72 700 Td (Price: 900) Tj ET";
        let after = append_increment(
            &before,
            (1, 0),
            9,
            &[(5, b"[8 0 R]".to_vec()), (8, stream_body("", swapped))],
        );
        let shown = Document::load_mem(&after).expect("lopdf");
        assert_eq!(
            shown
                .get_page_content(shown.get_pages()[&1])
                .unwrap()
                .trim_ascii_end(),
            swapped
        );

        let audit = audit_increment(&before, &after).expect("audit");
        assert!(
            audit
                .violations
                .iter()
                .any(|v| v.contains("object 5 0 was modified")),
            "{:?}",
            audit.violations
        );
    }

    /// The general case of finding 1: an object the previous revision lists but lopdf cannot
    /// read there (here a damaged array) cannot be redefined as if it were new, since other
    /// readers may have shown it.
    #[test]
    fn an_object_unreadable_before_cannot_be_redefined() {
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>";
        let before = pdf_with_object_stream(
            4,
            &[(7, "<< /Unused true >>")],
            &[
                (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
                (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec()),
                (3, page.to_vec()),
                (5, b"[6 0 R".to_vec()),
                (6, stream_body("", b"BT ET")),
            ],
        );
        let old = load_for_inspection(&before, ImageBytes::Digest).expect("parse");
        assert!(
            old.get_object((5, 0)).is_err(),
            "lopdf now reads the damaged object"
        );

        let after = append_increment(&before, (1, 0), 9, &[(5, b"[6 0 R]".to_vec())]);
        let audit = audit_increment(&before, &after).expect("audit");
        assert!(
            audit
                .violations
                .iter()
                .any(|v| v.contains("object 5 0 could not be read in the previous revision")),
            "{:?}",
            audit.violations
        );

        // A genuinely new object, numbered above the previous revision's, is not refused.
        let added = append_increment(&before, (1, 0), 10, &[(9, b"[6 0 R]".to_vec())]);
        let audit = audit_increment(&before, &added).expect("audit");
        assert!(
            !audit
                .violations
                .iter()
                .any(|v| v.contains("could not be read")),
            "{:?}",
            audit.violations
        );
    }

    /// Review finding 2: an attachment the engine writes is read in full whatever its MIME type
    /// (`/Subtype`), and a stream that claims to be an image XObject is refused rather than
    /// read as its placeholder.
    #[test]
    fn attachments_are_never_read_as_a_placeholder() {
        let data = large_pixels();
        let (pdf, _, _) = pdf_with_large_image(&[7u8; 16]);
        let embedded = embed_attachment(
            &pdf,
            &EmbeddedFile {
                name: "photo.bin".into(),
                data: data.clone(),
                mime: "Image".into(),
                relationship: "Data".into(),
                description: "a large attachment whose MIME type reads Image".into(),
            },
        )
        .expect("embed");
        assert_eq!(read_attachment(&embedded, "photo.bin").expect("read"), data);

        let typed = pdf_with_attachment("a.bin", "/Type /EmbeddedFile /Subtype /Image", &data);
        assert_eq!(read_attachment(&typed, "a.bin").expect("read"), data);

        for size in [16, data.len()] {
            let untyped = pdf_with_attachment("a.bin", "/Subtype /Image", &data[..size]);
            let err = read_attachment(&untyped, "a.bin").expect_err("an image is no attachment");
            assert!(err.to_string().contains("image stream"), "{err}");
        }
    }

    /// An attachment of [`COMPRESS_FROM`] bytes or more is stored compressed
    /// (`/FlateDecode`, with its own size in `/Params`) and read back as it was; a short one is
    /// stored as it is.
    #[test]
    fn attachments_are_compressed_and_read_back() {
        let (pdf, _, _) = pdf_with_large_image(&[7u8; 16]);
        let record = br#"{"signer_id":"s1","kind":"signed","signed_at":"2026-11-02T00:00:00Z"},"#;
        let json = record.repeat(200);
        for data in [b"{\"short\":true}".to_vec(), json] {
            let embedded = embed_attachment(
                &pdf,
                &EmbeddedFile {
                    name: "e.json".into(),
                    data: data.clone(),
                    mime: "application/json".into(),
                    relationship: "Data".into(),
                    description: "an envelope".into(),
                },
            )
            .expect("embed");
            let increment = &embedded[pdf.len()..];
            let compressed = data.len() >= COMPRESS_FROM;
            let has = |needle: &[u8]| increment.windows(needle.len()).any(|w| w == needle);
            assert_eq!(has(b"/Filter /FlateDecode"), compressed);
            assert!(has(format!("/Params << /Size {} >>", data.len()).as_bytes()));
            if compressed {
                assert!(increment.len() < data.len() / 4, "{}", increment.len());
            }
            assert_eq!(read_attachment(&embedded, "e.json").expect("read"), data);
        }
    }

    /// A compressed attachment is read only as `/FlateDecode` without parameters, whole, and up
    /// to [`MAX_ATTACHMENT_INFLATED`] bytes: anything else is an encoding error, never bytes
    /// returned undecoded.
    #[test]
    fn compressed_attachments_are_read_within_bounds() {
        let json = b"{\"a\":1}";
        let packed = miniz_oxide::deflate::compress_to_vec_zlib(json, 6);
        for dict in ["/Filter /FlateDecode", "/Filter [/FlateDecode]"] {
            let pdf =
                pdf_with_attachment("a.json", &format!("/Type /EmbeddedFile {dict}"), &packed);
            assert_eq!(read_attachment(&pdf, "a.json").expect("read"), json);
        }
        let bomb =
            miniz_oxide::deflate::compress_to_vec_zlib(&vec![0; MAX_ATTACHMENT_INFLATED + 1], 1);
        for (dict, data) in [
            ("/Filter /LZWDecode", &packed[..]),
            ("/Filter [/ASCIIHexDecode /FlateDecode]", &packed[..]),
            (
                "/Filter /FlateDecode /DecodeParms << /Predictor 12 >>",
                &packed[..],
            ),
            ("/Filter 7", &packed[..]),
            ("/Filter /FlateDecode", &packed[..packed.len() - 3]),
            ("/Filter /FlateDecode", &bomb[..]),
        ] {
            let pdf = pdf_with_attachment("a.json", &format!("/Type /EmbeddedFile {dict}"), data);
            let err = read_attachment(&pdf, "a.json").expect_err(dict);
            assert!(matches!(err, SignPdfError::Encoding(_)), "{dict}: {err}");
        }
    }

    /// A signature without a timestamp reserves room for its own CMS, not a fixed 8 KB.
    #[test]
    fn the_signature_placeholder_fits_its_cms() {
        for der_len in [1, 845, 900, 1900] {
            let hex = reserved_contents_hex(der_len);
            assert!(hex >= der_len * 2 + CONTENTS_HEADROOM_HEX, "{der_len}");
            assert_eq!(hex % CONTENTS_ROUND_HEX, 0);
            assert!(hex < der_len * 2 + CONTENTS_HEADROOM_HEX + CONTENTS_ROUND_HEX);
        }
    }

    /// The audit reads the bytes of added appearance streams. Form XObjects are never filtered,
    /// whatever their size; an appearance stream that claims to be an image (and so holds only
    /// a digest in the audit's parse) is reported, which fails verification.
    #[test]
    fn appearance_streams_keep_their_bytes_or_are_reported() {
        let (before, _, root_id) = pdf_with_large_image(&large_pixels());
        let mut content = b"q 0 0 1 rg 0 0 100 50 re f Q\n".to_vec();
        content.resize(LARGE_IMAGE + 1, b' ');

        let form = with_added_widget(&before, root_id, "/Type /XObject /Subtype /Form", &content);
        let audit = audit_increment(&before, &form).expect("audit");
        let added = &audit.added_annotations[0];
        assert_eq!(
            added.appearance.as_ref().expect("appearance").content,
            content
        );

        let image = with_added_widget(&before, root_id, "/Type /XObject /Subtype /Image", &content);
        let audit = audit_increment(&before, &image).expect("audit");
        let added = &audit.added_annotations[0];
        assert_ne!(
            added.appearance.as_ref().expect("appearance").content,
            content
        );
        assert!(
            added
                .shape_problems
                .iter()
                .any(|p| p.contains("not a form XObject")),
            "{:?}",
            added.shape_problems
        );
    }
}
