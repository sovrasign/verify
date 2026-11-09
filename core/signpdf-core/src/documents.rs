//! Several documents in one envelope: the envelope's `documents` index.
//!
//! The engine signs one PDF. An envelope of several documents signs their combination, one PDF
//! whose pages are the documents' pages in the order the preparer chose, and the envelope carries
//! an index of where each document begins and ends ([`EnvelopeDocument`]: name, first page, page
//! count, and the SHA-256 of the document as it was given). One revision per signer then covers
//! every document, with one sign-in and one proof.
//!
//! * [`combine`] makes the combined PDF and its index from the documents. The preparer passes the
//!   index in [`crate::workflow::PrepareRequest::documents`]; prepare checks it against the PDF
//!   ([`check_index`]) and it becomes part of the prepared terms, which no signer can change. The
//!   verifier checks it again against the preparer's revision.
//! * [`extract`] cuts one document out of a prepared or signed envelope as a **convenience
//!   copy**: a new PDF with only that document's pages, as they look in the envelope (field
//!   values and signature boxes included), and a banner above its first page saying that it is a
//!   copy and that the combined PDF is what was signed. A copy carries no signature: it cannot be
//!   verified, only compared with the combined file. [`convenience_copy_name`] gives its file
//!   name.
//! * [`MAX_ENVELOPE_BYTES`] (50 MB) is the largest envelope, all its documents together:
//!   [`combine`] refuses a larger total, and prepare a larger source, with
//!   [`SignPdfError::TooLarge`]. Signing a 50 MB envelope in a phone browser is what the engine's
//!   memory budget is measured on.
//!
//! ## What combining keeps
//!
//! Every page as it is drawn: its content, resources (fonts, images), boxes, rotation and
//! annotations (links, comments, form widgets). Inherited page attributes are written on each
//! page. The documents' form fields are merged into one form (a top-level field whose name an
//! earlier document already uses is renamed `name (n)`, `n` being its document's number);
//! optional content (layers) is merged with each document's default visibility; attachments are
//! merged (a name an earlier document uses gets ` (n)`). Named destinations are replaced by the
//! explicit destinations they name, so links and bookmarks keep working, and a local destination
//! given as a page number is replaced by that page. The combined PDF opens with a bookmark per
//! document, holding that document's own bookmarks.
//!
//! What it drops, because it belongs to one document and not to the combination: document-level
//! scripts and actions (open actions, `/AA`, named JavaScript) and page-level `/AA` actions, the
//! logical structure (tags), XMP metadata, page labels, article threads, output intents, viewer
//! preferences, XFA forms and usage rights (`/Perms /UR3`, which unlock features of one maker's
//! viewer). A document that is encrypted, certified or signed is refused: combining would remove
//! the encryption and break the signature. Send a signed document in an envelope of its own. The
//! combined PDF is deterministic: the same documents, in the same order and with the same names,
//! give the same bytes with the same engine build.

use std::collections::{BTreeMap, HashMap, HashSet};

use lopdf::xref::{Xref, XrefType};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat};

use crate::container;
use crate::crypto::sha256_hex;
use crate::error::{Result, SignPdfError};
use crate::model::{Envelope, EnvelopeDocument};
use crate::pades;
use crate::workflow::{self, ENVELOPE_NAME};

/// The most documents an envelope holds.
pub const MAX_DOCUMENTS: usize = 20;

/// The largest envelope, all its documents together, in bytes: 50 MB (counted as MiB, as the
/// hosted service counts its limits). [`combine`] refuses documents that add up to more, and
/// prepare a larger source.
pub const MAX_ENVELOPE_BYTES: usize = 50 * MIB;

/// The longest document name, in characters.
pub const MAX_DOCUMENT_NAME_CHARS: usize = 200;

const MIB: usize = 1024 * 1024;

/// How far up a page tree an inherited attribute is looked for (as `pades::page_geometry`).
const INHERIT_DEPTH: usize = 32;

/// How many name-tree or outline nodes are read per document at most: a bound against hostile
/// files, far above what real documents have.
const MAX_NODES: usize = 100_000;

/// One document to combine: its name (a file name or a title, shown to signers) and its PDF.
#[derive(Debug, Clone, Copy)]
pub struct SourceDocument<'a> {
    pub name: &'a str,
    pub pdf: &'a [u8],
}

/// The result of [`combine`]: the combined PDF and its index, which the preparer passes in
/// [`crate::workflow::PrepareRequest::documents`].
#[derive(Debug, Clone)]
pub struct Combined {
    pub pdf: Vec<u8>,
    pub documents: Vec<EnvelopeDocument>,
}

fn wf(msg: impl Into<String>) -> SignPdfError {
    SignPdfError::Workflow(msg.into())
}

/// Refuse more than [`MAX_ENVELOPE_BYTES`]. `what` starts the message ("the documents together
/// are", "the source document is").
pub fn check_size(len: usize, what: &str) -> Result<()> {
    if len > MAX_ENVELOPE_BYTES {
        return Err(SignPdfError::TooLarge(format!(
            "{what} {:.1} MB, more than the {} MB an envelope can hold (all its documents \
             together)",
            len as f64 / MIB as f64,
            MAX_ENVELOPE_BYTES / MIB
        )));
    }
    Ok(())
}

/// Characters that reorder text when it is shown (bidirectional controls): a name holding one
/// can be shown as something else ("invoice\u{202E}fdp.exe").
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Check a document name: 1 to [`MAX_DOCUMENT_NAME_CHARS`] characters, not only spaces, without
/// control characters (line breaks included) or bidirectional controls.
pub fn check_name(name: &str) -> std::result::Result<(), String> {
    if name.trim().is_empty() {
        return Err("a document needs a name".into());
    }
    if name.chars().count() > MAX_DOCUMENT_NAME_CHARS {
        let start: String = name.chars().take(40).collect();
        return Err(format!(
            "the document name '{start}…' is longer than {MAX_DOCUMENT_NAME_CHARS} characters"
        ));
    }
    if name.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(format!(
            "the document name '{}' holds a control character (a line break, a tab or a \
             direction mark)",
            name.escape_debug()
        ));
    }
    Ok(())
}

fn is_sha256_hex(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Check a documents index against a PDF of `pages` pages: at most [`MAX_DOCUMENTS`] entries,
/// each with a valid name ([`check_name`]), a lower-case hex SHA-256 and at least one page, the
/// first starting at page index 0 and each starting where the previous one ends, covering every
/// page. An empty index is valid (an envelope of one document without one).
pub fn check_index(documents: &[EnvelopeDocument], pages: u32) -> std::result::Result<(), String> {
    if documents.is_empty() {
        return Ok(());
    }
    if documents.len() > MAX_DOCUMENTS {
        return Err(format!(
            "the document index lists {} documents; an envelope holds at most {MAX_DOCUMENTS}",
            documents.len()
        ));
    }
    let mut next = 0u32;
    for (i, d) in documents.iter().enumerate() {
        let n = i + 1;
        check_name(&d.name).map_err(|e| format!("document {n}: {e}"))?;
        if !is_sha256_hex(&d.source_digest) {
            return Err(format!(
                "document {n} ('{}'): its source_digest is not 64 lower-case hex digits",
                d.name
            ));
        }
        if d.page_count == 0 {
            return Err(format!("document {n} ('{}') has no pages", d.name));
        }
        if d.first_page != next {
            return Err(format!(
                "document {n} ('{}') starts at page index {} where page index {next} was \
                 expected: documents follow each other, without gaps, from page index 0",
                d.name, d.first_page
            ));
        }
        next = next
            .checked_add(d.page_count)
            .ok_or_else(|| format!("document {n} ('{}') has too many pages", d.name))?;
    }
    if next != pages {
        return Err(format!(
            "the document index covers {next} page(s), but the PDF has {pages}"
        ));
    }
    Ok(())
}

// --- combine -------------------------------------------------------------------------------

/// Combine `docs`, in order, into one PDF, and return it with its index (see the module
/// documentation for what is kept).
///
/// One document is returned as it is, byte for byte, with an index of one entry. Refused: no
/// document or more than [`MAX_DOCUMENTS`], an invalid name ([`check_name`]), a file that is not
/// a PDF, has no pages, is encrypted or carries a signature or a SignPDF envelope (workflow
/// errors), and documents that add up to more than [`MAX_ENVELOPE_BYTES`], or a combination
/// larger than that ([`SignPdfError::TooLarge`]).
///
/// Memory: every document is parsed at once, then the combination written out: about three
/// times the documents' total size at the peak. Hosts combine on a server or a desktop; a phone
/// browser receives the combined PDF.
pub fn combine(docs: &[SourceDocument<'_>]) -> Result<Combined> {
    if docs.is_empty() {
        return Err(wf("there are no documents to combine"));
    }
    if docs.len() > MAX_DOCUMENTS {
        return Err(wf(format!(
            "an envelope holds at most {MAX_DOCUMENTS} documents, and {} were given",
            docs.len()
        )));
    }
    for (i, d) in docs.iter().enumerate() {
        check_name(d.name).map_err(|e| wf(format!("document {}: {e}", i + 1)))?;
        if !container::is_pdf(d.pdf) {
            return Err(wf(format!(
                "document {} ('{}') is not a PDF",
                i + 1,
                d.name
            )));
        }
    }
    let total = docs
        .iter()
        .fold(0usize, |t, d| t.saturating_add(d.pdf.len()));
    check_size(total, "the documents together are")?;

    if let [only] = docs {
        let pages = pades::page_geometry(only.pdf)
            .map_err(|e| wf(format!("document 1 ('{}') cannot be read: {e}", only.name)))?
            .len();
        if pages == 0 {
            return Err(wf(format!("document 1 ('{}') has no pages", only.name)));
        }
        return Ok(Combined {
            pdf: only.pdf.to_vec(),
            documents: vec![EnvelopeDocument {
                name: only.name.to_string(),
                first_page: 0,
                page_count: u32::try_from(pages).map_err(|_| wf("too many pages"))?,
                source_digest: sha256_hex(only.pdf),
            }],
        });
    }

    let mut next_id = 1u32;
    let mut parts = Vec::with_capacity(docs.len());
    for (i, d) in docs.iter().enumerate() {
        parts.push(Part::load(i + 1, d, &mut next_id)?);
    }
    let (mut out, documents) = assemble(parts, next_id)?;
    let mut pdf = Vec::new();
    out.save_to(&mut pdf)
        .map_err(|e| SignPdfError::Pades(format!("cannot write the combined PDF: {e}")))?;
    check_size(pdf.len(), "the combined PDF is")?;
    Ok(Combined { pdf, documents })
}

/// One document being combined, its objects renumbered into the combination's numbering.
struct Part {
    /// 1-based position in the envelope.
    number: usize,
    name: String,
    digest: String,
    doc: Document,
    pages: Vec<ObjectId>,
}

impl Part {
    fn load(number: usize, src: &SourceDocument<'_>, next_id: &mut u32) -> Result<Part> {
        let label = format!("document {number} ('{}')", src.name);
        let mut doc = Document::load_mem(src.pdf)
            .map_err(|e| wf(format!("{label} cannot be read as a PDF: {e}")))?;
        if doc.is_encrypted() || doc.was_encrypted() {
            return Err(wf(format!(
                "{label} is encrypted (password protected): remove the protection, or print it \
                 to a new PDF, before adding it to an envelope"
            )));
        }
        if let Some(why) = signed(&doc) {
            return Err(wf(format!(
                "{label} {why}: combining it with other documents would break its signature. \
                 Send it in an envelope of its own"
            )));
        }
        // Cross-reference and object streams are rewritten as plain objects.
        doc.objects
            .retain(|_, o| !matches!(o.type_name(), Ok(t) if t == b"ObjStm" || t == b"XRef"));
        renumber(&mut doc, next_id).map_err(|e| wf(format!("{label}: {e}")))?;
        // A page listed twice (a page tree that loops back on itself) is one page.
        let mut seen = HashSet::new();
        let pages: Vec<ObjectId> = doc.page_iter().filter(|p| seen.insert(*p)).collect();
        if pages.is_empty() {
            return Err(wf(format!("{label} has no pages")));
        }
        Ok(Part {
            number,
            name: src.name.to_string(),
            digest: sha256_hex(src.pdf),
            doc,
            pages,
        })
    }

    fn catalog(&self) -> Dictionary {
        self.doc.catalog().cloned().unwrap_or_default()
    }

    /// The catalog entry `key`, resolved to a dictionary.
    fn catalog_dict(&self, key: &[u8]) -> Option<Dictionary> {
        let catalog = self.doc.catalog().ok()?;
        dict_of(&self.doc, catalog.get(key).ok()?).cloned()
    }
}

/// Why `doc` cannot be combined because of a signature, if it carries one: a certification, a
/// signature or document-timestamp dictionary, or a SignPDF envelope.
///
/// Usage rights (`/Perms /UR3`, which a viewer's maker signs to unlock features of its viewer
/// such as saving a filled form) are not the document's signatures: the combination drops them
/// with the rest of the catalog, so they are not a reason to refuse it.
fn signed(doc: &Document) -> Option<&'static str> {
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|r| r.as_reference().ok());
    let perms = doc
        .catalog()
        .ok()
        .and_then(|c| dict_of(doc, c.get(b"Perms").ok()?));
    if perms.is_some_and(|p| p.has(b"DocMDP")) {
        return Some("is certified (it carries a certification signature)");
    }
    let mut skip: HashSet<ObjectId> = HashSet::new();
    if let Ok(Object::Reference(id)) = doc.catalog().and_then(|c| c.get(b"Perms")) {
        skip.insert(*id);
    }
    for key in [&b"UR"[..], b"UR3"] {
        if let Some(Object::Reference(id)) = perms.and_then(|p| p.get(key).ok()) {
            skip.insert(*id);
        }
    }
    for (id, obj) in &doc.objects {
        if skip.contains(id) {
            continue;
        }
        let mut stack = vec![obj];
        // The catalog is read without its usage rights.
        let without_perms;
        if Some(*id) == catalog_id {
            if let Object::Dictionary(d) = obj {
                let mut d = d.clone();
                d.remove(b"Perms");
                without_perms = Object::Dictionary(d);
                stack = vec![&without_perms];
            }
        }
        while let Some(o) = stack.pop() {
            match o {
                Object::Dictionary(d) => {
                    let is_signature = matches!(d.get(b"Type"), Ok(Object::Name(t))
                        if t == b"Sig" || t == b"DocTimeStamp")
                        || (d.has(b"ByteRange") && d.has(b"Contents") && d.has(b"Filter"));
                    if is_signature {
                        return Some("is signed");
                    }
                    stack.extend(d.iter().map(|(_, v)| v));
                }
                Object::Array(a) => stack.extend(a.iter()),
                Object::Stream(s) => stack.extend(s.dict.iter().map(|(_, v)| v)),
                _ => {}
            }
        }
    }
    let names = doc
        .catalog()
        .ok()
        .and_then(|c| dict_of(doc, c.get(b"Names").ok()?))
        .and_then(|n| n.get(b"EmbeddedFiles").ok());
    if let Some(tree) = names {
        if name_tree(doc, tree)
            .iter()
            .any(|(k, _)| k.as_slice() == ENVELOPE_NAME.as_bytes())
        {
            return Some("is already a SignPDF envelope");
        }
    }
    None
}

/// Give every object of `doc` a new number from `next_id` on (generation 0), in the order of
/// the old numbers, and rewrite every reference. A reference to an object the document does not
/// have becomes `null`, as a reader treats it, so that it cannot point into another document.
fn renumber(doc: &mut Document, next_id: &mut u32) -> std::result::Result<(), String> {
    let old = std::mem::take(&mut doc.objects);
    let mut map: HashMap<ObjectId, ObjectId> = HashMap::with_capacity(old.len());
    for id in old.keys() {
        map.insert(*id, (*next_id, 0));
        *next_id = next_id
            .checked_add(1)
            .ok_or("too many objects to combine")?;
    }
    let remap = |o: &mut Object| {
        if let Object::Reference(id) = o {
            *o = match map.get(id) {
                Some(new) => Object::Reference(*new),
                None => Object::Null,
            };
        }
    };
    let mut objects = BTreeMap::new();
    for (id, mut obj) in old {
        each_reference_mut(&mut obj, remap);
        objects.insert(map[&id], obj);
    }
    for (_, v) in doc.trailer.iter_mut() {
        each_reference_mut(v, remap);
    }
    doc.objects = objects;
    doc.max_id = next_id.saturating_sub(1);
    Ok(())
}

/// Call `f` on every reference inside `obj` (itself included), without recursion: a hostile
/// file can nest arrays deeply.
fn each_reference_mut(obj: &mut Object, f: impl Fn(&mut Object)) {
    let mut stack: Vec<&mut Object> = vec![obj];
    while let Some(o) = stack.pop() {
        match o {
            Object::Reference(_) => f(o),
            Object::Array(a) => stack.extend(a.iter_mut()),
            Object::Dictionary(d) => stack.extend(d.iter_mut().map(|(_, v)| v)),
            Object::Stream(s) => stack.extend(s.dict.iter_mut().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// Every object number `obj` refers to.
fn references(obj: &Object, out: &mut Vec<ObjectId>) {
    let mut stack = vec![obj];
    while let Some(o) = stack.pop() {
        match o {
            Object::Reference(id) => out.push(*id),
            Object::Array(a) => stack.extend(a.iter()),
            Object::Dictionary(d) => stack.extend(d.iter().map(|(_, v)| v)),
            Object::Stream(s) => stack.extend(s.dict.iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// Remove every object the trailer does not reach (lopdf's `prune_objects` is quadratic in the
/// number of objects).
fn prune(doc: &mut Document) {
    let mut todo = Vec::new();
    for (_, v) in doc.trailer.iter() {
        references(v, &mut todo);
    }
    let mut seen: HashSet<ObjectId> = HashSet::new();
    while let Some(id) = todo.pop() {
        if seen.insert(id) {
            if let Some(o) = doc.objects.get(&id) {
                references(o, &mut todo);
            }
        }
    }
    doc.objects.retain(|id, _| seen.contains(id));
}

/// Follow references from `obj` (a few levels at most) to a direct object.
fn deref<'a>(doc: &'a Document, mut obj: &'a Object) -> Option<&'a Object> {
    for _ in 0..8 {
        match obj {
            Object::Reference(id) => obj = doc.get_object(*id).ok()?,
            other => return Some(other),
        }
    }
    None
}

fn dict_of<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Dictionary> {
    deref(doc, obj)?.as_dict().ok()
}

fn array_of<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Vec<Object>> {
    deref(doc, obj)?.as_array().ok()
}

/// The `(key, value)` pairs of a name tree (ISO 32000-1 §7.9.6), in tree order, read without
/// recursion and with a bound on the nodes visited.
fn name_tree(doc: &Document, root: &Object) -> Vec<(Vec<u8>, Object)> {
    let mut out = Vec::new();
    let mut todo = vec![root];
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut visited = 0;
    while let Some(node) = todo.pop() {
        visited += 1;
        if visited > MAX_NODES {
            break;
        }
        if let Object::Reference(id) = node {
            if !seen.insert(*id) {
                continue;
            }
        }
        let Some(dict) = dict_of(doc, node) else {
            continue;
        };
        if let Some(names) = dict.get(b"Names").ok().and_then(|n| array_of(doc, n)) {
            for [key, value] in names.as_chunks::<2>().0 {
                if let Some(Object::String(key, _)) = deref(doc, key) {
                    out.push((key.clone(), value.clone()));
                }
            }
        }
        if let Some(kids) = dict.get(b"Kids").ok().and_then(|k| array_of(doc, k)) {
            // Reversed onto the stack, so the kids are read in order.
            todo.extend(kids.iter().rev());
        }
    }
    out
}

/// A document's named destinations: the name tree `/Names /Dests` (keyed by strings) and the
/// older `/Dests` dictionary (keyed by names), each resolved to an explicit destination array.
#[derive(Default)]
struct NamedDestinations {
    by_string: HashMap<Vec<u8>, Vec<Object>>,
    by_name: HashMap<Vec<u8>, Vec<Object>>,
}

impl NamedDestinations {
    fn read(doc: &Document) -> NamedDestinations {
        let mut named = NamedDestinations::default();
        let Ok(catalog) = doc.catalog() else {
            return named;
        };
        let explicit = |value: &Object| -> Option<Vec<Object>> {
            match deref(doc, value)? {
                Object::Array(a) => Some(a.clone()),
                Object::Dictionary(d) => array_of(doc, d.get(b"D").ok()?).cloned(),
                _ => None,
            }
        };
        if let Some(tree) = catalog
            .get(b"Names")
            .ok()
            .and_then(|n| dict_of(doc, n))
            .and_then(|n| n.get(b"Dests").ok())
        {
            for (key, value) in name_tree(doc, tree) {
                if let Some(dest) = explicit(&value) {
                    named.by_string.entry(key).or_insert(dest);
                }
            }
        }
        if let Some(dests) = catalog.get(b"Dests").ok().and_then(|d| dict_of(doc, d)) {
            for (key, value) in dests.iter() {
                if let Some(dest) = explicit(value) {
                    named.by_name.insert(key.clone(), dest);
                }
            }
        }
        named
    }

    /// The explicit destination for `dest` (a name, a string or an array), with a page given as
    /// a page number (which only a remote destination may use) replaced by that page of `pages`.
    /// `None` when it names nothing.
    fn resolve(&self, dest: &Object, pages: &[ObjectId]) -> Option<Object> {
        let array = match dest {
            Object::Name(n) => self.by_name.get(n)?.clone(),
            Object::String(s, _) => self.by_string.get(s)?.clone(),
            Object::Array(a) => a.clone(),
            _ => return None,
        };
        let mut array = array;
        if let Some(Object::Integer(i)) = array.first() {
            let page = usize::try_from(*i).ok().and_then(|i| pages.get(i))?;
            array[0] = Object::Reference(*page);
        }
        Some(Object::Array(array))
    }

    /// Replace the named destinations of a link annotation or an outline item (`/Dest`, and the
    /// `/D` of a `GoTo` action) by explicit ones; one that names nothing is removed.
    fn fix(&self, doc: &Document, dict: &mut Dictionary, pages: &[ObjectId]) {
        if let Ok(dest) = dict.get(b"Dest") {
            let resolved = deref(doc, dest).and_then(|d| self.resolve(d, pages));
            match resolved {
                Some(d) => dict.set("Dest", d),
                None => {
                    dict.remove(b"Dest");
                }
            }
        }
        let goto = match dict.get(b"A") {
            Ok(Object::Dictionary(a)) => Some(a.clone()),
            _ => None,
        };
        if let Some(mut action) = goto {
            if matches!(action.get(b"S"), Ok(Object::Name(s)) if s == b"GoTo") {
                if let Some(d) = action.get(b"D").ok().and_then(|d| deref(doc, d)) {
                    match self.resolve(d, pages) {
                        Some(d) => action.set("D", d),
                        None => {
                            action.remove(b"D");
                        }
                    }
                    dict.set("A", Object::Dictionary(action));
                }
            }
        }
    }
}

/// Fix the destinations of the link annotations on `part`'s pages, and of the `GoTo` actions
/// they use when those are objects of their own.
fn fix_link_destinations(part: &mut Part, named: &NamedDestinations) {
    let mut annots: Vec<ObjectId> = Vec::new();
    let mut direct_on: Vec<ObjectId> = Vec::new();
    for page in &part.pages {
        let Some(list) = part
            .doc
            .get_dictionary(*page)
            .ok()
            .and_then(|p| p.get(b"Annots").ok())
            .and_then(|a| array_of(&part.doc, a))
        else {
            continue;
        };
        for a in list {
            match a {
                Object::Reference(id) => annots.push(*id),
                Object::Dictionary(_) => direct_on.push(*page),
                _ => {}
            }
        }
    }
    for id in annots {
        let Some(mut dict) = part.doc.get_dictionary(id).ok().cloned() else {
            continue;
        };
        if !matches!(dict.get(b"Subtype"), Ok(Object::Name(s)) if s == b"Link") {
            continue;
        }
        // A GoTo action may be an object of its own.
        if let Ok(Object::Reference(action)) = dict.get(b"A") {
            if let Some(a) = part.doc.get_dictionary(*action).ok().cloned() {
                dict.set("A", Object::Dictionary(a));
            }
        }
        named.fix(&part.doc, &mut dict, &part.pages);
        part.doc.objects.insert(id, Object::Dictionary(dict));
    }
    direct_on.dedup();
    for page in direct_on {
        let Some(mut page_dict) = part.doc.get_dictionary(page).ok().cloned() else {
            continue;
        };
        if let Ok(Object::Array(list)) = page_dict.get_mut(b"Annots") {
            let mut fixed = Vec::with_capacity(list.len());
            for a in list.iter() {
                match a {
                    Object::Dictionary(d) if matches!(d.get(b"Subtype"), Ok(Object::Name(s)) if s == b"Link") =>
                    {
                        let mut d = d.clone();
                        named.fix(&part.doc, &mut d, &part.pages);
                        fixed.push(Object::Dictionary(d));
                    }
                    other => fixed.push(other.clone()),
                }
            }
            *list = fixed;
        }
        part.doc.objects.insert(page, Object::Dictionary(page_dict));
    }
}

/// The value of inheritable page attribute `key` (`Resources`, `MediaBox`, `CropBox`, `Rotate`)
/// for `page`: its own, or the nearest ancestor's.
fn inherited(doc: &Document, page: ObjectId, key: &[u8]) -> Option<Object> {
    let mut current = Some(page);
    for _ in 0..INHERIT_DEPTH {
        let id = current?;
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(v) = dict.get(key) {
            return Some(v.clone());
        }
        current = dict.get(b"Parent").ok().and_then(|o| o.as_reference().ok());
    }
    None
}

/// `page`'s dictionary standing alone under the page tree node `parent`: inherited attributes
/// written on it, and without what refers to structures the combination drops.
fn standalone_page(doc: &Document, page: ObjectId, parent: ObjectId) -> Dictionary {
    let mut dict = doc.get_dictionary(page).cloned().unwrap_or_default();
    for key in [&b"Resources"[..], b"MediaBox", b"CropBox", b"Rotate"] {
        if !dict.has(key) {
            if let Some(v) = inherited(doc, page, key) {
                dict.set(key.to_vec(), v);
            }
        }
    }
    if !dict.has(b"MediaBox") {
        // What `pades::page_geometry` assumes, written down so every reader agrees.
        dict.set(
            "MediaBox",
            Object::Array(vec![0.into(), 0.into(), 612.into(), 792.into()]),
        );
    }
    for key in [&b"AA"[..], b"B", b"StructParents", b"Parent"] {
        dict.remove(key);
    }
    dict.set("Type", Object::Name(b"Page".to_vec()));
    dict.set("Parent", Object::Reference(parent));
    dict
}

/// `s` as a PDF text string: literal while it is printable ASCII, otherwise UTF-16BE with a
/// byte-order mark.
fn text_string(s: &str) -> Object {
    if s.chars().all(|c| (' '..='~').contains(&c)) {
        Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Object::String(bytes, StringFormat::Hexadecimal)
    }
}

/// `suffix` appended to the text string `bytes`, in its encoding.
fn with_suffix(bytes: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if bytes.starts_with(&[0xFE, 0xFF]) {
        for unit in suffix.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    } else {
        out.extend_from_slice(suffix.as_bytes());
    }
    out
}

/// The PDF version a header or catalog states, as `(major, minor)`.
fn pdf_version(v: &str) -> (u32, u32) {
    let mut it = v.trim().split('.');
    let major = it.next().and_then(|m| m.parse().ok()).unwrap_or(1);
    let minor = it.next().and_then(|m| m.parse().ok()).unwrap_or(4);
    (major, minor)
}

/// The items of an outline level: `first`, then each `/Next`, stopping at an item already met
/// anywhere in the outline (`seen`), at a dictionary-less item, or at the node budget.
fn outline_level(
    doc: &Document,
    first: Option<ObjectId>,
    seen: &mut HashSet<ObjectId>,
) -> Vec<ObjectId> {
    let mut items = Vec::new();
    let mut current = first;
    while let Some(id) = current {
        let Ok(item) = doc.get_dictionary(id) else {
            break;
        };
        if seen.len() >= MAX_NODES || !seen.insert(id) {
            break;
        }
        items.push(id);
        current = item.get(b"Next").ok().and_then(|n| n.as_reference().ok());
    }
    items
}

/// Hang `part`'s own outline (bookmarks) under the item `parent`, relinked so that it cannot
/// loop: each level's items chained `/Prev`-`/Next` in order under their `/Parent`, an item met
/// twice left out, every item with children closed. Named destinations become explicit, and
/// references to the dropped structure tree (`/SE`) go. Returns the first and last top-level
/// items and their number, when there are any.
fn adopt_outline(
    part: &mut Part,
    named: &NamedDestinations,
    parent: ObjectId,
) -> Option<(ObjectId, ObjectId, usize)> {
    let first = part
        .catalog_dict(b"Outlines")
        .and_then(|o| o.get(b"First").ok().and_then(|f| f.as_reference().ok()));
    let mut seen = HashSet::new();
    let top = outline_level(&part.doc, first, &mut seen);
    let result = Some((*top.first()?, *top.last()?, top.len()));
    let mut levels = vec![(parent, top)];
    while let Some((level_parent, items)) = levels.pop() {
        for (i, id) in items.iter().enumerate() {
            let Some(mut item) = part.doc.get_dictionary(*id).ok().cloned() else {
                continue;
            };
            item.set("Parent", Object::Reference(level_parent));
            item.remove(b"Prev");
            item.remove(b"Next");
            if i > 0 {
                item.set("Prev", Object::Reference(items[i - 1]));
            }
            if let Some(next) = items.get(i + 1) {
                item.set("Next", Object::Reference(*next));
            }
            let child = item.get(b"First").ok().and_then(|f| f.as_reference().ok());
            let children = outline_level(&part.doc, child, &mut seen);
            item.remove(b"First");
            item.remove(b"Last");
            item.remove(b"Count");
            if let (Some(f), Some(l)) = (children.first(), children.last()) {
                item.set("First", Object::Reference(*f));
                item.set("Last", Object::Reference(*l));
                item.set("Count", -(children.len() as i64));
                levels.push((*id, children));
            }
            item.remove(b"SE");
            if let Ok(Object::Reference(action)) = item.get(b"A") {
                if let Some(a) = part.doc.get_dictionary(*action).ok().cloned() {
                    item.set("A", Object::Dictionary(a));
                }
            }
            named.fix(&part.doc, &mut item, &part.pages);
            part.doc.objects.insert(*id, Object::Dictionary(item));
        }
    }
    result
}

/// The form fields of every document merged into one form.
#[derive(Default)]
struct MergedForm {
    fields: Vec<Object>,
    names: HashSet<Vec<u8>>,
    resources: Dictionary,
    da: Option<Object>,
    q: Option<Object>,
    need_appearances: bool,
    sig_flags: i64,
    calculation_order: Vec<Object>,
    any: bool,
}

impl MergedForm {
    fn add(&mut self, part: &mut Part) {
        let Some(form) = part.catalog_dict(b"AcroForm") else {
            return;
        };
        self.any = true;
        let fields = form
            .get(b"Fields")
            .ok()
            .and_then(|f| array_of(&part.doc, f))
            .cloned()
            .unwrap_or_default();
        for field in fields {
            if let Object::Reference(id) = field {
                if let Some(mut dict) = part.doc.get_dictionary(id).ok().cloned() {
                    if let Some(Object::String(name, format)) = dict
                        .get(b"T")
                        .ok()
                        .and_then(|t| deref(&part.doc, t))
                        .cloned()
                    {
                        let mut unique = name.clone();
                        let mut k = 1;
                        while self.names.contains(&unique) {
                            let suffix = if k == 1 {
                                format!(" ({})", part.number)
                            } else {
                                format!(" ({}.{k})", part.number)
                            };
                            unique = with_suffix(&name, &suffix);
                            k += 1;
                        }
                        if unique != name {
                            dict.set("T", Object::String(unique.clone(), format));
                            part.doc.objects.insert(id, Object::Dictionary(dict));
                        }
                        self.names.insert(unique);
                    }
                }
            }
            self.fields.push(field);
        }
        if let Some(dr) = form.get(b"DR").ok().and_then(|d| dict_of(&part.doc, d)) {
            for (category, entries) in dr.iter() {
                let Some(entries) = dict_of(&part.doc, entries) else {
                    continue;
                };
                let mut merged = match self.resources.get(category) {
                    Ok(Object::Dictionary(d)) => d.clone(),
                    _ => Dictionary::new(),
                };
                for (k, v) in entries.iter() {
                    if !merged.has(k) {
                        merged.set(k.clone(), v.clone());
                    }
                }
                self.resources
                    .set(category.clone(), Object::Dictionary(merged));
            }
        }
        if self.da.is_none() {
            self.da = form.get(b"DA").ok().cloned();
        }
        if self.q.is_none() {
            self.q = form.get(b"Q").ok().cloned();
        }
        self.need_appearances |= matches!(
            form.get(b"NeedAppearances")
                .ok()
                .and_then(|n| deref(&part.doc, n)),
            Some(Object::Boolean(true))
        );
        if let Some(Object::Integer(f)) =
            form.get(b"SigFlags").ok().and_then(|f| deref(&part.doc, f))
        {
            self.sig_flags |= f & 3;
        }
        if let Some(co) = form.get(b"CO").ok().and_then(|c| array_of(&part.doc, c)) {
            self.calculation_order.extend(co.iter().cloned());
        }
    }

    fn into_dict(self) -> Option<Dictionary> {
        if !self.any {
            return None;
        }
        let mut form = Dictionary::new();
        form.set("Fields", Object::Array(self.fields));
        if !self.resources.is_empty() {
            form.set("DR", Object::Dictionary(self.resources));
        }
        if let Some(da) = self.da {
            form.set("DA", da);
        }
        if let Some(q) = self.q {
            form.set("Q", q);
        }
        if self.need_appearances {
            form.set("NeedAppearances", true);
        }
        if self.sig_flags != 0 {
            form.set("SigFlags", self.sig_flags);
        }
        if !self.calculation_order.is_empty() {
            form.set("CO", Object::Array(self.calculation_order));
        }
        Some(form)
    }
}

/// Every document's optional content (layers), merged with each one's default visibility.
#[derive(Default)]
struct MergedLayers {
    ocgs: Vec<Object>,
    on: Vec<Object>,
    off: Vec<Object>,
    order: Vec<Object>,
    locked: Vec<Object>,
    rb_groups: Vec<Object>,
    auto_state: Vec<Object>,
}

impl MergedLayers {
    fn add(&mut self, part: &Part) {
        let Some(props) = part.catalog_dict(b"OCProperties") else {
            return;
        };
        let doc = &part.doc;
        let list = |d: &Dictionary, key: &[u8]| -> Vec<Object> {
            d.get(key)
                .ok()
                .and_then(|v| array_of(doc, v))
                .cloned()
                .unwrap_or_default()
        };
        let ocgs = list(&props, b"OCGs");
        let config = props
            .get(b"D")
            .ok()
            .and_then(|d| dict_of(doc, d))
            .cloned()
            .unwrap_or_default();
        let on = list(&config, b"ON");
        let off = list(&config, b"OFF");
        // A group the default configuration does not name takes its base state.
        if matches!(config.get(b"BaseState"), Ok(Object::Name(b)) if b == b"OFF") {
            self.off
                .extend(ocgs.iter().filter(|g| !on.contains(g)).cloned());
        }
        self.on.extend(on);
        self.off.extend(off);
        self.order.extend(list(&config, b"Order"));
        self.locked.extend(list(&config, b"Locked"));
        self.rb_groups.extend(list(&config, b"RBGroups"));
        self.auto_state.extend(list(&config, b"AS"));
        self.ocgs.extend(ocgs);
    }

    fn into_dict(self) -> Option<Dictionary> {
        if self.ocgs.is_empty() {
            return None;
        }
        let mut config = Dictionary::new();
        for (key, list) in [
            ("ON", self.on),
            ("OFF", self.off),
            ("Order", self.order),
            ("Locked", self.locked),
            ("RBGroups", self.rb_groups),
            ("AS", self.auto_state),
        ] {
            if !list.is_empty() {
                config.set(key, Object::Array(list));
            }
        }
        let mut props = Dictionary::new();
        props.set("OCGs", Object::Array(self.ocgs));
        props.set("D", Object::Dictionary(config));
        Some(props)
    }
}

/// Put the parts together into one document; returns it with its index.
fn assemble(mut parts: Vec<Part>, mut next_id: u32) -> Result<(Document, Vec<EnvelopeDocument>)> {
    let mut new_id = || -> Result<ObjectId> {
        let id = (next_id, 0);
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| wf("too many objects to combine"))?;
        Ok(id)
    };
    let pages_id = new_id()?;
    let catalog_id = new_id()?;
    let outlines_id = new_id()?;

    let mut version = (1, 4);
    let mut kids = Vec::new();
    let mut index = Vec::with_capacity(parts.len());
    let mut form = MergedForm::default();
    let mut layers = MergedLayers::default();
    let mut attachments: Vec<(Vec<u8>, Object)> = Vec::new();
    let mut attachment_names: HashSet<Vec<u8>> = HashSet::new();
    let mut langs: Vec<Option<Object>> = Vec::new();
    let mut bookmarks: Vec<(ObjectId, Dictionary)> = Vec::new();

    for part in &mut parts {
        let catalog = part.catalog();
        version = version.max(pdf_version(&part.doc.version));
        if let Ok(Object::Name(v)) = catalog.get(b"Version") {
            version = version.max(pdf_version(&String::from_utf8_lossy(v)));
        }
        langs.push(catalog.get(b"Lang").ok().cloned());

        let named = NamedDestinations::read(&part.doc);
        fix_link_destinations(part, &named);

        // The document's own bookmarks, under one bookmark for the document.
        let bookmark_id = new_id()?;
        let mut bookmark = Dictionary::new();
        bookmark.set("Title", text_string(&part.name));
        bookmark.set("Parent", Object::Reference(outlines_id));
        bookmark.set(
            "Dest",
            Object::Array(vec![
                Object::Reference(part.pages[0]),
                Object::Name(b"Fit".to_vec()),
            ]),
        );
        if let Some((first, last, count)) = adopt_outline(part, &named, bookmark_id) {
            bookmark.set("First", Object::Reference(first));
            bookmark.set("Last", Object::Reference(last));
            // Closed: the document's own bookmarks show when it is opened.
            bookmark.set("Count", -(count as i64));
        }
        bookmarks.push((bookmark_id, bookmark));

        form.add(part);
        layers.add(part);

        if let Some(tree) = part
            .catalog_dict(b"Names")
            .and_then(|n| n.get(b"EmbeddedFiles").ok().cloned())
        {
            for (name, spec) in name_tree(&part.doc, &tree) {
                let mut unique = name.clone();
                let mut k = 1;
                while attachment_names.contains(&unique) {
                    let suffix = if k == 1 {
                        format!(" ({})", part.number)
                    } else {
                        format!(" ({}.{k})", part.number)
                    };
                    unique = with_suffix(&name, &suffix);
                    k += 1;
                }
                attachment_names.insert(unique.clone());
                attachments.push((unique, spec));
            }
        }

        for page in &part.pages {
            let dict = standalone_page(&part.doc, *page, pages_id);
            part.doc.objects.insert(*page, Object::Dictionary(dict));
            kids.push(Object::Reference(*page));
        }
        let first_page = index
            .last()
            .map(|d: &EnvelopeDocument| d.first_page + d.page_count)
            .unwrap_or(0);
        index.push(EnvelopeDocument {
            name: part.name.clone(),
            first_page,
            page_count: u32::try_from(part.pages.len()).map_err(|_| wf("too many pages"))?,
            source_digest: part.digest.clone(),
        });
    }
    // The page count must fit the index's numbering.
    u32::try_from(kids.len()).map_err(|_| wf("too many pages"))?;

    let mut out = Document::with_version(format!("{}.{}", version.0, version.1));
    out.reference_table = Xref::new(0, XrefType::CrossReferenceTable);
    for part in parts {
        out.objects.extend(part.doc.objects);
    }

    // Bookmarks: one per document, chained.
    let count = bookmarks.len();
    for i in 0..count {
        let (id, mut item) = bookmarks[i].clone();
        if i > 0 {
            item.set("Prev", Object::Reference(bookmarks[i - 1].0));
        }
        if i + 1 < count {
            item.set("Next", Object::Reference(bookmarks[i + 1].0));
        }
        out.objects.insert(id, Object::Dictionary(item));
    }
    let mut outlines = Dictionary::new();
    outlines.set("Type", Object::Name(b"Outlines".to_vec()));
    outlines.set("First", Object::Reference(bookmarks[0].0));
    outlines.set("Last", Object::Reference(bookmarks[count - 1].0));
    outlines.set("Count", count as i64);
    out.objects
        .insert(outlines_id, Object::Dictionary(outlines));

    let mut tree = Dictionary::new();
    tree.set("Type", Object::Name(b"Pages".to_vec()));
    tree.set("Count", kids.len() as i64);
    tree.set("Kids", Object::Array(kids));
    out.objects.insert(pages_id, Object::Dictionary(tree));

    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    catalog.set("Outlines", Object::Reference(outlines_id));
    catalog.set("PageMode", Object::Name(b"UseOutlines".to_vec()));
    if let Some(form) = form.into_dict() {
        catalog.set("AcroForm", Object::Dictionary(form));
    }
    if let Some(layers) = layers.into_dict() {
        catalog.set("OCProperties", Object::Dictionary(layers));
    }
    if !attachments.is_empty() {
        attachments.sort_by(|a, b| a.0.cmp(&b.0));
        let mut names = Vec::with_capacity(attachments.len() * 2);
        for (name, spec) in attachments {
            names.push(Object::String(name, StringFormat::Literal));
            names.push(spec);
        }
        let mut files = Dictionary::new();
        files.set("Names", Object::Array(names));
        let mut name_dict = Dictionary::new();
        name_dict.set("EmbeddedFiles", Object::Dictionary(files));
        catalog.set("Names", Object::Dictionary(name_dict));
    }
    if let Some(Some(lang)) = langs.first() {
        if langs.iter().all(|l| l.as_ref() == Some(lang)) {
            catalog.set("Lang", lang.clone());
        }
    }
    out.objects.insert(catalog_id, Object::Dictionary(catalog));

    // A file identifier that depends only on the documents and their order.
    let mut seed = b"signpdf-combine".to_vec();
    for d in &index {
        seed.extend_from_slice(d.source_digest.as_bytes());
    }
    let id = hex::decode(&sha256_hex(&seed)[..32]).unwrap_or_default();
    out.trailer.set("Root", Object::Reference(catalog_id));
    out.trailer.set(
        "ID",
        Object::Array(vec![
            Object::String(id.clone(), StringFormat::Hexadecimal),
            Object::String(id, StringFormat::Hexadecimal),
        ]),
    );
    prune(&mut out);
    out.max_id = out.objects.keys().map(|k| k.0).max().unwrap_or(0);
    Ok((out, index))
}

/// [`combine`] over a byte-buffer interface, for the FFI and WebAssembly bridges, which pass
/// buffers rather than lists.
///
/// The documents come as one buffer holding their PDFs one after the other, and a manifest that
/// names them and says how long each is: `{"documents": [{"name": "NDA.pdf", "len": 48211},
/// …]}`, in order (the lengths add up to the buffer's). The result is one buffer: the length
/// of the index JSON as 4 bytes (big-endian), the index JSON `{"documents": [{"name",
/// "first_page", "page_count", "source_digest"}, …]}`, then the combined PDF.
pub mod wire {
    use serde::{Deserialize, Serialize};

    use super::{Combined, SourceDocument};
    use crate::model::EnvelopeDocument;

    /// The manifest of a combine call.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Manifest {
        pub documents: Vec<ManifestEntry>,
    }

    /// One document of a [`Manifest`]: its name and the length of its PDF in the buffer.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ManifestEntry {
        pub name: String,
        pub len: usize,
    }

    /// The documents of `data` as `manifest` describes them; refused when the lengths do not
    /// add up to the buffer's.
    pub fn split<'a>(
        manifest: &'a Manifest,
        data: &'a [u8],
    ) -> std::result::Result<Vec<SourceDocument<'a>>, String> {
        let mut at = 0usize;
        let mut docs = Vec::with_capacity(manifest.documents.len());
        for (i, d) in manifest.documents.iter().enumerate() {
            let end = at
                .checked_add(d.len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| {
                    format!(
                        "the manifest's document {} ends past the {} bytes given",
                        i + 1,
                        data.len()
                    )
                })?;
            docs.push(SourceDocument {
                name: &d.name,
                pdf: &data[at..end],
            });
            at = end;
        }
        if at != data.len() {
            return Err(format!(
                "the manifest's documents add up to {at} bytes, but {} were given",
                data.len()
            ));
        }
        Ok(docs)
    }

    #[derive(Serialize)]
    struct Index<'a> {
        documents: &'a [EnvelopeDocument],
    }

    /// `combined` as one buffer: the index JSON's length (4 bytes, big-endian), the index JSON,
    /// the PDF.
    pub fn frame(combined: &Combined) -> crate::Result<Vec<u8>> {
        let index = serde_json::to_vec(&Index {
            documents: &combined.documents,
        })?;
        let len = u32::try_from(index.len())
            .map_err(|_| crate::SignPdfError::Encoding("index too long".into()))?;
        let mut out = Vec::with_capacity(4 + index.len() + combined.pdf.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&combined.pdf);
        Ok(out)
    }
}

// --- extract -------------------------------------------------------------------------------

/// Annotation flags of what the copy draws: print, read-only, locked.
const FIXED_ANNOTATION: i64 = 4 | 64 | 128;

/// The height of the banner strip added above a convenience copy's first page, in points.
const BANNER_HEIGHT: f32 = 30.0;

/// The resource name of the banner's font.
const BANNER_FONT: &str = "SignPDFBanner";

/// A convenience copy of document `index` (0-based, in the envelope's `documents` index) of a
/// prepared or signed envelope: a new PDF with only that document's pages, as they look in
/// `pdf`, and a banner strip added above its first page that says it is a copy of document
/// `index + 1` of the envelope and that the combined PDF is what was signed.
///
/// Field values, signature boxes and the document's own form fields are kept as fixed
/// appearances (read-only stamps); signatures, the envelope and everything else that belongs to
/// the combination are not. The copy is not verifiable on its own: whoever needs proof verifies
/// the combined PDF. Refused for an envelope without a documents index, an index out of range,
/// and an envelope written by a newer build ([`SignPdfError::UnsupportedSchemaVersion`]).
pub fn extract(pdf: &[u8], index: usize) -> Result<Vec<u8>> {
    let env = workflow::read_envelope(pdf)?;
    let count = env.documents.len();
    let entry = env.documents.get(index).cloned().ok_or_else(|| {
        if count == 0 {
            wf("this envelope has no document index: its PDF is one document")
        } else {
            wf(format!(
                "there is no document {} in this envelope, which has {count}",
                index + 1
            ))
        }
    })?;
    let mut doc = Document::load_mem(pdf)
        .map_err(|e| SignPdfError::Pades(format!("cannot parse PDF: {e}")))?;
    let pages: Vec<ObjectId> = doc.page_iter().collect();
    let range = entry.pages();
    let keep = pages
        .get(range.start as usize..range.end as usize)
        .ok_or_else(|| {
            wf(format!(
                "the PDF has {} pages, fewer than its document index says",
                pages.len()
            ))
        })?
        .to_vec();

    let mut next_id = doc.objects.keys().map(|k| k.0).max().unwrap_or(0);
    let mut new_id = || {
        next_id += 1;
        (next_id, 0)
    };
    let pages_id = new_id();
    let catalog_id = new_id();

    let banner = banner_lines(&env, index, &entry);
    for (k, page) in keep.iter().enumerate() {
        let mut dict = standalone_page(&doc, *page, pages_id);
        fix_annotations(&mut doc, &mut dict);
        if k == 0 {
            add_banner(&mut doc, &mut dict, &banner, &mut new_id);
        }
        doc.objects.insert(*page, Object::Dictionary(dict));
    }

    let mut tree = Dictionary::new();
    tree.set("Type", Object::Name(b"Pages".to_vec()));
    tree.set("Count", keep.len() as i64);
    tree.set(
        "Kids",
        Object::Array(keep.iter().map(|p| Object::Reference(*p)).collect()),
    );
    doc.objects.insert(pages_id, Object::Dictionary(tree));
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    doc.objects.insert(catalog_id, Object::Dictionary(catalog));

    let mut seed = format!("signpdf-convenience-copy|{index}|").into_bytes();
    seed.extend_from_slice(sha256_hex(pdf).as_bytes());
    let id = hex::decode(&sha256_hex(&seed)[..32]).unwrap_or_default();
    doc.trailer = Dictionary::new();
    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::String(id.clone(), StringFormat::Hexadecimal),
            Object::String(id, StringFormat::Hexadecimal),
        ]),
    );
    doc.objects
        .retain(|_, o| !matches!(o.type_name(), Ok(t) if t == b"ObjStm" || t == b"XRef"));
    // Nothing the copy keeps may lead to the other documents: a reference to a page it does not
    // hold, or to the envelope's page tree or catalog, becomes null (an annotation's `/P`, a
    // link's destination), so those pages and everything they draw stay out of the file.
    let kept: HashSet<ObjectId> = keep.iter().copied().collect();
    let cut: HashSet<ObjectId> = doc
        .objects
        .iter()
        .filter(|(id, o)| {
            let kind = o.as_dict().ok().and_then(|d| d.get_type().ok());
            match kind {
                Some(b"Page") => !kept.contains(id),
                Some(b"Pages") => **id != pages_id,
                Some(b"Catalog") => **id != catalog_id,
                _ => false,
            }
        })
        .map(|(id, _)| *id)
        .chain(pages.iter().filter(|p| !kept.contains(p)).copied())
        .collect();
    for obj in doc.objects.values_mut() {
        each_reference_mut(obj, |r| {
            if matches!(r, Object::Reference(id) if cut.contains(id)) {
                *r = Object::Null;
            }
        });
    }
    prune(&mut doc);
    doc.max_id = doc.objects.keys().map(|k| k.0).max().unwrap_or(0);
    doc.reference_table = Xref::new(0, XrefType::CrossReferenceTable);
    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| SignPdfError::Pades(format!("cannot write the copy: {e}")))?;
    Ok(out)
}

/// The file name for a convenience copy of `document`: its name without a `.pdf` ending, with
/// the characters file systems refuse replaced, and `(convenience copy - verify the combined
/// file).pdf` after it.
pub fn convenience_copy_name(document: &EnvelopeDocument) -> String {
    let name = document.name.trim();
    let stem = match name.len().checked_sub(4) {
        Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(".pdf") => {
            &name[..cut]
        }
        _ => name,
    };
    let stem: String = stem
        .chars()
        .map(|c| {
            if c.is_control()
                || is_bidi_control(c)
                || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let stem = stem.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let stem = if stem.is_empty() { "document" } else { stem };
    format!("{stem} (convenience copy - verify the combined file).pdf")
}

/// The banner's two lines.
fn banner_lines(env: &Envelope, index: usize, entry: &EnvelopeDocument) -> [String; 2] {
    [
        "Convenience copy - not the signed original. Verify the combined PDF of the envelope."
            .to_string(),
        format!(
            "Document {} of {}: {} - SignPDF envelope {}",
            index + 1,
            env.documents.len(),
            entry.name,
            env.envelope_id
        ),
    ]
}

/// Replace each form widget on the page by a read-only stamp drawing the widget's appearance
/// (its current state's), so the copy shows what the envelope shows without carrying fields or
/// signatures; a widget that draws nothing is dropped.
fn fix_annotations(doc: &mut Document, page: &mut Dictionary) {
    let list = page
        .get(b"Annots")
        .ok()
        .and_then(|a| array_of(doc, a))
        .cloned()
        .unwrap_or_default();
    let mut kept = Vec::with_capacity(list.len());
    for a in list {
        let (id, dict) = match &a {
            Object::Reference(id) => match doc.get_dictionary(*id) {
                Ok(d) => (Some(*id), d.clone()),
                Err(_) => continue,
            },
            Object::Dictionary(d) => (None, d.clone()),
            _ => continue,
        };
        if !matches!(dict.get(b"Subtype"), Ok(Object::Name(s)) if s == b"Widget") {
            kept.push(a);
            continue;
        }
        let Some(stamp) = widget_as_stamp(doc, &dict) else {
            continue;
        };
        match id {
            Some(id) => {
                doc.objects.insert(id, Object::Dictionary(stamp));
                kept.push(a);
            }
            None => kept.push(Object::Dictionary(stamp)),
        }
    }
    if kept.is_empty() {
        page.remove(b"Annots");
    } else {
        page.set("Annots", Object::Array(kept));
    }
}

/// A read-only stamp drawing `widget`'s normal appearance, or `None` when it draws nothing.
fn widget_as_stamp(doc: &Document, widget: &Dictionary) -> Option<Dictionary> {
    let rect = widget.get(b"Rect").ok().and_then(|r| array_of(doc, r))?;
    let nums: Vec<f32> = rect
        .iter()
        .filter_map(|n| match deref(doc, n)? {
            Object::Integer(i) => Some(*i as f32),
            Object::Real(r) => Some(*r),
            _ => None,
        })
        .collect();
    if nums.len() != 4 || nums[0] == nums[2] || nums[1] == nums[3] {
        return None;
    }
    let normal = widget
        .get(b"AP")
        .ok()
        .and_then(|ap| dict_of(doc, ap))
        .and_then(|ap| ap.get(b"N").ok())?;
    let appearance = match normal {
        Object::Reference(id) if doc.get_object(*id).is_ok_and(|o| o.as_stream().is_ok()) => {
            Object::Reference(*id)
        }
        other => {
            // A dictionary of states (check boxes, radio buttons): the one `/AS` selects.
            let states = dict_of(doc, other)?;
            let state = widget.get(b"AS").ok().and_then(|s| s.as_name().ok())?;
            match states.get(state).ok()? {
                Object::Reference(id) => Object::Reference(*id),
                _ => return None,
            }
        }
    };
    let mut stamp = Dictionary::new();
    stamp.set("Type", Object::Name(b"Annot".to_vec()));
    stamp.set("Subtype", Object::Name(b"Stamp".to_vec()));
    stamp.set("Rect", Object::Array(rect.clone()));
    stamp.set("F", FIXED_ANNOTATION);
    let mut ap = Dictionary::new();
    ap.set("N", appearance);
    stamp.set("AP", Object::Dictionary(ap));
    if let Ok(contents) = widget.get(b"TU").or_else(|_| widget.get(b"T")) {
        stamp.set("Contents", contents.clone());
    }
    Some(stamp)
}

fn number(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

/// A normalised box `[x1, y1, x2, y2]` from a page attribute.
fn page_box(doc: &Document, page: &Dictionary, key: &[u8]) -> Option<[f32; 4]> {
    let a = page.get(key).ok().and_then(|b| array_of(doc, b))?;
    let v: Vec<f32> = a
        .iter()
        .filter_map(|n| deref(doc, n).and_then(number))
        .collect();
    if v.len() != 4 || v.iter().any(|n| !n.is_finite()) {
        return None;
    }
    Some([
        v[0].min(v[2]),
        v[1].min(v[3]),
        v[0].max(v[2]),
        v[1].max(v[3]),
    ])
}

fn box_object(b: [f32; 4]) -> Object {
    Object::Array(b.iter().map(|n| Object::Real(*n)).collect())
}

/// Add a banner strip above the page as it is shown (its rotation applied): the visible area
/// grows by [`BANNER_HEIGHT`] on that side, so the banner covers nothing of the page.
fn add_banner(
    doc: &mut Document,
    page: &mut Dictionary,
    lines: &[String; 2],
    new_id: &mut impl FnMut() -> ObjectId,
) {
    let media = page_box(doc, page, b"MediaBox").unwrap_or([0.0, 0.0, 612.0, 792.0]);
    let crop = page_box(doc, page, b"CropBox")
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
    let rotate = match page.get(b"Rotate").ok().and_then(|r| deref(doc, r)) {
        Some(Object::Integer(r)) if r % 90 == 0 => r.rem_euclid(360),
        _ => 0,
    };
    let h = BANNER_HEIGHT;
    let [x1, y1, x2, y2] = crop;
    // The visible box grown on the side shown at the top, and the matrix from the strip's own
    // frame (origin at the shown bottom-left of the grown box, x to the right, y up) to user
    // space.
    let (grown, matrix) = match rotate {
        90 => {
            let g = [x1 - h, y1, x2, y2];
            (g, [0.0, 1.0, -1.0, 0.0, g[2], g[1]])
        }
        180 => {
            let g = [x1, y1 - h, x2, y2];
            (g, [-1.0, 0.0, 0.0, -1.0, g[2], g[3]])
        }
        270 => {
            let g = [x1, y1, x2 + h, y2];
            (g, [0.0, -1.0, 1.0, 0.0, g[0], g[3]])
        }
        _ => {
            let g = [x1, y1, x2, y2 + h];
            (g, [1.0, 0.0, 0.0, 1.0, g[0], g[1]])
        }
    };
    let (width, height) = if rotate == 90 || rotate == 270 {
        (grown[3] - grown[1], grown[2] - grown[0])
    } else {
        (grown[2] - grown[0], grown[3] - grown[1])
    };
    page.set("CropBox", box_object(grown));
    page.set(
        "MediaBox",
        box_object([
            media[0].min(grown[0]),
            media[1].min(grown[1]),
            media[2].max(grown[2]),
            media[3].max(grown[3]),
        ]),
    );

    let pad = 6.0;
    let fmt = |n: f32| {
        if n == n.trunc() && n.abs() < 1e9 {
            format!("{}", n as i64)
        } else {
            format!("{n:.3}")
        }
    };
    let mut ops = String::from("Q\nq\n");
    ops.push_str(&format!(
        "{} cm\n",
        matrix.iter().map(|n| fmt(*n)).collect::<Vec<_>>().join(" ")
    ));
    ops.push_str(&format!(
        "1 0.96 0.78 rg 0 {} {} {} re f\n0.55 0.45 0.1 RG 0.75 w 0 {} m {} {} l S\n0.15 0.1 0 rg\n",
        fmt(height - h),
        fmt(width),
        fmt(h),
        fmt(height - h),
        fmt(width),
        fmt(height - h),
    ));
    for (i, line) in lines.iter().enumerate() {
        let text: String = line.chars().map(pades::drawable).collect();
        let size = pades::fit_size(&text, 9.0, (width - 2.0 * pad).max(1.0));
        let y = height - 12.5 - 11.0 * i as f32;
        ops.push_str(&format!(
            "BT /{BANNER_FONT} {} Tf {} {} Td ({}) Tj ET\n",
            fmt(size),
            fmt(pad),
            fmt(y),
            pades::winansi_literal(&text)
        ));
    }
    ops.push_str("Q\n");

    // The page's own content runs inside `q ... Q`, so that it cannot leave a transformation or a
    // clip that moves or hides the banner.
    let open = new_id();
    doc.objects.insert(
        open,
        Object::Stream(Stream::new(Dictionary::new(), b"q\n".to_vec())),
    );
    let close = new_id();
    doc.objects.insert(
        close,
        Object::Stream(Stream::new(Dictionary::new(), ops.into_bytes())),
    );
    let mut contents = vec![Object::Reference(open)];
    match page
        .get(b"Contents")
        .ok()
        .and_then(|c| deref(doc, c).cloned())
    {
        Some(Object::Array(a)) => contents.extend(a),
        Some(Object::Stream(_)) => {
            if let Ok(c) = page.get(b"Contents") {
                contents.push(c.clone());
            }
        }
        _ => {}
    }
    contents.push(Object::Reference(close));
    page.set("Contents", Object::Array(contents));

    // The banner's font, in a copy of the page's resources.
    let mut resources = page
        .get(b"Resources")
        .ok()
        .and_then(|r| dict_of(doc, r))
        .cloned()
        .unwrap_or_default();
    let mut fonts = resources
        .get(b"Font")
        .ok()
        .and_then(|f| dict_of(doc, f))
        .cloned()
        .unwrap_or_default();
    let mut font = Dictionary::new();
    font.set("Type", Object::Name(b"Font".to_vec()));
    font.set("Subtype", Object::Name(b"Type1".to_vec()));
    font.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
    font.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
    fonts.set(BANNER_FONT, Object::Dictionary(font));
    resources.set("Font", Object::Dictionary(fonts));
    page.set("Resources", Object::Dictionary(resources));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, first: u32, count: u32) -> EnvelopeDocument {
        EnvelopeDocument {
            name: name.into(),
            first_page: first,
            page_count: count,
            source_digest: "ab".repeat(32),
        }
    }

    #[test]
    fn an_index_must_cover_every_page_in_order() {
        let ok = [entry("A", 0, 2), entry("B", 2, 1)];
        assert_eq!(check_index(&ok, 3), Ok(()));
        assert_eq!(check_index(&[], 7), Ok(()));
        for (index, pages, why) in [
            (vec![entry("A", 0, 2), entry("B", 2, 1)], 4, "covers 3"),
            (vec![entry("A", 1, 2)], 3, "page index 1"),
            (vec![entry("A", 0, 1), entry("B", 2, 1)], 3, "page index 2"),
            (vec![entry("A", 0, 2), entry("B", 1, 2)], 3, "page index 1"),
            (vec![entry("A", 0, 0), entry("B", 0, 3)], 3, "no pages"),
            (vec![entry(" ", 0, 3)], 3, "needs a name"),
            (vec![entry("A\nB", 0, 3)], 3, "control character"),
            (
                vec![entry("A\u{202E}fdp.exe", 0, 3)],
                3,
                "control character",
            ),
            (
                vec![entry("A", 0, u32::MAX), entry("B", u32::MAX, 2)],
                3,
                "",
            ),
        ] {
            let err = check_index(&index, pages).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
        let mut bad = entry("A", 0, 3);
        bad.source_digest = "AB".repeat(32);
        assert!(check_index(&[bad], 3).unwrap_err().contains("hex"));
        let many: Vec<_> = (0..=MAX_DOCUMENTS as u32)
            .map(|i| entry("D", i, 1))
            .collect();
        assert!(check_index(&many, many.len() as u32)
            .unwrap_err()
            .contains("at most"));
    }

    #[test]
    fn names_are_checked() {
        assert!(check_name("Schedule A - fees.pdf").is_ok());
        assert!(check_name("Contrat de bail, annexe 2 (signée).pdf").is_ok());
        assert!(check_name(&"x".repeat(MAX_DOCUMENT_NAME_CHARS)).is_ok());
        assert!(check_name(&"x".repeat(MAX_DOCUMENT_NAME_CHARS + 1)).is_err());
        for bad in ["", "   ", "a\tb", "a\u{0}b", "a\u{200F}b", "a\u{2066}b"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_size_limit_is_50_mib() {
        assert!(check_size(MAX_ENVELOPE_BYTES, "x").is_ok());
        let err = check_size(MAX_ENVELOPE_BYTES + 1, "the documents together are").unwrap_err();
        assert!(matches!(err, SignPdfError::TooLarge(_)), "{err}");
        assert!(err.to_string().contains("50 MB"), "{err}");
    }

    #[test]
    fn convenience_copy_names_say_what_they_are() {
        assert_eq!(
            convenience_copy_name(&entry("Schedule A.PDF", 0, 1)),
            "Schedule A (convenience copy - verify the combined file).pdf"
        );
        assert_eq!(
            convenience_copy_name(&entry("a/b:c?.pdf", 0, 1)),
            "a_b_c_ (convenience copy - verify the combined file).pdf"
        );
        assert_eq!(
            convenience_copy_name(&entry("...", 0, 1)),
            "document (convenience copy - verify the combined file).pdf"
        );
        assert_eq!(
            convenience_copy_name(&entry("Annexe é.pdf", 0, 1)),
            "Annexe é (convenience copy - verify the combined file).pdf"
        );
    }

    #[test]
    fn dangling_references_become_null() {
        let mut doc = Document::with_version("1.7");
        doc.objects.insert(
            (5, 0),
            Object::Array(vec![Object::Reference((5, 0)), Object::Reference((9, 0))]),
        );
        let mut next = 100;
        renumber(&mut doc, &mut next).unwrap();
        assert_eq!(next, 101);
        assert_eq!(
            doc.objects[&(100, 0)],
            Object::Array(vec![Object::Reference((100, 0)), Object::Null])
        );
    }

    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        let mut o = Object::Reference((1, 0));
        for _ in 0..200_000 {
            o = Object::Array(vec![o]);
        }
        let mut found = Vec::new();
        references(&o, &mut found);
        assert_eq!(found, vec![(1, 0)]);
        each_reference_mut(&mut o, |r| *r = Object::Null);
        // Dropping a deeply nested value recurses in Rust's own drop glue: unwind it by hand.
        let mut o = o;
        while let Object::Array(mut a) = o {
            o = a.pop().unwrap_or(Object::Null);
        }
        assert_eq!(o, Object::Null);
    }
}
