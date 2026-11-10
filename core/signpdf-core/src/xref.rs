//! Cross-reference sections read from the bytes, not through lopdf.
//!
//! The increment audits ([`crate::pades::audit_increment`], [`crate::pades::audit_ltv_increment`])
//! compare two lopdf parses of a document. lopdf 0.42 reads a cross-reference section differently
//! from PDF viewers in ways that matter to that comparison: it ignores free entries, it keeps the
//! last of two entries for one object number where viewers keep the first, and it reads hybrid
//! sections in another order (docs/SECURITY_REVIEW_2026-10-27.md, finding 1). So the audits no
//! longer trust lopdf's reading of what an increment defines:
//!
//! * [`read_increments`] parses every increment of an audited span from its bytes and accepts
//!   only the form SignPDF writes: one classic table per increment, chained by `/Prev`, with
//!   in-use entries only (and the conventional `0 65535 f` head), each object number once, each
//!   entry pointing at the `N G obj` of that number inside the increment, and nothing in the
//!   increment but those objects and the table. For such an increment every reader resolves each
//!   listed number to the same bytes.
//! * [`viewer_xref`] reads a revision's cross-reference chain the way pdf.js does (the first entry
//!   seen for a number wins, free entries included), so the audit can check that an object an
//!   increment rewrites was defined the same way for viewers and for the engine before.
//!   [`object_header_at`] finds an entry's object the way readers do: past the whitespace and
//!   comments they all skip at the offset, and nothing else.
//! * Two entries alike are not enough: lopdf files every object under the number of the header
//!   it finds, so another entry can hand it a second copy of an object, and it fills an object it
//!   cannot read from any object stream that lists it. [`object_header_number_at`] finds the
//!   entries that lead to a copy, and the audit checks that lopdf's copy of every object it
//!   compares is the one the object's own entry leads to (`pades::EntryReader`).

use lopdf::{Dictionary, Object, ObjectId, StringFormat};
use std::collections::{HashMap, HashSet, VecDeque};

/// Nesting allowed in the objects parsed here (they are the engine's own, or trailer and
/// cross-reference stream dictionaries).
const MAX_DEPTH: usize = 32;

/// Increments followed back from the end of a span, at most (each one is checked to lie after
/// the previous one, so the walk ends anyway; this bounds the work on a hostile file).
const MAX_INCREMENTS: usize = 256;

fn is_ws(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_ws(b) && !is_delim(b)
}

/// A cursor over PDF bytes that parses direct objects into lopdf [`Object`]s.
///
/// Strict mode (the engine's own increments) refuses comments; lenient mode (reading a previous
/// revision the way a viewer does) skips them as whitespace.
struct Lexer<'a> {
    buf: &'a [u8],
    pos: usize,
    lenient: bool,
}

impl<'a> Lexer<'a> {
    fn new(buf: &'a [u8], pos: usize, lenient: bool) -> Self {
        Lexer { buf, pos, lenient }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn at(&self, s: &[u8]) -> bool {
        self.buf.get(self.pos..).is_some_and(|b| b.starts_with(s))
    }

    /// Skip whitespace (and comments, when lenient). A comment in strict mode is an error.
    fn skip_ws(&mut self) -> Result<(), String> {
        while let Some(b) = self.peek() {
            if is_ws(b) {
                self.pos += 1;
            } else if b == b'%' {
                if !self.lenient {
                    return Err(format!("comment at byte {}", self.pos));
                }
                while let Some(c) = self.peek() {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// The keyword `kw` at the cursor, followed by a non-regular byte (or the end).
    fn keyword(&mut self, kw: &[u8]) -> bool {
        if self.at(kw)
            && self
                .buf
                .get(self.pos + kw.len())
                .is_none_or(|b| !is_regular(*b))
        {
            self.pos += kw.len();
            true
        } else {
            false
        }
    }

    /// One end of line: `\r\n`, `\n` or `\r`.
    fn eol(&mut self) -> bool {
        if self.at(b"\r\n") {
            self.pos += 2;
            true
        } else if matches!(self.peek(), Some(b'\n' | b'\r')) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// An unsigned decimal integer.
    fn uint(&mut self) -> Option<u64> {
        let start = self.pos;
        let mut v: u64 = 0;
        while let Some(b) = self.peek().filter(u8::is_ascii_digit) {
            v = v.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
            self.pos += 1;
        }
        (self.pos > start).then_some(v)
    }

    /// A direct object (a reference `N G R` included).
    fn object(&mut self, depth: usize) -> Result<Object, String> {
        if depth > MAX_DEPTH {
            return Err("objects nested too deeply".into());
        }
        self.skip_ws()?;
        let start = self.pos;
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of data".to_string())?;
        match b {
            b'<' if self.at(b"<<") => {
                self.pos += 2;
                let mut d = Dictionary::new();
                loop {
                    self.skip_ws()?;
                    if self.at(b">>") {
                        self.pos += 2;
                        return Ok(Object::Dictionary(d));
                    }
                    let key = match self.object(depth + 1)? {
                        Object::Name(n) => n,
                        _ => return Err(format!("dictionary key is not a name at byte {start}")),
                    };
                    let value = self.object(depth + 1)?;
                    d.set(key, value);
                }
            }
            b'<' => {
                self.pos += 1;
                let mut digits = Vec::new();
                loop {
                    match self.peek() {
                        Some(b'>') => {
                            self.pos += 1;
                            break;
                        }
                        Some(c) if c.is_ascii_hexdigit() => {
                            digits.push(c);
                            self.pos += 1;
                        }
                        Some(c) if is_ws(c) => self.pos += 1,
                        _ => return Err(format!("bad hex string at byte {start}")),
                    }
                }
                if digits.len() % 2 == 1 {
                    digits.push(b'0');
                }
                let bytes = digits
                    .chunks(2)
                    .map(|p| {
                        let h = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
                        h(p[0]) << 4 | h(p[1])
                    })
                    .collect();
                Ok(Object::String(bytes, StringFormat::Hexadecimal))
            }
            b'(' => self
                .literal_string()
                .map(|s| Object::String(s, StringFormat::Literal)),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws()?;
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        return Ok(Object::Array(items));
                    }
                    items.push(self.object(depth + 1)?);
                }
            }
            b'/' => {
                self.pos += 1;
                let mut name = Vec::new();
                while let Some(c) = self.peek().filter(|c| is_regular(*c)) {
                    if c == b'#' {
                        let hex = self
                            .buf
                            .get(self.pos + 1..self.pos + 3)
                            .and_then(|h| std::str::from_utf8(h).ok())
                            .and_then(|h| u8::from_str_radix(h, 16).ok())
                            .ok_or_else(|| format!("bad name escape at byte {}", self.pos))?;
                        name.push(hex);
                        self.pos += 3;
                    } else {
                        name.push(c);
                        self.pos += 1;
                    }
                }
                Ok(Object::Name(name))
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.number_or_reference(),
            _ if self.keyword(b"true") => Ok(Object::Boolean(true)),
            _ if self.keyword(b"false") => Ok(Object::Boolean(false)),
            _ if self.keyword(b"null") => Ok(Object::Null),
            _ => Err(format!("unexpected byte 0x{b:02x} at byte {start}")),
        }
    }

    fn literal_string(&mut self) -> Result<Vec<u8>, String> {
        let start = self.pos;
        self.pos += 1;
        let mut out = Vec::new();
        let mut depth = 1usize;
        loop {
            let c = self
                .peek()
                .ok_or_else(|| format!("unterminated string at byte {start}"))?;
            self.pos += 1;
            match c {
                b'(' => {
                    depth += 1;
                    out.push(c);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(c);
                }
                b'\\' => {
                    let e = self
                        .peek()
                        .ok_or_else(|| format!("unterminated string at byte {start}"))?;
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push((v & 0xff) as u8);
                        }
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        other => out.push(other),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn number_or_reference(&mut self) -> Result<Object, String> {
        let start = self.pos;
        let mut end = self.pos;
        if matches!(self.buf.get(end), Some(b'+' | b'-')) {
            end += 1;
        }
        let digits_start = end;
        while self.buf.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        let int_digits = end - digits_start;
        let mut is_real = false;
        if self.buf.get(end) == Some(&b'.') {
            is_real = true;
            end += 1;
            while self.buf.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }
        if end == digits_start || (is_real && end == digits_start + 1 && int_digits == 0) {
            return Err(format!("bad number at byte {start}"));
        }
        if self.buf.get(end).is_some_and(|b| is_regular(*b)) {
            return Err(format!("bad number at byte {start}"));
        }
        let text = std::str::from_utf8(&self.buf[start..end]).map_err(|e| e.to_string())?;
        self.pos = end;
        if is_real {
            return text
                .parse::<f32>()
                .map(Object::Real)
                .map_err(|_| format!("bad number at byte {start}"));
        }
        let n: i64 = text
            .parse()
            .map_err(|_| format!("bad number at byte {start}"))?;
        // `N G R`: look ahead without consuming unless the whole reference is there.
        let save = self.pos;
        if n >= 0 && !text.starts_with('+') {
            let _ = self.skip_ws();
            if let Some(g) = self.uint() {
                if self.buf.get(self.pos).is_some_and(|b| !is_regular(*b)) {
                    let _ = self.skip_ws();
                    if self.keyword(b"R") {
                        let num = u32::try_from(n).map_err(|_| "object number too large")?;
                        let gen = u16::try_from(g).map_err(|_| "generation too large")?;
                        return Ok(Object::Reference((num, gen)));
                    }
                }
            }
        }
        self.pos = save;
        Ok(Object::Integer(n))
    }
}

/// The value of the last `startxref` of `pdf`: where the engine continues the chain (it writes
/// this as `/Prev` of the increment it appends).
pub(crate) fn last_startxref(pdf: &[u8]) -> Option<usize> {
    let needle = b"startxref";
    let pos = pdf.windows(needle.len()).rposition(|w| w == needle)?;
    let mut lx = Lexer::new(pdf, pos + needle.len(), false);
    while lx.peek().is_some_and(is_ws) {
        lx.pos += 1;
    }
    lx.uint().and_then(|v| usize::try_from(v).ok())
}

/// An in-use entry of an increment's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Listed {
    pub num: u32,
    pub gen: u16,
    pub offset: usize,
}

/// One increment in SignPDF's form.
#[derive(Debug, Clone)]
pub(crate) struct IncrementXref {
    /// Its in-use entries, in table order.
    pub entries: Vec<Listed>,
    /// Its trailer dictionary.
    pub trailer: Dictionary,
}

/// One classic table, its trailer, and the end of the increment (after `%%EOF`).
struct Section {
    entries: Vec<Listed>,
    trailer: Dictionary,
    end: usize,
}

/// Parse the classic table at `x` in SignPDF's form, up to and including its `%%EOF`.
fn strict_section(pdf: &[u8], x: usize) -> Result<Section, String> {
    let mut lx = Lexer::new(pdf, x, false);
    if !lx.keyword(b"xref") || !lx.eol() {
        return Err(format!("no cross-reference table at byte {x}"));
    }
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut next_min: u64 = 0;
    loop {
        if lx.keyword(b"trailer") {
            break;
        }
        let first = lx.uint().ok_or("bad subsection header")?;
        if !lx.at(b" ") {
            return Err("bad subsection header".into());
        }
        lx.pos += 1;
        let count = lx.uint().ok_or("bad subsection header")?;
        if !lx.eol() {
            return Err("bad subsection header".into());
        }
        if count == 0 || first < next_min {
            return Err("subsections are empty, out of order or overlapping".into());
        }
        next_min = first.checked_add(count).ok_or("bad subsection header")?;
        for i in 0..count {
            let e = pdf
                .get(lx.pos..lx.pos + 20)
                .ok_or("cross-reference table ends early")?;
            let digits = |r: std::ops::Range<usize>| -> Option<u64> {
                let s = &e[r];
                s.iter()
                    .all(u8::is_ascii_digit)
                    .then(|| std::str::from_utf8(s).ok()?.parse().ok())
                    .flatten()
            };
            let (Some(offset), Some(gen)) = (digits(0..10), digits(11..16)) else {
                return Err("bad cross-reference entry".into());
            };
            if e[10] != b' ' || e[16] != b' ' || !matches!(&e[18..20], b" \n" | b" \r" | b"\r\n") {
                return Err("bad cross-reference entry".into());
            }
            let num = u32::try_from(first + i).map_err(|_| "object number too large")?;
            if !seen.insert(num) {
                return Err(format!("object {num} is listed twice"));
            }
            match e[17] {
                b'n' => {
                    if num == 0 {
                        return Err("object 0 is listed as in use".into());
                    }
                    let gen = u16::try_from(gen).map_err(|_| "bad generation")?;
                    let offset = usize::try_from(offset).map_err(|_| "bad offset")?;
                    entries.push(Listed { num, gen, offset });
                }
                b'f' if num == 0 && offset == 0 && gen == 65535 => {}
                b'f' => return Err(format!("object {num} is listed as free")),
                _ => return Err("bad cross-reference entry".into()),
            }
            lx.pos += 20;
        }
    }
    lx.skip_ws()?;
    let trailer = match lx.object(0)? {
        Object::Dictionary(d) => d,
        _ => return Err("the trailer is not a dictionary".into()),
    };
    lx.skip_ws()?;
    if !lx.keyword(b"startxref") || !lx.eol() {
        return Err("no startxref after the trailer".into());
    }
    if lx.uint() != Some(x as u64) || !lx.eol() {
        return Err("startxref does not point at this table".into());
    }
    if !lx.at(b"%%EOF") {
        return Err("no %%EOF after startxref".into());
    }
    lx.pos += 5;
    if lx.pos < pdf.len() && !lx.eol() {
        return Err("no end of line after %%EOF".into());
    }
    Ok(Section {
        entries,
        trailer,
        end: lx.pos,
    })
}

/// The objects written between `start` and `end` (an increment's body), each `N G obj ... endobj`
/// separated only by whitespace: their `(offset, number, generation)`. Streams must give their
/// `/Length` directly.
fn strict_objects(pdf: &[u8], start: usize, end: usize) -> Result<Vec<Listed>, String> {
    let body = &pdf[..end];
    let mut lx = Lexer::new(body, start, false);
    let mut out = Vec::new();
    loop {
        lx.skip_ws()?;
        if lx.pos >= end {
            return Ok(out);
        }
        let offset = lx.pos;
        let header = (|| {
            let num = lx.uint()?;
            lx.at(b" ").then(|| lx.pos += 1)?;
            let gen = lx.uint()?;
            lx.at(b" ").then(|| lx.pos += 1)?;
            lx.keyword(b"obj").then_some((num, gen))
        })();
        let Some((num, gen)) =
            header.and_then(|(n, g)| Some((u32::try_from(n).ok()?, u16::try_from(g).ok()?)))
        else {
            return Err(format!("unexpected bytes at {offset} (not an object)"));
        };
        let value = lx.object(0)?;
        lx.skip_ws()?;
        if lx.keyword(b"stream") {
            let Object::Dictionary(d) = &value else {
                return Err(format!("object {num} has a stream but no dictionary"));
            };
            let len = match d.get(b"Length").map(offset_of) {
                Ok(Ok(n)) => n,
                _ => return Err(format!("stream of object {num} has no direct /Length")),
            };
            if !lx.at(b"\r\n") && !lx.at(b"\n") {
                return Err(format!(
                    "stream of object {num} does not start on a new line"
                ));
            }
            lx.eol();
            lx.pos = lx
                .pos
                .checked_add(len)
                .filter(|p| *p <= end)
                .ok_or_else(|| format!("stream of object {num} runs past the increment"))?;
            lx.eol();
            if !lx.keyword(b"endstream") {
                return Err(format!(
                    "stream of object {num} does not end at its /Length"
                ));
            }
            lx.skip_ws()?;
        }
        if !lx.keyword(b"endobj") {
            return Err(format!("object {num} does not end with endobj"));
        }
        out.push(Listed { num, gen, offset });
    }
}

/// Every increment between `before` (a revision) and `after` (which extends it), parsed and
/// checked from the bytes: each must be in the form SignPDF writes (see the module comment).
/// Returns them in file order, or why the span is not in that form.
pub(crate) fn read_increments(before: &[u8], after: &[u8]) -> Result<Vec<IncrementXref>, String> {
    if after.len() <= before.len() || !after.starts_with(before) {
        return Err("the revision does not extend the previous one".into());
    }
    let prev_start = last_startxref(before).ok_or("the previous revision has no startxref")?;
    let mut x = last_startxref(after).ok_or("no startxref at the end")?;
    // Walk back from the end to the previous revision, one table at a time.
    let mut sections: Vec<(usize, Section)> = Vec::new();
    loop {
        if sections.len() >= MAX_INCREMENTS {
            return Err("too many increments".into());
        }
        if x < before.len() || sections.last().is_some_and(|(later, _)| x >= *later) {
            return Err(format!(
                "a cross-reference table at byte {x} is not inside the new increments, in order"
            ));
        }
        let section = strict_section(after, x)?;
        let prev = match section.trailer.get(b"Prev").map(offset_of) {
            Ok(Ok(p)) => p,
            _ => return Err("a trailer has no /Prev".into()),
        };
        sections.push((x, section));
        if prev == prev_start {
            break;
        }
        x = prev;
    }
    sections.reverse();
    let mut out = Vec::with_capacity(sections.len());
    let mut start = before.len();
    for (x, s) in sections {
        if x < start {
            return Err(format!(
                "the cross-reference table at byte {x} overlaps another increment"
            ));
        }
        let mut objects = strict_objects(after, start, x)?;
        let mut listed = s.entries.clone();
        objects.sort_by_key(|o| o.offset);
        listed.sort_by_key(|o| o.offset);
        if objects != listed {
            return Err(format!(
                "the increment at byte {start} holds objects its cross-reference does not list, \
                 or lists objects it does not hold"
            ));
        }
        if let Some((k, _)) = s
            .trailer
            .iter()
            .find(|(k, _)| !matches!(k.as_slice(), b"Size" | b"Root" | b"Prev" | b"ID" | b"Info"))
        {
            return Err(format!(
                "a trailer carries /{}, which SignPDF never writes",
                String::from_utf8_lossy(k)
            ));
        }
        let max = s.entries.iter().map(|e| e.num).max().unwrap_or(0);
        match s.trailer.get(b"Size") {
            Ok(Object::Integer(n)) if *n > i64::from(max) => {}
            _ => return Err("a trailer's /Size does not cover its entries".into()),
        }
        out.push(IncrementXref {
            entries: s.entries,
            trailer: s.trailer,
        });
        start = s.end;
    }
    if start != after.len() {
        return Err("bytes follow the last increment's %%EOF".into());
    }
    Ok(out)
}

/// A cross-reference entry as a viewer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewerEntry {
    Free,
    InUse { offset: usize, gen: u16 },
    Compressed { stream: u32, index: u32 },
}

/// A revision's cross-reference chain read the way pdf.js reads it: sections from the newest,
/// a hybrid file's `/XRefStm` before its `/Prev`, and for each object number the **first** entry
/// seen, free entries included.
#[derive(Debug, Clone, Default)]
pub(crate) struct ViewerXref {
    pub entries: HashMap<u32, ViewerEntry>,
    /// Every section in the chain was read. When not, an entry can be missing or not be the one
    /// a viewer uses, so callers must not rely on any of them.
    pub complete: bool,
}

impl ViewerXref {
    /// The entry a viewer uses for `num`, if any (pdf.js treats an entry at offset 0 as absent).
    pub fn get(&self, num: u32) -> Option<ViewerEntry> {
        match self.entries.get(&num) {
            Some(ViewerEntry::InUse { offset: 0, .. }) | None => None,
            Some(ViewerEntry::Compressed { stream: 0, .. }) => None,
            Some(e) => Some(*e),
        }
    }

    fn put(&mut self, num: u32, e: ViewerEntry) {
        self.entries.entry(num).or_insert(e);
    }
}

/// Read the chain starting at the section at `start` (see [`ViewerXref`]). `length_of` resolves
/// a cross-reference stream's indirect `/Length`.
pub(crate) fn viewer_xref(
    pdf: &[u8],
    start: usize,
    length_of: &dyn Fn(ObjectId) -> Option<i64>,
) -> ViewerXref {
    let mut out = ViewerXref {
        complete: true,
        ..Default::default()
    };
    let mut queue = VecDeque::from([start]);
    let mut seen = HashSet::new();
    while let Some(pos) = queue.pop_front() {
        if !seen.insert(pos) {
            continue;
        }
        if seen.len() > MAX_INCREMENTS * 4 {
            out.complete = false;
            break;
        }
        match viewer_section(pdf, pos, &mut out, length_of) {
            Ok(next) => queue.extend(next),
            Err(_) => out.complete = false,
        }
    }
    out
}

/// The most bytes a cross-reference stream may inflate to (a table of a million objects at
/// eight bytes a row is 8 MiB).
pub(crate) const MAX_XREF_STREAM_INFLATED: usize = 32 * 1024 * 1024;

/// A byte offset or length written as a PDF integer.
///
/// Checked, never cast with `as`: on 32-bit WebAssembly `as usize` keeps the low 32 bits of a
/// 64-bit value, so the browser verifier would read an offset native verifiers refuse.
fn offset_of(o: &Object) -> Result<usize, String> {
    match o {
        Object::Integer(n) => {
            usize::try_from(*n).map_err(|_| format!("offset {n} is out of range"))
        }
        _ => Err("not an offset".into()),
    }
}

/// Whether `o` holds an indirect reference anywhere inside it.
fn has_reference(o: &Object) -> bool {
    match o {
        Object::Reference(_) => true,
        Object::Array(a) => a.iter().any(has_reference),
        Object::Dictionary(d) => d.iter().any(|(_, v)| has_reference(v)),
        _ => false,
    }
}

/// Read one section at `pos` into `out`; return the sections it points to, in the order pdf.js
/// queues them.
fn viewer_section(
    pdf: &[u8],
    pos: usize,
    out: &mut ViewerXref,
    length_of: &dyn Fn(ObjectId) -> Option<i64>,
) -> Result<Vec<usize>, String> {
    let mut lx = Lexer::new(pdf, pos, true);
    lx.skip_ws()?;
    // `/Prev` or `/XRefStm`: absent, a number, or (as pdf.js reads it) a reference's number.
    // Anything else makes readers part ways (pdf.js then scans the whole file), so it is refused.
    let as_offset = |o: Result<&Object, lopdf::Error>| -> Result<Option<usize>, String> {
        match o {
            Err(_) => Ok(None),
            Ok(Object::Reference((n, _))) => Ok(usize::try_from(*n).ok()),
            Ok(o) => offset_of(o)
                .map(Some)
                .map_err(|_| "a section pointer is not a usable offset".to_string()),
        }
    };
    if lx.keyword(b"xref") {
        fn int(lx: &mut Lexer<'_>) -> Result<u64, String> {
            lx.skip_ws()?;
            lx.uint()
                .ok_or_else(|| "bad cross-reference table".to_string())
        }
        loop {
            lx.skip_ws()?;
            if lx.keyword(b"trailer") {
                break;
            }
            let first = int(&mut lx)?;
            let count = int(&mut lx)?;
            for i in 0..count {
                let offset = int(&mut lx)?;
                let gen = int(&mut lx)?;
                lx.skip_ws()?;
                let free = if lx.keyword(b"f") {
                    true
                } else if lx.keyword(b"n") {
                    false
                } else {
                    return Err("bad cross-reference entry".into());
                };
                // pdf.js renumbers a subsection starting at 1 whose first entry is free from 0;
                // PDFium and lopdf read it as written. Readers disagree, so it is refused.
                if i == 0 && free && first == 1 {
                    return Err("a subsection starting at 1 begins with a free entry".into());
                }
                let num = u32::try_from(first + i).map_err(|_| "object number too large")?;
                let entry = if free {
                    ViewerEntry::Free
                } else {
                    ViewerEntry::InUse {
                        offset: usize::try_from(offset).map_err(|_| "bad offset")?,
                        gen: u16::try_from(gen).map_err(|_| "bad generation")?,
                    }
                };
                out.put(num, entry);
            }
        }
        if matches!(out.entries.get(&0), Some(ViewerEntry::InUse { .. })) {
            return Err("object 0 is in use".into());
        }
        let trailer = match lx.object(0)? {
            Object::Dictionary(d) => d,
            _ => return Err("the trailer is not a dictionary".into()),
        };
        let mut next = Vec::new();
        next.extend(as_offset(trailer.get(b"XRefStm"))?);
        next.extend(as_offset(trailer.get(b"Prev"))?);
        return Ok(next);
    }
    // A cross-reference stream: `N G obj << ... >> stream`.
    let num = lx.uint().ok_or("no cross-reference section")?;
    lx.skip_ws()?;
    lx.uint().ok_or("no cross-reference section")?;
    lx.skip_ws()?;
    if !lx.keyword(b"obj") {
        return Err("no cross-reference section".into());
    }
    let dict = match lx.object(0)? {
        Object::Dictionary(d) => d,
        _ => return Err("bad cross-reference stream".into()),
    };
    lx.skip_ws()?;
    if !lx.keyword(b"stream") || !lx.eol() {
        return Err("bad cross-reference stream".into());
    }
    // pdf.js queues a cross-reference stream's `/XRefStm` before its `/Prev`; lopdf ignores it.
    if dict.has(b"XRefStm") {
        return Err("a cross-reference stream carries /XRefStm".into());
    }
    // pdf.js dereferences these keys; lopdf does not (it would decode with no filter, no
    // predictor, or the default `/Index`). Only direct values are read alike.
    for key in [&b"Filter"[..], b"DecodeParms", b"Index", b"W", b"Size"] {
        if dict.get(key).is_ok_and(has_reference) {
            return Err(format!(
                "a cross-reference stream's /{} is indirect",
                String::from_utf8_lossy(key)
            ));
        }
    }
    let flate = match dict.get(b"Filter") {
        Err(_) => false,
        Ok(Object::Name(n)) if n == b"FlateDecode" => true,
        Ok(Object::Array(a)) if matches!(a.as_slice(), [Object::Name(n)] if n == b"FlateDecode") => {
            true
        }
        Ok(_) => {
            return Err("a cross-reference stream uses a filter other than /FlateDecode".into())
        }
    };
    let len = match dict.get(b"Length") {
        Ok(Object::Integer(n)) => Some(*n),
        Ok(Object::Reference(r)) => length_of(*r),
        _ => None,
    }
    .and_then(|n| usize::try_from(n).ok())
    .ok_or("cross-reference stream without a usable /Length")?;
    let data_start = lx.pos;
    let data = pdf
        .get(data_start..data_start.checked_add(len).ok_or("bad /Length")?)
        .ok_or("cross-reference stream runs past the file")?;
    lx.pos = data_start + len;
    lx.eol();
    if !lx.keyword(b"endstream") {
        return Err(format!(
            "cross-reference stream {num} does not end at its /Length"
        ));
    }
    if flate {
        // Bound the inflated size before lopdf inflates it without a limit. Other inflate errors
        // are left to lopdf, which reads the stream as it always has.
        if let Err(e) =
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, MAX_XREF_STREAM_INFLATED)
        {
            if e.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
                return Err("a cross-reference stream inflates past its limit".into());
            }
        }
    }
    let content = lopdf::Stream::new(dict.clone(), data.to_vec())
        .decompressed_content()
        .map_err(|e| format!("cannot decode cross-reference stream: {e}"))?;
    let ints = |o: Result<&Object, lopdf::Error>| -> Option<Vec<i64>> {
        o.ok()?
            .as_array()
            .ok()?
            .iter()
            .map(|v| v.as_i64().ok())
            .collect()
    };
    let w = ints(dict.get(b"W")).ok_or("cross-reference stream without /W")?;
    let [w0, w1, w2] = <[i64; 3]>::try_from(w.as_slice()).map_err(|_| "bad /W")?;
    if [w0, w1, w2].iter().any(|v| !(0..=8).contains(v)) || w0 + w1 + w2 == 0 {
        return Err("bad /W".into());
    }
    let (w0, w1, w2) = (w0 as usize, w1 as usize, w2 as usize);
    let index = match ints(dict.get(b"Index")) {
        Some(v) => v,
        None if dict.has(b"Index") => return Err("bad /Index".into()),
        None => vec![
            0,
            dict.get(b"Size")
                .and_then(Object::as_i64)
                .map_err(|_| "no /Size")?,
        ],
    };
    if index.len() % 2 != 0 {
        return Err("bad /Index".into());
    }
    let field = |bytes: &[u8]| bytes.iter().fold(0u64, |v, b| v << 8 | u64::from(*b));
    let mut at = 0usize;
    for pair in index.chunks(2) {
        let (first, n) = (pair[0], pair[1]);
        if first < 0 || n < 0 {
            return Err("bad /Index".into());
        }
        for i in 0..n as u64 {
            let row = content
                .get(at..at + w0 + w1 + w2)
                .ok_or("cross-reference stream ends early")?;
            at += w0 + w1 + w2;
            let kind = if w0 == 0 { 1 } else { field(&row[..w0]) };
            let a = field(&row[w0..w0 + w1]);
            let b = field(&row[w0 + w1..]);
            let num = u32::try_from(first as u64 + i).map_err(|_| "object number too large")?;
            let entry = match kind {
                0 => ViewerEntry::Free,
                1 => ViewerEntry::InUse {
                    offset: usize::try_from(a).map_err(|_| "bad offset")?,
                    gen: u16::try_from(b).map_err(|_| "bad generation")?,
                },
                2 => ViewerEntry::Compressed {
                    stream: u32::try_from(a).map_err(|_| "bad object stream")?,
                    index: u32::try_from(b).map_err(|_| "bad index")?,
                },
                _ => return Err("unknown cross-reference entry type".into()),
            };
            out.put(num, entry);
        }
    }
    Ok(as_offset(dict.get(b"Prev"))?.into_iter().collect())
}

/// Whether a reader that fetches the object at `offset` finds `num gen obj` there.
///
/// Readers do not start at the offset's exact byte: before the object number they skip PDF
/// whitespace (NUL, TAB, LF, FF, CR, SPACE) and comments (`%` to the end of the line). pdf.js
/// lexes from the offset (`XRef.fetchUncompressed`, whose `Lexer.getObj` skips both), PDFium
/// moves to the next word (`CPDF_SyntaxParser::GetIndirectObject`, through `ToNextWord`), and
/// lopdf, which the engine parses with, starts the header with `space`
/// (`parser::_indirect_object`). Files rely on it: Microsoft Print to PDF points every entry at
/// the line feed before `N 0 obj`.
///
/// This mirrors that skip and nothing more. After it, the entry's own number and generation must
/// follow, as unsigned decimal integers, then the keyword `obj`. Anything else is an entry that
/// viewers refuse (pdf.js then rebuilds the cross-reference from a scan of the file, PDFium
/// returns no object), so the caller treats the object as ambiguous. Headers that some viewers
/// accept and lopdf does not (a sign, a decimal point, `obj` run into the next word) are not
/// mirrored: they count as a mismatch, which refuses more, never less.
pub(crate) fn object_header_at(pdf: &[u8], offset: usize, num: u32, gen: u16) -> bool {
    let mut lx = Lexer::new(pdf, offset, true);
    lx.skip_ws().is_ok()
        && lx.uint() == Some(u64::from(num))
        && lx.skip_ws().is_ok()
        && lx.uint() == Some(u64::from(gen))
        && lx.skip_ws().is_ok()
        && lx.keyword(b"obj")
}

/// The object number of the `N G obj` lopdf may find at `offset` (past the whitespace and
/// comments of [`object_header_at`]), whatever the number.
///
/// lopdf files an object under the number of the header it finds there, not under the number of
/// the entry that led to it, so an entry can give lopdf a second copy of another object. The
/// audits look for such entries with this, so it errs towards finding a header: `obj` may run
/// into the next word, as lopdf allows.
pub(crate) fn object_header_number_at(pdf: &[u8], offset: usize) -> Option<u32> {
    let mut lx = Lexer::new(pdf, offset, true);
    lx.skip_ws().ok()?;
    let num = u32::try_from(lx.uint()?).ok()?;
    lx.skip_ws().ok()?;
    u16::try_from(lx.uint()?).ok()?;
    lx.skip_ws().ok()?;
    lx.at(b"obj").then_some(num)
}

/// The object numbers an object stream's (decoded) header lists, in order, when the header is
/// read alike by every reader: `header` (the bytes before `/First`) holds exactly `n` pairs of
/// unsigned decimal integers separated by SPACE, TAB, LF, FF or CR, and nothing else.
///
/// Readers split it differently otherwise: viewers lex it (skipping comments and NUL), lopdf
/// splits it at Unicode whitespace and pairs whatever tokens result, so a comment or a stray
/// token shifts its pairs. `None` then, and the caller treats the stream's objects as ambiguous.
pub(crate) fn object_stream_numbers(header: &[u8], n: usize) -> Option<Vec<u32>> {
    let mut tokens = header
        .split(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0c | b'\r'))
        .filter(|t| !t.is_empty());
    let mut numbers = Vec::new();
    for _ in 0..n {
        let mut next = || -> Option<u64> {
            let t = tokens.next()?;
            if !t.iter().all(u8::is_ascii_digit) || t.len() > 10 {
                return None;
            }
            std::str::from_utf8(t).ok()?.parse().ok()
        };
        numbers.push(u32::try_from(next()?).ok()?);
        u32::try_from(next()?).ok()?;
    }
    tokens.next().is_none().then_some(numbers)
}

/// One fuzzing input through every reader of this module (the `xref` fuzz target,
/// `core/fuzz`). `data` is split at a point its first two bytes
/// choose: the part before it is the previous revision, the whole is the revision that extends
/// it. Nothing here may panic, however malformed the bytes.
pub(crate) fn fuzz(data: &[u8]) {
    let cut = match data {
        [a, b, ..] => usize::from(u16::from_le_bytes([*a, *b])) % data.len(),
        _ => 0,
    };
    let _ = read_increments(&data[..cut], data);
    let start = last_startxref(data).unwrap_or(cut);
    let _ = viewer_xref(data, start, &|_| i64::try_from(cut).ok());
    let _ = viewer_xref(data, cut, &|_| None);
    let _ = object_header_number_at(data, cut);
    let _ = object_header_at(data, cut, 1, 0);
    let _ = object_stream_numbers(data, usize::from(data.first().copied().unwrap_or(0) % 8));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fuzz entry takes any bytes, including the module's own valid forms cut anywhere.
    #[test]
    fn the_fuzz_entry_never_panics() {
        let b = base();
        let body = with_increment(&b, &[(40, "<< /A 1 >>"), (41, "(x)")], one_per_line, "");
        for input in [&b""[..], b"x", b"\xff\xff%PDF-1.7", &b, &body] {
            fuzz(input);
        }
        for cut in (0..body.len()).step_by(13) {
            let mut v = body[..cut].to_vec();
            v.extend_from_slice(&body[..body.len() - cut]);
            fuzz(&v);
        }
    }

    /// `body` followed by one increment holding `objects` (number, body) and a table built by
    /// `table` from their offsets.
    fn with_increment(
        body: &[u8],
        objects: &[(u32, &str)],
        table: impl Fn(&[(u32, usize)]) -> String,
        trailer_extra: &str,
    ) -> Vec<u8> {
        let prev = last_startxref(body).unwrap();
        let mut out = body.to_vec();
        let mut offs = Vec::new();
        for (n, b) in objects {
            offs.push((*n, out.len()));
            out.extend_from_slice(format!("{n} 0 obj\n{b}\nendobj\n").as_bytes());
        }
        let x = out.len();
        out.extend_from_slice(
            format!(
                "xref\n{}trailer\n<< /Size 100 /Root 1 0 R /Prev {prev}{trailer_extra} >>\n\
                 startxref\n{x}\n%%EOF\n",
                table(&offs)
            )
            .as_bytes(),
        );
        out
    }

    fn base() -> Vec<u8> {
        crate::container::make_sample_pdf("base")
    }

    fn one_per_line(offs: &[(u32, usize)]) -> String {
        offs.iter()
            .map(|(n, o)| format!("{n} 1\n{o:010} 00000 n \n"))
            .collect()
    }

    #[test]
    fn the_engines_own_form_is_read() {
        let b = base();
        let a = with_increment(&b, &[(40, "<< /A 1 >>"), (41, "(x)")], one_per_line, "");
        let incs = read_increments(&b, &a).unwrap();
        assert_eq!(incs.len(), 1);
        assert_eq!(
            incs[0].entries.iter().map(|e| e.num).collect::<Vec<_>>(),
            vec![40, 41]
        );
        // Two increments chained by /Prev.
        let a2 = with_increment(&a, &[(42, "<< >>")], one_per_line, "");
        assert_eq!(read_increments(&b, &a2).unwrap().len(), 2);
        // The conventional free head is accepted.
        let a3 = with_increment(
            &b,
            &[(1, "<< /Type /Catalog >>")],
            |o| format!("0 2\n0000000000 65535 f \n{:010} 00000 n \n", o[0].1),
            "",
        );
        read_increments(&b, &a3).unwrap();
    }

    #[test]
    fn a_number_listed_twice_is_refused() {
        let b = base();
        let a = with_increment(
            &b,
            &[(40, "<< /A 1 >>"), (41, "<< /A 2 >>")],
            |o| {
                format!(
                    "40 1\n{:010} 00000 n \n40 1\n{:010} 00000 n \n",
                    o[0].1, o[1].1
                )
            },
            "",
        );
        assert!(read_increments(&b, &a).is_err());
    }

    #[test]
    fn a_free_entry_is_refused() {
        let b = base();
        let a = with_increment(
            &b,
            &[(40, "<< /A 1 >>")],
            |o| format!("5 1\n0000000000 00001 f \n40 1\n{:010} 00000 n \n", o[0].1),
            "",
        );
        assert!(read_increments(&b, &a)
            .unwrap_err()
            .contains("listed as free"));
    }

    #[test]
    fn other_forms_are_refused() {
        let b = base();
        // An entry pointing at another object's header.
        let a = with_increment(
            &b,
            &[(40, "<< >>"), (41, "<< >>")],
            |o| format!("40 2\n{:010} 00000 n \n{:010} 00000 n \n", o[1].1, o[0].1),
            "",
        );
        assert!(read_increments(&b, &a).is_err());
        // An object the table does not list.
        let a = with_increment(
            &b,
            &[(40, "<< >>"), (41, "<< >>")],
            |o| format!("40 1\n{:010} 00000 n \n", o[0].1),
            "",
        );
        assert!(read_increments(&b, &a).is_err());
        // A hybrid pointer.
        let a = with_increment(&b, &[(40, "<< >>")], one_per_line, " /XRefStm 0");
        assert!(read_increments(&b, &a).is_err());
        // Bytes after %%EOF.
        let mut a = with_increment(&b, &[(40, "<< >>")], one_per_line, "");
        a.extend_from_slice(b"junk");
        assert!(read_increments(&b, &a).is_err());
        // A stream whose /Length is indirect.
        let a = with_increment(
            &b,
            &[
                (40, "<< /Length 41 0 R >>\nstream\nab\nendstream"),
                (41, "2"),
            ],
            one_per_line,
            "",
        );
        assert!(read_increments(&b, &a).is_err());
        // A comment between objects.
        let mut a = b.clone();
        a.extend_from_slice(b"% note\n");
        let a = with_increment(&a, &[(40, "<< >>")], one_per_line, "");
        assert!(read_increments(&b, &a).is_err());
    }

    #[test]
    fn viewers_keep_the_first_entry_and_free_entries() {
        let b = base();
        let a = with_increment(
            &b,
            &[(40, "<< /A 1 >>"), (41, "<< /A 2 >>")],
            |o| {
                format!(
                    "40 1\n{:010} 00000 n \n40 1\n{:010} 00000 n \n5 1\n0000000000 00001 f \n",
                    o[0].1, o[1].1
                )
            },
            "",
        );
        let v = viewer_xref(&a, last_startxref(&a).unwrap(), &|_| None);
        assert!(v.complete);
        let first = a.windows(8).position(|w| w == b"40 0 obj").unwrap();
        assert_eq!(
            v.get(40),
            Some(ViewerEntry::InUse {
                offset: first,
                gen: 0
            })
        );
        assert_eq!(v.get(5), Some(ViewerEntry::Free));
        // The sample document's own objects are still there, from its first table.
        assert!(matches!(v.get(1), Some(ViewerEntry::InUse { .. })));
    }

    /// `body` followed by object 40 and a cross-reference stream (object 50) listing it, with
    /// `extra` in the stream's dictionary and its rows passed through `encode` (which returns the
    /// stream bytes and any `/Filter` entry).
    fn with_xref_stream(
        body: &[u8],
        extra: &str,
        encode: impl Fn(Vec<u8>) -> (Vec<u8>, &'static str),
    ) -> Vec<u8> {
        let prev = last_startxref(body).unwrap();
        let mut out = body.to_vec();
        let at = out.len();
        out.extend_from_slice(b"40 0 obj\n<< /A 1 >>\nendobj\n");
        let mut rows = vec![1u8];
        rows.extend_from_slice(&u32::try_from(at).unwrap().to_be_bytes());
        rows.extend_from_slice(&[0, 0]);
        let (data, filter) = encode(rows);
        let x = out.len();
        out.extend_from_slice(
            format!(
                "50 0 obj\n<< /Type /XRef /Size 100 /W [1 4 2] /Index [40 1] /Root 1 0 R \
                 /Prev {prev} /Length {}{filter}{extra} >>\nstream\n",
                data.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&data);
        out.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{x}\n%%EOF\n").as_bytes());
        out
    }

    fn viewer_of(pdf: &[u8]) -> ViewerXref {
        viewer_xref(pdf, last_startxref(pdf).unwrap(), &|_| None)
    }

    #[test]
    fn a_plain_cross_reference_stream_is_read() {
        let a = with_xref_stream(&base(), "", |rows| (rows, ""));
        let v = viewer_of(&a);
        assert!(v.complete);
        assert!(matches!(v.get(40), Some(ViewerEntry::InUse { .. })));
        let a = with_xref_stream(&base(), "", |rows| {
            (
                miniz_oxide::deflate::compress_to_vec_zlib(&rows, 6),
                " /Filter /FlateDecode",
            )
        });
        assert!(viewer_of(&a).complete);
    }

    /// Review 2026-11-09 B1: pdf.js follows `/XRefStm` before `/Prev` whatever kind of section
    /// carries it; lopdf ignores it on a cross-reference stream. Readers disagree, so the chain
    /// cannot be relied on.
    #[test]
    fn a_cross_reference_stream_with_xrefstm_is_ambiguous() {
        let b = base();
        let prev = last_startxref(&b).unwrap();
        let a = with_xref_stream(&b, &format!(" /XRefStm {prev}"), |rows| (rows, ""));
        assert!(!viewer_of(&a).complete);
    }

    /// Review 2026-11-09 B2: a subsection starting at 1 whose first entry is free is renumbered
    /// from 0 by pdf.js and read as written by PDFium and lopdf.
    #[test]
    fn a_free_subsection_starting_at_one_is_ambiguous() {
        let b = base();
        for head in ["0000000000 00001 f ", "0000000000 65535 f "] {
            let a = with_increment(
                &b,
                &[(42, "<< /A 1 >>")],
                |o| format!("1 2\n{head}\n{head}\n42 1\n{:010} 00000 n \n", o[0].1),
                "",
            );
            assert!(!viewer_of(&a).complete, "{head}");
        }
    }

    /// Review 2026-11-09 B3: pdf.js dereferences an indirect `/Index`, `/DecodeParms` or
    /// `/Filter`; lopdf and this reader used to ignore it and fall back to the default.
    /// Unusable section pointers are refused rather than skipped.
    #[test]
    fn indirect_or_unusable_stream_keys_are_ambiguous() {
        let b = base();
        for extra in [
            " /Index 7 0 R",
            " /DecodeParms 7 0 R",
            " /DecodeParms << /Columns 7 0 R >>",
            " /Prev (12)",
        ] {
            // A second /Index or /Prev key replaces the first one in the parsed dictionary.
            let a = with_xref_stream(&b, extra, |rows| (rows, ""));
            assert!(!viewer_of(&a).complete, "{extra}");
        }
        let a = with_xref_stream(&b, "", |rows| (rows, " /Filter 7 0 R"));
        assert!(!viewer_of(&a).complete);
        let a = with_xref_stream(&b, "", |rows| (rows, " /Filter /LZWDecode"));
        assert!(!viewer_of(&a).complete);
        let a = with_increment(&b, &[(40, "<< >>")], one_per_line, " /XRefStm -5");
        assert!(!viewer_of(&a).complete);
    }

    /// Review 2026-11-09 B5: a cross-reference stream is inflated only up to
    /// [`MAX_XREF_STREAM_INFLATED`] bytes.
    #[test]
    fn a_cross_reference_stream_bomb_is_refused() {
        let a = with_xref_stream(&base(), "", |mut rows| {
            rows.resize(MAX_XREF_STREAM_INFLATED + 1, 0);
            (
                miniz_oxide::deflate::compress_to_vec_zlib(&rows, 1),
                " /Filter /FlateDecode",
            )
        });
        assert!(!viewer_of(&a).complete);
    }

    /// Review 2026-11-09 B4: offsets and lengths are converted with a range check, never `as`.
    #[test]
    fn offsets_that_do_not_fit_are_refused() {
        assert_eq!(offset_of(&Object::Integer(5)), Ok(5));
        assert!(offset_of(&Object::Integer(-1)).is_err());
        if usize::BITS < 64 {
            assert!(offset_of(&Object::Integer((1i64 << 32) + 5)).is_err());
        }
    }

    /// Readers skip whitespace and comments between an entry's offset and `N G obj`; the model
    /// mirrors that skip and nothing else.
    #[test]
    fn an_object_header_after_whitespace_and_comments() {
        let at = |s: &[u8], num, gen| object_header_at(s, 0, num, gen);
        assert!(at(b"3 0 obj\n<< >>", 3, 0));
        // Microsoft Print to PDF: the offset is the line feed before the header.
        assert!(at(b"\n3 0 obj\n<< >>", 3, 0));
        // Every PDF whitespace character, and comments, in any mix.
        assert!(at(b"\r\n\t\x0c\x00 3 0 obj<< >>", 3, 0));
        assert!(at(b"\n% a comment\r\n%another\r 3 0 obj", 3, 0));
        assert!(at(b"\n12 3 obj", 12, 3));
        // Before another object, with another generation, or no header at all: what viewers
        // refuse (and then rebuild the cross-reference) stays a mismatch.
        assert!(!at(b"\n4 0 obj\n<< >>", 3, 0));
        assert!(!at(b"\n3 1 obj\n<< >>", 3, 0));
        assert!(!at(b" /Type /Pages /Kids [3 0 R] >>", 3, 0));
        assert!(!at(b" 3 0 R >>\nendobj\n3 0 obj", 3, 0));
        assert!(!at(b"\n% 3 0 obj\n", 3, 0));
        assert!(!at(b"\n% no end of line", 3, 0));
        assert!(!at(b"\n\n", 3, 0));
        assert!(!at(b"", 3, 0));
        // Forms some viewers accept and lopdf does not are not mirrored (a refusal).
        assert!(!at(b"\n+3 0 obj", 3, 0));
        assert!(!at(b"\n3.0 0 obj", 3, 0));
        assert!(!at(b"\n3 0 objx", 3, 0));
        // Only bytes the specification calls whitespace are skipped.
        assert!(!at(b"\x0b3 0 obj", 3, 0));
        assert!(!at(b"\xa03 0 obj", 3, 0));
    }

    #[test]
    fn the_number_of_any_object_header() {
        let at = |s: &[u8]| object_header_number_at(s, 0);
        assert_eq!(at(b"6 0 obj\n<< >>"), Some(6));
        assert_eq!(at(b"\n% a comment\r\n 6 1 obj<< >>"), Some(6));
        assert_eq!(at(b"\n6 0 obj123"), Some(6), "lopdf reads this header too");
        assert_eq!(at(b"\n6 0 R >>"), None);
        assert_eq!(at(b"\n6 obj"), None);
        assert_eq!(at(b"<< /Type /Page >>"), None);
        assert_eq!(at(b"\n99999999999 0 obj"), None);
        assert_eq!(at(b""), None);
    }

    #[test]
    fn object_stream_headers_every_reader_splits_alike() {
        let numbers = |s: &[u8], n| object_stream_numbers(s, n);
        assert_eq!(numbers(b"6 0 7 31 ", 2), Some(vec![6, 7]));
        assert_eq!(numbers(b"6 0\r\n7\t31\x0c", 2), Some(vec![6, 7]));
        assert_eq!(
            numbers(b"6 0 6 31 ", 2),
            Some(vec![6, 6]),
            "the caller refuses twice"
        );
        assert_eq!(numbers(b"", 0), Some(vec![]));
        // Not exactly `n` pairs: lopdf pairs every token, viewers read `n` pairs.
        assert_eq!(numbers(b"6 0 7 31 ", 1), None);
        assert_eq!(numbers(b"6 0 7 31 8", 2), None);
        assert_eq!(numbers(b"6 0 7", 2), None);
        // Tokens lopdf splits or reads differently from viewers.
        assert_eq!(numbers(b"6 0 %c\n7 31 ", 2), None);
        assert_eq!(numbers(b"6 0\x007 31 ", 2), None);
        assert_eq!(numbers(b"6 0\x0b7 31 ", 2), None);
        assert_eq!(numbers(b"+6 0 7 31 ", 2), None);
        assert_eq!(numbers(b"6 0 7 4294967296 ", 2), None);
    }

    #[test]
    fn the_lexer_reads_what_the_engine_writes() {
        let src = b"<< /Name (a\\)b\\050c) /H <48 49> /N -1.5 /R 12 0 R /A [1 2 R 3] /T true /X#20y null >>";
        let mut lx = Lexer::new(src, 0, false);
        let Object::Dictionary(d) = lx.object(0).unwrap() else {
            panic!("not a dictionary")
        };
        assert_eq!(d.get(b"Name").unwrap().as_str().unwrap(), b"a)b(c");
        assert_eq!(d.get(b"H").unwrap().as_str().unwrap(), b"HI");
        assert_eq!(d.get(b"R").unwrap(), &Object::Reference((12, 0)));
        assert_eq!(
            d.get(b"A").unwrap(),
            &Object::Array(vec![Object::Reference((1, 2)), Object::Integer(3)])
        );
        assert_eq!(d.get(b"N").unwrap(), &Object::Real(-1.5));
        assert!(d.get(b"X y").is_ok());
    }
}
