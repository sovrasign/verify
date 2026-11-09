//! Typed signatures (feature `typed`): a name turned into the glyph outlines of a font, as
//! [`InkPaths`] the engine fills in the signer's signature box.
//!
//! The host ships the fonts (handwriting-style faces whose licence allows it, such as the SIL Open
//! Font License) and passes the bytes of the one the signer picked; the outlines are made on the
//! signer's device and never need the font again: the PDF carries filled paths, not text, so it
//! looks the same in every viewer and no font is embedded.
//!
//! Layout is deliberately simple: one glyph per character from the font's character map, its
//! advance width, and pair kerning (OpenType `GPOS` `kern` feature, or the older `kern` table). No
//! shaping engine runs, so only scripts written left to right without contextual forms can be
//! typed: Latin, Greek, Cyrillic, Armenian, Georgian, Ethiopic, Cherokee, Canadian syllabics,
//! kana, Hangul syllables and CJK ideographs. A name in another script (Arabic, Hebrew, the
//! Indic scripts, Thai…) is refused rather than drawn wrongly; its signer draws instead, or adopts
//! the identity caption alone. Combining marks are refused too: hosts normalize the name to NFC
//! first (`text.normalize("NFC")` in JavaScript), which composes accented letters.

use ttf_parser::gpos::{PairAdjustment, PositioningSubtable};
use ttf_parser::{Face, GlyphId, OutlineBuilder, Tag};

use super::{validate_paths, InkPaths, PathSegment};

/// Most characters a typed name may have.
pub const MAX_TYPED_CHARS: usize = 64;

/// The size the outlines are written at: one em is this many units, with y pointing down and
/// the baseline at 0, rounded to a tenth of a unit (a thousandth of an em, about the precision
/// fonts are drawn at; the record and the PDF carry every number, so fewer digits keep them
/// small). The engine scales the drawing to its box, so only proportions matter.
const EM: f32 = 100.0;

/// The glyph outlines of `text` set in `font` (a TrueType or OpenType font file, the first face
/// of a collection), ready for [`crate::workflow::SignRequest::typed_signature`]. Runs of white
/// space count as one space; leading and trailing space is dropped.
///
/// Refused, with a message for the signer: an empty name or one over [`MAX_TYPED_CHARS`]
/// characters, a character of a script that needs shaping or of none, a character the font has
/// no glyph for (all of them are named, so the host can offer another font), a font that cannot
/// be read, and outlines over the drawing limits ([`super::MAX_TYPED_PATHS`],
/// [`super::MAX_TYPED_POINTS`]).
pub fn typed_signature(font: &[u8], text: &str) -> Result<InkPaths, String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let name = words.join(" ");
    if name.is_empty() {
        return Err("type a name to use as your signature".into());
    }
    if name.chars().count() > MAX_TYPED_CHARS {
        return Err(format!(
            "a typed signature has at most {MAX_TYPED_CHARS} characters"
        ));
    }
    if let Some(c) = name.chars().find(|c| !typeable(*c)) {
        return Err(format!(
            "'{c}' (U+{:04X}) cannot be typed as a signature: its script needs shaping the \
             engine does not do, or it is not a letter, digit or punctuation mark; draw your \
             signature instead",
            u32::from(c)
        ));
    }
    let face =
        Face::parse(font, 0).map_err(|e| format!("the signature font cannot be read: {e}"))?;
    let missing: Vec<String> = name
        .chars()
        .filter(|c| *c != ' ' && glyph(&face, *c).is_none())
        .map(|c| format!("'{c}'"))
        .fold(Vec::new(), |mut seen, c| {
            if !seen.contains(&c) {
                seen.push(c);
            }
            seen
        });
    if !missing.is_empty() {
        return Err(format!(
            "this font has no {}: choose another font, or draw your signature",
            missing.join(", ")
        ));
    }

    let kern = Kerning::new(&face);
    let scale = EM / f32::from(face.units_per_em().max(1));
    let mut outline = Outline {
        scale,
        pen: 0.0,
        current: [0.0; 2],
        path: Vec::new(),
        paths: Vec::new(),
    };
    let mut previous: Option<GlyphId> = None;
    for c in name.chars() {
        if c == ' ' {
            outline.pen += match glyph(&face, ' ') {
                Some(space) => advance(&face, space),
                None => f32::from(face.units_per_em()) / 4.0,
            };
            previous = None;
            continue;
        }
        let id = glyph(&face, c).expect("checked above");
        if let Some(left) = previous {
            outline.pen += f32::from(kern.pair(left, id));
        }
        face.outline_glyph(id, &mut outline);
        outline.end_path();
        outline.pen += advance(&face, id);
        previous = Some(id);
    }
    let paths = outline.paths;
    if paths.is_empty() {
        return Err("this font draws nothing for that name: choose another font".into());
    }
    validate_paths(&paths).map_err(|_| {
        "this name is too long or too detailed to type in this font: shorten it, choose another \
         font, or draw your signature"
            .to_string()
    })?;
    Ok(paths)
}

/// The glyph of `c` in `face`, when it has one (not the `.notdef` glyph).
fn glyph(face: &Face, c: char) -> Option<GlyphId> {
    face.glyph_index(c).filter(|g| g.0 != 0)
}

fn advance(face: &Face, id: GlyphId) -> f32 {
    f32::from(face.glyph_hor_advance(id).unwrap_or(0))
}

/// Whether `c` can be typed: a printable character of a script written left to right without
/// contextual forms, reordering or combining marks, so one glyph per character draws it.
fn typeable(c: char) -> bool {
    matches!(u32::from(c),
        0x20..=0x7E               // ASCII
        | 0xA0..=0x2AF            // Latin-1, Latin Extended-A and -B, IPA
        | 0x2B0..=0x2FF           // spacing modifier letters
        | 0x370..=0x3FF           // Greek and Coptic
        | 0x400..=0x482           // Cyrillic (0x483..=0x489 are combining)
        | 0x48A..=0x52F           // Cyrillic, Cyrillic Supplement
        | 0x531..=0x58A           // Armenian
        | 0x10A0..=0x10FF         // Georgian
        | 0x1200..=0x135C         // Ethiopic (0x135D..=0x135F are combining)
        | 0x1360..=0x137C
        | 0x13A0..=0x13FD         // Cherokee
        | 0x1400..=0x167F         // Unified Canadian Aboriginal Syllabics
        | 0x1C80..=0x1C88         // Cyrillic Extended-C
        | 0x1C90..=0x1CBF         // Georgian Extended
        | 0x1E00..=0x1FFF         // Latin Extended Additional, Greek Extended
        | 0x2010..=0x2027         // punctuation (not the zero-width or direction controls)
        | 0x2030..=0x205E
        | 0x20A0..=0x20C0         // currency symbols
        | 0x2100..=0x214F         // letterlike symbols
        | 0x2C60..=0x2C7F         // Latin Extended-C
        | 0x3000..=0x3029         // CJK symbols (0x302A..=0x302F are combining)
        | 0x3030..=0x303F
        | 0x3041..=0x3096         // Hiragana (0x3099..=0x309A are combining)
        | 0x309B..=0x30FF         // Hiragana and Katakana
        | 0x3105..=0x312F         // Bopomofo
        | 0x31F0..=0x31FF         // Katakana Phonetic Extensions
        | 0x3400..=0x4DBF         // CJK Extension A
        | 0x4E00..=0x9FFF         // CJK Unified Ideographs
        | 0xA720..=0xA7FF         // Latin Extended-D
        | 0xAB30..=0xAB6F         // Latin Extended-E
        | 0xAC00..=0xD7A3         // Hangul syllables (not conjoining jamo)
        | 0xF900..=0xFAFF         // CJK Compatibility Ideographs
        | 0xFF01..=0xFFEE         // half- and full-width forms
        | 0x20000..=0x3134F       // CJK Extensions B to G
    )
}

/// Pair kerning: the `kern` feature of the font's `GPOS` table when it has one, otherwise its
/// horizontal `kern` table.
struct Kerning<'a> {
    face: &'a Face<'a>,
    /// Indices of the `GPOS` lookups the `kern` feature uses.
    lookups: Vec<u16>,
}

impl<'a> Kerning<'a> {
    fn new(face: &'a Face<'a>) -> Self {
        let mut lookups = Vec::new();
        if let Some(gpos) = face.tables().gpos {
            for feature in gpos.features {
                if feature.tag == Tag::from_bytes(b"kern") {
                    lookups.extend(feature.lookup_indices);
                }
            }
            lookups.sort_unstable();
            lookups.dedup();
        }
        Kerning { face, lookups }
    }

    /// The advance adjustment between `left` and `right`, in font units.
    fn pair(&self, left: GlyphId, right: GlyphId) -> i16 {
        if let (Some(gpos), false) = (self.face.tables().gpos, self.lookups.is_empty()) {
            let mut total: i16 = 0;
            for lookup in self.lookups.iter().filter_map(|i| gpos.lookups.get(*i)) {
                // Within a lookup, the first subtable that has the pair applies.
                let applied = lookup
                    .subtables
                    .into_iter::<PositioningSubtable>()
                    .find_map(|sub| match sub {
                        PositioningSubtable::Pair(pair) => pair_value(&pair, left, right),
                        _ => None,
                    });
                total = total.saturating_add(applied.unwrap_or(0));
            }
            return total;
        }
        self.face
            .tables()
            .kern
            .and_then(|kern| {
                kern.subtables
                    .into_iter()
                    .filter(|s| s.horizontal && !s.variable && !s.has_cross_stream)
                    .find_map(|s| s.glyphs_kerning(left, right))
            })
            .unwrap_or(0)
    }
}

/// The advance adjustment a `GPOS` pair subtable gives `left` before `right`, when it covers the
/// pair.
fn pair_value(pair: &PairAdjustment, left: GlyphId, right: GlyphId) -> Option<i16> {
    match pair {
        PairAdjustment::Format1 { coverage, sets } => coverage
            .get(left)
            .and_then(|i| sets.get(i))
            .and_then(|set| set.get(right))
            .map(|(first, _)| first.x_advance),
        PairAdjustment::Format2 {
            coverage,
            classes,
            matrix,
        } => coverage
            .contains(left)
            .then(|| matrix.get((classes.0.get(left), classes.1.get(right))))
            .flatten()
            .map(|(first, _)| first.x_advance),
    }
}

/// Collects glyph outlines as [`InkPaths`]: font units moved by the pen position, scaled to
/// [`EM`], y flipped to point down, rounded to a tenth; quadratic curves (TrueType) become the
/// cubic curves that draw them exactly.
struct Outline {
    scale: f32,
    /// Pen position, in font units.
    pen: f32,
    /// The current point, in font units (for quadratic curves).
    current: [f32; 2],
    path: Vec<PathSegment>,
    paths: InkPaths,
}

impl Outline {
    fn point(&self, x: f32, y: f32) -> [f32; 2] {
        let round = |v: f32| (v * 10.0).round() / 10.0;
        // `+ 0.0` turns a negative zero into a plain one.
        [
            round((self.pen + x) * self.scale) + 0.0,
            round(-y * self.scale) + 0.0,
        ]
    }

    fn end_path(&mut self) {
        let mut path = std::mem::take(&mut self.path);
        // A line back to the start says nothing: every path is closed when it is filled.
        if path.len() > 2 && path.last() == path.first() {
            path.pop();
        }
        if path.len() >= 2 {
            self.paths.push(path);
        }
    }
}

impl OutlineBuilder for Outline {
    fn move_to(&mut self, x: f32, y: f32) {
        self.end_path();
        self.path.push(PathSegment::Line(self.point(x, y)));
        self.current = [x, y];
    }

    fn line_to(&mut self, x: f32, y: f32) {
        self.path.push(PathSegment::Line(self.point(x, y)));
        self.current = [x, y];
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let [x0, y0] = self.current;
        let (c1x, c1y) = (x0 + 2.0 / 3.0 * (x1 - x0), y0 + 2.0 / 3.0 * (y1 - y0));
        let (c2x, c2y) = (x + 2.0 / 3.0 * (x1 - x), y + 2.0 / 3.0 * (y1 - y));
        self.curve_to(c1x, c1y, c2x, c2y, x, y);
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let [a, b] = self.point(x1, y1);
        let [c, d] = self.point(x2, y2);
        let [e, f] = self.point(x, y);
        self.path.push(PathSegment::Curve([a, b, c, d, e, f]));
        self.current = [x, y];
    }

    fn close(&mut self) {
        self.end_path();
    }
}

/// A tiny TrueType font made in code, for tests and the reference CLI's demo (never in a
/// production build): no font file has to be checked in. Its glyphs are shapes, not letters:
/// capital letters draw a swash (two quadratic curves through an implied point), lower-case
/// vowels and `é` a ring (quadratic curves around a counter), other lower-case letters, `Ж` and
/// `ب` a slanted stem (straight lines). It has a space; it has no digits. It kerns a capital
/// before a stem by -80 units in its `kern` table, and, in [`font`] only, a stem before a ring
/// by -50 units through the `GPOS` `kern` feature (which then replaces the `kern` table).
#[cfg(any(test, feature = "test-issuer"))]
pub mod testing {
    /// The test font with a `GPOS` `kern` feature.
    pub fn font() -> Vec<u8> {
        build(true)
    }

    /// The test font with only a `kern` table.
    pub fn font_without_gpos() -> Vec<u8> {
        build(false)
    }

    const SPACE: u16 = 1;
    const RING: u16 = 2;
    const STEM: u16 = 3;
    const SWASH: u16 = 4;

    /// A contour: `(x, y, on_curve)` points.
    type Contour = Vec<(i16, i16, bool)>;

    /// Each glyph's contours and advance width.
    fn glyphs() -> Vec<(Vec<Contour>, u16)> {
        vec![
            (vec![], 500), // .notdef
            (vec![], 250), // space
            (
                vec![
                    vec![
                        (50, 250, true),
                        (50, 500, false),
                        (300, 500, true),
                        (550, 500, false),
                        (550, 250, true),
                        (550, 0, false),
                        (300, 0, true),
                        (50, 0, false),
                    ],
                    vec![
                        (150, 250, true),
                        (150, 100, false),
                        (300, 100, true),
                        (450, 100, false),
                        (450, 250, true),
                        (450, 400, false),
                        (300, 400, true),
                        (150, 400, false),
                    ],
                ],
                600,
            ),
            (
                vec![vec![
                    (40, 0, true),
                    (140, 600, true),
                    (240, 600, true),
                    (140, 0, true),
                ]],
                300,
            ),
            (
                vec![vec![
                    (0, 300, true),
                    (200, 700, false),
                    (500, 700, false),
                    (700, 300, true),
                    (600, 250, true),
                    (400, 550, false),
                    (250, 550, false),
                    (100, 250, true),
                ]],
                700,
            ),
        ]
    }

    /// Character map: code point → glyph.
    fn cmap() -> Vec<(u32, u16)> {
        let mut map = vec![(0x20, SPACE), (0xE9, RING), (0x416, STEM), (0x628, STEM)];
        map.extend((u32::from(b'A')..=u32::from(b'Z')).map(|c| (c, SWASH)));
        map.extend((u32::from(b'a')..=u32::from(b'z')).map(|c| {
            let vowel = matches!(char::from_u32(c), Some('a' | 'e' | 'i' | 'o' | 'u'));
            (c, if vowel { RING } else { STEM })
        }));
        map.sort_unstable();
        map
    }

    fn u16be(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn i16be(out: &mut Vec<u8>, v: i16) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn u32be(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn glyph_data(contours: &[Contour]) -> Vec<u8> {
        let mut out = Vec::new();
        if contours.is_empty() {
            return out;
        }
        let points: Vec<&(i16, i16, bool)> = contours.iter().flatten().collect();
        let xs = points.iter().map(|p| p.0);
        let ys = points.iter().map(|p| p.1);
        i16be(&mut out, contours.len() as i16);
        i16be(&mut out, xs.clone().min().unwrap_or(0));
        i16be(&mut out, ys.clone().min().unwrap_or(0));
        i16be(&mut out, xs.max().unwrap_or(0));
        i16be(&mut out, ys.max().unwrap_or(0));
        let mut end = 0u16;
        for c in contours {
            end += c.len() as u16;
            u16be(&mut out, end - 1);
        }
        u16be(&mut out, 0); // no instructions
                            // Flags: on-curve or not; coordinates as 16-bit deltas.
        out.extend(points.iter().map(|p| u8::from(p.2)));
        let (mut x, mut y) = (0i16, 0i16);
        for p in &points {
            i16be(&mut out, p.0 - x);
            x = p.0;
        }
        for p in &points {
            i16be(&mut out, p.1 - y);
            y = p.1;
        }
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn build(with_gpos: bool) -> Vec<u8> {
        let glyphs = glyphs();
        let count = glyphs.len() as u16;
        let mut tables: Vec<(&[u8; 4], Vec<u8>)> = Vec::new();

        let mut head = Vec::new();
        u32be(&mut head, 0x0001_0000);
        u32be(&mut head, 0x0001_0000);
        u32be(&mut head, 0);
        u32be(&mut head, 0x5F0F_3CF5);
        u16be(&mut head, 3);
        u16be(&mut head, 1000); // units per em
        head.extend_from_slice(&[0; 16]); // created, modified
        for v in [0i16, -200, 1000, 800] {
            i16be(&mut head, v);
        }
        u16be(&mut head, 0);
        u16be(&mut head, 8);
        i16be(&mut head, 2);
        i16be(&mut head, 1); // long loca offsets
        i16be(&mut head, 0);
        tables.push((b"head", head));

        let mut hhea = Vec::new();
        u32be(&mut hhea, 0x0001_0000);
        for v in [800i16, -200, 0] {
            i16be(&mut hhea, v);
        }
        u16be(&mut hhea, 700);
        for v in [0i16, 0, 700, 1, 0, 0, 0, 0, 0, 0, 0] {
            i16be(&mut hhea, v);
        }
        u16be(&mut hhea, count);
        tables.push((b"hhea", hhea));

        let mut maxp = Vec::new();
        u32be(&mut maxp, 0x0000_5000);
        u16be(&mut maxp, count);
        tables.push((b"maxp", maxp));

        let mut hmtx = Vec::new();
        for (_, advance) in &glyphs {
            u16be(&mut hmtx, *advance);
            i16be(&mut hmtx, 0);
        }
        tables.push((b"hmtx", hmtx));

        let map = cmap();
        let mut cmap = Vec::new();
        u16be(&mut cmap, 0);
        u16be(&mut cmap, 1);
        u16be(&mut cmap, 3); // Windows
        u16be(&mut cmap, 10); // Unicode, full repertoire
        u32be(&mut cmap, 12);
        u16be(&mut cmap, 12); // format 12
        u16be(&mut cmap, 0);
        u32be(&mut cmap, 16 + 12 * map.len() as u32);
        u32be(&mut cmap, 0);
        u32be(&mut cmap, map.len() as u32);
        for (c, g) in &map {
            u32be(&mut cmap, *c);
            u32be(&mut cmap, *c);
            u32be(&mut cmap, u32::from(*g));
        }
        tables.push((b"cmap", cmap));

        let mut glyf = Vec::new();
        let mut loca = Vec::new();
        for (contours, _) in &glyphs {
            u32be(&mut loca, glyf.len() as u32);
            glyf.extend(glyph_data(contours));
        }
        u32be(&mut loca, glyf.len() as u32);
        tables.push((b"glyf", glyf));
        tables.push((b"loca", loca));

        // `kern` table, version 0: one horizontal format-0 subtable with one pair.
        let mut kern = Vec::new();
        u16be(&mut kern, 0);
        u16be(&mut kern, 1);
        u16be(&mut kern, 0);
        u16be(&mut kern, 6 + 8 + 6);
        u16be(&mut kern, 0x0001);
        for v in [1u16, 6, 0, 0] {
            u16be(&mut kern, v);
        }
        u16be(&mut kern, SWASH);
        u16be(&mut kern, STEM);
        i16be(&mut kern, -80);
        tables.push((b"kern", kern));

        if with_gpos {
            // GPOS 1.0: no scripts, one `kern` feature using one lookup of one pair-adjustment
            // subtable (format 1): stem before ring, x advance -50.
            let mut gpos = Vec::new();
            for v in [1u16, 0, 10, 12, 26] {
                u16be(&mut gpos, v);
            }
            u16be(&mut gpos, 0); // ScriptList at 10: no scripts
                                 // FeatureList at 12: one record, the feature table 8 bytes in.
            u16be(&mut gpos, 1);
            gpos.extend_from_slice(b"kern");
            u16be(&mut gpos, 8);
            for v in [0u16, 1, 0] {
                u16be(&mut gpos, v);
            }
            // LookupList at 26: one lookup, 4 bytes in.
            u16be(&mut gpos, 1);
            u16be(&mut gpos, 4);
            // Lookup: type 2 (pair), no flags, one subtable 8 bytes in.
            for v in [2u16, 0, 1, 8] {
                u16be(&mut gpos, v);
            }
            // PairPos format 1: coverage at 18, value formats (x advance, none), one pair set
            // at 12.
            for v in [1u16, 18, 0x0004, 0, 1, 12] {
                u16be(&mut gpos, v);
            }
            u16be(&mut gpos, 1); // PairSet: one pair
            u16be(&mut gpos, RING);
            i16be(&mut gpos, -50);
            for v in [1u16, 1, STEM] {
                u16be(&mut gpos, v); // Coverage format 1: the stem
            }
            tables.push((b"GPOS", gpos));
        }

        tables.sort_by(|a, b| a.0.cmp(b.0));
        let mut font = Vec::new();
        u32be(&mut font, 0x0001_0000);
        let n = tables.len() as u16;
        let entry_selector = 15 - n.leading_zeros() as u16;
        let search_range = 16 << entry_selector;
        for v in [n, search_range, entry_selector, n * 16 - search_range] {
            u16be(&mut font, v);
        }
        let mut offset = 12 + 16 * tables.len();
        let mut body = Vec::new();
        for (tag, data) in &tables {
            font.extend_from_slice(*tag);
            u32be(&mut font, 0); // checksum, unchecked
            u32be(&mut font, offset as u32);
            u32be(&mut font, data.len() as u32);
            let mut padded = data.clone();
            while padded.len() % 4 != 0 {
                padded.push(0);
            }
            offset += padded.len();
            body.extend(padded);
        }
        font.extend(body);
        font
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{font, font_without_gpos};
    use super::*;
    use crate::ink::{fill_ops, is_filled_paths, PathSegment::Curve, PathSegment::Line};

    #[test]
    fn a_name_becomes_the_outlines_of_its_glyphs() {
        let paths = typed_signature(&font(), "o").unwrap();
        // A ring: the outline and its counter, four quadratic curves each, as cubic curves.
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.len() == 5), "{paths:?}");
        // From (50, 250) in font units: x / 10, y / -10.
        assert_eq!(paths[0][0], Line([5.0, -25.0]));
        // The quadratic curve through (50, 500) to (300, 500), as a cubic one.
        assert_eq!(paths[0][1], Curve([5.0, -41.7, 13.3, -50.0, 30.0, -50.0]));
        // The last curve comes back to the start.
        assert!(matches!(paths[0][4], Curve([.., 5.0, -25.0])), "{paths:?}");

        // Straight lines stay lines; two off-curve points in a row imply one between them.
        let stem = typed_signature(&font(), "b").unwrap();
        assert_eq!(
            stem,
            vec![vec![
                Line([4.0, 0.0]),
                Line([14.0, -60.0]),
                Line([24.0, -60.0]),
                Line([14.0, 0.0]),
            ]]
        );
        let swash = typed_signature(&font(), "A").unwrap();
        assert_eq!(swash.len(), 1);
        let curves = swash[0].iter().filter(|s| matches!(s, Curve(_))).count();
        assert_eq!(curves, 4, "{swash:?}");
        assert!(swash[0].contains(&Curve([13.3, -56.7, 25.0, -70.0, 35.0, -70.0])));
    }

    /// Where each glyph starts: the x of its first point.
    fn starts(paths: &InkPaths) -> Vec<f32> {
        paths
            .iter()
            .filter_map(|p| match p[0] {
                Line([x, _]) => Some(x),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn glyphs_advance_and_kern() {
        // A stem (advance 300) then a ring: GPOS kerns the pair by -50.
        assert_eq!(
            starts(&typed_signature(&font(), "ba").unwrap()),
            [4.0, 30.0, 40.0]
        );
        // Without GPOS, the `kern` table has no such pair.
        assert_eq!(
            starts(&typed_signature(&font_without_gpos(), "ba").unwrap()),
            [4.0, 35.0, 45.0]
        );
        // A capital before a stem: -80 in the `kern` table, which GPOS replaces.
        assert_eq!(
            starts(&typed_signature(&font_without_gpos(), "Ab").unwrap()),
            [0.0, 66.0]
        );
        assert_eq!(
            starts(&typed_signature(&font(), "Ab").unwrap()),
            [0.0, 74.0]
        );
        // A space is its advance (250); runs of space and the ends are trimmed; no kerning
        // across a space.
        assert_eq!(
            starts(&typed_signature(&font(), "  b \t a ").unwrap()),
            [4.0, 60.0, 70.0]
        );
        // Other scripts the engine can type, when the font has them: é, Ж.
        assert_eq!(typed_signature(&font(), "é").unwrap().len(), 2);
        assert_eq!(typed_signature(&font(), "Ж").unwrap().len(), 1);
    }

    #[test]
    fn what_cannot_be_typed_is_refused_with_a_reason() {
        let refused = |text: &str| typed_signature(&font(), text).unwrap_err();
        assert!(refused("").contains("type a name"));
        assert!(refused(" \t ").contains("type a name"));
        assert!(refused(&"a".repeat(MAX_TYPED_CHARS + 1)).contains("at most 64"));
        assert!(typed_signature(&font(), &"a".repeat(MAX_TYPED_CHARS)).is_ok());
        // The font has no digits: every missing character is named once.
        let missing = refused("Ab1 2 1");
        assert!(missing.contains("no '1', '2'"), "{missing}");
        // The font draws Arabic, but the engine cannot shape it.
        assert!(refused("بa").contains("U+0628"));
        // Combining marks, direction marks and joiners, control characters.
        for text in ["e\u{301}", "a\u{200f}b", "a\u{200d}b", "a\u{7}b"] {
            assert!(refused(text).contains("cannot be typed"), "{text:?}");
        }
        let bad_font = typed_signature(b"not a font", "abc").unwrap_err();
        assert!(bad_font.contains("cannot be read"), "{bad_font}");
        let truncated = font()[..200].to_vec();
        assert!(typed_signature(&truncated, "abc").is_err());
    }

    #[test]
    fn a_typed_name_fills_its_box_by_the_ink_rule() {
        let paths = typed_signature(&font(), "Bob Builder").unwrap();
        assert!(validate_paths(&paths).is_ok());
        let area = [4.0, 3.0, 84.0, 34.0];
        let ops = fill_ops(&paths, area);
        assert!(is_filled_paths(&ops, area), "{ops}");
        // Deterministic: the same name and font give the same paths.
        assert_eq!(typed_signature(&font(), "Bob  Builder").unwrap(), paths);
    }
}
