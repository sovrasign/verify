//! Where the document-ID stamp goes on the first page: a spot where the page draws nothing, so
//! the stamp never hides the document's own text (a footer, a page number, a legal line).
//!
//! The page's content stream is read once and every mark it paints (text runs, stroked lines,
//! filled shapes, images) becomes a rough box in default user space. Text is measured with a
//! generous average glyph width, since the page's own fonts are not loaded: a box may be a
//! little wider than the ink, never narrower in practice. Candidate spots are then tried in a
//! fixed order (the bottom margin from the left, the top margin from the left) and the first
//! one clear of every box wins. When none is clear (a scanned page is one big image), the spot
//! that covers the least is taken, so the stamp falls back to the lower-left corner it always
//! had on such pages.
//!
//! The verifier does not check where the stamp is, only what it draws, so this choice can
//! improve without an envelope schema version.

use lopdf::content::Content;
use lopdf::{Dictionary, Document, Object, ObjectId};

/// A 2D affine matrix `[a b c d e f]`, as PDF writes it.
type Matrix = [f32; 6];

const IDENTITY: Matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// The most content operators read before giving up on a page (a very busy page is placed as
/// before, in the lower-left corner).
const MAX_OPERATIONS: usize = 200_000;

/// Distance from the page edge of the first candidate row, in points (the stamp's spot before
/// the engine looked at the page).
const EDGE: f32 = 18.0;

/// A closer row, still clear of what most printers cannot print.
const EDGE_NEAR: f32 = 12.0;

/// Clear space kept around the stamp, in points.
const GAP: f32 = 2.0;

/// Step between candidate spots along a row, in points.
const STEP: f32 = 4.0;

/// `m` × `n`: first `m`, then `n`.
fn mul(m: &Matrix, n: &Matrix) -> Matrix {
    [
        m[0] * n[0] + m[1] * n[2],
        m[0] * n[1] + m[1] * n[3],
        m[2] * n[0] + m[3] * n[2],
        m[2] * n[1] + m[3] * n[3],
        m[4] * n[0] + m[5] * n[2] + n[4],
        m[4] * n[1] + m[5] * n[3] + n[5],
    ]
}

fn apply(m: &Matrix, x: f32, y: f32) -> (f32, f32) {
    (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])
}

fn translate(x: f32, y: f32) -> Matrix {
    [1.0, 0.0, 0.0, 1.0, x, y]
}

/// The box around the points, or `None` without any finite point.
fn bounds(points: impl IntoIterator<Item = (f32, f32)>) -> Option<[f32; 4]> {
    let mut b: Option<[f32; 4]> = None;
    for (x, y) in points {
        if !x.is_finite() || !y.is_finite() {
            continue;
        }
        b = Some(match b {
            None => [x, y, x, y],
            Some(b) => [b[0].min(x), b[1].min(y), b[2].max(x), b[3].max(y)],
        });
    }
    b
}

/// The box `[x0, y0, x1, y1]` (in `m`'s target space) of the unit-space rectangle given.
fn mapped_rect(m: &Matrix, r: [f32; 4]) -> Option<[f32; 4]> {
    bounds([
        apply(m, r[0], r[1]),
        apply(m, r[2], r[1]),
        apply(m, r[0], r[3]),
        apply(m, r[2], r[3]),
    ])
}

fn num(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

fn nums<const N: usize>(ops: &[Object]) -> Option<[f32; N]> {
    if ops.len() < N {
        return None;
    }
    let mut out = [0.0; N];
    for (slot, o) in out.iter_mut().zip(&ops[ops.len() - N..]) {
        *slot = num(o)?;
    }
    Some(out)
}

fn deref<'a>(doc: &'a Document, o: &'a Object) -> Option<&'a Object> {
    match o {
        Object::Reference(id) => doc.get_object(*id).ok(),
        o => Some(o),
    }
}

/// A named entry of the page's resource category `kind` (`Font`, `XObject`), resolved.
fn resource<'a>(
    doc: &'a Document,
    resources: &[&'a Dictionary],
    kind: &[u8],
    name: &[u8],
) -> Option<&'a Object> {
    resources.iter().find_map(|res| {
        let cat = deref(doc, res.get(kind).ok()?)?.as_dict().ok()?;
        deref(doc, cat.get(name).ok()?)
    })
}

/// The page's resource dictionaries, its own first, then those it inherits.
fn page_resources(doc: &Document, page: ObjectId) -> Vec<&Dictionary> {
    let Ok((own, inherited)) = doc.get_page_resources(page) else {
        return Vec::new();
    };
    own.into_iter()
        .chain(
            inherited
                .into_iter()
                .filter_map(|id| doc.get_dictionary(id).ok()),
        )
        .collect()
}

/// Text state while reading a text object.
#[derive(Clone)]
struct TextState {
    tm: Matrix,
    tlm: Matrix,
    size: f32,
    leading: f32,
    char_spacing: f32,
    word_spacing: f32,
    scale: f32,
    rise: f32,
    /// A composite (Type0) font: two bytes per glyph.
    two_byte: bool,
}

impl Default for TextState {
    fn default() -> Self {
        TextState {
            tm: IDENTITY,
            tlm: IDENTITY,
            size: 0.0,
            leading: 0.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            scale: 1.0,
            rise: 0.0,
            two_byte: false,
        }
    }
}

/// An average glyph advance, in em, generous for proportional fonts.
const GLYPH_EM: f32 = 0.6;

/// The boxes, in default user space, of what the content of `page` paints. `None` when the
/// content cannot be read or is too long to read.
pub(crate) fn painted_boxes(doc: &Document, page: ObjectId) -> Option<Vec<[f32; 4]>> {
    let content = doc.get_page_content(page).ok()?;
    let ops = Content::decode(&content).ok()?.operations;
    if ops.len() > MAX_OPERATIONS {
        return None;
    }
    let resources = page_resources(doc, page);
    let mut boxes = Vec::new();
    let mut ctm = IDENTITY;
    let mut stack: Vec<(Matrix, bool)> = Vec::new();
    let mut ts = TextState::default();
    // The current path, already in user space, as subpaths of points.
    let mut path: Vec<Vec<(f32, f32)>> = Vec::new();
    let mut line_width = 1.0_f32;
    // Whether the fill colour is white (a white fill is the page itself, not a mark).
    let mut white_fill = false;

    for op in &ops {
        let o = &op.operands;
        match op.operator.as_str() {
            "q" => stack.push((ctm, white_fill)),
            "Q" => {
                if let Some((m, w)) = stack.pop() {
                    ctm = m;
                    white_fill = w;
                }
            }
            "cm" => {
                if let Some(m) = nums::<6>(o) {
                    ctm = mul(&m, &ctm);
                }
            }
            "w" => {
                if let Some([w]) = nums::<1>(o) {
                    line_width = w.abs();
                }
            }
            "g" => white_fill = nums::<1>(o).is_some_and(|[g]| g >= 0.99),
            "rg" => white_fill = nums::<3>(o).is_some_and(|c| c.iter().all(|v| *v >= 0.99)),
            "k" => white_fill = nums::<4>(o).is_some_and(|c| c.iter().all(|v| *v <= 0.01)),
            "sc" | "scn" | "cs" => white_fill = false,
            "m" => {
                if let Some([x, y]) = nums::<2>(o) {
                    path.push(vec![apply(&ctm, x, y)]);
                }
            }
            "l" => {
                if let Some([x, y]) = nums::<2>(o) {
                    push_point(&mut path, apply(&ctm, x, y));
                }
            }
            "c" => {
                if let Some(p) = nums::<6>(o) {
                    for i in 0..3 {
                        push_point(&mut path, apply(&ctm, p[2 * i], p[2 * i + 1]));
                    }
                }
            }
            "v" | "y" => {
                if let Some(p) = nums::<4>(o) {
                    push_point(&mut path, apply(&ctm, p[0], p[1]));
                    push_point(&mut path, apply(&ctm, p[2], p[3]));
                }
            }
            "re" => {
                if let Some([x, y, w, h]) = nums::<4>(o) {
                    path.push(vec![
                        apply(&ctm, x, y),
                        apply(&ctm, x + w, y),
                        apply(&ctm, x + w, y + h),
                        apply(&ctm, x, y + h),
                        apply(&ctm, x, y),
                    ]);
                }
            }
            "S" | "s" => {
                stroke_boxes(&path, line_width * scale_of(&ctm), &mut boxes);
                path.clear();
            }
            "f" | "F" | "f*" => {
                if !white_fill {
                    fill_boxes(&path, &mut boxes);
                }
                path.clear();
            }
            "B" | "B*" | "b" | "b*" => {
                if !white_fill {
                    fill_boxes(&path, &mut boxes);
                }
                stroke_boxes(&path, line_width * scale_of(&ctm), &mut boxes);
                path.clear();
            }
            "n" => path.clear(),
            "BT" => {
                ts.tm = IDENTITY;
                ts.tlm = IDENTITY;
            }
            "Tf" => {
                if let (Some(Object::Name(name)), Some(size)) = (o.first(), o.get(1).and_then(num))
                {
                    ts.size = size;
                    ts.two_byte = resource(doc, &resources, b"Font", name)
                        .and_then(|f| f.as_dict().ok())
                        .and_then(|f| f.get(b"Subtype").ok())
                        .is_some_and(|s| matches!(s, Object::Name(n) if n == b"Type0"));
                }
            }
            "Tc" => ts.char_spacing = nums::<1>(o).map_or(0.0, |[v]| v),
            "Tw" => ts.word_spacing = nums::<1>(o).map_or(0.0, |[v]| v),
            "Tz" => ts.scale = nums::<1>(o).map_or(1.0, |[v]| v / 100.0),
            "TL" => ts.leading = nums::<1>(o).map_or(0.0, |[v]| v),
            "Ts" => ts.rise = nums::<1>(o).map_or(0.0, |[v]| v),
            "Td" => {
                if let Some([x, y]) = nums::<2>(o) {
                    next_line(&mut ts, x, y);
                }
            }
            "TD" => {
                if let Some([x, y]) = nums::<2>(o) {
                    ts.leading = -y;
                    next_line(&mut ts, x, y);
                }
            }
            "Tm" => {
                if let Some(m) = nums::<6>(o) {
                    ts.tm = m;
                    ts.tlm = m;
                }
            }
            "T*" => {
                let l = ts.leading;
                next_line(&mut ts, 0.0, -l);
            }
            "Tj" => show(&mut ts, &ctm, o.first(), &mut boxes),
            "'" => {
                let l = ts.leading;
                next_line(&mut ts, 0.0, -l);
                show(&mut ts, &ctm, o.first(), &mut boxes);
            }
            "\"" => {
                if let Some([aw, ac]) = o.get(..2).and_then(nums::<2>) {
                    ts.word_spacing = aw;
                    ts.char_spacing = ac;
                }
                let l = ts.leading;
                next_line(&mut ts, 0.0, -l);
                show(&mut ts, &ctm, o.get(2), &mut boxes);
            }
            "TJ" => {
                if let Some(Object::Array(items)) = o.first() {
                    for item in items {
                        match item {
                            Object::String(..) => show(&mut ts, &ctm, Some(item), &mut boxes),
                            other => {
                                if let Some(n) = num(other) {
                                    let dx = -n / 1000.0 * ts.size * ts.scale;
                                    ts.tm = mul(&translate(dx, 0.0), &ts.tm);
                                }
                            }
                        }
                    }
                }
            }
            "Do" => {
                let Some(Object::Name(name)) = o.first() else {
                    continue;
                };
                let Some(Object::Stream(x)) = resource(doc, &resources, b"XObject", name) else {
                    continue;
                };
                let subtype = x.dict.get(b"Subtype").ok();
                if matches!(subtype, Some(Object::Name(n)) if n == b"Form") {
                    let bbox = x
                        .dict
                        .get(b"BBox")
                        .ok()
                        .and_then(|b| deref(doc, b))
                        .and_then(|b| b.as_array().ok())
                        .and_then(|a| nums::<4>(a));
                    let matrix = x
                        .dict
                        .get(b"Matrix")
                        .ok()
                        .and_then(|m| deref(doc, m))
                        .and_then(|m| m.as_array().ok())
                        .and_then(|a| nums::<6>(a))
                        .unwrap_or(IDENTITY);
                    if let Some(b) = bbox.and_then(|b| mapped_rect(&mul(&matrix, &ctm), b)) {
                        boxes.push(b);
                    }
                } else if let Some(b) = mapped_rect(&ctm, [0.0, 0.0, 1.0, 1.0]) {
                    boxes.push(b);
                }
            }
            "BI" => {
                if let Some(b) = mapped_rect(&ctm, [0.0, 0.0, 1.0, 1.0]) {
                    boxes.push(b);
                }
            }
            _ => {}
        }
    }
    Some(boxes)
}

fn push_point(path: &mut Vec<Vec<(f32, f32)>>, p: (f32, f32)) {
    match path.last_mut() {
        Some(sub) => sub.push(p),
        None => path.push(vec![p]),
    }
}

/// How much `m` scales lengths, roughly (for line widths).
fn scale_of(m: &Matrix) -> f32 {
    ((m[0] * m[3] - m[1] * m[2]).abs()).sqrt()
}

/// A stroked path marks each of its segments (a page border marks four thin strips, not the
/// whole page), widened by half the line width.
fn stroke_boxes(path: &[Vec<(f32, f32)>], width: f32, boxes: &mut Vec<[f32; 4]>) {
    let half = (width / 2.0).max(0.5);
    for sub in path {
        for pair in sub.windows(2) {
            if let Some(b) = bounds([pair[0], pair[1]]) {
                boxes.push([b[0] - half, b[1] - half, b[2] + half, b[3] + half]);
            }
        }
        if let [p] = sub.as_slice() {
            boxes.push([p.0 - half, p.1 - half, p.0 + half, p.1 + half]);
        }
    }
}

/// A filled path marks the box of each subpath.
fn fill_boxes(path: &[Vec<(f32, f32)>], boxes: &mut Vec<[f32; 4]>) {
    for sub in path {
        if let Some(b) = bounds(sub.iter().copied()) {
            boxes.push(b);
        }
    }
}

fn next_line(ts: &mut TextState, x: f32, y: f32) {
    ts.tlm = mul(&translate(x, y), &ts.tlm);
    ts.tm = ts.tlm;
}

/// Show the string `s`: mark its box and advance the text matrix.
fn show(ts: &mut TextState, ctm: &Matrix, s: Option<&Object>, boxes: &mut Vec<[f32; 4]>) {
    let Some(Object::String(bytes, _)) = s else {
        return;
    };
    let glyphs = if ts.two_byte {
        bytes.len().div_ceil(2)
    } else {
        bytes.len()
    } as f32;
    let spaces = if ts.two_byte {
        0.0
    } else {
        bytes.iter().filter(|b| **b == b' ').count() as f32
    };
    let advance =
        (glyphs * (GLYPH_EM * ts.size + ts.char_spacing) + spaces * ts.word_spacing) * ts.scale;
    if glyphs > 0.0 && ts.size != 0.0 {
        let to_user = mul(&ts.tm, ctm);
        let (lo, hi) = (ts.rise - 0.25 * ts.size, ts.rise + 0.9 * ts.size);
        if let Some(b) = mapped_rect(&to_user, [0.0, lo.min(hi), advance, lo.max(hi)]) {
            boxes.push(b);
        }
    }
    ts.tm = mul(&translate(advance, 0.0), &ts.tm);
}

/// Whether two boxes overlap.
fn overlaps(a: &[f32; 4], b: &[f32; 4]) -> bool {
    a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3]
}

fn overlap_area(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let w = a[2].min(b[2]) - a[0].max(b[0]);
    let h = a[3].min(b[3]) - a[1].max(b[1]);
    if w > 0.0 && h > 0.0 {
        w * h
    } else {
        0.0
    }
}

/// The lower-left corner of a `w`×`h` stamp on a page whose visible area is `page` and whose
/// marks are `taken`: the first candidate spot clear of every mark (with [`GAP`] around it), else
/// the one covering the least. Candidates: the bottom row [`EDGE`] from the edge from left to
/// right, the same row [`EDGE_NEAR`] from the edge, then the same two rows at the top.
pub(crate) fn stamp_spot(page: [f32; 4], w: f32, h: f32, taken: &[[f32; 4]]) -> (f32, f32) {
    let legacy = (page[0] + EDGE, page[1] + EDGE);
    let (pw, ph) = (page[2] - page[0], page[3] - page[1]);
    if w + 2.0 * EDGE_NEAR > pw || h + 2.0 * EDGE_NEAR > ph {
        return legacy;
    }
    let rows = [
        page[1] + EDGE,
        page[1] + EDGE_NEAR,
        page[3] - EDGE - h,
        page[3] - EDGE_NEAR - h,
    ];
    let mut best = (f32::INFINITY, legacy);
    for y in rows {
        let mut x = page[0] + EDGE;
        let last = page[2] - EDGE - w;
        loop {
            let spot = [x - GAP, y - GAP, x + w + GAP, y + h + GAP];
            let covered: f32 = taken
                .iter()
                .filter(|t| overlaps(&spot, t))
                .map(|t| overlap_area(&spot, t))
                .sum();
            if covered == 0.0 {
                return (x, y);
            }
            if covered < best.0 {
                best = (covered, (x, y));
            }
            if x >= last {
                break;
            }
            x = (x + STEP).min(last);
        }
    }
    best.1
}

#[cfg(test)]
mod tests {
    use super::*;

    const A4: [f32; 4] = [0.0, 0.0, 595.0, 842.0];

    #[test]
    fn an_empty_page_keeps_the_lower_left_corner() {
        assert_eq!(stamp_spot(A4, 176.0, 26.0, &[]), (18.0, 18.0));
    }

    #[test]
    fn a_footer_moves_the_stamp_beside_or_under_it() {
        // The founder's report: a footer at x 72-178 and a page number at x 482-523, 38-49 pt
        // from the bottom.
        let footer = [72.0, 38.0, 178.0, 49.0];
        let number = [482.0, 38.0, 523.0, 49.0];
        let (x, y) = stamp_spot(A4, 176.0, 26.0, &[footer, number]);
        let stamp = [x, y, x + 176.0, y + 26.0];
        assert!(
            !overlaps(&stamp, &footer) && !overlaps(&stamp, &number),
            "{stamp:?}"
        );
        assert!(y < 100.0, "the stamp stays at the bottom: {stamp:?}");
    }

    #[test]
    fn a_full_bottom_row_sends_the_stamp_to_the_top() {
        let band = [0.0, 0.0, 595.0, 60.0];
        let (_, y) = stamp_spot(A4, 176.0, 26.0, &[band]);
        assert!(y > 700.0, "{y}");
    }

    #[test]
    fn a_covered_page_falls_back_to_the_lower_left_corner() {
        let scan = [0.0, 0.0, 595.0, 842.0];
        assert_eq!(stamp_spot(A4, 176.0, 26.0, &[scan]), (18.0, 18.0));
    }

    #[test]
    fn text_is_measured_in_user_space() {
        let mut ts = TextState {
            size: 10.0,
            tm: [1.0, 0.0, 0.0, 1.0, 72.0, 40.0],
            ..TextState::default()
        };
        let mut boxes = Vec::new();
        let s = Object::string_literal("Footer");
        show(&mut ts, &IDENTITY, Some(&s), &mut boxes);
        let b = boxes[0];
        assert!(
            (b[0] - 72.0).abs() < 0.01 && (b[2] - 108.0).abs() < 0.01,
            "{b:?}"
        );
        assert!(b[1] < 40.0 && b[3] > 48.0, "{b:?}");
        assert!((ts.tm[4] - 108.0).abs() < 0.01);
    }
}
