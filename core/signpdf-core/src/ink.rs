//! A signer's drawing in their signature box: hand-drawn pen strokes, or a typed signature made
//! of filled vector paths (the glyph outlines of the typed name in a handwriting-style font).
//!
//! The drawing is **decoration**. It sits beside the caption the verifier redraws from the
//! verified identity (`Signed by:`, email, key code, time, provider), which stays the evidence of
//! who signed; a typed name is not a claim about the signer's name.
//!
//! Both kinds are drawn with path operators only, in one colour, inside the drawing area of the
//! box: no text, fonts, images, XObjects or transforms can hide in them, and the verifier holds
//! them to that rule ([`is_ink`], [`is_filled_paths`]). From envelope schema version 6 the
//! signer's [`SignatureRecord`](crate::model::SignatureRecord) carries the drawing
//! ([`SignatureDrawing`]), so the verifier redraws it and compares what the box shows byte for
//! byte, and labels the box `drawn` or `typed`.
//!
//! A typed signature is made on the signer's device, from a font the host ships: with the `typed`
//! feature, [`typed::typed_signature`] turns a name into paths, so a page needs no font library.
//! The PDF never embeds the font.

use serde::{Deserialize, Serialize};

/// Hand-drawn pen strokes, each a polyline of `[x, y]` points in the drawing surface's own units
/// (any scale), with y pointing down.
pub type InkStrokes = Vec<Vec<[f32; 2]>>;

/// Most strokes, and most points in total, a hand-drawn signature may have.
pub const MAX_INK_STROKES: usize = 200;
pub const MAX_INK_POINTS: usize = 5000;

/// One step of a filled path, in the drawing's own units with y pointing down: `[x, y]`, a
/// straight line to that point (or, first in a path, its start), or `[x1, y1, x2, y2, x, y]`, a
/// cubic Bézier curve to `(x, y)` with control points `(x1, y1)` and `(x2, y2)`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathSegment {
    Line([f32; 2]),
    Curve([f32; 6]),
}

impl PathSegment {
    /// The points the segment names (its end point last).
    pub fn points(&self) -> impl Iterator<Item = [f32; 2]> + Clone + '_ {
        let coords: &[f32] = match self {
            PathSegment::Line(p) => p,
            PathSegment::Curve(c) => c,
        };
        coords.as_chunks::<2>().0.iter().copied()
    }

    /// How many points the segment counts for in [`MAX_TYPED_POINTS`].
    fn weight(&self) -> usize {
        match self {
            PathSegment::Line(_) => 1,
            PathSegment::Curve(_) => 3,
        }
    }
}

/// Filled paths: each a closed outline that starts with a [`PathSegment::Line`] (its start point)
/// followed by at least one more segment. Filled together with the nonzero winding rule, so the
/// counters of letters (the hole in an `o`) stay open, as in the font.
pub type InkPaths = Vec<Vec<PathSegment>>;

/// Most paths, and most points in total (a curve counts three), a typed signature may have.
pub const MAX_TYPED_PATHS: usize = 600;
pub const MAX_TYPED_POINTS: usize = 12_000;

/// Largest coordinate accepted in either kind of drawing.
const MAX_COORD: f32 = 1e6;

/// What a signer drew in their signature box, as their signature record keeps it (schema
/// version 6 and later): `{"kind": "drawn", "strokes": …}` or `{"kind": "typed", "paths": …}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignatureDrawing {
    /// Pen strokes drawn by hand.
    Drawn { strokes: InkStrokes },
    /// The outlines of a typed name, filled.
    Typed { paths: InkPaths },
}

impl SignatureDrawing {
    /// `drawn` or `typed`: how the verifier labels the box.
    pub fn kind(&self) -> &'static str {
        match self {
            SignatureDrawing::Drawn { .. } => "drawn",
            SignatureDrawing::Typed { .. } => "typed",
        }
    }

    /// Check that the drawing can be drawn ([`validate_ink`], [`validate_paths`]).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            SignatureDrawing::Drawn { strokes } => validate_ink(strokes),
            SignatureDrawing::Typed { paths } => validate_paths(paths),
        }
    }
}

fn coordinate_ok(p: [f32; 2]) -> bool {
    p.iter().all(|v| v.is_finite() && v.abs() <= MAX_COORD)
}

/// Check that a hand-drawn signature can be drawn: at least one point, within the limits, and
/// only finite coordinates.
pub fn validate_ink(strokes: &InkStrokes) -> Result<(), String> {
    let points: usize = strokes.iter().map(Vec::len).sum();
    if points == 0 {
        return Err("the drawn signature is empty".into());
    }
    if strokes.len() > MAX_INK_STROKES || points > MAX_INK_POINTS {
        return Err(format!(
            "the drawn signature is too detailed (at most {MAX_INK_STROKES} strokes and \
             {MAX_INK_POINTS} points)"
        ));
    }
    if !strokes.iter().flatten().all(|p| coordinate_ok(*p)) {
        return Err("the drawn signature has invalid coordinates".into());
    }
    Ok(())
}

/// Check that a typed signature can be drawn: at least one path, every path a start point and
/// at least one segment, within the limits, and only finite coordinates.
pub fn validate_paths(paths: &InkPaths) -> Result<(), String> {
    if paths.is_empty() {
        return Err("the typed signature is empty".into());
    }
    let points: usize = paths.iter().flatten().map(PathSegment::weight).sum();
    if paths.len() > MAX_TYPED_PATHS || points > MAX_TYPED_POINTS {
        return Err(format!(
            "the typed signature is too detailed (at most {MAX_TYPED_PATHS} paths and \
             {MAX_TYPED_POINTS} points)"
        ));
    }
    for path in paths {
        if path.len() < 2 || !matches!(path[0], PathSegment::Line(_)) {
            return Err(
                "each path of the typed signature must start with a point and draw at least one \
                 segment"
                    .into(),
            );
        }
    }
    if !paths
        .iter()
        .flatten()
        .flat_map(PathSegment::points)
        .all(coordinate_ok)
    {
        return Err("the typed signature has invalid coordinates".into());
    }
    Ok(())
}

/// The pen a hand-drawn signature is stroked with: dark blue, 0.9 pt, round caps and joins.
pub(crate) const INK_PEN: &str = "0.05 0.05 0.30 RG\n0.9 w\n1 J\n1 j\n";

/// The colour a typed signature is filled with: the pen's dark blue.
pub(crate) const INK_FILL: &str = "0.05 0.05 0.30 rg\n";

/// A coordinate as the drawings write it: rounded to a hundredth of a point.
fn num(v: f32) -> String {
    crate::pades::fmt_num((v * 100.0).round() / 100.0)
}

/// The scale and offset that fit points spanning `[x0, x1] × [y0, y1]` (y down) into the box
/// `[x, y, w, h]` (y up), keeping their proportions and centred, leaving `margin` on each side.
/// `None` when there is nothing to fit or no room.
struct Fit {
    x0: f32,
    y1: f32,
    scale: f32,
    ox: f32,
    oy: f32,
}

impl Fit {
    fn new(
        points: impl Iterator<Item = [f32; 2]> + Clone,
        area: [f32; 4],
        margin: f32,
    ) -> Option<Fit> {
        let [x, y, w, h] = area;
        let min = |i: usize| points.clone().map(|p| p[i]).fold(f32::INFINITY, f32::min);
        let max = |i: usize| {
            points
                .clone()
                .map(|p| p[i])
                .fold(f32::NEG_INFINITY, f32::max)
        };
        let (x0, x1, y0, y1) = (min(0), max(0), min(1), max(1));
        if !(x0.is_finite() && y0.is_finite()) || w <= 0.0 || h <= 0.0 {
            return None;
        }
        let (dw, dh) = ((x1 - x0).max(1e-3), (y1 - y0).max(1e-3));
        // Never magnify a tiny drawing beyond the box.
        let scale = ((w - margin) / dw).min((h - margin) / dh).max(0.0);
        let (ox, oy) = (x + (w - dw * scale) / 2.0, y + (h - dh * scale) / 2.0);
        Some(Fit {
            x0,
            y1,
            scale,
            ox,
            oy,
        })
    }

    /// `p` in the form's coordinates: the drawing's y axis points down, the form's up.
    fn place(&self, p: [f32; 2]) -> (f32, f32) {
        (
            self.ox + (p[0] - self.x0) * self.scale,
            self.oy + (self.y1 - p[1]) * self.scale,
        )
    }
}

/// Content-stream operators stroking `strokes` scaled (keeping their proportions) and centred in
/// `area` = `[x, y, w, h]` of a form whose y axis points up. The rendering of every schema
/// version: pinned by the tests, since documents compare against it.
pub(crate) fn stroke_ops(strokes: &InkStrokes, area: [f32; 4]) -> String {
    // Leave room for the pen width.
    let Some(fit) = Fit::new(strokes.iter().flatten().copied(), area, 0.9) else {
        return String::new();
    };
    let mut s = INK_PEN.to_string();
    for stroke in strokes.iter().filter(|st| !st.is_empty()) {
        for (i, p) in stroke.iter().enumerate() {
            let (px, py) = fit.place(*p);
            s.push_str(&format!(
                "{} {} {}\n",
                num(px),
                num(py),
                if i == 0 { 'm' } else { 'l' }
            ));
        }
        if stroke.len() == 1 {
            // A single point: a zero-length line, which the round cap draws as a dot.
            let (px, py) = fit.place(stroke[0]);
            s.push_str(&format!("{} {} l\n", num(px), num(py)));
        }
        s.push_str("S\n");
    }
    s
}

/// The clipping rectangle a typed signature is drawn in, and its fill colour.
fn fill_head(area: [f32; 4]) -> String {
    format!(
        "q\n{} {} {} {} re\nW\nn\n{INK_FILL}",
        num(area[0]),
        num(area[1]),
        num(area[2]),
        num(area[3])
    )
}

/// Content-stream operators filling `paths` scaled (keeping their proportions) and centred in
/// `area` = `[x, y, w, h]` of a form whose y axis points up, clipped to it. Each path is
/// `x y m`, then `x y l` or `x1 y1 x2 y2 x y c` per segment, then `h`; one `f` (nonzero winding)
/// fills them all. Every point, control points included, lands inside the area, so the curves do
/// too (a Bézier curve stays inside the hull of its points).
pub(crate) fn fill_ops(paths: &InkPaths, area: [f32; 4]) -> String {
    let points = paths.iter().flatten().flat_map(|s| s.points());
    let Some(fit) = Fit::new(points, area, 0.0) else {
        return String::new();
    };
    let mut s = fill_head(area);
    for path in paths {
        for (i, seg) in path.iter().enumerate() {
            match seg {
                PathSegment::Line(p) => {
                    let (x, y) = fit.place(*p);
                    s.push_str(&format!(
                        "{} {} {}\n",
                        num(x),
                        num(y),
                        if i == 0 { 'm' } else { 'l' }
                    ));
                }
                PathSegment::Curve(c) => {
                    let (x1, y1) = fit.place([c[0], c[1]]);
                    let (x2, y2) = fit.place([c[2], c[3]]);
                    let (x, y) = fit.place([c[4], c[5]]);
                    s.push_str(&format!(
                        "{} {} {} {} {} {} c\n",
                        num(x1),
                        num(y1),
                        num(x2),
                        num(y2),
                        num(x),
                        num(y)
                    ));
                }
            }
        }
        s.push_str("h\n");
    }
    s.push_str("f\nQ\n");
    s
}

/// What the engine draws for `drawing` in `area` (nothing for a drawing it cannot draw).
pub(crate) fn drawing_ops(drawing: &SignatureDrawing, area: [f32; 4]) -> String {
    if drawing.validate().is_err() {
        return String::new();
    }
    match drawing {
        SignatureDrawing::Drawn { strokes } => stroke_ops(strokes, area),
        SignatureDrawing::Typed { paths } => fill_ops(paths, area),
    }
}

/// A number as the drawings write it: optional minus, digits and at most one dot, short.
fn plain_number(t: &str) -> Option<f32> {
    let digits = t.strip_prefix('-').unwrap_or(t);
    let plain = !digits.is_empty()
        && digits.len() <= 12
        && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        && digits.matches('.').count() <= 1;
    plain.then(|| t.parse().ok()).flatten()
}

/// Whether `(x, y)` lies inside `area` (`[x, y, w, h]`), give or take the rounding of the
/// written numbers.
fn inside(area: [f32; 4], x: f32, y: f32) -> bool {
    const SLACK: f32 = 0.01;
    x >= area[0] - SLACK
        && x <= area[0] + area[2] + SLACK
        && y >= area[1] - SLACK
        && y <= area[1] + area[3] + SLACK
}

/// Whether `ops` is nothing but pen strokes as [`stroke_ops`] writes them (or empty): the pen
/// setup, then `x y m`, one or more `x y l`, `S` per stroke, every point inside `area`
/// (`[x, y, w, h]`). Anything else — text, fills, images, another colour — is refused, so the
/// drawing area can only ever hold a scribble.
pub(crate) fn is_ink(ops: &str, area: [f32; 4]) -> bool {
    if ops.is_empty() {
        return true;
    }
    let Some(strokes) = ops.strip_prefix(INK_PEN) else {
        return false;
    };
    let (mut stroke_count, mut points, mut in_stroke) = (0usize, 0usize, 0usize);
    for line in strokes.strip_suffix('\n').unwrap_or("").split('\n') {
        if line == "S" {
            // A stroke is a start point and at least one line to draw.
            if in_stroke < 2 {
                return false;
            }
            in_stroke = 0;
            stroke_count += 1;
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        let [x, y, op] = parts[..] else {
            return false;
        };
        let (Some(x), Some(y)) = (plain_number(x), plain_number(y)) else {
            return false;
        };
        let expected_op = if in_stroke == 0 { "m" } else { "l" };
        if op != expected_op || !inside(area, x, y) {
            return false;
        }
        in_stroke += 1;
        points += 1;
    }
    // Twice the drawing limit: a single point is written as two (a zero-length line).
    in_stroke == 0 && (1..=MAX_INK_STROKES).contains(&stroke_count) && points <= 2 * MAX_INK_POINTS
}

/// Whether `ops` is nothing but filled paths as [`fill_ops`] writes them: the clip to `area`
/// (`[x, y, w, h]`) and the fill colour, then per path `x y m`, one or more `x y l` or
/// `x1 y1 x2 y2 x y c`, and `h`, then one `f` and `Q`; every point, control points included,
/// inside `area`, within the limits. No other operator, colour, text, image or XObject.
pub(crate) fn is_filled_paths(ops: &str, area: [f32; 4]) -> bool {
    let Some(body) = ops
        .strip_prefix(fill_head(area).as_str())
        .and_then(|rest| rest.strip_suffix("f\nQ\n"))
    else {
        return false;
    };
    let (mut paths, mut points, mut in_path) = (0usize, 0usize, 0usize);
    for line in body.strip_suffix('\n').unwrap_or("").split('\n') {
        if line == "h" {
            if in_path < 2 {
                return false;
            }
            in_path = 0;
            paths += 1;
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        let Some((op, coords)) = parts.split_last() else {
            return false;
        };
        let expected = match (*op, coords.len(), in_path) {
            ("m", 2, 0) => 1,
            ("l", 2, 1..) => 1,
            ("c", 6, 1..) => 3,
            _ => return false,
        };
        let Some(values) = coords
            .iter()
            .map(|t| plain_number(t))
            .collect::<Option<Vec<f32>>>()
        else {
            return false;
        };
        if !values
            .as_chunks::<2>()
            .0
            .iter()
            .all(|p| inside(area, p[0], p[1]))
        {
            return false;
        }
        in_path += 1;
        points += expected;
    }
    in_path == 0 && (1..=MAX_TYPED_PATHS).contains(&paths) && points <= MAX_TYPED_POINTS
}

#[cfg(feature = "typed")]
pub mod typed;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strokes_are_scaled_into_their_box_with_y_flipped() {
        // A 100 x 50 drawing into a 50 x 50 box at (10, 5): scale ~0.49, centred vertically.
        let ink: InkStrokes = vec![vec![[0.0, 0.0], [100.0, 50.0]]];
        let ops = stroke_ops(&ink, [10.0, 5.0, 50.0, 50.0]);
        let coords: Vec<Vec<f32>> = ops
            .lines()
            .filter(|l| l.ends_with(" m") || l.ends_with(" l"))
            .map(|l| l.split(' ').take(2).map(|v| v.parse().unwrap()).collect())
            .collect();
        // The top-left of the drawing (y = 0, pointing down) is the higher point on the page.
        assert!(coords[0][1] > coords[1][1], "{ops}");
        for p in &coords {
            assert!(
                (10.0..=60.0).contains(&p[0]) && (5.0..=55.0).contains(&p[1]),
                "{ops}"
            );
        }
        assert!((coords[1][0] - coords[0][0] - 49.1).abs() < 0.05, "{ops}");
        // A single point is drawn as a dot (a zero-length stroke with a round cap).
        let dot = stroke_ops(&vec![vec![[3.0, 3.0]]], [0.0, 0.0, 20.0, 20.0]);
        assert!(dot.contains(" m\n") && dot.contains(" l\nS\n"), "{dot}");
    }

    #[test]
    fn only_pen_strokes_count_as_ink() {
        let area = [4.0, 3.0, 84.0, 34.0];
        let ink = |strokes: &str| is_ink(&format!("{INK_PEN}{strokes}"), area);
        assert!(is_ink("", area), "no drawing at all");
        assert!(ink("10 10 m\n20 20 l\nS\n"));
        assert!(ink(
            "10 10 m\n10 10 l\nS\n40.25 12.5 m\n50 30 l\n60 12 l\nS\n"
        ));

        assert!(!is_ink("10 10 m\n20 20 l\nS\n", area), "another pen");
        assert!(!ink(""), "pen set up, nothing drawn");
        assert!(!ink("10 10 m\nS\n"), "a stroke needs a line");
        assert!(!ink("10 10 m\n20 20 l\n"), "unfinished stroke");
        assert!(!ink("10 10 m\n20 20 l\nf\n"), "a fill");
        assert!(!ink("10 10 m\n20 20 l\nS\n1 0 0 rg\n"), "a colour change");
        assert!(!ink("10 10 m\n20 20 30 30 40 40 c\nS\n"), "a curve");
        assert!(!ink("10 10 m\n200 20 l\nS\n"), "outside the area");
        assert!(!ink("10 -5 m\n20 20 l\nS\n"), "below the area");
        assert!(!ink("1e1 10 m\n20 20 l\nS\n"), "not a plain number");
        assert!(!ink("10 10 m\n20 20 l\nS\nBT\n(x) Tj\nET\n"), "text");
        assert!(!ink("10 10 m \n20 20 l\nS\n"), "stray space");
        // A typed signature is not pen strokes.
        let typed = fill_ops(&ring(), area);
        assert!(!is_ink(&typed, area));
    }

    /// A ring: an outer contour and a counter, curves and lines.
    fn ring() -> InkPaths {
        use PathSegment::{Curve, Line};
        vec![
            vec![
                Line([0.0, 50.0]),
                Curve([0.0, 0.0, 100.0, 0.0, 100.0, 50.0]),
                Curve([100.0, 100.0, 0.0, 100.0, 0.0, 50.0]),
            ],
            vec![
                Line([30.0, 50.0]),
                Line([50.0, 70.0]),
                Line([70.0, 50.0]),
                Line([50.0, 30.0]),
            ],
        ]
    }

    #[test]
    fn typed_paths_are_filled_in_their_box_clipped_with_y_flipped() {
        let area = [4.0, 3.0, 84.0, 34.0];
        let ops = fill_ops(&ring(), area);
        assert_eq!(
            ops,
            "q\n4 3 84 34 re\nW\nn\n0.05 0.05 0.30 rg\n\
             29 20 m\n29 37 63 37 63 20 c\n63 3 29 3 29 20 c\nh\n\
             39.2 20 m\n46 13.2 l\n52.8 20 l\n46 26.8 l\nh\nf\nQ\n"
        );
        assert!(is_filled_paths(&ops, area));
        // The point at the top of the drawing (y = 30, y pointing down) is the higher one on
        // the page; every point stays in the box.
        assert!(ops.contains("46 26.8 l"), "{ops}");
    }

    #[test]
    fn only_filled_paths_in_one_colour_count_as_typed() {
        let area = [4.0, 3.0, 84.0, 34.0];
        let head = fill_head(area);
        let typed = |body: &str| is_filled_paths(&format!("{head}{body}f\nQ\n"), area);
        assert!(typed("10 10 m\n20 20 l\nh\n"));
        assert!(typed(
            "10 10 m\n10 30 20 30 20 10 c\n15 5 l\nh\n40 10 m\n50 20 l\nh\n"
        ));

        assert!(!is_filled_paths("", area), "nothing at all");
        assert!(!typed(""), "set up, nothing filled");
        assert!(!typed("10 10 m\nh\n"), "a path needs a segment");
        assert!(!typed("10 10 m\n20 20 l\n"), "unclosed path");
        assert!(
            !typed("10 10 20 20 30 30 c\nh\n"),
            "a path must start with a point"
        );
        assert!(!typed("10 10 m\n20 20 m\nh\n"), "two starts");
        assert!(!typed("10 10 m\n20 20 l\nh\n1 0 0 rg\n"), "a colour change");
        assert!(!typed("10 10 m\n20 20 l\nS\n"), "a stroke");
        assert!(!typed("10 10 m\n20 20 l\nh\nBT\n(x) Tj\nET\n"), "text");
        assert!(!typed("10 10 m\n20 20 l\nh\n/Im0 Do\n"), "an XObject");
        assert!(
            !typed("10 10 m\n20 20 l\nh\n2 0 0 2 0 0 cm\n"),
            "a transform"
        );
        assert!(
            !typed("10 10 m\n20 20 l\n30 30 v\nh\n"),
            "another curve operator"
        );
        assert!(
            !typed("10 10 m\n20 20 l\n20 20 30 30 l\nh\n"),
            "wrong arity"
        );
        assert!(!typed("10 10 m\n200 20 l\nh\n"), "outside the area");
        assert!(
            !typed("10 10 m\n20 20 200 20 30 30 c\nh\n"),
            "a control point outside"
        );
        assert!(!typed("10 10 m\n20 1e1 l\nh\n"), "not a plain number");
        assert!(!typed("10 10 m\n20  20 l\nh\n"), "stray space");
        // Another clip, or none.
        let other = format!("q\n0 0 220 40 re\nW\nn\n{INK_FILL}10 10 m\n20 20 l\nh\nf\nQ\n");
        assert!(!is_filled_paths(&other, area));
        let unclipped = format!("{INK_FILL}10 10 m\n20 20 l\nh\nf\n");
        assert!(!is_filled_paths(&unclipped, area));
        // Even-odd filling, or a fill and a stroke.
        assert!(!is_filled_paths(
            &format!("{head}10 10 m\n20 20 l\nh\nf*\nQ\n"),
            area
        ));
        assert!(!is_filled_paths(
            &format!("{head}10 10 m\n20 20 l\nh\nB\nQ\n"),
            area
        ));
        // Pen strokes are not filled paths.
        assert!(!is_filled_paths(
            &stroke_ops(&vec![vec![[0.0, 0.0], [5.0, 5.0]]], area),
            area
        ));
    }

    #[test]
    fn a_typed_signature_over_the_limits_is_refused_by_the_rule_too() {
        let area = [0.0, 0.0, 100.0, 100.0];
        let path = vec![PathSegment::Line([1.0, 1.0]), PathSegment::Line([2.0, 2.0])];
        let many: InkPaths = vec![path; MAX_TYPED_PATHS + 1];
        assert!(validate_paths(&many).is_err());
        assert!(!is_filled_paths(&fill_ops(&many, area), area));
        let at_limit: InkPaths = many[..MAX_TYPED_PATHS].to_vec();
        assert!(validate_paths(&at_limit).is_ok());
        assert!(is_filled_paths(&fill_ops(&at_limit, area), area));
    }

    #[test]
    fn drawings_are_validated() {
        use PathSegment::{Curve, Line};
        assert!(validate_paths(&ring()).is_ok());
        assert!(validate_paths(&vec![]).is_err());
        assert!(validate_paths(&vec![vec![Line([0.0, 0.0])]]).is_err());
        assert!(validate_paths(&vec![vec![
            Curve([0.0, 0.0, 1.0, 1.0, 2.0, 2.0]),
            Line([3.0, 3.0])
        ]])
        .is_err());
        assert!(validate_paths(&vec![vec![Line([0.0, 0.0]), Line([f32::NAN, 1.0])]]).is_err());
        assert!(validate_paths(&vec![vec![
            Line([0.0, 0.0]),
            Curve([0.0, 0.0, 2e6, 1.0, 2.0, 2.0])
        ]])
        .is_err());
        let points = MAX_TYPED_POINTS / 3 + 1;
        let curvy = vec![std::iter::once(Line([0.0, 0.0]))
            .chain(std::iter::repeat_n(Curve([1.0; 6]), points))
            .collect::<Vec<_>>()];
        assert!(
            validate_paths(&curvy).is_err(),
            "a curve counts three points"
        );

        assert!(validate_ink(&vec![]).is_err());
        assert!(validate_ink(&vec![vec![[0.0, f32::INFINITY]]]).is_err());
        assert!(SignatureDrawing::Typed { paths: vec![] }
            .validate()
            .is_err());
        assert!(SignatureDrawing::Drawn {
            strokes: vec![vec![[0.0, 0.0]]]
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn a_drawing_reads_and_writes_as_its_kind() {
        let typed = SignatureDrawing::Typed { paths: ring() };
        let json = serde_json::to_string(&typed).unwrap();
        assert!(
            json.starts_with(
                r#"{"kind":"typed","paths":[[[0.0,50.0],[0.0,0.0,100.0,0.0,100.0,50.0]"#
            ),
            "{json}"
        );
        assert_eq!(
            serde_json::from_str::<SignatureDrawing>(&json).unwrap(),
            typed
        );
        let drawn: SignatureDrawing =
            serde_json::from_str(r#"{"kind":"drawn","strokes":[[[1.5,2],[3,4]]]}"#).unwrap();
        assert_eq!(
            drawn,
            SignatureDrawing::Drawn {
                strokes: vec![vec![[1.5, 2.0], [3.0, 4.0]]]
            }
        );
        assert_eq!((drawn.kind(), typed.kind()), ("drawn", "typed"));
        for bad in [
            r#"{"kind":"image","data":"…"}"#,
            r#"{"kind":"typed","paths":[[[1,2],[1,2,3]]]}"#,
            r#"{"kind":"typed","paths":[[[1,2]]],"text":"Bob"}"#,
            r#"{"kind":"drawn","strokes":[],"paths":[]}"#,
            r#"{"strokes":[[[1,2]]]}"#,
        ] {
            assert!(
                serde_json::from_str::<SignatureDrawing>(bad).is_err(),
                "{bad}"
            );
        }
    }
}
