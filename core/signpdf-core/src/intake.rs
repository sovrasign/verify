//! Intake: what a client does to a file before it becomes an envelope's source document.
//!
//! - [`images_to_pdf`]: photos, scans and image files as one PDF, one page per image, on the
//!   device (no server ever parses an image). JPEG files go in as they are (`DCTDecode`); TIFF
//!   files, multi-page ones included, go in without decoding a pixel: each strip keeps its own
//!   compression, which PDF readers decode themselves (CCITT G3/G4 fax, LZW, Deflate, PackBits,
//!   JPEG). Other formats (PNG, WebP, HEIC, GIF, BMP) are decoded by the host, which has decoders
//!   for them (a browser's), and handed over as JPEG.
//! - [`source_info`]: what a PDF needs before it can be prepared: its encryption (an open password
//!   is asked for and removed on the device), its PDF/A claim (signing keeps the claim but the
//!   result may no longer conform) and its layers (flattened by the service's sanitizer).
//! - [`decrypt`]: a PDF with an open password, decrypted with the password the person typed and
//!   saved again without encryption, so the password never leaves the device.
//!
//! The image layout: every image is fitted to the paper (A4 or US Letter, the host chooses by
//! the person's region), turned to landscape when it is wide, centred, with a margin the host
//! chooses (a photo gets one; a scan, already a page, fills the paper). The image's physical
//! aspect ratio is kept: a fax TIFF at 204 x 98 dpi is not stretched. Its EXIF or TIFF
//! orientation is applied.
//!
//! Limits: at most [`MAX_PAGES`] pages in one call and
//! [`MAX_PIXELS`] pixels per image. A refusal is an [`IntakeError`]: a stable `code` the host
//! translates, and an English `message`.

use std::collections::HashSet;
use std::fmt;

use lopdf::{dictionary, Dictionary, Document, Object, ObjectId, Stream, StringFormat};
use serde::{Deserialize, Serialize};

/// Pages one call may make (images, TIFF pages counted one by one).
pub const MAX_PAGES: usize = 100;
/// Pixels in one image (50 megapixels).
pub const MAX_PIXELS: u64 = 50_000_000;
/// The margin around a photo, in points, when the host gives none.
pub const PHOTO_MARGIN: f32 = 18.0;

/// Why a file could not be taken in. `code` is stable (hosts translate it); `message` is
/// English detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeError {
    /// `not_an_image`, `unsupported_image`, `unreadable_image`, `too_many_pages`,
    /// `too_many_pixels`, `no_image`, `unreadable_pdf`, `not_encrypted`, `no_open_password`,
    /// `wrong_password` or `certificate_encryption`.
    pub code: &'static str,
    pub message: String,
}

impl IntakeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        IntakeError {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for IntakeError {
    /// `code: message`, so a host that only passes the text along can still read the code.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IntakeError {}

type R<T> = std::result::Result<T, IntakeError>;

fn unsupported(what: impl Into<String>) -> IntakeError {
    IntakeError::new("unsupported_image", what)
}

fn unreadable(what: impl Into<String>) -> IntakeError {
    IntakeError::new("unreadable_image", what)
}

// ---------- the paper ----------------------------------------------------------------------

/// The paper images are fitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Paper {
    #[default]
    A4,
    Letter,
}

impl Paper {
    /// Portrait width and height in points.
    pub fn size(self) -> (f32, f32) {
        match self {
            Paper::A4 => (595.28, 841.89),
            Paper::Letter => (612.0, 792.0),
        }
    }
}

// ---------- images to PDF ------------------------------------------------------------------

/// One image file for [`images_to_pdf`].
#[derive(Debug, Clone, Copy)]
pub struct ImageInput<'a> {
    /// The file: JPEG or TIFF (told apart by their first bytes).
    pub bytes: &'a [u8],
    /// The margin around each of its pages, in points (0 for a scan).
    pub margin: f32,
}

/// The PDF [`images_to_pdf`] made.
#[derive(Debug, Clone)]
pub struct ImagesPdf {
    pub pdf: Vec<u8>,
    /// Pages each input became (a multi-page TIFF several), in order.
    pub pages: Vec<usize>,
}

/// The kind of an image file, from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Jpeg,
    Tiff,
}

/// What `bytes` is, or None when it is neither JPEG nor TIFF.
pub fn image_kind(bytes: &[u8]) -> Option<ImageKind> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(ImageKind::Jpeg)
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        Some(ImageKind::Tiff)
    } else if bytes.starts_with(b"II+\0") || bytes.starts_with(b"MM\0+") {
        // BigTIFF: still a TIFF, refused with a clearer message below.
        Some(ImageKind::Tiff)
    } else {
        None
    }
}

/// One PDF of `images`, one page per image (per page of a multi-page TIFF), fitted to `paper`.
pub fn images_to_pdf(images: &[ImageInput<'_>], paper: Paper) -> R<ImagesPdf> {
    if images.is_empty() {
        return Err(IntakeError::new("no_image", "no image was given"));
    }
    let mut pictures: Vec<(Picture, f32)> = vec![];
    let mut pages = Vec::with_capacity(images.len());
    for (i, img) in images.iter().enumerate() {
        let found = match image_kind(img.bytes) {
            Some(ImageKind::Jpeg) => vec![jpeg_picture(img.bytes)?],
            Some(ImageKind::Tiff) => tiff_pictures(img.bytes, MAX_PAGES - pictures.len())?,
            None => {
                return Err(IntakeError::new(
                    "not_an_image",
                    format!("image {} is neither JPEG nor TIFF", i + 1),
                ))
            }
        };
        pages.push(found.len());
        let margin = if img.margin.is_finite() {
            img.margin.clamp(0.0, 144.0)
        } else {
            PHOTO_MARGIN
        };
        for p in found {
            if pictures.len() >= MAX_PAGES {
                return Err(too_many_pages());
            }
            pictures.push((p, margin));
        }
    }
    let pdf = build_pdf(&pictures, paper)?;
    Ok(ImagesPdf { pdf, pages })
}

fn too_many_pages() -> IntakeError {
    IntakeError::new(
        "too_many_pages",
        format!("one document can be made from at most {MAX_PAGES} images or TIFF pages"),
    )
}

/// One image ready to be placed: its pixel size, its physical aspect, its orientation and the
/// image XObjects that draw it, top to bottom.
struct Picture {
    width: u32,
    height: u32,
    /// Horizontal and vertical resolution, only their ratio matters (1, 1 when unknown).
    res_x: f32,
    res_y: f32,
    /// EXIF / TIFF orientation, 1 to 8.
    orientation: u8,
    strips: Vec<StripImage>,
}

struct StripImage {
    rows: u32,
    stream: Stream,
}

fn check_pixels(width: u32, height: u32) -> R<()> {
    if width == 0 || height == 0 {
        return Err(unreadable("the image has no pixels"));
    }
    if width as u64 * height as u64 > MAX_PIXELS {
        return Err(IntakeError::new(
            "too_many_pixels",
            format!(
                "the image has {} megapixels; at most {} are accepted",
                (width as u64 * height as u64).div_ceil(1_000_000),
                MAX_PIXELS / 1_000_000
            ),
        ));
    }
    Ok(())
}

// ----- JPEG -----

/// The JPEG facts a PDF needs: size, components, and the Adobe marker (inverted CMYK), plus
/// the EXIF orientation.
struct JpegInfo {
    width: u32,
    height: u32,
    components: u8,
    adobe: bool,
    orientation: u8,
}

fn jpeg_info(b: &[u8]) -> R<JpegInfo> {
    let mut at = 2usize;
    let mut adobe = false;
    let mut orientation = 1u8;
    loop {
        // Fill bytes before a marker.
        while b.get(at) == Some(&0xFF) && b.get(at + 1) == Some(&0xFF) {
            at += 1;
        }
        if b.get(at) != Some(&0xFF) {
            return Err(unreadable("the JPEG file is damaged (no frame header)"));
        }
        let marker = *b
            .get(at + 1)
            .ok_or_else(|| unreadable("the JPEG file ends early"))?;
        at += 2;
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if marker == 0xD9 || marker == 0xDA {
            return Err(unreadable("the JPEG file has no frame header"));
        }
        let len = be16(b, at).ok_or_else(|| unreadable("the JPEG file ends early"))? as usize;
        if len < 2 || at + len > b.len() {
            return Err(unreadable(
                "the JPEG file is damaged (a segment runs past its end)",
            ));
        }
        let seg = &b[at + 2..at + len];
        match marker {
            0xE1 if seg.starts_with(b"Exif\0\0") => {
                if let Ok(t) = Tiff::open(&seg[6..]) {
                    if let Ok(Some(ifd)) = t.first_ifd() {
                        if let Some(o) = t.value(&ifd, TAG_ORIENTATION) {
                            if (1..=8).contains(&o) {
                                orientation = o as u8;
                            }
                        }
                    }
                }
            }
            0xEE if seg.starts_with(b"Adobe") => adobe = true,
            0xC0..=0xCF if marker != 0xC4 && marker != 0xC8 && marker != 0xCC => {
                if matches!(marker, 0xC9..=0xCB | 0xCD..=0xCF) {
                    return Err(unsupported(
                        "this JPEG uses arithmetic coding, which PDF readers do not all show; save it again as a regular JPEG",
                    ));
                }
                if seg.len() < 6 {
                    return Err(unreadable("the JPEG frame header is too short"));
                }
                if seg[0] != 8 {
                    return Err(unsupported(format!(
                        "this JPEG has {} bits per sample; save it again as a regular 8-bit JPEG",
                        seg[0]
                    )));
                }
                let height = u16::from_be_bytes([seg[1], seg[2]]) as u32;
                let width = u16::from_be_bytes([seg[3], seg[4]]) as u32;
                let components = seg[5];
                if !matches!(components, 1 | 3 | 4) {
                    return Err(unsupported(format!(
                        "a JPEG with {components} colour components"
                    )));
                }
                return Ok(JpegInfo {
                    width,
                    height,
                    components,
                    adobe,
                    orientation,
                });
            }
            _ => {}
        }
        at += len;
    }
}

fn jpeg_picture(b: &[u8]) -> R<Picture> {
    let info = jpeg_info(b)?;
    check_pixels(info.width, info.height)?;
    let mut dict = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Image",
        "Width" => info.width as i64,
        "Height" => info.height as i64,
        "BitsPerComponent" => 8,
        "Filter" => "DCTDecode",
    };
    dict.set("ColorSpace", device_space(info.components));
    if info.components == 4 && info.adobe {
        // Adobe's CMYK JPEGs store inverted values.
        dict.set("Decode", inverted(4));
    }
    let mut stream = Stream::new(dict, b.to_vec());
    stream.allows_compression = false;
    Ok(Picture {
        width: info.width,
        height: info.height,
        res_x: 1.0,
        res_y: 1.0,
        orientation: info.orientation,
        strips: vec![StripImage {
            rows: info.height,
            stream,
        }],
    })
}

fn device_space(components: u8) -> Object {
    Object::Name(
        match components {
            1 => "DeviceGray",
            4 => "DeviceCMYK",
            _ => "DeviceRGB",
        }
        .into(),
    )
}

fn inverted(components: usize) -> Object {
    Object::Array(
        (0..components)
            .flat_map(|_| [Object::Integer(1), Object::Integer(0)])
            .collect(),
    )
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

// ----- TIFF -----

const TAG_SUBFILE_TYPE: u16 = 254;
const TAG_WIDTH: u16 = 256;
const TAG_HEIGHT: u16 = 257;
const TAG_BITS: u16 = 258;
const TAG_COMPRESSION: u16 = 259;
const TAG_PHOTOMETRIC: u16 = 262;
const TAG_FILL_ORDER: u16 = 266;
const TAG_STRIP_OFFSETS: u16 = 273;
const TAG_ORIENTATION: u16 = 274;
const TAG_SAMPLES: u16 = 277;
const TAG_ROWS_PER_STRIP: u16 = 278;
const TAG_STRIP_COUNTS: u16 = 279;
const TAG_X_RES: u16 = 282;
const TAG_Y_RES: u16 = 283;
const TAG_PLANAR: u16 = 284;
const TAG_T4_OPTIONS: u16 = 292;
const TAG_PREDICTOR: u16 = 317;
const TAG_COLOR_MAP: u16 = 320;
const TAG_TILE_WIDTH: u16 = 322;
const TAG_EXTRA_SAMPLES: u16 = 338;
const TAG_INK_SET: u16 = 332;
const TAG_JPEG_TABLES: u16 = 347;

/// A TIFF file (or the TIFF structure inside a JPEG's EXIF block).
struct Tiff<'a> {
    b: &'a [u8],
    le: bool,
}

/// One IFD entry: its tag, type, count and where its value is (inline or an offset).
#[derive(Clone, Copy)]
struct Entry {
    tag: u16,
    kind: u16,
    count: u32,
    /// Offset of the value's bytes in the file.
    at: usize,
}

impl<'a> Tiff<'a> {
    fn open(b: &'a [u8]) -> R<Self> {
        let le =
            match b.get(0..4) {
                Some(b"II*\0") => true,
                Some(b"MM\0*") => false,
                Some(b"II+\0") | Some(b"MM\0+") => return Err(unsupported(
                    "BigTIFF files are not accepted; save the image as a regular TIFF, PNG or JPEG",
                )),
                _ => return Err(unreadable("not a TIFF file")),
            };
        Ok(Tiff { b, le })
    }

    fn u16_at(&self, at: usize) -> Option<u16> {
        let s = self.b.get(at..at + 2)?;
        Some(if self.le {
            u16::from_le_bytes([s[0], s[1]])
        } else {
            u16::from_be_bytes([s[0], s[1]])
        })
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        let s = self.b.get(at..at + 4)?;
        let a = [s[0], s[1], s[2], s[3]];
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn first_ifd(&self) -> R<Option<Vec<Entry>>> {
        let at = self
            .u32_at(4)
            .ok_or_else(|| unreadable("the TIFF file ends early"))?;
        Ok(if at == 0 {
            None
        } else {
            Some(self.ifd(at as usize)?.0)
        })
    }

    /// The entries of the IFD at `at`, and the offset of the next one (0: none).
    fn ifd(&self, at: usize) -> R<(Vec<Entry>, u32)> {
        let damaged = || unreadable("the TIFF file is damaged (a directory runs past its end)");
        let n = self.u16_at(at).ok_or_else(damaged)? as usize;
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let e = at + 2 + i * 12;
            let tag = self.u16_at(e).ok_or_else(damaged)?;
            let kind = self.u16_at(e + 2).ok_or_else(damaged)?;
            let count = self.u32_at(e + 4).ok_or_else(damaged)?;
            let size = match kind {
                1 | 2 | 6 | 7 => 1usize,
                3 | 8 => 2,
                4 | 9 | 11 => 4,
                5 | 10 | 12 => 8,
                _ => 0, // unknown type: skipped
            };
            let total = size.saturating_mul(count as usize);
            let value_at = if total <= 4 {
                e + 8
            } else {
                self.u32_at(e + 8).ok_or_else(damaged)? as usize
            };
            entries.push(Entry {
                tag,
                kind,
                count,
                at: value_at,
            });
        }
        let next = self.u32_at(at + 2 + n * 12).ok_or_else(damaged)?;
        Ok((entries, next))
    }

    fn entry(ifd: &[Entry], tag: u16) -> Option<Entry> {
        ifd.iter().find(|e| e.tag == tag).copied()
    }

    /// The integer values of an entry (BYTE, SHORT or LONG), at most `max` of them.
    fn values(&self, e: &Entry, max: usize) -> R<Vec<u32>> {
        let count = e.count as usize;
        if count > max {
            return Err(unreadable("the TIFF file is damaged (a list is too long)"));
        }
        let damaged = || unreadable("the TIFF file is damaged (a value runs past its end)");
        (0..count)
            .map(|i| match e.kind {
                1 | 7 => self.b.get(e.at + i).map(|v| *v as u32).ok_or_else(damaged),
                3 => self.u16_at(e.at + i * 2).map(u32::from).ok_or_else(damaged),
                4 => self.u32_at(e.at + i * 4).ok_or_else(damaged),
                _ => Err(unreadable(
                    "the TIFF file has a number of an unexpected type",
                )),
            })
            .collect()
    }

    /// The first integer value of `tag` in `ifd`.
    fn value(&self, ifd: &[Entry], tag: u16) -> Option<u32> {
        let e = Self::entry(ifd, tag)?;
        self.values(&e, u32::MAX as usize).ok()?.first().copied()
    }

    /// A RATIONAL value.
    fn rational(&self, ifd: &[Entry], tag: u16) -> Option<f32> {
        let e = Self::entry(ifd, tag)?;
        if e.kind != 5 || e.count == 0 {
            return None;
        }
        let n = self.u32_at(e.at)? as f32;
        let d = self.u32_at(e.at + 4)? as f32;
        (d > 0.0 && n > 0.0).then_some(n / d)
    }

    fn bytes_of(&self, e: &Entry) -> R<&'a [u8]> {
        self.b
            .get(e.at..e.at + e.count as usize)
            .ok_or_else(|| unreadable("the TIFF file is damaged (a value runs past its end)"))
    }
}

/// Every page of a TIFF file (reduced-resolution copies skipped), at most `room` of them.
fn tiff_pictures(b: &[u8], room: usize) -> R<Vec<Picture>> {
    let t = Tiff::open(b)?;
    let mut out = vec![];
    let mut seen = HashSet::new();
    let mut at = t
        .u32_at(4)
        .ok_or_else(|| unreadable("the TIFF file ends early"))?;
    while at != 0 {
        if !seen.insert(at) {
            return Err(unreadable("the TIFF file is damaged (its pages loop)"));
        }
        let (ifd, next) = t.ifd(at as usize)?;
        at = next;
        // A thumbnail or another reduced-resolution copy of a page.
        if t.value(&ifd, TAG_SUBFILE_TYPE).is_some_and(|v| v & 1 == 1) {
            continue;
        }
        if out.len() >= room {
            return Err(too_many_pages());
        }
        out.push(tiff_page(&t, &ifd).map_err(|e| IntakeError {
            code: e.code,
            message: format!("page {} of the TIFF file: {}", out.len() + 1, e.message),
        })?);
    }
    if out.is_empty() {
        return Err(unreadable("the TIFF file has no page"));
    }
    Ok(out)
}

fn unsupported_colour(photometric: u32) -> IntakeError {
    unsupported(format!(
        "the colour model {photometric}; save the image as RGB, greyscale or black and white"
    ))
}

fn tiff_page(t: &Tiff<'_>, ifd: &[Entry]) -> R<Picture> {
    let width = t
        .value(ifd, TAG_WIDTH)
        .ok_or_else(|| unreadable("no width"))?;
    let height = t
        .value(ifd, TAG_HEIGHT)
        .ok_or_else(|| unreadable("no height"))?;
    check_pixels(width, height)?;
    if Tiff::entry(ifd, TAG_TILE_WIDTH).is_some() {
        return Err(unsupported(
            "tiled TIFF files are not accepted; save the image as a regular TIFF, PNG or JPEG",
        ));
    }
    let samples = t.value(ifd, TAG_SAMPLES).unwrap_or(1);
    let bits = match Tiff::entry(ifd, TAG_BITS) {
        Some(e) => {
            let v = t.values(&e, 16)?;
            if v.iter().any(|x| *x != v[0]) {
                return Err(unsupported("samples of different sizes"));
            }
            v.first().copied().unwrap_or(1)
        }
        None => 1,
    };
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(unsupported(format!(
            "{bits} bits per sample; save the image as an 8-bit TIFF, PNG or JPEG"
        )));
    }
    let compression = t.value(ifd, TAG_COMPRESSION).unwrap_or(1);
    let photometric = t
        .value(ifd, TAG_PHOTOMETRIC)
        .ok_or_else(|| unreadable("no colour model (Photometric)"))?;
    let planar = t.value(ifd, TAG_PLANAR).unwrap_or(1);
    if samples > 1 && planar != 1 {
        return Err(unsupported(
            "colour planes stored separately; save the image as a regular TIFF, PNG or JPEG",
        ));
    }
    let colors = match photometric {
        0 | 1 | 3 => 1,
        2 | 6 => 3,
        5 => 4,
        other => return Err(unsupported_colour(other)),
    };
    if samples != colors || Tiff::entry(ifd, TAG_EXTRA_SAMPLES).is_some() {
        return Err(unsupported(
            "a TIFF with transparency or extra channels; save the image as PNG or JPEG",
        ));
    }
    if photometric == 6 && compression != 7 {
        return Err(unsupported("YCbCr colour without JPEG compression"));
    }
    if photometric == 5 && t.value(ifd, TAG_INK_SET).is_some_and(|ink| ink != 1) {
        return Err(unsupported("colour separations other than CMYK"));
    }
    let fill_reversed = t.value(ifd, TAG_FILL_ORDER) == Some(2);
    let predictor = t.value(ifd, TAG_PREDICTOR).unwrap_or(1);
    if !matches!(predictor, 1 | 2) {
        return Err(unsupported("a floating-point predictor"));
    }
    let orientation = t
        .value(ifd, TAG_ORIENTATION)
        .filter(|o| (1..=8).contains(o))
        .unwrap_or(1) as u8;
    let (res_x, res_y) = match (t.rational(ifd, TAG_X_RES), t.rational(ifd, TAG_Y_RES)) {
        (Some(x), Some(y)) if (0.01..=100.0).contains(&(x / y)) => (x, y),
        _ => (1.0, 1.0),
    };

    // The strips.
    let offsets_e = Tiff::entry(ifd, TAG_STRIP_OFFSETS)
        .ok_or_else(|| unreadable("no image data (StripOffsets)"))?;
    let counts_e = Tiff::entry(ifd, TAG_STRIP_COUNTS)
        .ok_or_else(|| unreadable("no image data sizes (StripByteCounts)"))?;
    let rows_per_strip = t
        .value(ifd, TAG_ROWS_PER_STRIP)
        .filter(|r| *r > 0)
        .unwrap_or(height)
        .min(height);
    let strips_n = height.div_ceil(rows_per_strip) as usize;
    let offsets = t.values(&offsets_e, strips_n.max(1))?;
    let counts = t.values(&counts_e, strips_n.max(1))?;
    if offsets.len() != strips_n || counts.len() != strips_n {
        return Err(unreadable(
            "the number of image strips does not match the image height",
        ));
    }
    let mut data: Vec<&[u8]> = Vec::with_capacity(strips_n);
    for (o, c) in offsets.iter().zip(&counts) {
        let (o, c) = (*o as usize, *c as usize);
        data.push(
            t.b.get(o..o.saturating_add(c))
                .ok_or_else(|| unreadable("image data runs past the end of the file"))?,
        );
    }
    let rows_of = |i: usize| -> u32 {
        let start = i as u32 * rows_per_strip;
        rows_per_strip.min(height - start)
    };

    // The colour space and decode array.
    let mut base = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Image",
        "Width" => width as i64,
        "BitsPerComponent" => bits as i64,
    };
    match photometric {
        3 => {
            let e = Tiff::entry(ifd, TAG_COLOR_MAP)
                .ok_or_else(|| unreadable("a palette image without its palette (ColorMap)"))?;
            let n = 1usize << bits;
            let map = t.values(&e, 3 * n)?;
            if map.len() != 3 * n {
                return Err(unreadable("the palette (ColorMap) has the wrong size"));
            }
            let mut lookup = Vec::with_capacity(3 * n);
            for i in 0..n {
                for c in 0..3 {
                    lookup.push((map[c * n + i] >> 8) as u8);
                }
            }
            base.set(
                "ColorSpace",
                vec![
                    Object::Name(b"Indexed".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Integer(n as i64 - 1),
                    Object::String(lookup, StringFormat::Hexadecimal),
                ],
            );
        }
        _ => base.set("ColorSpace", device_space(colors as u8)),
    }
    let ccitt = matches!(compression, 2..=4);
    // WhiteIsZero: CCITT says so with BlackIs1; other data is inverted with /Decode.
    if photometric == 0 && !ccitt && compression != 7 {
        base.set("Decode", inverted(1));
    }

    let raw_row = (width as usize * samples as usize * bits as usize).div_ceil(8);
    let fix = |s: &[u8]| -> Vec<u8> {
        if fill_reversed {
            s.iter().map(|v| v.reverse_bits()).collect()
        } else {
            s.to_vec()
        }
    };
    let predictor_parms = || {
        dictionary! {
            "Predictor" => 2,
            "Colors" => samples as i64,
            "BitsPerComponent" => bits as i64,
            "Columns" => width as i64,
        }
    };

    let mut strips = vec![];
    match compression {
        // Uncompressed: one image, compressed with Flate.
        1 => {
            let need = raw_row * height as usize;
            let mut all = Vec::with_capacity(need);
            for s in &data {
                all.extend_from_slice(&fix(s));
            }
            if all.len() < need {
                return Err(unreadable("the image data is shorter than the image"));
            }
            all.truncate(need);
            let mut dict = base.clone();
            dict.set("Height", height as i64);
            let mut stream = Stream::new(dict, all);
            stream
                .compress()
                .map_err(|e| unreadable(format!("could not compress the image: {e}")))?;
            stream.allows_compression = false;
            strips.push(StripImage {
                rows: height,
                stream,
            });
        }
        _ => {
            let tables = match (compression, Tiff::entry(ifd, TAG_JPEG_TABLES)) {
                (7, Some(e)) => Some(t.bytes_of(&e)?),
                _ => None,
            };
            let t4 = t.value(ifd, TAG_T4_OPTIONS).unwrap_or(0);
            for (i, s) in data.iter().enumerate() {
                let rows = rows_of(i);
                let mut dict = base.clone();
                dict.set("Height", rows as i64);
                let content = match compression {
                    2..=4 => {
                        if bits != 1 || samples != 1 {
                            return Err(unreadable("fax compression on a colour image"));
                        }
                        let k: i64 = match compression {
                            4 => -1,
                            3 if t4 & 1 == 1 => 1,
                            _ => 0,
                        };
                        dict.set("Filter", "CCITTFaxDecode");
                        dict.set(
                            "DecodeParms",
                            dictionary! {
                                "K" => k,
                                "Columns" => width as i64,
                                "Rows" => rows as i64,
                                "BlackIs1" => photometric == 0,
                                "EncodedByteAlign" => compression == 2 || (compression == 3 && t4 & 4 == 4),
                                "EndOfBlock" => false,
                            },
                        );
                        fix(s)
                    }
                    5 | 8 | 32946 => {
                        dict.set(
                            "Filter",
                            if compression == 5 {
                                "LZWDecode"
                            } else {
                                "FlateDecode"
                            },
                        );
                        if predictor == 2 {
                            dict.set("DecodeParms", predictor_parms());
                        }
                        s.to_vec()
                    }
                    32773 => {
                        // PackBits is PDF's RunLengthDecode.
                        dict.set("Filter", "RunLengthDecode");
                        fix(s)
                    }
                    7 => {
                        dict.set("Filter", "DCTDecode");
                        if bits != 8 {
                            return Err(unsupported("JPEG data that is not 8-bit"));
                        }
                        if photometric == 2 {
                            // RGB stored as is: no YCbCr transform when decoding.
                            dict.set("DecodeParms", dictionary! { "ColorTransform" => 0 });
                        }
                        match tables {
                            Some(tb) if tb.len() >= 4 && s.len() >= 2 && s.starts_with(&[0xFF, 0xD8]) => {
                                // The shared tables (SOI … EOI) and the strip (SOI …) as one JPEG.
                                let tb = tb.strip_suffix(&[0xFF, 0xD9]).unwrap_or(tb);
                                let mut j = Vec::with_capacity(tb.len() + s.len());
                                j.extend_from_slice(tb);
                                j.extend_from_slice(&s[2..]);
                                j
                            }
                            _ => s.to_vec(),
                        }
                    }
                    6 => {
                        return Err(unsupported(
                            "old-style JPEG compression in a TIFF; save the image as JPEG or as a newer TIFF",
                        ))
                    }
                    other => {
                        return Err(unsupported(format!(
                            "TIFF compression {other}; save the image as a TIFF with LZW, ZIP or fax compression, a PNG or a JPEG"
                        )))
                    }
                };
                let mut stream = Stream::new(dict, content);
                stream.allows_compression = false;
                strips.push(StripImage { rows, stream });
            }
        }
    }
    Ok(Picture {
        width,
        height,
        res_x,
        res_y,
        orientation,
        strips,
    })
}

// ----- the PDF -----

/// The orientation's map from the stored image's unit square (y up, row 0 at the top) to the
/// shown one, as a PDF matrix `[a b c d e f]`.
fn orientation_matrix(o: u8) -> [f32; 6] {
    match o {
        2 => [-1.0, 0.0, 0.0, 1.0, 1.0, 0.0],
        3 => [-1.0, 0.0, 0.0, -1.0, 1.0, 1.0],
        4 => [1.0, 0.0, 0.0, -1.0, 0.0, 1.0],
        5 => [0.0, -1.0, -1.0, 0.0, 1.0, 1.0],
        6 => [0.0, -1.0, 1.0, 0.0, 0.0, 1.0],
        7 => [0.0, 1.0, 1.0, 0.0, 0.0, 0.0],
        8 => [0.0, 1.0, -1.0, 0.0, 1.0, 0.0],
        _ => [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    }
}

fn num(v: f32) -> String {
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" {
        "0".into()
    } else {
        s.into()
    }
}

/// Where a picture goes on its page: the page size, and the shown image's box.
fn layout(p: &Picture, paper: Paper, margin: f32) -> ((f32, f32), [f32; 4]) {
    // The physical size, in the stored orientation, then as shown.
    let w = p.width as f32 / p.res_x;
    let h = p.height as f32 / p.res_y;
    let (sw, sh) = if p.orientation >= 5 { (h, w) } else { (w, h) };
    let (pw, ph) = paper.size();
    let (pw, ph) = if sw > sh { (ph, pw) } else { (pw, ph) };
    let scale = ((pw - 2.0 * margin) / sw).min((ph - 2.0 * margin) / sh);
    let (bw, bh) = (sw * scale, sh * scale);
    ((pw, ph), [(pw - bw) / 2.0, (ph - bh) / 2.0, bw, bh])
}

fn build_pdf(pictures: &[(Picture, f32)], paper: Paper) -> R<Vec<u8>> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let mut kids = vec![];
    for (p, margin) in pictures {
        let ((pw, ph), [x, y, bw, bh]) = layout(p, paper, *margin);
        let m = orientation_matrix(p.orientation);
        let mut content = format!(
            "q {} 0 0 {} {} {} cm {} {} {} {} {} {} cm\n",
            num(bw),
            num(bh),
            num(x),
            num(y),
            num(m[0]),
            num(m[1]),
            num(m[2]),
            num(m[3]),
            num(m[4]),
            num(m[5])
        );
        let mut xobjects = Dictionary::new();
        let mut row = 0u32;
        for (i, s) in p.strips.iter().enumerate() {
            let id: ObjectId = doc.add_object(s.stream.clone());
            let name = format!("Im{i}");
            xobjects.set(name.clone(), id);
            let scale = s.rows as f32 / p.height as f32;
            let bottom = 1.0 - (row + s.rows) as f32 / p.height as f32;
            content.push_str(&format!(
                "q 1 0 0 {} 0 {} cm /{name} Do Q\n",
                num(scale),
                num(bottom)
            ));
            row += s.rows;
        }
        content.push_str("Q\n");
        let contents = doc.add_object(Stream::new(Dictionary::new(), content.into_bytes()));
        let page = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), Object::Real(pw), Object::Real(ph)],
            "Resources" => dictionary! { "XObject" => xobjects },
            "Contents" => contents,
        });
        kids.push(Object::Reference(page));
    }
    let count = kids.len() as i64;
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => count }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| unreadable(format!("could not write the PDF: {e}")))?;
    Ok(out)
}

/// The byte form of [`images_to_pdf`] for hosts that pass buffers rather than lists (the WASM
/// module and the FFI library): a manifest `{"paper": "a4" | "letter", "images": [{"len":
/// <bytes>, "margin": <points>}, …]}` with the image files one after the other in one buffer,
/// and the result as one buffer: the length of a JSON summary as 4 bytes (big-endian), the
/// summary `{"pages": [<pages of each image>, …]}`, then the PDF.
pub mod wire {
    use serde::Deserialize;

    use super::{ImageInput, ImagesPdf, Paper, PHOTO_MARGIN};

    /// The manifest of an images call.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Manifest {
        #[serde(default)]
        pub paper: Paper,
        pub images: Vec<ManifestEntry>,
    }

    /// One image of a [`Manifest`]: its length in the buffer and its margin in points (a
    /// photo's [`PHOTO_MARGIN`] when absent).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ManifestEntry {
        pub len: usize,
        #[serde(default)]
        pub margin: Option<f32>,
    }

    /// The images of `data` as `manifest` describes them; refused when the lengths do not add
    /// up to the buffer's.
    pub fn split<'a>(
        manifest: &Manifest,
        data: &'a [u8],
    ) -> std::result::Result<Vec<ImageInput<'a>>, String> {
        let mut at = 0usize;
        let mut out = Vec::with_capacity(manifest.images.len());
        for (i, img) in manifest.images.iter().enumerate() {
            let end = at
                .checked_add(img.len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| {
                    format!(
                        "the manifest's image {} ends past the {} bytes given",
                        i + 1,
                        data.len()
                    )
                })?;
            out.push(ImageInput {
                bytes: &data[at..end],
                margin: img.margin.unwrap_or(PHOTO_MARGIN),
            });
            at = end;
        }
        if at != data.len() {
            return Err(format!(
                "the manifest's images add up to {at} bytes, but {} were given",
                data.len()
            ));
        }
        Ok(out)
    }

    /// `made` as one buffer: the summary JSON's length (4 bytes, big-endian), the summary, the
    /// PDF.
    pub fn frame(made: &ImagesPdf) -> Vec<u8> {
        let summary = serde_json::json!({ "pages": made.pages })
            .to_string()
            .into_bytes();
        let mut out = Vec::with_capacity(4 + summary.len() + made.pdf.len());
        out.extend_from_slice(&(summary.len() as u32).to_be_bytes());
        out.extend_from_slice(&summary);
        out.extend_from_slice(&made.pdf);
        out
    }
}

// ---------- source PDFs ----------------------------------------------------------------------

/// How a PDF is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    None,
    /// An owner password only (restrictions on printing, copying, editing): it opens without a
    /// password; the service removes the restrictions after the sender confirms.
    Restrictions,
    /// An open password: [`decrypt`] with the password the person types.
    OpenPassword,
    /// Certificate (public-key) encryption: refused.
    Certificate,
}

/// What a PDF needs before it can be prepared (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub encryption: Encryption,
    /// The PDF/A claim of its XMP metadata, such as `2b` or `1a`; None without one. Unknown
    /// while the document is encrypted with an open password.
    pub pdfa: Option<String>,
    /// Optional content groups (layers), and how many are hidden when the file opens.
    pub layers: usize,
    pub hidden_layers: usize,
    /// Pages (0 while the document is encrypted with an open password).
    pub pages: usize,
}

fn unreadable_pdf(e: impl fmt::Display) -> IntakeError {
    IntakeError::new(
        "unreadable_pdf",
        format!("the file could not be read as a PDF: {e}"),
    )
}

fn has_encrypt(pdf: &[u8]) -> bool {
    pdf.windows(8).any(|w| w == b"/Encrypt")
}

/// The encryption of a loaded document whose trailer still names `/Encrypt` (the empty password
/// did not open it).
fn locked_kind(doc: &Document) -> Encryption {
    match doc
        .get_encrypted()
        .ok()
        .and_then(|d| d.get(b"Filter").ok())
        .and_then(|f| f.as_name().ok())
    {
        Some(b"Standard") => Encryption::OpenPassword,
        _ => Encryption::Certificate,
    }
}

/// What a PDF needs before it can be prepared.
pub fn source_info(pdf: &[u8]) -> R<SourceInfo> {
    let doc = match Document::load_mem(pdf) {
        Ok(d) => d,
        Err(e) => {
            // lopdf refuses some files it cannot decrypt (certificate encryption, which its
            // password handler does not know) instead of returning them locked.
            if has_encrypt(pdf) {
                if pdf.windows(6).any(|w| w == b"PubSec") {
                    return Ok(locked(Encryption::Certificate));
                }
                if matches!(e, lopdf::Error::InvalidPassword) {
                    return Ok(locked(Encryption::OpenPassword));
                }
            }
            return Err(unreadable_pdf(e));
        }
    };
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Ok(locked(locked_kind(&doc)));
    }
    let encryption = if doc.encryption_state.is_some() {
        Encryption::Restrictions
    } else {
        Encryption::None
    };
    let (layers, hidden_layers) = layer_counts(&doc);
    Ok(SourceInfo {
        encryption,
        pdfa: pdfa_claim(&doc),
        layers,
        hidden_layers,
        pages: doc.get_pages().len(),
    })
}

fn locked(encryption: Encryption) -> SourceInfo {
    SourceInfo {
        encryption,
        pdfa: None,
        layers: 0,
        hidden_layers: 0,
        pages: 0,
    }
}

fn catalog(doc: &Document) -> Option<&Dictionary> {
    doc.trailer
        .get(b"Root")
        .ok()
        .and_then(|r| doc.dereference(r).ok())
        .and_then(|(_, o)| o.as_dict().ok())
}

fn resolve<'a>(doc: &'a Document, o: &'a Object) -> &'a Object {
    doc.dereference(o).map(|(_, o)| o).unwrap_or(o)
}

/// Layers, and how many are hidden when the file opens (its default configuration's
/// `BaseState` and `ON` / `OFF` lists).
fn layer_counts(doc: &Document) -> (usize, usize) {
    let Some(oc) = catalog(doc)
        .and_then(|c| c.get(b"OCProperties").ok())
        .and_then(|o| resolve(doc, o).as_dict().ok())
    else {
        return (0, 0);
    };
    let ids = |o: Option<&Object>| -> Vec<ObjectId> {
        o.map(|o| resolve(doc, o))
            .and_then(|o| o.as_array().ok())
            .map(|a| a.iter().filter_map(|x| x.as_reference().ok()).collect())
            .unwrap_or_default()
    };
    let all = ids(oc.get(b"OCGs").ok());
    let d = oc
        .get(b"D")
        .ok()
        .and_then(|o| resolve(doc, o).as_dict().ok());
    let base_off = d
        .and_then(|d| d.get(b"BaseState").ok())
        .and_then(|b| b.as_name().ok())
        == Some(b"OFF");
    let on: HashSet<ObjectId> = ids(d.and_then(|d| d.get(b"ON").ok())).into_iter().collect();
    let off: HashSet<ObjectId> = ids(d.and_then(|d| d.get(b"OFF").ok()))
        .into_iter()
        .collect();
    let hidden = all
        .iter()
        .filter(|id| {
            if base_off {
                !on.contains(id)
            } else {
                off.contains(id)
            }
        })
        .count();
    (all.len(), hidden)
}

/// The PDF/A claim in the catalog's XMP metadata: `pdfaid:part` and `pdfaid:conformance`, as
/// `2b`.
fn pdfa_claim(doc: &Document) -> Option<String> {
    let meta = catalog(doc)?.get(b"Metadata").ok()?;
    let stream = resolve(doc, meta).as_stream().ok()?;
    let xmp = stream.get_plain_content().ok()?;
    let text = String::from_utf8_lossy(&xmp);
    let part = xmp_field(&text, "pdfaid:part")?;
    if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let conformance = xmp_field(&text, "pdfaid:conformance")
        .filter(|c| c.len() == 1 && c.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|c| c.to_ascii_lowercase())
        .unwrap_or_default();
    Some(format!("{part}{conformance}"))
}

/// An XMP property written as an attribute (`name="v"`) or an element (`<name>v</name>`).
fn xmp_field(text: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = text[from..].find(name) {
        let at = from + i + name.len();
        let rest = text[at..].trim_start();
        if let Some(r) = rest.strip_prefix('=') {
            let r = r.trim_start();
            let q = r.chars().next()?;
            if q == '"' || q == '\'' {
                let v = &r[1..];
                return v.find(q).map(|end| v[..end].trim().to_string());
            }
        } else if let Some(r) = rest.strip_prefix('>') {
            return r.find('<').map(|end| r[..end].trim().to_string());
        }
        from = at;
    }
    None
}

/// `pdf` decrypted with `password` (its open password, or its owner password) and saved again
/// without encryption. Refused with `not_encrypted` (nothing to do), `no_open_password` (it
/// opens without one: only restrictions, which the service removes), `certificate_encryption`
/// or `wrong_password`.
pub fn decrypt(pdf: &[u8], password: &str) -> R<Vec<u8>> {
    match source_info(pdf)?.encryption {
        Encryption::None => {
            return Err(IntakeError::new(
                "not_encrypted",
                "this PDF is not encrypted",
            ))
        }
        Encryption::Restrictions => {
            return Err(IntakeError::new(
                "no_open_password",
                "this PDF opens without a password; only its restrictions are set",
            ))
        }
        Encryption::Certificate => {
            return Err(IntakeError::new(
                "certificate_encryption",
                "this PDF is encrypted for certificates, not with a password; remove the encryption in the program that made it",
            ))
        }
        Encryption::OpenPassword => {}
    }
    let mut doc =
        match Document::load_mem_with_options(pdf, lopdf::LoadOptions::with_password(password)) {
            Ok(d) => d,
            Err(lopdf::Error::InvalidPassword) => {
                return Err(IntakeError::new(
                    "wrong_password",
                    "the password does not open this PDF",
                ))
            }
            Err(e) => return Err(unreadable_pdf(e)),
        };
    if doc.trailer.get(b"Encrypt").is_ok() || doc.objects.is_empty() {
        return Err(IntakeError::new(
            "wrong_password",
            "the password does not open this PDF",
        ));
    }
    doc.encryption_state = None;
    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(unreadable_pdf)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny baseline JPEG header (SOI, APP0, SOF0 for `w` x `h` with `c` components, EOI):
    /// enough for the parser; PDF readers are not asked to show it here.
    fn jpeg(w: u16, h: u16, c: u8, exif_orientation: Option<u16>) -> Vec<u8> {
        let mut b = vec![0xFF, 0xD8];
        if let Some(o) = exif_orientation {
            // APP1 Exif with a big-endian TIFF holding one IFD entry: Orientation.
            let mut tiff = b"MM\0*\0\0\0\x08".to_vec();
            tiff.extend_from_slice(&1u16.to_be_bytes());
            tiff.extend_from_slice(&274u16.to_be_bytes());
            tiff.extend_from_slice(&3u16.to_be_bytes());
            tiff.extend_from_slice(&1u32.to_be_bytes());
            tiff.extend_from_slice(&o.to_be_bytes());
            tiff.extend_from_slice(&[0, 0]);
            tiff.extend_from_slice(&0u32.to_be_bytes());
            let mut seg = b"Exif\0\0".to_vec();
            seg.extend_from_slice(&tiff);
            b.extend_from_slice(&[0xFF, 0xE1]);
            b.extend_from_slice(&((seg.len() + 2) as u16).to_be_bytes());
            b.extend_from_slice(&seg);
        }
        b.extend_from_slice(&[0xFF, 0xE0, 0, 16]);
        b.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        let mut sof = vec![8];
        sof.extend_from_slice(&h.to_be_bytes());
        sof.extend_from_slice(&w.to_be_bytes());
        sof.push(c);
        for i in 0..c {
            sof.extend_from_slice(&[i + 1, 0x11, 0]);
        }
        b.extend_from_slice(&[0xFF, 0xC0]);
        b.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        b.extend_from_slice(&sof);
        b.extend_from_slice(&[0xFF, 0xD9]);
        b
    }

    /// A little-endian TIFF: `pages` pages of `w` x `h`, each `(compression, photometric, bits,
    /// samples, data strips, extra tags)`.
    type Page = (u16, u16, u16, u16, Vec<Vec<u8>>, Vec<(u16, u16, Vec<u32>)>);

    fn tiff(w: u32, h: u32, pages: &[Page]) -> Vec<u8> {
        let mut out = b"II*\0\0\0\0\0".to_vec();
        let mut prev_next_at = 4usize;
        for (compression, photometric, bits, samples, strips, extra) in pages {
            // Strip data first.
            let mut offsets = vec![];
            let mut counts = vec![];
            for s in strips {
                offsets.push(out.len() as u32);
                counts.push(s.len() as u32);
                out.extend_from_slice(s);
            }
            if out.len() % 2 == 1 {
                out.push(0);
            }
            let rows = h.div_ceil(strips.len() as u32);
            let mut tags: Vec<(u16, u16, Vec<u32>)> = vec![
                (256, 4, vec![w]),
                (257, 4, vec![h]),
                (258, 3, vec![*bits as u32; *samples as usize]),
                (259, 3, vec![*compression as u32]),
                (262, 3, vec![*photometric as u32]),
                (273, 4, offsets),
                (277, 3, vec![*samples as u32]),
                (278, 4, vec![rows]),
                (279, 4, counts),
            ];
            tags.extend(extra.iter().cloned());
            tags.sort_by_key(|t| t.0);
            // Out-of-line values.
            let mut placed = vec![];
            for (_, kind, vals) in &tags {
                let size = if *kind == 3 { 2 } else { 4 };
                if vals.len() * size > 4 {
                    placed.push(Some(out.len() as u32));
                    for v in vals {
                        if *kind == 3 {
                            out.extend_from_slice(&(*v as u16).to_le_bytes());
                        } else {
                            out.extend_from_slice(&v.to_le_bytes());
                        }
                    }
                } else {
                    placed.push(None);
                }
            }
            if out.len() % 2 == 1 {
                out.push(0);
            }
            let ifd_at = out.len() as u32;
            out[prev_next_at..prev_next_at + 4].copy_from_slice(&ifd_at.to_le_bytes());
            out.extend_from_slice(&(tags.len() as u16).to_le_bytes());
            for ((tag, kind, vals), at) in tags.iter().zip(&placed) {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&kind.to_le_bytes());
                let count = if *kind == 5 {
                    vals.len() / 2
                } else {
                    vals.len()
                };
                out.extend_from_slice(&(count as u32).to_le_bytes());
                match at {
                    Some(a) => out.extend_from_slice(&a.to_le_bytes()),
                    None => {
                        let mut v = [0u8; 4];
                        for (i, x) in vals.iter().enumerate() {
                            if *kind == 3 {
                                v[i * 2..i * 2 + 2].copy_from_slice(&(*x as u16).to_le_bytes());
                            } else {
                                v.copy_from_slice(&x.to_le_bytes());
                            }
                        }
                        out.extend_from_slice(&v);
                    }
                }
            }
            prev_next_at = out.len();
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out
    }

    fn pages_of(pdf: &[u8]) -> Vec<(Dictionary, String)> {
        let doc = Document::load_mem(pdf).expect("the PDF opens");
        doc.get_pages()
            .values()
            .map(|id| {
                let page = doc.get_dictionary(*id).unwrap().clone();
                let content = String::from_utf8(doc.get_page_content(*id).unwrap()).unwrap();
                (page, content)
            })
            .collect()
    }

    fn images_of(pdf: &[u8]) -> Vec<Dictionary> {
        let doc = Document::load_mem(pdf).unwrap();
        doc.objects
            .values()
            .filter_map(|o| o.as_stream().ok())
            .filter(|s| s.dict.get(b"Subtype").and_then(|v| v.as_name()).ok() == Some(b"Image"))
            .map(|s| s.dict.clone())
            .collect()
    }

    fn media(page: &Dictionary) -> Vec<f32> {
        page.get(b"MediaBox")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_float().unwrap())
            .collect()
    }

    #[test]
    fn jpegs_become_one_page_each_fitted_to_the_paper() {
        let tall = jpeg(600, 800, 3, None);
        let wide = jpeg(800, 600, 1, None);
        let out = images_to_pdf(
            &[
                ImageInput {
                    bytes: &tall,
                    margin: PHOTO_MARGIN,
                },
                ImageInput {
                    bytes: &wide,
                    margin: 0.0,
                },
            ],
            Paper::Letter,
        )
        .unwrap();
        assert_eq!(out.pages, vec![1, 1]);
        let pages = pages_of(&out.pdf);
        assert_eq!(pages.len(), 2);
        assert_eq!(media(&pages[0].0), vec![0.0, 0.0, 612.0, 792.0]);
        // The wide one turned the page to landscape and fills it (no margin).
        assert_eq!(media(&pages[1].0), vec![0.0, 0.0, 792.0, 612.0]);
        assert!(
            pages[1]
                .1
                .starts_with("q 792 0 0 594 0 9 cm 1 0 0 1 0 0 cm"),
            "{}",
            pages[1].1
        );
        let images = images_of(&out.pdf);
        assert_eq!(images.len(), 2);
        assert!(images
            .iter()
            .all(|d| d.get(b"Filter").unwrap().as_name().unwrap() == b"DCTDecode"));
        let spaces: HashSet<Vec<u8>> = images
            .iter()
            .map(|d| d.get(b"ColorSpace").unwrap().as_name().unwrap().to_vec())
            .collect();
        assert!(
            spaces.contains(b"DeviceGray".as_slice()) && spaces.contains(b"DeviceRGB".as_slice())
        );
    }

    #[test]
    fn exif_orientation_turns_the_page() {
        // Stored 800 x 600 (wide), orientation 6: shown 600 x 800 (tall), portrait page.
        let j = jpeg(800, 600, 3, Some(6));
        let out = images_to_pdf(
            &[ImageInput {
                bytes: &j,
                margin: 0.0,
            }],
            Paper::A4,
        )
        .unwrap();
        let pages = pages_of(&out.pdf);
        let mb = media(&pages[0].0);
        assert!(mb[3] > mb[2], "portrait: {mb:?}");
        assert!(pages[0].1.contains(" cm 0 -1 1 0 0 1 cm"), "{}", pages[0].1);
    }

    #[test]
    fn a_multi_page_fax_tiff_keeps_its_compression_and_aspect() {
        // Two G4 pages at 204 x 98 dpi (fax "normal" resolution): 1728 x 1100 pixels are
        // 8.47 x 11.2 inches, a tall page, though the pixels are wider than tall.
        let res = |v: u32| vec![v, 1];
        let extra = vec![
            (282u16, 5u16, res(204)),
            (283, 5, res(98)),
            (296, 3, vec![2]),
        ];
        let g4 = vec![vec![0x26, 0xA0, 0x00, 0x10, 0x01]];
        let file = tiff(
            1728,
            1100,
            &[
                (4, 0, 1, 1, g4.clone(), extra.clone()),
                (4, 0, 1, 1, g4.clone(), extra.clone()),
            ],
        );
        let out = images_to_pdf(
            &[ImageInput {
                bytes: &file,
                margin: 0.0,
            }],
            Paper::A4,
        )
        .unwrap();
        assert_eq!(out.pages, vec![2]);
        let pages = pages_of(&out.pdf);
        assert_eq!(pages.len(), 2);
        let mb = media(&pages[0].0);
        assert!(mb[3] > mb[2], "a fax page stays portrait: {mb:?}");
        let images = images_of(&out.pdf);
        assert_eq!(images.len(), 2);
        let d = &images[0];
        assert_eq!(
            d.get(b"Filter").unwrap().as_name().unwrap(),
            b"CCITTFaxDecode"
        );
        let p = d.get(b"DecodeParms").unwrap().as_dict().unwrap();
        assert_eq!(p.get(b"K").unwrap().as_i64().unwrap(), -1);
        assert_eq!(p.get(b"Columns").unwrap().as_i64().unwrap(), 1728);
        assert_eq!(p.get(b"Rows").unwrap().as_i64().unwrap(), 1100);
        assert!(p.get(b"BlackIs1").unwrap().as_bool().unwrap());
    }

    #[test]
    fn tiff_strips_are_stacked_top_to_bottom() {
        // 4 x 4 grey LZW in two strips of 2 rows.
        let strip = vec![0x80, 0x00, 0x00];
        let file = tiff(
            4,
            4,
            &[(
                5,
                1,
                8,
                1,
                vec![strip.clone(), strip],
                vec![(317, 3, vec![2])],
            )],
        );
        let out = images_to_pdf(
            &[ImageInput {
                bytes: &file,
                margin: 0.0,
            }],
            Paper::A4,
        )
        .unwrap();
        let (_, content) = &pages_of(&out.pdf)[0];
        assert!(
            content.contains("q 1 0 0 0.5 0 0.5 cm /Im0 Do Q"),
            "{content}"
        );
        assert!(
            content.contains("q 1 0 0 0.5 0 0 cm /Im1 Do Q"),
            "{content}"
        );
        let images = images_of(&out.pdf);
        assert!(images
            .iter()
            .all(|d| d.get(b"Filter").unwrap().as_name().unwrap() == b"LZWDecode"));
        let p = images[0].get(b"DecodeParms").unwrap().as_dict().unwrap();
        assert_eq!(p.get(b"Predictor").unwrap().as_i64().unwrap(), 2);
    }

    #[test]
    fn uncompressed_palette_and_cmyk_tiffs() {
        // 2 x 2, 8-bit palette.
        let n = 256u32;
        let mut map = vec![0u32; 3 * n as usize];
        map[1] = 0xFFFF; // red of entry 1
        let pal = tiff(
            2,
            2,
            &[(1, 3, 8, 1, vec![vec![0, 1, 1, 0]], vec![(320, 3, map)])],
        );
        // 2 x 2 CMYK, 8-bit.
        let cmyk = tiff(2, 2, &[(1, 5, 8, 4, vec![vec![0u8; 16]], vec![])]);
        let out = images_to_pdf(
            &[
                ImageInput {
                    bytes: &pal,
                    margin: 0.0,
                },
                ImageInput {
                    bytes: &cmyk,
                    margin: 0.0,
                },
            ],
            Paper::A4,
        )
        .unwrap();
        let images = images_of(&out.pdf);
        assert_eq!(images.len(), 2);
        let spaces: Vec<String> = images
            .iter()
            .map(|d| match d.get(b"ColorSpace").unwrap() {
                Object::Name(n) => String::from_utf8_lossy(n).into_owned(),
                Object::Array(a) => String::from_utf8_lossy(a[0].as_name().unwrap()).into_owned(),
                _ => String::new(),
            })
            .collect();
        assert!(
            spaces.contains(&"Indexed".to_string()) && spaces.contains(&"DeviceCMYK".to_string()),
            "{spaces:?}"
        );
    }

    #[test]
    fn what_cannot_be_taken_in_is_refused_with_a_code() {
        let code = |b: &[u8]| {
            images_to_pdf(
                &[ImageInput {
                    bytes: b,
                    margin: 0.0,
                }],
                Paper::A4,
            )
            .unwrap_err()
            .code
        };
        assert_eq!(code(b"\x89PNG\r\n\x1a\n...."), "not_an_image");
        assert_eq!(code(&jpeg(10_000, 6_000, 3, None)), "too_many_pixels");
        assert_eq!(code(&[0xFF, 0xD8, 0xFF, 0xD9]), "unreadable_image");
        // Transparency.
        let rgba = tiff(
            1,
            1,
            &[(1, 2, 8, 4, vec![vec![0; 4]], vec![(338, 3, vec![2])])],
        );
        assert_eq!(code(&rgba), "unsupported_image");
        // 16 bits.
        let deep = tiff(1, 1, &[(1, 1, 16, 1, vec![vec![0; 2]], vec![])]);
        assert_eq!(code(&deep), "unsupported_image");
        // A page loop.
        let mut looped = tiff(1, 1, &[(1, 1, 8, 1, vec![vec![0]], vec![])]);
        let first = u32::from_le_bytes(looped[4..8].try_into().unwrap());
        let n = looped.len();
        looped[n - 4..].copy_from_slice(&first.to_le_bytes());
        assert_eq!(code(&looped), "unreadable_image");
        assert_eq!(images_to_pdf(&[], Paper::A4).unwrap_err().code, "no_image");
        // Over 100 pages in one call.
        let one = jpeg(10, 10, 3, None);
        let many: Vec<_> = (0..=MAX_PAGES)
            .map(|_| ImageInput {
                bytes: &one,
                margin: 0.0,
            })
            .collect();
        assert_eq!(
            images_to_pdf(&many, Paper::A4).unwrap_err().code,
            "too_many_pages"
        );
    }

    fn simple_pdf(extra: impl FnOnce(&mut Document, ObjectId)) -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let contents = doc.add_object(Stream::new(Dictionary::new(), b"BT ET".to_vec()));
        let page = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Contents" => contents,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(
                dictionary! { "Type" => "Pages", "Kids" => vec![page.into()], "Count" => 1 },
            ),
        );
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        extra(&mut doc, cat);
        let mut out = vec![];
        doc.save_to(&mut out).unwrap();
        out
    }

    fn encrypted(user: &str) -> Vec<u8> {
        let mut doc = Document::load_mem(&simple_pdf(|_, _| {})).unwrap();
        doc.trailer.set(
            "ID",
            vec![
                Object::string_literal(vec![7u8; 16]),
                Object::string_literal(vec![7u8; 16]),
            ],
        );
        let state = lopdf::encryption::EncryptionState::try_from(
            lopdf::encryption::EncryptionVersion::V2 {
                document: &doc,
                owner_password: "owner-secret",
                user_password: user,
                key_length: 128,
                permissions: lopdf::encryption::Permissions::all(),
            },
        )
        .unwrap();
        doc.encrypt(&state).unwrap();
        let mut out = vec![];
        doc.save_to(&mut out).unwrap();
        out
    }

    #[test]
    fn source_info_reads_pdfa_and_layers() {
        let pdf = simple_pdf(|doc, cat| {
            let xmp = br#"<x:xmpmeta><rdf:Description xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/" pdfaid:part="2" pdfaid:conformance="B"/></x:xmpmeta>"#;
            let meta = doc.add_object(Stream::new(
                dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
                xmp.to_vec(),
            ));
            let a = doc
                .add_object(dictionary! { "Type" => "OCG", "Name" => Object::string_literal("A") });
            let b = doc
                .add_object(dictionary! { "Type" => "OCG", "Name" => Object::string_literal("B") });
            let c = doc.get_object_mut(cat).unwrap().as_dict_mut().unwrap();
            c.set("Metadata", meta);
            c.set(
                "OCProperties",
                dictionary! {
                    "OCGs" => vec![a.into(), b.into()],
                    "D" => dictionary! { "OFF" => vec![b.into()] },
                },
            );
        });
        let info = source_info(&pdf).unwrap();
        assert_eq!(info.encryption, Encryption::None);
        assert_eq!(info.pdfa.as_deref(), Some("2b"));
        assert_eq!((info.layers, info.hidden_layers, info.pages), (2, 1, 1));
        // The element form.
        assert_eq!(
            xmp_field("<pdfaid:part>3</pdfaid:part>", "pdfaid:part").as_deref(),
            Some("3")
        );
        let plain = source_info(&simple_pdf(|_, _| {})).unwrap();
        assert_eq!(plain.pdfa, None);
        assert_eq!(plain.layers, 0);
    }

    #[test]
    fn an_open_password_is_removed_on_the_device() {
        let pdf = encrypted("open sesame");
        assert_eq!(
            source_info(&pdf).unwrap().encryption,
            Encryption::OpenPassword
        );
        assert_eq!(decrypt(&pdf, "wrong").unwrap_err().code, "wrong_password");
        let clear = decrypt(&pdf, "open sesame").unwrap();
        assert!(!has_encrypt(&clear));
        let info = source_info(&clear).unwrap();
        assert_eq!(info.encryption, Encryption::None);
        assert_eq!(info.pages, 1);
        // The owner password opens it too.
        assert!(decrypt(&pdf, "owner-secret").is_ok());
    }

    #[test]
    fn restrictions_and_plain_files_are_not_decrypted_here() {
        let owner_only = encrypted("");
        assert_eq!(
            source_info(&owner_only).unwrap().encryption,
            Encryption::Restrictions
        );
        assert_eq!(
            decrypt(&owner_only, "x").unwrap_err().code,
            "no_open_password"
        );
        assert_eq!(
            decrypt(&simple_pdf(|_, _| {}), "x").unwrap_err().code,
            "not_encrypted"
        );
        let cert = simple_pdf(|doc, _| {
            let e = doc.add_object(dictionary! { "Filter" => "Adobe.PubSec", "V" => 4 });
            doc.trailer.set("Encrypt", e);
        });
        assert_eq!(
            source_info(&cert).unwrap().encryption,
            Encryption::Certificate
        );
        assert_eq!(
            decrypt(&cert, "x").unwrap_err().code,
            "certificate_encryption"
        );
        assert_eq!(
            source_info(b"not a pdf").unwrap_err().code,
            "unreadable_pdf"
        );
    }
}
