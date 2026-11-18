//! Intake, what the engine does to an uploaded file on the device before it becomes a source
//! document (`intake::source_info`, `intake::decrypt`, `intake::images_to_pdf`): must never
//! panic on untrusted bytes. Every input goes through all three, so the PDF seeds reach the
//! PDF checks and decryption, and mutations that start with a JPEG or TIFF header reach the
//! image path (TIFF directories, strips, EXIF orientation). A PDF that `images_to_pdf` makes
//! must be one `source_info` reads, with one page per page it reports.
//!
//! The service's own upload sanitizer (sovrasign `service/api/src/render/sanitize.rs`) is fuzzed
//! in that repository.
#![no_main]
use libfuzzer_sys::fuzz_target;
use signpdf_core::intake::{decrypt, images_to_pdf, source_info, ImageInput, Paper};

fuzz_target!(|data: &[u8]| {
    let _ = source_info(data);
    // The password is the first line when there is one, so the fuzzer can find a matching one
    // for a seed it encrypted; otherwise a fixed one.
    let password = data
        .iter()
        .position(|&b| b == b'\n')
        .filter(|&i| i <= 32)
        .and_then(|i| std::str::from_utf8(&data[..i]).ok())
        .unwrap_or("password");
    let _ = decrypt(data, password);

    let paper = if data.len() % 2 == 0 { Paper::A4 } else { Paper::Letter };
    let images = [ImageInput {
        bytes: data,
        margin: f32::from(data.first().copied().unwrap_or(0) % 64),
    }];
    if let Ok(made) = images_to_pdf(&images, paper) {
        let info = source_info(&made.pdf).expect("images_to_pdf made a PDF source_info refuses");
        let pages: usize = made.pages.iter().sum();
        assert_eq!(info.pages, pages, "page count of the PDF images_to_pdf made");
    }
});
