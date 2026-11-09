//! The format specification (`spec/envelope-format.md`) is versioned with the envelope schema:
//! these checks fail when the engine's schema versions or its catalogue of finding codes move
//! without the specification.

use std::path::Path;

use signpdf_core::messages::CODES;
use signpdf_core::schema::OLDEST_SCHEMA_VERSION;
use signpdf_core::SCHEMA_VERSION;

fn spec() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/envelope-format.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The number after the bold `label` in the specification's header.
fn header_number(spec: &str, label: &str) -> u32 {
    let line = spec
        .lines()
        .find(|l| l.starts_with(&format!("**{label}:**")))
        .unwrap_or_else(|| panic!("the specification has no '**{label}:**' line"));
    let rest = line.split(":**").nth(1).unwrap().trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("no number in {line:?}"))
}

/// The text of section `heading` (a `## ` heading starting with it) up to the next `## `.
fn section<'a>(spec: &'a str, heading: &str) -> &'a str {
    let start = spec
        .find(&format!("\n## {heading}"))
        .unwrap_or_else(|| panic!("no section '## {heading}'"));
    let rest = &spec[start + 1..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

#[test]
fn the_specification_describes_this_build_s_schema_versions() {
    let spec = spec();
    assert_eq!(
        header_number(&spec, "Envelope schema version"),
        SCHEMA_VERSION,
        "spec/envelope-format.md describes another schema version than SCHEMA_VERSION: update it \
         with the schema (its §13.3)"
    );
    assert_eq!(
        header_number(&spec, "Oldest supported version"),
        OLDEST_SCHEMA_VERSION
    );
    assert_eq!(
        header_number(&spec, "Specification revision"),
        SCHEMA_VERSION,
        "the specification's major revision is the schema version it describes"
    );
    let versions = section(&spec, "13. Versioning");
    for v in OLDEST_SCHEMA_VERSION..=SCHEMA_VERSION {
        assert!(
            versions.contains(&format!("\n| {v} | ")),
            "§13.1 has no row for schema version {v}"
        );
    }
}

#[test]
fn the_specification_lists_every_finding_code() {
    let spec = spec();
    let appendix = section(&spec, "Appendix A");
    let missing: Vec<&str> = CODES
        .iter()
        .map(|c| c.code)
        .filter(|code| !appendix.contains(&format!("| `{code}` |")))
        .collect();
    assert!(
        missing.is_empty(),
        "spec/envelope-format.md Appendix A lacks {missing:?}: regenerate it from messages.rs"
    );
    // And lists nothing the engine does not have (a renamed code is a new code: §11).
    for line in appendix.lines().filter(|l| l.starts_with("| `")) {
        let code = line[3..].split('`').next().unwrap();
        assert!(
            CODES.iter().any(|c| c.code == code),
            "Appendix A lists `{code}`, which messages.rs does not have"
        );
    }
}
