//! The letters the engine stamps in a signer's further initials fields, and the rule that gives
//! them, which the envelope names so that a verifier can check them again.
//!
//! A signer's *primary* signature field (their first signature field, else their first initials
//! field) carries their signature box. Every other initials field of theirs gets an engine stamp:
//! letters the verifier can establish on its own, so no one can write other text there and the
//! verifier rejects a stamp that differs (`stamp_mismatch`).
//!
//! ## The rules
//!
//! * **`signer-v1`** (envelope schema version 12): the letters **the signer chose**, 1 to 3
//!   letters the stamp font draws ([`check_signer_initials`]), kept in their own signature record
//!   (`initials`), which their signature covers. A host offers [`signer_v1_default`] (the
//!   `name-v1` letters) as the starting value. Only the signer's own revision writes them, so
//!   neither the preparer nor another signer chooses what stands in someone's initials boxes.
//! * **`name-v1`** (envelope schema versions 9 to 11, written in the envelope's
//!   `initials_rule`): the initials of the signer's **name as the preparer gave it** (the slot's
//!   `name`, part of the prepared terms the preparer signs), else of the verified email address
//!   ([`name_v1`]).
//! * **The email rule** (versions 3 to 8, which name no rule): the initials of the verified email
//!   address's local part, or of a name label ([`email_rule`]). It stays the rule of those
//!   versions' documents.
//!
//! ## `name-v1` in detail
//!
//! 1. The name is cut into words at white space (Unicode `White_Space`). A word holding `@` (an
//!    address typed into the name) and a word without a letter (Unicode `Alphabetic`: `&`, `-`,
//!    `2`) are left out.
//! 2. While two words or more are left, a leading title is left out (`Mr`, `Mrs`, `Ms`, `Mx`,
//!    `Dr`, `Prof`, `Mme`, `Mlle`) and a trailing generational suffix (`Jr`, `Sr`, `II`, `III`,
//!    `IV`), compared without `.` and `,` and in capitals: `Dr. Jane Smith Jr.` is `Jane Smith`.
//! 3. The first and the last word give one letter each, the first letter of the word; a single
//!    word gives one. So a name gives one or two letters: `Felix Fairfax` gives `FF`,
//!    `Ludwig van Beethoven` `LB` (particles in the middle are skipped by taking the last word),
//!    `Jean-Luc Picard` `JP` (a hyphenated name is one word), `Madonna` `M`.
//! 4. Each letter is written in capitals (Unicode's full mapping, so `ß` is `SS`), and must be one
//!    the stamp font draws (WinAnsiEncoding, [`crate::pades`]): `É`, `Ø`, `Ñ` and `Š` are kept as
//!    they are; a Latin letter the font lacks is written as its base letter (`Ł` as `L`, `Ő` as
//!    `O`, `Ș` as `S`, Vietnamese `Ư` as `U`: [`fold`]). A letter of another script (Cyrillic,
//!    Greek, Chinese, Arabic...) cannot be drawn, so the name gives no initials.
//! 5. A name that gives no initials (empty, only an address, another script) falls back to the
//!    **verified email address**: the first and last of the parts of its local part split at every
//!    character that is not a letter or digit (`alice.martin@` gives `AM`, `alice@` `A`), each
//!    part's first letter or digit, written as in step 4 (a part whose letter cannot be drawn is
//!    skipped). Nothing usable gives `?`.
//!
//! The decomposed form of an accented letter (`E` followed by a combining accent) gives the bare
//! letter (`E`): the rule reads characters as they are, without Unicode normalization, so that
//! every implementation gives the same letters without normalization tables.
//!
//! The shared test vectors are in `spec/vectors/initials-name-v1.json`; a host that shows the
//! letters before signing (a signing page) must give the same letters for each of them.
//!
//! ## `signer-v1` in detail
//!
//! The signer's letters are 1 to 3 characters (Unicode scalar values), each an *initials letter*
//! ([`is_initials_letter`]): `A` to `Z`, `a` to `z`, the letters of Latin-1 (U+00C0 to U+00FF
//! except `×` U+00D7 and `÷` U+00F7) and `Š` `š` `Œ` `œ` `Ž` `ž` `Ÿ`: exactly the letters
//! WinAnsiEncoding draws, without the ordinal indicators `ª` `º`, the micro sign `µ`, the
//! florin `ƒ` and the modifier circumflex `ˆ`. No space, digit, punctuation, combining mark or control character, and no
//! normalization: a host composes what the signer typed (NFC) before it sends it, and the engine
//! refuses anything else rather than change it. Capitals and small letters are kept as the
//! signer wrote them (`JvB`). The shared test vectors are in
//! `spec/vectors/initials-signer-v1.json`.

use serde::{Deserialize, Serialize};

/// How an envelope's initials stamps are derived (the envelope's `initials_rule`, from schema
/// version 9). Versions 3 to 8 name none and use [`email_rule`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InitialsRule {
    /// [`name_v1`]: the slot's name, else the verified email address (versions 9 to 11).
    #[serde(rename = "name-v1")]
    NameV1,
    /// The letters the signer chose, kept in their signature record (version 12).
    #[serde(rename = "signer-v1")]
    SignerV1,
}

impl InitialsRule {
    /// The rule's name as the envelope writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            InitialsRule::NameV1 => "name-v1",
            InitialsRule::SignerV1 => "signer-v1",
        }
    }
}

/// The initials stamped for a signer under `rule` (`None`: an envelope of version 3 to 8):
/// `slot_name` is the name the preparer gave the signer's slot, `verified_email` the email address
/// the signer's identity provider verified, `chosen` the letters the signer's record keeps
/// (`signer-v1`; `None` when it keeps none, which gives no letters).
pub fn stamp_initials(
    rule: Option<InitialsRule>,
    slot_name: &str,
    verified_email: &str,
    chosen: Option<&str>,
) -> Option<String> {
    match rule {
        Some(InitialsRule::SignerV1) => chosen.map(str::to_string),
        Some(InitialsRule::NameV1) => Some(name_v1(slot_name, verified_email)),
        None => Some(email_rule(verified_email)),
    }
}

/// The most letters a signer's chosen initials may have (`signer-v1`).
pub const MAX_SIGNER_INITIALS: usize = 3;

/// Whether `c` may stand in a signer's chosen initials (`signer-v1`): a letter WinAnsiEncoding
/// draws, other than `ª`, `º`, `µ`, `ƒ` and `ˆ`. See the module documentation.
pub fn is_initials_letter(c: char) -> bool {
    c.is_ascii_alphabetic()
        || (('\u{C0}'..='\u{FF}').contains(&c) && c != '\u{D7}' && c != '\u{F7}')
        || matches!(c, 'Š' | 'š' | 'Œ' | 'œ' | 'Ž' | 'ž' | 'Ÿ')
}

/// Check the initials a signer chose (`signer-v1`): 1 to [`MAX_SIGNER_INITIALS`] initials
/// letters ([`is_initials_letter`]) and nothing else. The error says what is wrong.
pub fn check_signer_initials(letters: &str) -> Result<(), String> {
    let n = letters.chars().count();
    if n == 0 {
        return Err("initials need at least one letter".into());
    }
    if n > MAX_SIGNER_INITIALS {
        return Err(format!(
            "initials are at most {MAX_SIGNER_INITIALS} letters, and these have {n}"
        ));
    }
    if let Some(c) = letters.chars().find(|c| !is_initials_letter(*c)) {
        return Err(format!(
            "initials are letters the stamp can draw, and U+{:04X} is not one",
            c as u32
        ));
    }
    Ok(())
}

/// The letters a host offers a signer to start from under `signer-v1`: the `name-v1` letters of
/// the slot's name (else of the verified email address), keeping only initials letters, at most
/// [`MAX_SIGNER_INITIALS`]. `None` when nothing is left (a name of another script and an address
/// of digits): the signer types their own.
pub fn signer_v1_default(slot_name: &str, verified_email: &str) -> Option<String> {
    let letters: String = name_v1(slot_name, verified_email)
        .chars()
        .filter(|c| is_initials_letter(*c))
        .take(MAX_SIGNER_INITIALS)
        .collect();
    (!letters.is_empty()).then_some(letters)
}

/// Titles left out before a name (rule `name-v1`, step 2), compared without `.` and `,`.
const TITLES: &[&str] = &["MR", "MRS", "MS", "MX", "DR", "PROF", "MME", "MLLE"];

/// Generational suffixes left out after a name (rule `name-v1`, step 2).
const SUFFIXES: &[&str] = &["JR", "SR", "II", "III", "IV"];

/// Rule `name-v1`: the initials of `name` (the slot's name), else of `verified_email`; see the
/// module documentation.
pub fn name_v1(name: &str, verified_email: &str) -> String {
    name_initials(name).unwrap_or_else(|| email_initials(verified_email))
}

/// Steps 1 to 4 of `name-v1`: `None` when the name gives no initials.
fn name_initials(name: &str) -> Option<String> {
    let mut words: Vec<&str> = name
        .split_whitespace()
        .filter(|w| !w.contains('@') && w.chars().any(char::is_alphabetic))
        .collect();
    while words.len() >= 2 && TITLES.contains(&compare_key(words[0]).as_str()) {
        words.remove(0);
    }
    while words.len() >= 2 && SUFFIXES.contains(&compare_key(words[words.len() - 1]).as_str()) {
        words.pop();
    }
    let mut out = String::new();
    for word in first_and_last(&words) {
        let letter = word.chars().find(|c| c.is_alphabetic())?;
        out.push_str(&drawable_capital(letter)?);
    }
    (!out.is_empty()).then_some(out)
}

/// Step 5 of `name-v1`: the initials of an email address's local part, `?` when it has none.
fn email_initials(email: &str) -> String {
    let local = email.split('@').next().unwrap_or_default();
    let parts: Vec<&str> = local
        .split(|c: char| !c.is_alphanumeric())
        .filter(|p| !p.is_empty())
        .collect();
    let out: String = first_and_last(&parts)
        .into_iter()
        .filter_map(|p| p.chars().find(|c| c.is_alphanumeric()))
        .filter_map(drawable_capital)
        .collect();
    if out.is_empty() {
        "?".into()
    } else {
        out
    }
}

/// The first and the last of `words` (one when there is one, none when there are none).
fn first_and_last<'a>(words: &[&'a str]) -> Vec<&'a str> {
    match words {
        [] => vec![],
        [one] => vec![one],
        [first, .., last] => vec![first, last],
    }
}

/// A word as the title and suffix lists are compared with: without `.` and `,`, in capitals.
fn compare_key(word: &str) -> String {
    word.chars()
        .filter(|c| *c != '.' && *c != ',')
        .flat_map(char::to_uppercase)
        .collect()
}

/// `c` in capitals as the stamp font draws it: each character of its upper-case mapping as it is
/// when WinAnsiEncoding has it, else folded to its base letter ([`fold`]); `None` when a character
/// can be neither.
fn drawable_capital(c: char) -> Option<String> {
    c.to_uppercase()
        .map(|u| {
            if crate::pades::winansi_code(u).is_some() {
                Some(u)
            } else {
                fold(u).filter(|f| crate::pades::winansi_code(*f).is_some())
            }
        })
        .collect()
}

/// Latin Extended-A (U+0100 to U+017F), each letter's capital base letter, in code point order.
const LATIN_EXTENDED_A: &str = concat!(
    "AAAAAA",       // Ā ā Ă ă Ą ą
    "CCCCCCCC",     // Ć ć Ĉ ĉ Ċ ċ Č č
    "DDDD",         // Ď ď Đ đ
    "EEEEEEEEEE",   // Ē ē Ĕ ĕ Ė ė Ę ę Ě ě
    "GGGGGGGG",     // Ĝ ĝ Ğ ğ Ġ ġ Ģ ģ
    "HHHH",         // Ĥ ĥ Ħ ħ
    "IIIIIIIIII",   // Ĩ ĩ Ī ī Ĭ ĭ Į į İ ı
    "II",           // Ĳ ĳ
    "JJ",           // Ĵ ĵ
    "KKK",          // Ķ ķ ĸ
    "LLLLLLLLLL",   // Ĺ ĺ Ļ ļ Ľ ľ Ŀ ŀ Ł ł
    "NNNNNNN",      // Ń ń Ņ ņ Ň ň ŉ
    "NN",           // Ŋ ŋ
    "OOOOOO",       // Ō ō Ŏ ŏ Ő ő
    "ŒŒ",           // Œ œ
    "RRRRRR",       // Ŕ ŕ Ŗ ŗ Ř ř
    "SSSSSSŠŠ",     // Ś ś Ŝ ŝ Ş ş Š š
    "TTTTTT",       // Ţ ţ Ť ť Ŧ ŧ
    "UUUUUUUUUUUU", // Ũ ũ Ū ū Ŭ ŭ Ů ů Ű ű Ų ų
    "WW",           // Ŵ ŵ
    "YYŸ",          // Ŷ ŷ Ÿ
    "ZZZZŽŽ",       // Ź ź Ż ż Ž ž
    "S",            // ſ
);

/// The capital base letter of a Latin letter with a diacritic that WinAnsiEncoding lacks: Latin
/// Extended-A (`Ł`, `Ő`, `Č`...), the Romanian `Ș` `Ț` (comma below), the Vietnamese `Ơ` `Ư` and
/// Latin Extended Additional's Vietnamese letters (`Ạ` to `ỹ`). `None` for anything else.
pub fn fold(c: char) -> Option<char> {
    let n = c as u32;
    match n {
        0x0100..=0x017F => LATIN_EXTENDED_A.chars().nth((n - 0x0100) as usize),
        0x01A0 | 0x01A1 => Some('O'),
        0x01AF | 0x01B0 => Some('U'),
        0x0218 | 0x0219 => Some('S'),
        0x021A | 0x021B => Some('T'),
        0x1EA0..=0x1EB7 => Some('A'),
        0x1EB8..=0x1EC7 => Some('E'),
        0x1EC8..=0x1ECB => Some('I'),
        0x1ECC..=0x1EE3 => Some('O'),
        0x1EE4..=0x1EF1 => Some('U'),
        0x1EF2..=0x1EF9 => Some('Y'),
        _ => None,
    }
}

/// The rule of envelope schema versions 3 to 8: initials for an identity label. An email gives
/// the first and last parts of what precedes the `@` (`alice.martin@example.com` → `AM`,
/// `alice@example.com` → `A`); a name gives its first and last words (`Alice Martin` → `AM`).
/// Those versions stamp the initials of the verified email address. Kept unchanged so that their
/// documents keep verifying.
pub fn email_rule(label: &str) -> String {
    let words: Vec<&str> = label.split_whitespace().collect();
    let parts: Vec<&str> = match words.as_slice() {
        [one] if one.contains('@') => one
            .split('@')
            .next()
            .unwrap_or(one)
            .split(|c: char| !c.is_alphanumeric())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => words,
    };
    let s: String = first_and_last(&parts)
        .iter()
        .filter_map(|w| w.chars().find(|c| c.is_alphanumeric()))
        .flat_map(|c| c.to_uppercase())
        .collect();
    if s.is_empty() {
        "?".into()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        rule: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        email: String,
        initials: String,
    }

    #[test]
    fn the_shared_vectors_give_their_initials() {
        let v: Vectors =
            serde_json::from_str(include_str!("../../../spec/vectors/initials-name-v1.json"))
                .unwrap();
        assert_eq!(v.rule, InitialsRule::NameV1.as_str());
        assert!(v.vectors.len() >= 40);
        for t in &v.vectors {
            assert_eq!(
                stamp_initials(Some(InitialsRule::NameV1), &t.name, &t.email, Some("XYZ")),
                Some(t.initials.clone()),
                "name {:?}, email {:?}",
                t.name,
                t.email
            );
        }
    }

    #[test]
    fn the_email_rule_of_versions_3_to_8_is_unchanged() {
        assert_eq!(email_rule("Alice Martin"), "AM");
        assert_eq!(email_rule("Jean-Luc van der Berg"), "JB");
        assert_eq!(email_rule("alice@example.com"), "A");
        assert_eq!(email_rule("alice.martin@example.com"), "AM");
        assert_eq!(email_rule("jean-luc.van_der.berg@example.com"), "JB");
        assert_eq!(email_rule("élodie durand"), "ÉD");
        assert_eq!(email_rule("   "), "?");
        assert_eq!(
            stamp_initials(None, "Felix Fairfax", "ffairfax@example.com", Some("XYZ")),
            Some("F".into())
        );
    }

    #[test]
    fn the_fold_table_covers_latin_extended_a() {
        assert_eq!(LATIN_EXTENDED_A.chars().count(), 0x80);
        for (c, base) in [
            ('Ā', 'A'),
            ('č', 'C'),
            ('Đ', 'D'),
            ('ě', 'E'),
            ('Ğ', 'G'),
            ('ħ', 'H'),
            ('İ', 'I'),
            ('ı', 'I'),
            ('Ĵ', 'J'),
            ('ĸ', 'K'),
            ('Ł', 'L'),
            ('ň', 'N'),
            ('Ŋ', 'N'),
            ('Ő', 'O'),
            ('œ', 'Œ'),
            ('ř', 'R'),
            ('Ś', 'S'),
            ('š', 'Š'),
            ('Ţ', 'T'),
            ('ű', 'U'),
            ('Ŵ', 'W'),
            ('ŷ', 'Y'),
            ('Ÿ', 'Ÿ'),
            ('ź', 'Z'),
            ('Ž', 'Ž'),
            ('ſ', 'S'),
            ('Ș', 'S'),
            ('ț', 'T'),
            ('Ư', 'U'),
            ('Ạ', 'A'),
            ('ỹ', 'Y'),
            ('Ệ', 'E'),
            ('Ộ', 'O'),
        ] {
            assert_eq!(fold(c), Some(base), "{c}");
        }
        assert_eq!(fold('A'), None);
        assert_eq!(fold('Ж'), None);
        assert_eq!(fold('王'), None);
    }

    #[test]
    fn the_rule_is_written_by_its_name() {
        assert_eq!(
            serde_json::to_string(&InitialsRule::NameV1).unwrap(),
            r#""name-v1""#
        );
        assert_eq!(
            serde_json::to_string(&InitialsRule::SignerV1).unwrap(),
            r#""signer-v1""#
        );
        assert!(serde_json::from_str::<InitialsRule>(r#""name-v2""#).is_err());
        assert!(serde_json::from_str::<InitialsRule>(r#""signer-v2""#).is_err());
    }

    #[derive(Deserialize)]
    struct SignerVectors {
        rule: String,
        max_letters: usize,
        valid: Vec<Case>,
        invalid: Vec<Case>,
        prefill: Vec<Prefill>,
    }

    #[derive(Deserialize)]
    struct Case {
        initials: String,
    }

    #[derive(Deserialize)]
    struct Prefill {
        name: String,
        email: String,
        prefill: Option<String>,
    }

    #[test]
    fn the_signer_rule_s_shared_vectors_hold() {
        let v: SignerVectors = serde_json::from_str(include_str!(
            "../../../spec/vectors/initials-signer-v1.json"
        ))
        .unwrap();
        assert_eq!(v.rule, InitialsRule::SignerV1.as_str());
        assert_eq!(v.max_letters, MAX_SIGNER_INITIALS);
        assert!(v.valid.len() >= 10 && v.invalid.len() >= 15 && v.prefill.len() >= 8);
        for c in &v.valid {
            assert_eq!(
                check_signer_initials(&c.initials),
                Ok(()),
                "{:?}",
                c.initials
            );
            // The stamp is exactly the chosen letters, whatever the slot's name.
            assert_eq!(
                stamp_initials(
                    Some(InitialsRule::SignerV1),
                    "Felix Fairfax",
                    "f@example.com",
                    Some(&c.initials)
                ),
                Some(c.initials.clone())
            );
        }
        for c in &v.invalid {
            assert!(
                check_signer_initials(&c.initials).is_err(),
                "{:?}",
                c.initials
            );
        }
        for p in &v.prefill {
            assert_eq!(
                signer_v1_default(&p.name, &p.email),
                p.prefill,
                "{:?}",
                p.name
            );
            if let Some(letters) = &p.prefill {
                assert_eq!(check_signer_initials(letters), Ok(()), "{letters:?}");
            }
        }
    }

    #[test]
    fn initials_letters_are_the_letters_winansi_draws() {
        // Every initials letter is one the stamp font draws, and every alphabetic character it
        // draws is one, except the five symbols left out on purpose.
        for n in 0..0x3000u32 {
            let Some(c) = char::from_u32(n) else { continue };
            let drawn = crate::pades::winansi_code(c).is_some();
            if is_initials_letter(c) {
                assert!(drawn && c.is_alphabetic(), "{c:?}");
            } else if drawn && c.is_alphabetic() {
                assert!(matches!(c, 'ª' | 'º' | 'µ' | 'ƒ' | 'ˆ'), "{c:?}");
            }
        }
        // Under signer-v1, a record without letters gives none.
        assert_eq!(
            stamp_initials(
                Some(InitialsRule::SignerV1),
                "Felix Fairfax",
                "f@example.com",
                None
            ),
            None
        );
    }
}
