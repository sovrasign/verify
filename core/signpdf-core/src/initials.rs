//! The letters the engine stamps in a signer's further initials fields, and the rule that derives
//! them, which the envelope names so that a verifier can derive them again.
//!
//! A signer's *primary* signature field (their first signature field, else their first initials
//! field) carries their signature box. Every other initials field of theirs gets an engine stamp:
//! letters derived only from data the verifier has, so a signer cannot write other text there
//! and the verifier rejects a stamp that differs (`stamp_mismatch`).
//!
//! ## The rules
//!
//! * **`name-v1`** (envelope schema version 9 and later, written in the envelope's
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

use serde::{Deserialize, Serialize};

/// How an envelope's initials stamps are derived (the envelope's `initials_rule`, from schema
/// version 9). Versions 3 to 8 name none and use [`email_rule`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InitialsRule {
    /// [`name_v1`]: the slot's name, else the verified email address.
    #[serde(rename = "name-v1")]
    NameV1,
}

impl InitialsRule {
    /// The rule's name as the envelope writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            InitialsRule::NameV1 => "name-v1",
        }
    }
}

/// The initials stamped for a signer under `rule` (`None`: an envelope of version 3 to 8):
/// `slot_name` is the name the preparer gave the signer's slot, `verified_email` the email address
/// the signer's identity provider verified.
pub fn stamp_initials(rule: Option<InitialsRule>, slot_name: &str, verified_email: &str) -> String {
    match rule {
        Some(InitialsRule::NameV1) => name_v1(slot_name, verified_email),
        None => email_rule(verified_email),
    }
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
                stamp_initials(Some(InitialsRule::NameV1), &t.name, &t.email),
                t.initials,
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
            stamp_initials(None, "Felix Fairfax", "ffairfax@example.com"),
            "F"
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
        assert!(serde_json::from_str::<InitialsRule>(r#""name-v2""#).is_err());
    }
}
