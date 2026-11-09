//! Validation formats for field values: email, phone, number, amount, postal code, IBAN, masked
//! identifiers and custom patterns, plus character limits.
//!
//! A preparer can ask that a text field's value have a given format. The same check runs in the
//! signer's page (instant feedback), in the engine when the signer signs (an invalid value is
//! refused) and in the verifier (a document with one is rejected), so it lives here, once.
//! [`Format::check`] returns the value in its **canonical** form, which is what the envelope
//! stores (`+33 6 12 34 56 78` becomes `+33612345678`), or a [`FormatError`] whose
//! [`FormatError::code`] a page turns into a message in the signer's language.
//!
//! Values are checked exactly as given, after the host has trimmed surrounding spaces and turned
//! locale entry (`1 250,50`) into canonical numbers ([`crate::decimal`]).
//!
//! Number fields use [`Format::Number`] through their sealed [`crate::numbers::NumberFormat`]
//! (envelope schema version 7). From envelope schema version 8, text and multi-line fields carry
//! a [`ValueFormat`] (the JSON form of a [`Format`], `value_format`) and a [`LengthRule`]
//! (`length`) in the prepared terms; [`FieldCheck`] applies a field's sealed rules, the same way
//! at signing, in the verifier and in hosts (the WebAssembly `signpdf_check_value`).

use serde::{Deserialize, Serialize};

use crate::currency::Currency;
use crate::decimal::{Decimal, DecimalError};
use crate::numbers::NumberFormat;
use crate::pattern::Pattern;

/// The longest email address accepted (RFC 5321's path limit, less the angle brackets).
pub const MAX_EMAIL_LEN: usize = 254;

/// Why a value does not have its field's format. [`FormatError::code`] is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// Not an email address.
    Email,
    /// Not a phone number in international form (`+` and 7 to 15 digits).
    Phone,
    /// Not a number in canonical form, or out of the number range.
    Number,
    /// More decimal places than the field allows.
    TooManyDecimals,
    /// Below the field's minimum.
    BelowMinimum,
    /// Above the field's maximum.
    AboveMaximum,
    /// A negative amount.
    NegativeAmount,
    /// Not a postal code of the field's country.
    PostalCode,
    /// The field's country has no postal-code rule in this build.
    UnsupportedCountry,
    /// Not an IBAN: wrong characters or length.
    Iban,
    /// An IBAN whose check digits are wrong (usually a typo).
    IbanChecksum,
    /// Not a US Social Security number.
    UsSsn,
    /// Not a US Employer Identification Number.
    UsEin,
    /// Fewer characters than the field's minimum.
    TooShort,
    /// More characters than the field's maximum.
    TooLong,
    /// Does not match the field's custom pattern ([`crate::pattern`]).
    Pattern,
}

impl FormatError {
    /// A stable code for the error, in `snake_case`.
    pub fn code(self) -> &'static str {
        match self {
            FormatError::Email => "invalid_email",
            FormatError::Phone => "invalid_phone",
            FormatError::Number => "invalid_number",
            FormatError::TooManyDecimals => "too_many_decimals",
            FormatError::BelowMinimum => "below_minimum",
            FormatError::AboveMaximum => "above_maximum",
            FormatError::NegativeAmount => "negative_amount",
            FormatError::PostalCode => "invalid_postal_code",
            FormatError::UnsupportedCountry => "unsupported_country",
            FormatError::Iban => "invalid_iban",
            FormatError::IbanChecksum => "iban_checksum",
            FormatError::UsSsn => "invalid_us_ssn",
            FormatError::UsEin => "invalid_us_ein",
            FormatError::TooShort => "too_short",
            FormatError::TooLong => "too_long",
            FormatError::Pattern => "pattern_mismatch",
        }
    }
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for FormatError {}

/// A format a field's value must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    /// An email address (RFC 5322's common form: a dot-atom local part and a domain name with at
    /// least two labels; letters beyond ASCII allowed). The domain is stored in lower case.
    Email,
    /// A phone number in international form, stored as E.164 (`+` then 7 to 15 digits, no
    /// spaces). Spaces, dashes, dots and parentheses are dropped, and a leading `00` is read as
    /// `+`. A page's country picker turns a national number into this form.
    Phone,
    /// A decimal number with at most `decimals` decimal places, within `min` and `max`
    /// (inclusive) when they are set. Stored with exactly `decimals` places (`12.5` → `12.50`).
    Number {
        min: Option<Decimal>,
        max: Option<Decimal>,
        decimals: u8,
    },
    /// A non-negative amount in a currency, with at most the currency's decimal places. Stored
    /// with exactly that many (`12.5` USD → `12.50`).
    Amount(Currency),
    /// A postal code of a country (ISO 3166-1 alpha-2 code, see [`POSTAL_CODE_COUNTRIES`]),
    /// stored in the country's usual written form (`sw1a1aa` → `SW1A 1AA`).
    PostalCode(String),
    /// An international bank account number, checked with its check digits and the country's
    /// length, stored without spaces in upper case.
    Iban,
    /// A US Social Security number, stored as `123-45-6789` and drawn masked
    /// ([`Format::display`]).
    UsSsn,
    /// A US Employer Identification Number, stored as `12-3456789` and drawn masked.
    UsEin,
    /// A value the whole of which matches a preparer's custom pattern ([`crate::pattern`]),
    /// stored as given.
    Pattern(Pattern),
}

impl Format {
    /// Checks `value` and returns its canonical form.
    pub fn check(&self, value: &str) -> Result<String, FormatError> {
        match self {
            Format::Email => email(value),
            Format::Phone => phone(value),
            Format::Number { min, max, decimals } => {
                number(value, min.as_ref(), max.as_ref(), *decimals)
            }
            Format::Amount(currency) => amount(value, currency),
            Format::PostalCode(country) => postal_code(value, country),
            Format::Iban => iban(value),
            Format::UsSsn => us_ssn(value),
            Format::UsEin => us_ein(value),
            Format::Pattern(p) => {
                if p.is_match(value) {
                    Ok(value.to_string())
                } else {
                    Err(FormatError::Pattern)
                }
            }
        }
    }

    /// The text drawn on the page for a canonical value. Identifiers that should not be read over
    /// a shoulder are masked but for their last four digits (`•••-••-6789`); an IBAN is drawn in
    /// groups of four; an amount after its currency code (`EUR 1250.50`). The envelope keeps the
    /// full value: the mask hides it from casual view, not from someone who opens the file.
    pub fn display(&self, canonical: &str) -> String {
        let last4 = |s: &str| {
            s.chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
        };
        match self {
            Format::UsSsn => format!("•••-••-{}", last4(canonical).collect::<String>()),
            Format::UsEin => format!("••-•••{}", last4(canonical).collect::<String>()),
            Format::Iban => canonical
                .as_bytes()
                .chunks(4)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            Format::Amount(currency) => format!("{} {canonical}", currency.code()),
            _ => canonical.to_string(),
        }
    }
}

/// Checks that `value` has between `min` and `max` characters (Unicode scalar values), when
/// they are set.
pub fn check_length(value: &str, min: Option<u32>, max: Option<u32>) -> Result<(), FormatError> {
    let n = value.chars().count();
    if min.is_some_and(|m| n < m as usize) {
        return Err(FormatError::TooShort);
    }
    if max.is_some_and(|m| n > m as usize) {
        return Err(FormatError::TooLong);
    }
    Ok(())
}

// ---- sealed field rules (envelope schema version 8) -------------------------------------------

/// The kinds of [`ValueFormat`], as written in the envelope (`"email"`, `"postal_code"`...).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ValueFormatKind {
    Email,
    Phone,
    /// Needs `currency`.
    Amount,
    /// Needs `country`.
    PostalCode,
    Iban,
    UsSsn,
    UsEin,
    /// Needs `pattern`.
    Pattern,
}

impl ValueFormatKind {
    /// Every kind, in the order a preparer is offered them.
    pub const ALL: [ValueFormatKind; 8] = [
        ValueFormatKind::Email,
        ValueFormatKind::Phone,
        ValueFormatKind::Amount,
        ValueFormatKind::PostalCode,
        ValueFormatKind::Iban,
        ValueFormatKind::UsSsn,
        ValueFormatKind::UsEin,
        ValueFormatKind::Pattern,
    ];

    /// The kind as written in the envelope.
    pub fn as_str(self) -> &'static str {
        match self {
            ValueFormatKind::Email => "email",
            ValueFormatKind::Phone => "phone",
            ValueFormatKind::Amount => "amount",
            ValueFormatKind::PostalCode => "postal_code",
            ValueFormatKind::Iban => "iban",
            ValueFormatKind::UsSsn => "us_ssn",
            ValueFormatKind::UsEin => "us_ein",
            ValueFormatKind::Pattern => "pattern",
        }
    }
}

/// The format sealed into a text or multi-line field (`value_format`, from envelope schema
/// version 8): a [`Format`] in JSON. `currency` (an ISO 4217 code such as `EUR`) goes with
/// `amount`, `country` (an ISO 3166-1 alpha-2 code of [`POSTAL_CODE_COUNTRIES`]) with
/// `postal_code`, and `pattern` ([`crate::pattern`], at most
/// [`crate::pattern::MAX_PATTERN_CHARS`] characters)
/// with `pattern`; no kind takes another's parameter. Part of the prepared terms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValueFormat {
    pub kind: ValueFormatKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

impl ValueFormat {
    /// A format of a kind that takes no parameter.
    pub fn of(kind: ValueFormatKind) -> ValueFormat {
        ValueFormat {
            kind,
            currency: None,
            country: None,
            pattern: None,
        }
    }

    /// The [`Format`] this stands for, or why the preparer's spec is refused (an English
    /// fragment that follows "field X ...": an unknown currency or country, a missing or extra
    /// parameter, a refused pattern).
    pub fn format(&self) -> Result<Format, String> {
        let kind = self.kind.as_str();
        let takes = match self.kind {
            ValueFormatKind::Amount => "currency",
            ValueFormatKind::PostalCode => "country",
            ValueFormatKind::Pattern => "pattern",
            _ => "",
        };
        for (name, present) in [
            ("currency", self.currency.is_some()),
            ("country", self.country.is_some()),
            ("pattern", self.pattern.is_some()),
        ] {
            if present && name != takes {
                return Err(format!("has a {kind} format, which takes no {name}"));
            }
        }
        Ok(match self.kind {
            ValueFormatKind::Email => Format::Email,
            ValueFormatKind::Phone => Format::Phone,
            ValueFormatKind::Iban => Format::Iban,
            ValueFormatKind::UsSsn => Format::UsSsn,
            ValueFormatKind::UsEin => Format::UsEin,
            ValueFormatKind::Amount => Format::Amount(
                currency(self.currency.as_deref())
                    .map_err(|e| format!("has an amount that {e}"))?,
            ),
            ValueFormatKind::PostalCode => {
                let country = self.country.as_deref().ok_or(
                    "has a postal_code format without its country (an ISO 3166-1 code such as FR)",
                )?;
                if !POSTAL_CODE_COUNTRIES.contains(&country) {
                    return Err(format!(
                        "has a postal_code format for '{country}', a country whose postal codes \
                         this build cannot check"
                    ));
                }
                Format::PostalCode(country.to_string())
            }
            ValueFormatKind::Pattern => {
                let source = self
                    .pattern
                    .as_deref()
                    .ok_or("has a pattern format without its pattern")?;
                Format::Pattern(Pattern::new(source).map_err(|e| format!("has a pattern: {e}"))?)
            }
        })
    }
}

/// The currency of an amount or a number format: an ISO 4217 code this build knows, in upper
/// case. The error follows "... that" or "... which".
pub(crate) fn currency(code: Option<&str>) -> Result<Currency, String> {
    let code = code.ok_or("needs a currency (an ISO 4217 code such as EUR)")?;
    Currency::from_code(code)
        .filter(|c| c.code() == code)
        .ok_or_else(|| format!("names the currency '{code}', which is not an ISO 4217 code"))
}

/// Most characters a [`LengthRule`] may ask for.
pub const MAX_LENGTH_LIMIT: u32 = 2000;

/// The number of characters a text or multi-line field's value may have (`length`, from envelope
/// schema version 8), counted on the stored value ([`check_length`]). Part of the prepared terms.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LengthRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl LengthRule {
    /// Check the rule at preparation: at least one bound, both within 0 to
    /// [`MAX_LENGTH_LIMIT`], a maximum of at least 1 and not below the minimum.
    pub fn validate(&self) -> Result<(), String> {
        match (self.min, self.max) {
            (None, None) => Err("has a length rule with neither a minimum nor a maximum".into()),
            (_, Some(0)) => Err("has a length rule whose maximum is 0".into()),
            (Some(n), _) | (_, Some(n)) if n > MAX_LENGTH_LIMIT => Err(format!(
                "has a length rule above {MAX_LENGTH_LIMIT} characters"
            )),
            (Some(lo), Some(hi)) if lo > hi => {
                Err("has a length rule whose minimum is above its maximum".into())
            }
            _ => Ok(()),
        }
    }
}

/// Longest owner message (`check_message`) a field may carry, in characters.
pub const MAX_CHECK_MESSAGE_CHARS: usize = 200;

/// Check a field's owner message at preparation: the preparer's own sentence, shown to the signer
/// instead of the standard message when the value is refused. 1 to [`MAX_CHECK_MESSAGE_CHARS`]
/// characters, not only spaces, no control characters. It is sealed with the terms but never
/// decides whether a value or a document is valid.
pub fn validate_check_message(message: &str) -> Result<(), String> {
    if message.trim().is_empty() || message.chars().count() > MAX_CHECK_MESSAGE_CHARS {
        return Err(format!(
            "has a check message that is empty or longer than {MAX_CHECK_MESSAGE_CHARS} characters"
        ));
    }
    if message.chars().any(char::is_control) {
        return Err("has a check message with a control character".into());
    }
    Ok(())
}

/// The rules sealed in one field, ready to apply to a value: what a signer's entry becomes in the
/// envelope ([`FieldCheck::check`]), whether a stored value obeys them ([`FieldCheck::holds`])
/// and how it is drawn ([`FieldCheck::display`]). Built by [`crate::model::Field::check`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FieldCheck {
    /// No rule: the value is kept as given.
    #[default]
    None,
    /// A text or multi-line field with a format, a length rule, or both.
    Text {
        format: Option<Format>,
        length: Option<LengthRule>,
    },
    /// A number field.
    Number(NumberFormat),
}

impl FieldCheck {
    /// A signer's entry as the envelope stores it, or why it is refused. An entry with a format
    /// is trimmed first; an empty entry is no answer and is stored empty (whether the field must
    /// be answered is checked separately). The length is counted on the stored value.
    pub fn check(&self, input: &str) -> Result<String, FormatError> {
        match self {
            FieldCheck::None => Ok(input.to_string()),
            FieldCheck::Number(n) => match input.trim() {
                "" => Ok(String::new()),
                v => n.check(v),
            },
            FieldCheck::Text { format, length } => {
                let value = match format {
                    Some(f) => match input.trim() {
                        "" => return Ok(String::new()),
                        v => f.check(v)?,
                    },
                    None if input.is_empty() => return Ok(String::new()),
                    None => input.to_string(),
                };
                if let Some(l) = length {
                    check_length(&value, l.min, l.max)?;
                }
                Ok(value)
            }
        }
    }

    /// Whether `stored` is a value [`FieldCheck::check`] stores: empty, or a valid value in its
    /// canonical form. The verifier applies this to every signer's values.
    pub fn holds(&self, stored: &str) -> Result<(), FormatError> {
        match self.check(stored) {
            Ok(v) if v == stored => Ok(()),
            Ok(_) => Err(match self {
                FieldCheck::Text {
                    format: Some(f), ..
                } => f.refusal(),
                _ => FormatError::Number,
            }),
            Err(e) => Err(e),
        }
    }

    /// The text drawn on the page for a stored value: masked identifiers, an IBAN in groups, an
    /// amount after its currency, a number in its sealed style.
    pub fn display(&self, stored: &str) -> String {
        match self {
            FieldCheck::Text {
                format: Some(f), ..
            } if !stored.is_empty() => f.display(stored),
            FieldCheck::Number(n) if !stored.is_empty() => n.display(stored),
            _ => stored.to_string(),
        }
    }
}

impl Format {
    /// The error for a value of this format that is valid but not written canonically.
    fn refusal(&self) -> FormatError {
        match self {
            Format::Email => FormatError::Email,
            Format::Phone => FormatError::Phone,
            Format::Number { .. } | Format::Amount(_) => FormatError::Number,
            Format::PostalCode(_) => FormatError::PostalCode,
            Format::Iban => FormatError::Iban,
            Format::UsSsn => FormatError::UsSsn,
            Format::UsEin => FormatError::UsEin,
            Format::Pattern(_) => FormatError::Pattern,
        }
    }
}

// ---- email ------------------------------------------------------------------------------------

fn email(value: &str) -> Result<String, FormatError> {
    let err = FormatError::Email;
    if value.len() > MAX_EMAIL_LEN {
        return Err(err);
    }
    let (local, domain) = value.split_once('@').ok_or(err)?;
    // Dot-atom local part: atoms of allowed characters separated by single dots.
    let atext = |c: char| {
        c.is_ascii_alphanumeric()
            || "!#$%&'*+/=?^_`{|}~-".contains(c)
            || (!c.is_ascii() && c.is_alphanumeric())
    };
    if local.is_empty()
        || local.len() > 64
        || local
            .split('.')
            .any(|atom| atom.is_empty() || !atom.chars().all(atext))
    {
        return Err(err);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && c.is_alphanumeric())
            })
    };
    let tld = labels.last().ok_or(err)?;
    if domain.len() > 253
        || labels.len() < 2
        || !labels.iter().all(label_ok)
        || tld.chars().all(|c| c.is_ascii_digit())
    {
        return Err(err);
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

// ---- phone ------------------------------------------------------------------------------------

fn phone(value: &str) -> Result<String, FormatError> {
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')'))
        .collect();
    let digits = compact
        .strip_prefix('+')
        .or_else(|| compact.strip_prefix("00"))
        .ok_or(FormatError::Phone)?;
    // Country codes never start with 0; E.164 allows at most 15 digits, and the shortest
    // numbers in use have 7.
    if !(7..=15).contains(&digits.len())
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.starts_with('0')
    {
        return Err(FormatError::Phone);
    }
    Ok(format!("+{digits}"))
}

// ---- numbers and amounts ----------------------------------------------------------------------

fn number(
    value: &str,
    min: Option<&Decimal>,
    max: Option<&Decimal>,
    decimals: u8,
) -> Result<String, FormatError> {
    let n = Decimal::parse(value).map_err(|_| FormatError::Number)?;
    let n = n.with_scale_exact(decimals).map_err(|e| match e {
        DecimalError::TooPrecise => FormatError::TooManyDecimals,
        _ => FormatError::Number,
    })?;
    if min.is_some_and(|m| n < *m) {
        return Err(FormatError::BelowMinimum);
    }
    if max.is_some_and(|m| n > *m) {
        return Err(FormatError::AboveMaximum);
    }
    Ok(n.to_string())
}

fn amount(value: &str, currency: &Currency) -> Result<String, FormatError> {
    let n = number(value, None, None, currency.minor_units())?;
    if n.starts_with('-') {
        return Err(FormatError::NegativeAmount);
    }
    Ok(n)
}

// ---- postal codes -----------------------------------------------------------------------------

/// The countries [`Format::PostalCode`] knows, as ISO 3166-1 alpha-2 codes.
pub const POSTAL_CODE_COUNTRIES: &[&str] = &[
    "AT", "AU", "BE", "BR", "CA", "CH", "DE", "DK", "ES", "FR", "GB", "IE", "IN", "IT", "JP", "MX",
    "NL", "NO", "PL", "PT", "SE", "US",
];

/// Whether `s` has the shape of `pattern`: `9` a digit, `A` an upper-case ASCII letter, `X`
/// either, any other character itself.
fn shape(s: &str, pattern: &str) -> bool {
    s.len() == pattern.len()
        && s.bytes().zip(pattern.bytes()).all(|(c, p)| match p {
            b'9' => c.is_ascii_digit(),
            b'A' => c.is_ascii_uppercase(),
            b'X' => c.is_ascii_digit() || c.is_ascii_uppercase(),
            _ => c == p,
        })
}

/// `c` with `sep` inserted before byte `at`, or unchanged if it is shorter (`c` is ASCII).
fn split_join(c: &str, at: usize, sep: char) -> String {
    match (c.get(..at), c.get(at..)) {
        (Some(a), Some(b)) => format!("{a}{sep}{b}"),
        _ => c.to_string(),
    }
}

fn postal_code(value: &str, country: &str) -> Result<String, FormatError> {
    if !POSTAL_CODE_COUNTRIES.contains(&country) {
        return Err(FormatError::UnsupportedCountry);
    }
    // At most one space or dash, then upper case without it: each country's written form is
    // rebuilt below.
    if value.chars().filter(|c| matches!(c, ' ' | '-')).count() > 1 {
        return Err(FormatError::PostalCode);
    }
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !compact.is_ascii() {
        return Err(FormatError::PostalCode);
    }
    let c = compact.as_str();
    let digits = |n: usize| shape(c, &"9".repeat(n));
    let first_not_zero = !c.starts_with('0');
    let (valid, canonical) = match country {
        "US" if digits(9) => (true, split_join(c, 5, '-')),
        "US" | "FR" | "DE" | "IT" | "MX" => (digits(5), c.to_string()),
        "ES" => {
            let province = c.get(..2).and_then(|p| p.parse::<u8>().ok()).unwrap_or(0);
            (digits(5) && (1..=52).contains(&province), c.to_string())
        }
        "AT" | "BE" | "CH" => (digits(4) && first_not_zero, c.to_string()),
        "AU" | "DK" | "NO" => (digits(4), c.to_string()),
        "IN" => (digits(6) && first_not_zero, c.to_string()),
        "NL" => (shape(c, "9999AA") && first_not_zero, split_join(c, 4, ' ')),
        "SE" => (digits(5) && first_not_zero, split_join(c, 3, ' ')),
        "PL" => (digits(5), split_join(c, 2, '-')),
        "PT" => (digits(7) && first_not_zero, split_join(c, 4, '-')),
        "JP" => (digits(7), split_join(c, 3, '-')),
        "BR" => (digits(8), split_join(c, 5, '-')),
        "CA" => {
            // The letters D, F, I, O, Q and U are never used; W and Z never come first.
            let letter = |i: usize| {
                let b = c.as_bytes()[i];
                !b"DFIOQU".contains(&b) && !(i == 0 && (b == b'W' || b == b'Z'))
            };
            let valid = shape(c, "A9A9A9") && letter(0) && letter(2) && letter(4);
            (valid, split_join(c, 3, ' '))
        }
        "GB" => {
            // An outward code of 2 to 4 characters, then the inward code: a digit, two letters.
            let split = c.len().saturating_sub(3);
            let (outward, inward) = (&c[..split], &c[split..]);
            let valid = (shape(inward, "9AA")
                && ["A9", "A99", "AA9", "AA99", "A9A", "AA9A"]
                    .iter()
                    .any(|p| shape(outward, p)))
                || c == "GIR0AA";
            (valid, split_join(c, split, ' '))
        }
        "IE" => {
            // Eircode: a routing key (a letter, a digit, then a digit or W: "D6W" is Dublin 6W)
            // and a unique identifier of four characters.
            let valid = c.len() == 7
                && shape(&c[..2], "A9")
                && (c.as_bytes()[2].is_ascii_digit() || c.as_bytes()[2] == b'W')
                && shape(&c[3..], "XXXX");
            (valid, split_join(c, 3, ' '))
        }
        _ => return Err(FormatError::UnsupportedCountry),
    };
    if valid {
        Ok(canonical)
    } else {
        Err(FormatError::PostalCode)
    }
}

// ---- IBAN -------------------------------------------------------------------------------------

/// IBAN lengths by country, from the IBAN registry. A country missing here is checked against
/// the general rule (15 to 34 characters) and its check digits.
#[rustfmt::skip]
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24), ("AE", 23), ("AL", 28), ("AT", 20), ("AZ", 28), ("BA", 20), ("BE", 16),
    ("BG", 22), ("BH", 22), ("BR", 29), ("BY", 28), ("CH", 21), ("CR", 22), ("CY", 28),
    ("CZ", 24), ("DE", 22), ("DK", 18), ("DO", 28), ("EE", 20), ("EG", 29), ("ES", 24),
    ("FI", 18), ("FO", 18), ("FR", 27), ("GB", 22), ("GE", 22), ("GI", 23), ("GL", 18),
    ("GR", 27), ("GT", 28), ("HR", 21), ("HU", 28), ("IE", 22), ("IL", 23), ("IQ", 23),
    ("IS", 26), ("IT", 27), ("JO", 30), ("KW", 30), ("KZ", 20), ("LB", 28), ("LC", 32),
    ("LI", 21), ("LT", 20), ("LU", 20), ("LV", 21), ("MC", 27), ("MD", 24), ("ME", 22),
    ("MK", 19), ("MR", 27), ("MT", 31), ("MU", 30), ("NL", 18), ("NO", 15), ("PK", 24),
    ("PL", 28), ("PS", 29), ("PT", 25), ("QA", 29), ("RO", 24), ("RS", 22), ("SA", 24),
    ("SC", 31), ("SE", 24), ("SI", 19), ("SK", 24), ("SM", 27), ("ST", 25), ("SV", 28),
    ("TL", 23), ("TN", 24), ("TR", 26), ("UA", 29), ("VA", 22), ("VG", 24), ("XK", 20),
];

fn iban(value: &str) -> Result<String, FormatError> {
    let compact: String = value
        .chars()
        .filter(|c| *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let b = compact.as_bytes();
    let well_formed = (15..=34).contains(&b.len())
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..4].iter().all(u8::is_ascii_digit)
        && b[4..]
            .iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase());
    if !well_formed {
        return Err(FormatError::Iban);
    }
    if let Some((_, len)) = IBAN_LENGTHS.iter().find(|(cc, _)| cc.as_bytes() == &b[..2]) {
        if b.len() != *len {
            return Err(FormatError::Iban);
        }
    }
    // ISO 13616: move the first four characters to the end, letters become 10..35, and the
    // number modulo 97 must be 1.
    let mut rem: u32 = 0;
    for &c in b[4..].iter().chain(&b[..4]) {
        let v = if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A') + 10
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    if rem != 1 {
        return Err(FormatError::IbanChecksum);
    }
    Ok(compact)
}

// ---- US identifiers ---------------------------------------------------------------------------

fn us_ssn(value: &str) -> Result<String, FormatError> {
    let err = FormatError::UsSsn;
    let digits: String = match value.len() {
        11 if shape(value, "999-99-9999") => value.replace('-', ""),
        9 if shape(value, "999999999") => value.to_string(),
        _ => return Err(err),
    };
    let (area, group, serial) = (&digits[..3], &digits[3..5], &digits[5..]);
    // Never issued: area 000, 666 or 900-999, group 00, serial 0000.
    if area == "000" || area == "666" || area.starts_with('9') || group == "00" || serial == "0000"
    {
        return Err(err);
    }
    Ok(format!("{area}-{group}-{serial}"))
}

fn us_ein(value: &str) -> Result<String, FormatError> {
    let digits: String = match value.len() {
        10 if shape(value, "99-9999999") => value.replace('-', ""),
        9 if shape(value, "999999999") => value.to_string(),
        _ => return Err(FormatError::UsEin),
    };
    if digits.starts_with("00") || &digits[2..] == "0000000" {
        return Err(FormatError::UsEin);
    }
    Ok(format!("{}-{}", &digits[..2], &digits[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(format: &Format, value: &str) -> Result<String, FormatError> {
        format.check(value)
    }

    #[test]
    fn emails() {
        for (input, canonical) in [
            ("name@example.com", "name@example.com"),
            (
                "First.Last+tag@Example.CO.uk",
                "First.Last+tag@example.co.uk",
            ),
            (
                "o'brien@sub-domain.example.org",
                "o'brien@sub-domain.example.org",
            ),
            ("josé@exemple.fr", "josé@exemple.fr"),
            ("user@münchen.de", "user@münchen.de"),
        ] {
            assert_eq!(
                check(&Format::Email, input).as_deref(),
                Ok(canonical),
                "{input}"
            );
        }
        let long_local = format!("{}@example.com", "a".repeat(65));
        let long_total = format!("a@{}.com", "b".repeat(250));
        for input in [
            "",
            "plain",
            "@example.com",
            "name@",
            "name@localhost",
            "name@@example.com",
            "na me@example.com",
            ".name@example.com",
            "name.@example.com",
            "na..me@example.com",
            "name@-example.com",
            "name@example-.com",
            "name@example..com",
            "name@example.123",
            "name@exa_mple.com",
            "\"quoted\"@example.com",
            "name@[192.0.2.1]",
            long_local.as_str(),
            long_total.as_str(),
        ] {
            assert_eq!(
                check(&Format::Email, input),
                Err(FormatError::Email),
                "{input}"
            );
        }
    }

    #[test]
    fn phones_become_e164() {
        for (input, canonical) in [
            ("+33 6 12 34 56 78", "+33612345678"),
            ("+1 (415) 555-0100", "+14155550100"),
            ("0044 20 7946 0000", "+442079460000"),
            ("+290 1234", "+2901234"),
            ("+49.30.1234567", "+49301234567"),
        ] {
            assert_eq!(
                check(&Format::Phone, input).as_deref(),
                Ok(canonical),
                "{input}"
            );
        }
        for input in [
            "",
            "06 12 34 56 78",
            "+0 123 456 789",
            "+123456",
            "+1234567890123456",
            "+33 6 12 34 56 7x",
            "+33/612345678",
            "++33612345678",
        ] {
            assert_eq!(
                check(&Format::Phone, input),
                Err(FormatError::Phone),
                "{input}"
            );
        }
    }

    #[test]
    fn numbers_keep_their_decimal_places_and_range() {
        let d = |s: &str| Decimal::parse(s).unwrap();
        let percent = Format::Number {
            min: Some(d("0")),
            max: Some(d("100")),
            decimals: 2,
        };
        assert_eq!(check(&percent, "12.5").as_deref(), Ok("12.50"));
        assert_eq!(check(&percent, "100").as_deref(), Ok("100.00"));
        assert_eq!(check(&percent, "0").as_deref(), Ok("0.00"));
        assert_eq!(check(&percent, "12.345"), Err(FormatError::TooManyDecimals));
        assert_eq!(check(&percent, "12.340").as_deref(), Ok("12.34"));
        assert_eq!(check(&percent, "-0.01"), Err(FormatError::BelowMinimum));
        assert_eq!(check(&percent, "100.01"), Err(FormatError::AboveMaximum));
        for bad in ["", "1,5", "1e2", "twelve", " 12"] {
            assert_eq!(check(&percent, bad), Err(FormatError::Number), "{bad}");
        }
        let count = Format::Number {
            min: None,
            max: None,
            decimals: 0,
        };
        assert_eq!(check(&count, "-42").as_deref(), Ok("-42"));
        assert_eq!(check(&count, "4.0").as_deref(), Ok("4"));
        assert_eq!(check(&count, "4.5"), Err(FormatError::TooManyDecimals));
    }

    #[test]
    fn amounts_use_the_currency_minor_unit() {
        let usd = Format::Amount(Currency::from_code("USD").unwrap());
        let jpy = Format::Amount(Currency::from_code("JPY").unwrap());
        assert_eq!(check(&usd, "1250.5").as_deref(), Ok("1250.50"));
        assert_eq!(check(&usd, "0").as_deref(), Ok("0.00"));
        assert_eq!(check(&usd, "1.001"), Err(FormatError::TooManyDecimals));
        assert_eq!(check(&usd, "-5"), Err(FormatError::NegativeAmount));
        assert_eq!(check(&jpy, "1250").as_deref(), Ok("1250"));
        assert_eq!(check(&jpy, "1250.5"), Err(FormatError::TooManyDecimals));
    }

    #[test]
    fn postal_codes_by_country() {
        let pc = |country: &str, value: &str| check(&Format::PostalCode(country.into()), value);
        for (country, input, canonical) in [
            ("US", "94105", "94105"),
            ("US", "94105-1234", "94105-1234"),
            ("US", "941051234", "94105-1234"),
            ("GB", "SW1A 1AA", "SW1A 1AA"),
            ("GB", "sw1a1aa", "SW1A 1AA"),
            ("GB", "M1 1AE", "M1 1AE"),
            ("GB", "B33 8TH", "B33 8TH"),
            ("GB", "CR2 6XH", "CR2 6XH"),
            ("GB", "DN55 1PT", "DN55 1PT"),
            ("GB", "W1A 0AX", "W1A 0AX"),
            ("GB", "GIR 0AA", "GIR 0AA"),
            ("CA", "k1a0b1", "K1A 0B1"),
            ("CA", "H3Z 2Y7", "H3Z 2Y7"),
            ("FR", "75008", "75008"),
            ("DE", "10115", "10115"),
            ("ES", "28013", "28013"),
            ("IT", "00184", "00184"),
            ("NL", "1012 AB", "1012 AB"),
            ("NL", "1012ab", "1012 AB"),
            ("BE", "1000", "1000"),
            ("CH", "8001", "8001"),
            ("AT", "1010", "1010"),
            ("AU", "0800", "0800"),
            ("DK", "2100", "2100"),
            ("NO", "0150", "0150"),
            ("SE", "114 55", "114 55"),
            ("SE", "11455", "114 55"),
            ("PL", "00-950", "00-950"),
            ("PT", "1000-001", "1000-001"),
            ("JP", "100-0001", "100-0001"),
            ("BR", "01310-100", "01310-100"),
            ("MX", "06600", "06600"),
            ("IN", "110001", "110001"),
            ("IE", "D02 X285", "D02 X285"),
            ("IE", "d6wxy12", "D6W XY12"),
        ] {
            assert_eq!(
                pc(country, input).as_deref(),
                Ok(canonical),
                "{country} {input}"
            );
        }
        for (country, input) in [
            ("US", "9410"),
            ("US", "94105-123"),
            ("US", "ABCDE"),
            ("GB", "SW1A"),
            ("GB", "1AA 1AA"),
            ("GB", "SW1A  1AA"),
            ("CA", "D1A 0B1"),
            ("CA", "W1A 0B1"),
            ("CA", "K1A 0BQ"),
            ("FR", "7500"),
            ("FR", "750088"),
            ("ES", "53001"),
            ("ES", "00100"),
            ("NL", "0123 AB"),
            ("NL", "1012 A1"),
            ("BE", "0999"),
            ("IN", "010001"),
            ("SE", "014 55"),
            ("IE", "D02X28"),
            ("DE", "1O115"),
            ("DE", "１0115"),
        ] {
            assert_eq!(
                pc(country, input),
                Err(FormatError::PostalCode),
                "{country} {input}"
            );
        }
        assert_eq!(pc("ZZ", "12345"), Err(FormatError::UnsupportedCountry));
        assert_eq!(pc("us", "94105"), Err(FormatError::UnsupportedCountry));
        for pair in POSTAL_CODE_COUNTRIES.windows(2) {
            assert!(pair[0] < pair[1]);
        }
    }

    #[test]
    fn ibans_are_checked_with_their_check_digits() {
        for (input, canonical) in [
            ("GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),
            ("de89370400440532013000", "DE89370400440532013000"),
            (
                "FR14 2004 1010 0505 0001 3M02 606",
                "FR1420041010050500013M02606",
            ),
            ("NO9386011117947", "NO9386011117947"),
            ("CH9300762011623852957", "CH9300762011623852957"),
        ] {
            assert_eq!(
                check(&Format::Iban, input).as_deref(),
                Ok(canonical),
                "{input}"
            );
        }
        // One changed digit, or two swapped, breaks the check digits.
        assert_eq!(
            check(&Format::Iban, "GB82WEST12345698765433"),
            Err(FormatError::IbanChecksum)
        );
        assert_eq!(
            check(&Format::Iban, "GB82WEST12345698765423"),
            Err(FormatError::IbanChecksum)
        );
        for input in [
            "",
            "GB82",
            "GB82WEST1234569876543",
            "GB82WEST123456987654321",
            "1B82WEST12345698765432",
            "GBX2WEST12345698765432",
            "GB82-WEST-1234-5698-7654-32",
            "GB82WÉST12345698765432",
        ] {
            assert_eq!(
                check(&Format::Iban, input),
                Err(FormatError::Iban),
                "{input}"
            );
        }
        assert_eq!(
            Format::Iban.display("GB82WEST12345698765432"),
            "GB82 WEST 1234 5698 7654 32"
        );
        for pair in IBAN_LENGTHS.windows(2) {
            assert!(pair[0].0 < pair[1].0);
        }
    }

    #[test]
    fn us_identifiers_are_stored_whole_and_drawn_masked() {
        assert_eq!(
            check(&Format::UsSsn, "123-45-6789").as_deref(),
            Ok("123-45-6789")
        );
        assert_eq!(
            check(&Format::UsSsn, "123456789").as_deref(),
            Ok("123-45-6789")
        );
        for bad in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-4567",
            "123-45-0000",
            "123-456-789",
            "12345678",
            "123 45 6789",
        ] {
            assert_eq!(check(&Format::UsSsn, bad), Err(FormatError::UsSsn), "{bad}");
        }
        assert_eq!(Format::UsSsn.display("123-45-6789"), "•••-••-6789");
        assert_eq!(
            check(&Format::UsEin, "12-3456789").as_deref(),
            Ok("12-3456789")
        );
        assert_eq!(
            check(&Format::UsEin, "123456789").as_deref(),
            Ok("12-3456789")
        );
        for bad in ["00-1234567", "12-0000000", "123-456789", "12-345678"] {
            assert_eq!(check(&Format::UsEin, bad), Err(FormatError::UsEin), "{bad}");
        }
        assert_eq!(Format::UsEin.display("12-3456789"), "••-•••6789");
        assert_eq!(Format::Phone.display("+33612345678"), "+33612345678");
    }

    #[test]
    fn odd_inputs_never_panic() {
        let inputs = [
            "",
            " ",
            "-",
            "--",
            "1",
            "A",
            "é",
            "12-",
            "-12",
            "A1",
            "9AA",
            "GIR",
            "0AA",
            "W",
            "D6W",
            "１",
            "\u{0}",
            "+",
            "00",
            "@",
            "a@b",
            "GB",
            "GB82",
            "999-99-",
            "€€€€€€€",
        ];
        let mut formats = vec![
            Format::Email,
            Format::Phone,
            Format::Iban,
            Format::UsSsn,
            Format::UsEin,
            Format::Amount(Currency::from_code("EUR").unwrap()),
            Format::Number {
                min: None,
                max: None,
                decimals: 18,
            },
        ];
        formats.extend(
            POSTAL_CODE_COUNTRIES
                .iter()
                .map(|c| Format::PostalCode(c.to_string())),
        );
        for format in &formats {
            for input in inputs {
                let _ = format.check(input);
                let _ = format.display(input);
            }
        }
    }

    #[test]
    fn lengths_count_characters_not_bytes() {
        assert_eq!(check_length("ab", Some(2), Some(80)), Ok(()));
        assert_eq!(
            check_length("a", Some(2), Some(80)),
            Err(FormatError::TooShort)
        );
        assert_eq!(check_length("éé", Some(2), Some(2)), Ok(()));
        assert_eq!(
            check_length("ééé", None, Some(2)),
            Err(FormatError::TooLong)
        );
        assert_eq!(check_length("", None, None), Ok(()));
    }
}
