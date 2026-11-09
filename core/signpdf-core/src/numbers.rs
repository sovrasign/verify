//! Number fields: the format a preparer seals into a number field (its decimal places, its
//! range and how the value is drawn), from envelope schema version 7.
//!
//! A number field's value is stored as a canonical decimal ([`crate::decimal`]) with exactly the
//! field's decimal places (`1250.50`), whatever the signer typed (`1 250,5` in French, `1,250.5`
//! in English: reading the signer's locale is the host's job). It is drawn in the field's sealed
//! [`NumberStyle`], not in the signer's locale, so every party reads the same text. The signer's
//! page, the engine at signing and the verifier apply the same rules ([`NumberFormat::check`]).
//! From envelope schema version 8 a number may be an amount in a currency
//! ([`NumberFormat::currency`]): it keeps the currency's decimal places and is drawn after its
//! code (`EUR 12 500,00`).

use serde::{Deserialize, Serialize};

use crate::decimal::Decimal;
use crate::formats::{Format, FormatError};

/// Most decimal places a number field may keep.
pub const MAX_NUMBER_DECIMALS: u8 = 6;

/// How a number field's value is drawn: its grouping and decimal marks. Part of the prepared
/// terms. The value itself is always stored canonically (`-1234.50`).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NumberStyle {
    /// `1234.5`: no grouping, a point (the canonical form).
    #[default]
    #[serde(rename = "1234.5")]
    Plain,
    /// `1,234.5`: as in English.
    #[serde(rename = "1,234.5")]
    CommaPoint,
    /// `1.234,5`: as in German, Italian, Spanish or Portuguese.
    #[serde(rename = "1.234,5")]
    PointComma,
    /// `1 234,5`: as in French, Russian or Polish (drawn with a plain space).
    #[serde(rename = "1 234,5")]
    SpaceComma,
    /// `1'234.5`: as in Switzerland.
    #[serde(rename = "1'234.5")]
    ApostrophePoint,
    /// `1234,5`: no grouping, a comma.
    #[serde(rename = "1234,5")]
    PlainComma,
}

impl NumberStyle {
    /// Every style, in the order a preparer is offered them.
    pub const ALL: [NumberStyle; 6] = [
        NumberStyle::Plain,
        NumberStyle::CommaPoint,
        NumberStyle::PointComma,
        NumberStyle::SpaceComma,
        NumberStyle::ApostrophePoint,
        NumberStyle::PlainComma,
    ];

    /// The default, which is not written into the envelope.
    pub fn is_plain(&self) -> bool {
        *self == NumberStyle::Plain
    }

    /// The pattern as written in the envelope, e.g. `1 234,5`.
    pub fn pattern(&self) -> &'static str {
        match self {
            NumberStyle::Plain => "1234.5",
            NumberStyle::CommaPoint => "1,234.5",
            NumberStyle::PointComma => "1.234,5",
            NumberStyle::SpaceComma => "1 234,5",
            NumberStyle::ApostrophePoint => "1'234.5",
            NumberStyle::PlainComma => "1234,5",
        }
    }

    /// The thousands separator (`None`: no grouping) and the decimal mark.
    fn marks(&self) -> (Option<char>, char) {
        match self {
            NumberStyle::Plain => (None, '.'),
            NumberStyle::CommaPoint => (Some(','), '.'),
            NumberStyle::PointComma => (Some('.'), ','),
            NumberStyle::SpaceComma => (Some(' '), ','),
            NumberStyle::ApostrophePoint => (Some('\''), '.'),
            NumberStyle::PlainComma => (None, ','),
        }
    }

    /// A canonical decimal (`-1234.50`) drawn in this style (`-1 234,50`). Anything else is
    /// returned unchanged (a signer revision never holds one: the verifier refuses it).
    pub fn format(&self, canonical: &str) -> String {
        if Decimal::parse(canonical).is_err() {
            return canonical.to_string();
        }
        let (sign, digits) = match canonical.strip_prefix('-') {
            Some(rest) => ("-", rest),
            None => ("", canonical),
        };
        let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
        let (group, mark) = self.marks();
        let mut out = String::from(sign);
        for (i, c) in int.chars().enumerate() {
            if let Some(g) = group {
                if i > 0 && (int.len() - i) % 3 == 0 {
                    out.push(g);
                }
            }
            out.push(c);
        }
        if !frac.is_empty() {
            out.push(mark);
            out.push_str(frac);
        }
        out
    }
}

/// The format sealed into a number field: how many decimal places it keeps, its range and how it
/// is drawn. Part of the prepared terms.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NumberFormat {
    /// Decimal places the value keeps, 0 to [`MAX_NUMBER_DECIMALS`]: the value is stored and
    /// drawn with exactly this many (`12.5` with 2 is `12.50`).
    #[serde(default)]
    pub decimals: u8,
    /// The smallest value accepted, a canonical decimal with at most `decimals` places.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    /// The largest value accepted, a canonical decimal with at most `decimals` places.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
    /// How the value is drawn. Omitted from the JSON when plain.
    #[serde(default, skip_serializing_if = "NumberStyle::is_plain")]
    pub style: NumberStyle,
    /// From envelope schema version 8: the currency of an amount, an ISO 4217 code (`EUR`).
    /// `decimals` must then be the currency's (2 for EUR, 0 for JPY), and the value is drawn after
    /// the code (`EUR 12 500,00`). Omitted from the JSON when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

impl NumberFormat {
    /// Check the format itself, at preparation: the decimal places, and the range's bounds
    /// (canonical decimals, with no more places than the field keeps, the minimum not above the
    /// maximum).
    pub fn validate(&self) -> Result<(), String> {
        if self.decimals > MAX_NUMBER_DECIMALS {
            return Err(format!(
                "keeps {} decimal places; at most {MAX_NUMBER_DECIMALS} are allowed",
                self.decimals
            ));
        }
        let bound = |name: &str, b: &Option<String>| -> Result<Option<Decimal>, String> {
            let Some(s) = b else { return Ok(None) };
            let d = Decimal::parse(s)
                .map_err(|_| format!("its {name} '{s}' is not a number written like -1234.5"))?;
            if d.scale() > self.decimals {
                return Err(format!(
                    "its {name} '{s}' has more decimal places than the field keeps"
                ));
            }
            Ok(Some(d))
        };
        if self.currency.is_some() {
            let currency = crate::formats::currency(self.currency.as_deref())?;
            if currency.minor_units() != self.decimals {
                return Err(format!(
                    "keeps {} decimal places, but {} amounts keep {}",
                    self.decimals,
                    currency.code(),
                    currency.minor_units()
                ));
            }
        }
        let (min, max) = (bound("minimum", &self.min)?, bound("maximum", &self.max)?);
        if let (Some(lo), Some(hi)) = (min, max) {
            if lo > hi {
                return Err("its minimum is above its maximum".into());
            }
        }
        Ok(())
    }

    /// Check a signer's value (already canonical: the host reads the signer's locale) and return
    /// it with exactly the field's decimal places, or the reason it is refused, whose
    /// [`FormatError::code`] a page translates.
    pub fn check(&self, value: &str) -> Result<String, FormatError> {
        let bound = |b: &Option<String>| b.as_deref().and_then(|s| Decimal::parse(s).ok());
        Format::Number {
            min: bound(&self.min),
            max: bound(&self.max),
            decimals: self.decimals,
        }
        .check(value)
    }

    /// A canonical value as the field draws it: in its style, after its currency code when it
    /// has one.
    pub fn display(&self, canonical: &str) -> String {
        match &self.currency {
            Some(code) => format!("{code} {}", self.style.format(canonical)),
            None => self.style.format(canonical),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn styles_draw_the_sealed_marks() {
        let cases = [
            (NumberStyle::Plain, "1234567.50", "1234567.50"),
            (NumberStyle::CommaPoint, "1234567.50", "1,234,567.50"),
            (NumberStyle::PointComma, "1234567.50", "1.234.567,50"),
            (NumberStyle::SpaceComma, "-1234.5", "-1 234,5"),
            (NumberStyle::ApostrophePoint, "999", "999"),
            (NumberStyle::ApostrophePoint, "1000", "1'000"),
            (NumberStyle::PlainComma, "0.25", "0,25"),
            (NumberStyle::CommaPoint, "-123456", "-123,456"),
        ];
        for (style, value, drawn) in cases {
            assert_eq!(style.format(value), drawn, "{style:?} {value}");
        }
        // Not canonical: unchanged.
        assert_eq!(NumberStyle::CommaPoint.format("1,5"), "1,5");
        for s in NumberStyle::ALL {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.pattern()));
            assert_eq!(serde_json::from_str::<NumberStyle>(&json).unwrap(), s);
        }
    }

    #[test]
    fn formats_check_their_bounds_and_values() {
        let percent = NumberFormat {
            decimals: 2,
            min: Some("0".into()),
            max: Some("100".into()),
            style: NumberStyle::SpaceComma,
            currency: None,
        };
        percent.validate().unwrap();
        assert_eq!(percent.check("12.5").as_deref(), Ok("12.50"));
        assert_eq!(percent.check("100.01"), Err(FormatError::AboveMaximum));
        assert_eq!(percent.check("1,5"), Err(FormatError::Number));
        assert_eq!(percent.display("1234.50"), "1 234,50");
        let json = serde_json::to_value(&percent).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"decimals": 2, "min": "0", "max": "100", "style": "1 234,5"})
        );
        // Defaults are not written.
        assert_eq!(
            serde_json::to_value(NumberFormat::default()).unwrap(),
            serde_json::json!({"decimals": 0})
        );
        for bad in [
            NumberFormat {
                decimals: 7,
                ..Default::default()
            },
            NumberFormat {
                min: Some("1.5".into()),
                ..Default::default()
            },
            NumberFormat {
                max: Some("1e3".into()),
                ..Default::default()
            },
            NumberFormat {
                min: Some("10".into()),
                max: Some("9".into()),
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
