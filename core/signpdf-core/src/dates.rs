//! Calendar dates in date fields: the canonical ISO form the envelope stores, the formats a
//! preparer can choose for drawing them, and the signer's local date.
//!
//! A date field's value is always stored as an ISO 8601 calendar date (`YYYY-MM-DD`), whatever
//! the signer's locale. The preparer may pick how it is drawn on the page ([`DateFormat`], part
//! of the prepared terms), so every party reads the same text. A date the engine fills in, the
//! *signing date*, is the signer's **local** date: the device clock's UTC time moved by the UTC
//! offset the host reports for the signer ([`crate::workflow::SignRequest::utc_offset_minutes`]),
//! which the signature record keeps as evidence. Without an offset the date is the UTC date.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, UtcOffset};

/// The westernmost UTC offset in use (UTC−12:00), in minutes.
pub const MIN_UTC_OFFSET_MINUTES: i32 = -12 * 60;
/// The easternmost UTC offset in use (UTC+14:00), in minutes.
pub const MAX_UTC_OFFSET_MINUTES: i32 = 14 * 60;

/// How a date field's value is drawn on the page. The value itself is always stored as
/// `YYYY-MM-DD`; this only changes the text drawn. Part of the prepared terms. Absent means ISO,
/// which is how every date field was drawn before formats existed.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DateFormat {
    /// `2026-11-02` (ISO 8601).
    #[default]
    #[serde(rename = "YYYY-MM-DD")]
    Iso,
    /// `02/11/2026`: day first, as in most of Europe and Latin America.
    #[serde(rename = "DD/MM/YYYY")]
    DayMonthYearSlash,
    /// `11/02/2026`: month first, as in the United States.
    #[serde(rename = "MM/DD/YYYY")]
    MonthDayYearSlash,
    /// `02.11.2026`, as in Germany, Switzerland or Russia.
    #[serde(rename = "DD.MM.YYYY")]
    DayMonthYearDot,
    /// `02-11-2026`, as in the Netherlands.
    #[serde(rename = "DD-MM-YYYY")]
    DayMonthYearDash,
    /// `2026/11/02`, as in Japan or China.
    #[serde(rename = "YYYY/MM/DD")]
    YearMonthDaySlash,
    /// `2026.11.02`, as in Korea or Hungary.
    #[serde(rename = "YYYY.MM.DD")]
    YearMonthDayDot,
}

impl DateFormat {
    /// Every format, in the order a preparer is offered them.
    pub const ALL: [DateFormat; 7] = [
        DateFormat::Iso,
        DateFormat::DayMonthYearSlash,
        DateFormat::MonthDayYearSlash,
        DateFormat::DayMonthYearDot,
        DateFormat::DayMonthYearDash,
        DateFormat::YearMonthDaySlash,
        DateFormat::YearMonthDayDot,
    ];

    /// The pattern as written in the envelope, e.g. `DD/MM/YYYY`.
    pub fn pattern(&self) -> &'static str {
        match self {
            DateFormat::Iso => "YYYY-MM-DD",
            DateFormat::DayMonthYearSlash => "DD/MM/YYYY",
            DateFormat::MonthDayYearSlash => "MM/DD/YYYY",
            DateFormat::DayMonthYearDot => "DD.MM.YYYY",
            DateFormat::DayMonthYearDash => "DD-MM-YYYY",
            DateFormat::YearMonthDaySlash => "YYYY/MM/DD",
            DateFormat::YearMonthDayDot => "YYYY.MM.DD",
        }
    }

    /// `date` drawn in this format.
    pub fn format(&self, date: Date) -> String {
        let (y, m, d) = (date.year(), date.month() as u8, date.day());
        match self {
            DateFormat::Iso => format!("{y:04}-{m:02}-{d:02}"),
            DateFormat::DayMonthYearSlash => format!("{d:02}/{m:02}/{y:04}"),
            DateFormat::MonthDayYearSlash => format!("{m:02}/{d:02}/{y:04}"),
            DateFormat::DayMonthYearDot => format!("{d:02}.{m:02}.{y:04}"),
            DateFormat::DayMonthYearDash => format!("{d:02}-{m:02}-{y:04}"),
            DateFormat::YearMonthDaySlash => format!("{y:04}/{m:02}/{d:02}"),
            DateFormat::YearMonthDayDot => format!("{y:04}.{m:02}.{d:02}"),
        }
    }
}

/// Parse a canonical date value: exactly `YYYY-MM-DD`, a real calendar date, years 0001–9999.
pub fn parse_iso_date(s: &str) -> Option<Date> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = &s[r];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (y, m, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    if y == 0 {
        return None;
    }
    let month = Month::try_from(u8::try_from(m).ok()?).ok()?;
    Date::from_calendar_date(i32::try_from(y).ok()?, month, u8::try_from(d).ok()?).ok()
}

/// `date` as `YYYY-MM-DD`.
pub fn iso_date(date: Date) -> String {
    DateFormat::Iso.format(date)
}

/// Check a UTC offset in minutes: between UTC−12:00 and UTC+14:00, the offsets in use.
pub fn check_utc_offset_minutes(minutes: i32) -> Result<(), String> {
    if (MIN_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES).contains(&minutes) {
        Ok(())
    } else {
        Err(format!(
            "UTC offset {minutes} minutes is outside UTC-12:00 to UTC+14:00"
        ))
    }
}

/// A UTC offset in minutes as written in a signature record: `+02:00`, `-05:30`, `+00:00`.
pub fn format_utc_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let m = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", m / 60, m % 60)
}

/// Parse a UTC offset as written in a signature record (`±HH:MM`, between `-12:00` and
/// `+14:00`; `-00:00` is refused, as RFC 3339 gives it the meaning "unknown"), into minutes.
pub fn parse_utc_offset(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    if b.len() != 6 || b[3] != b':' || !matches!(b[0], b'+' | b'-') {
        return None;
    }
    if ![1, 2, 4, 5].iter().all(|&i| b[i].is_ascii_digit()) {
        return None;
    }
    let hours: i32 = s[1..3].parse().ok()?;
    let mins: i32 = s[4..6].parse().ok()?;
    if mins >= 60 {
        return None;
    }
    let total = hours * 60 + mins;
    let signed = if b[0] == b'-' { -total } else { total };
    if b[0] == b'-' && total == 0 {
        return None;
    }
    check_utc_offset_minutes(signed).ok()?;
    Some(signed)
}

/// The instant `rfc3339` seen at a UTC offset of `offset_minutes`.
fn at_offset(rfc3339: &str, offset_minutes: i32) -> Option<OffsetDateTime> {
    let t = OffsetDateTime::parse(rfc3339, &Rfc3339).ok()?;
    let offset = UtcOffset::from_whole_seconds(offset_minutes.checked_mul(60)?).ok()?;
    Some(t.to_offset(offset))
}

/// The calendar date (`YYYY-MM-DD`) at instant `rfc3339` for someone at UTC offset
/// `offset_minutes`: the signer's local date of a signing time.
pub fn local_date(rfc3339: &str, offset_minutes: i32) -> Option<String> {
    at_offset(rfc3339, offset_minutes).map(|t| iso_date(t.date()))
}

/// Seconds since the Unix epoch as an RFC 3339 UTC time, e.g. `2026-11-02T09:14:03Z`.
pub fn utc_rfc3339(unix: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
}

/// Instant `rfc3339` written in RFC 3339 at UTC offset `offset_minutes`, e.g.
/// `2026-11-02T11:14:03+02:00`: the signer's local time of a signing time.
pub fn local_time(rfc3339: &str, offset_minutes: i32) -> Option<String> {
    at_offset(rfc3339, offset_minutes).and_then(|t| t.format(&Rfc3339).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates_are_parsed_strictly() {
        let d = parse_iso_date("2026-11-02").unwrap();
        assert_eq!(iso_date(d), "2026-11-02");
        assert!(parse_iso_date("2024-02-29").is_some());
        for bad in [
            "",
            "2026-11-2",
            "2026/11/02",
            "02/11/2026",
            "2026-13-01",
            "2026-00-10",
            "2025-02-29",
            "2026-11-31",
            "0000-01-01",
            "+2026-11-0",
            "2026-1-102",
            " 2026-11-0",
            "2026-11-02T00:00:00Z",
            "２０２６-11-02",
            "tomorrow",
        ] {
            assert!(parse_iso_date(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn every_format_draws_the_same_date() {
        let d = parse_iso_date("2026-01-09").unwrap();
        let drawn: Vec<String> = DateFormat::ALL.iter().map(|f| f.format(d)).collect();
        assert_eq!(
            drawn,
            [
                "2026-01-09",
                "09/01/2026",
                "01/09/2026",
                "09.01.2026",
                "09-01-2026",
                "2026/01/09",
                "2026.01.09",
            ]
        );
        for f in DateFormat::ALL {
            // The JSON name is the pattern, and the pattern has the length of what is drawn.
            assert_eq!(
                serde_json::to_value(f).unwrap(),
                serde_json::json!(f.pattern())
            );
            assert_eq!(f.pattern().len(), f.format(d).len());
        }
        assert_eq!(
            serde_json::from_str::<DateFormat>("\"MM/DD/YYYY\"").unwrap(),
            DateFormat::MonthDayYearSlash
        );
        assert!(serde_json::from_str::<DateFormat>("\"D MMMM YYYY\"").is_err());
    }

    #[test]
    fn utc_offsets_round_trip_within_the_offsets_in_use() {
        for (m, s) in [
            (0, "+00:00"),
            (120, "+02:00"),
            (-300, "-05:00"),
            (330, "+05:30"),
            (345, "+05:45"),
            (-570, "-09:30"),
            (MAX_UTC_OFFSET_MINUTES, "+14:00"),
            (MIN_UTC_OFFSET_MINUTES, "-12:00"),
        ] {
            assert_eq!(format_utc_offset(m), s);
            assert_eq!(parse_utc_offset(s), Some(m), "{s}");
        }
        for bad in [
            "", "Z", "+2:00", "+02", "+0200", "02:00", "+14:01", "-12:30", "+02:60", "-00:00",
            "+02:00 ", "+ 2:00",
        ] {
            assert_eq!(parse_utc_offset(bad), None, "{bad:?}");
        }
        assert!(check_utc_offset_minutes(841).is_err());
        assert!(check_utc_offset_minutes(-721).is_err());
    }

    #[test]
    fn the_local_date_follows_the_offset_not_utc_midnight() {
        // 23:30 UTC on 2 November is already 3 November in Paris and still 2 November in New
        // York; 00:30 UTC on 3 November is still 2 November in Los Angeles.
        assert_eq!(
            local_date("2026-11-02T23:30:00Z", 60).unwrap(),
            "2026-11-03"
        );
        assert_eq!(
            local_date("2026-11-02T23:30:00Z", -300).unwrap(),
            "2026-11-02"
        );
        assert_eq!(
            local_date("2026-11-03T00:30:00Z", -480).unwrap(),
            "2026-11-02"
        );
        assert_eq!(local_date("2026-11-03T00:30:00Z", 0).unwrap(), "2026-11-03");
        // The two ends of the offsets in use are a day apart, and more, at the same instant.
        assert_eq!(
            local_date("2026-12-31T11:00:00Z", 840).unwrap(),
            "2027-01-01"
        );
        assert_eq!(
            local_date("2026-12-31T11:00:00Z", -720).unwrap(),
            "2026-12-30"
        );
        assert_eq!(
            local_time("2026-11-02T09:14:03Z", 120).unwrap(),
            "2026-11-02T11:14:03+02:00"
        );
        assert!(local_date("not a time", 0).is_none());
        assert_eq!(utc_rfc3339(1_793_610_843).unwrap(), "2026-11-02T09:14:03Z");
    }
}
