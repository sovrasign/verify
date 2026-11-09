//! Currencies and money amounts for payment fields.
//!
//! An amount is stored as an integer count of the currency's **minor unit**, as ISO 4217 defines
//! it: cents for USD and EUR (2 decimal places), none for JPY and KRW (0), fils for KWD and BHD
//! (3). A total computed with exact decimals ([`crate::decimal`]) is rounded half up to the
//! currency's minor unit before it becomes an amount, so the payer's page, the engine and the
//! verifier arrive at the same integer.
//!
//! Payment processors sometimes count a currency differently from ISO 4217 in their own APIs
//! (a currency with no minor unit in ISO sent in hundredths, say). That conversion belongs to the
//! host's integration with its processor, at the processor boundary; the envelope always holds
//! the ISO 4217 amount.

use crate::decimal::{Decimal, DecimalError};

/// The largest single payment by default, in major units of the payment's currency (50,000 USD,
/// 50,000 EUR, 50,000 JPY): a guard against mistyped and fraudulent amounts that a host may
/// raise for an account.
pub const DEFAULT_MAX_PAYMENT_MAJOR_UNITS: i64 = 50_000;

/// A currency: its ISO 4217 code and the number of decimal places of its minor unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Currency {
    code: &'static str,
    minor_units: u8,
}

/// ISO 4217 currencies with a minor unit, as listed in 2026, and the decimal places of each.
/// Funds codes, precious metals and testing codes (`XAU`, `XDR`, `XTS`, `XXX`...) are left out:
/// nobody pays with them. Sorted by code.
#[rustfmt::skip]
const CURRENCIES: &[(&str, u8)] = &[
    ("AED", 2), ("AFN", 2), ("ALL", 2), ("AMD", 2), ("AOA", 2), ("ARS", 2), ("AUD", 2),
    ("AWG", 2), ("AZN", 2), ("BAM", 2), ("BBD", 2), ("BDT", 2), ("BGN", 2), ("BHD", 3),
    ("BIF", 0), ("BMD", 2), ("BND", 2), ("BOB", 2), ("BRL", 2), ("BSD", 2), ("BTN", 2),
    ("BWP", 2), ("BYN", 2), ("BZD", 2), ("CAD", 2), ("CDF", 2), ("CHF", 2), ("CLP", 0),
    ("CNY", 2), ("COP", 2), ("CRC", 2), ("CUP", 2), ("CVE", 2), ("CZK", 2), ("DJF", 0),
    ("DKK", 2), ("DOP", 2), ("DZD", 2), ("EGP", 2), ("ERN", 2), ("ETB", 2), ("EUR", 2),
    ("FJD", 2), ("FKP", 2), ("GBP", 2), ("GEL", 2), ("GHS", 2), ("GIP", 2), ("GMD", 2),
    ("GNF", 0), ("GTQ", 2), ("GYD", 2), ("HKD", 2), ("HNL", 2), ("HTG", 2), ("HUF", 2),
    ("IDR", 2), ("ILS", 2), ("INR", 2), ("IQD", 3), ("IRR", 2), ("ISK", 0), ("JMD", 2),
    ("JOD", 3), ("JPY", 0), ("KES", 2), ("KGS", 2), ("KHR", 2), ("KMF", 0), ("KPW", 2),
    ("KRW", 0), ("KWD", 3), ("KYD", 2), ("KZT", 2), ("LAK", 2), ("LBP", 2), ("LKR", 2),
    ("LRD", 2), ("LSL", 2), ("LYD", 3), ("MAD", 2), ("MDL", 2), ("MGA", 2), ("MKD", 2),
    ("MMK", 2), ("MNT", 2), ("MOP", 2), ("MRU", 2), ("MUR", 2), ("MVR", 2), ("MWK", 2),
    ("MXN", 2), ("MYR", 2), ("MZN", 2), ("NAD", 2), ("NGN", 2), ("NIO", 2), ("NOK", 2),
    ("NPR", 2), ("NZD", 2), ("OMR", 3), ("PAB", 2), ("PEN", 2), ("PGK", 2), ("PHP", 2),
    ("PKR", 2), ("PLN", 2), ("PYG", 0), ("QAR", 2), ("RON", 2), ("RSD", 2), ("RUB", 2),
    ("RWF", 0), ("SAR", 2), ("SBD", 2), ("SCR", 2), ("SDG", 2), ("SEK", 2), ("SGD", 2),
    ("SHP", 2), ("SLE", 2), ("SOS", 2), ("SRD", 2), ("SSP", 2), ("STN", 2), ("SVC", 2),
    ("SYP", 2), ("SZL", 2), ("THB", 2), ("TJS", 2), ("TMT", 2), ("TND", 3), ("TOP", 2),
    ("TRY", 2), ("TTD", 2), ("TWD", 2), ("TZS", 2), ("UAH", 2), ("UGX", 0), ("USD", 2),
    ("UYU", 2), ("UZS", 2), ("VES", 2), ("VND", 0), ("VUV", 0), ("WST", 2), ("XAF", 0),
    ("XCD", 2), ("XCG", 2), ("XOF", 0), ("XPF", 0), ("YER", 2), ("ZAR", 2), ("ZMW", 2),
    ("ZWG", 2),
];

/// Whether a payment is due: a computed total of zero means no payment step at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentDue {
    /// The total is zero: nothing to pay (for example, no optional item was chosen).
    Nothing,
    /// This many minor units are due.
    Amount(i64),
}

impl Currency {
    /// The currency with this ISO 4217 code (three upper-case letters, `"USD"`), if it is one
    /// people pay with.
    pub fn from_code(code: &str) -> Option<Currency> {
        CURRENCIES
            .binary_search_by(|(c, _)| (*c).cmp(code))
            .ok()
            .map(|i| Currency {
                code: CURRENCIES[i].0,
                minor_units: CURRENCIES[i].1,
            })
    }

    /// Every currency, in code order.
    pub fn all() -> impl Iterator<Item = Currency> {
        CURRENCIES
            .iter()
            .map(|&(code, minor_units)| Currency { code, minor_units })
    }

    /// The ISO 4217 code, e.g. `"EUR"`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The decimal places of the minor unit: 2 for EUR, 0 for JPY, 3 for KWD.
    pub fn minor_units(&self) -> u8 {
        self.minor_units
    }

    /// `value` rounded half up to the minor unit and written with exactly its decimal places
    /// (`12.345` USD is `12.35`; `1250.5` JPY is `1251`).
    pub fn round(&self, value: &Decimal) -> Result<Decimal, DecimalError> {
        value.round(self.minor_units)
    }

    /// `value` as a count of minor units, if it needs no rounding (`12.5` USD is 1250; `12.345`
    /// USD is [`DecimalError::TooPrecise`]). Use [`Currency::round`] first for a computed total.
    pub fn to_minor_units(&self, value: &Decimal) -> Result<i64, DecimalError> {
        let exact = value.with_scale_exact(self.minor_units)?;
        i64::try_from(exact.mantissa()).map_err(|_| DecimalError::TooLarge)
    }

    /// A count of minor units as a decimal with the currency's decimal places (1250 USD cents
    /// is `12.50`).
    pub fn from_minor_units(&self, minor: i64) -> Result<Decimal, DecimalError> {
        Decimal::new(i128::from(minor), self.minor_units)
    }

    /// The canonical text of an amount: the code, a space and the decimal (`USD 1250.00`,
    /// `JPY 1250`), the same in every locale. Pages show amounts in the reader's locale, always
    /// with the code.
    pub fn format(&self, minor: i64) -> Result<String, DecimalError> {
        Ok(format!("{} {}", self.code, self.from_minor_units(minor)?))
    }

    /// Checks a computed payment total and turns it into minor units: rounded half up to the
    /// minor unit; zero means no payment is due; a negative total, or one above
    /// `max_major_units` (see [`DEFAULT_MAX_PAYMENT_MAJOR_UNITS`]), is refused.
    pub fn payment_due(
        &self,
        total: &Decimal,
        max_major_units: i64,
    ) -> Result<PaymentDue, DecimalError> {
        let rounded = self.round(total)?;
        if rounded.is_negative() {
            return Err(DecimalError::Negative);
        }
        if rounded.is_zero() {
            return Ok(PaymentDue::Nothing);
        }
        let max = Decimal::from_int(max_major_units)?;
        if rounded > max {
            return Err(DecimalError::OverMaximum);
        }
        Ok(PaymentDue::Amount(self.to_minor_units(&rounded)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::parse(s).unwrap()
    }

    fn cur(code: &str) -> Currency {
        Currency::from_code(code).unwrap()
    }

    #[test]
    fn the_table_is_sorted_and_well_formed() {
        for pair in CURRENCIES.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
        }
        for (code, minor) in CURRENCIES {
            assert!(code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase()));
            assert!(matches!(minor, 0 | 2 | 3), "{code}");
        }
        assert_eq!(Currency::all().count(), CURRENCIES.len());
    }

    #[test]
    fn minor_units_follow_iso_4217() {
        for (code, minor) in [
            ("USD", 2),
            ("EUR", 2),
            ("GBP", 2),
            ("JPY", 0),
            ("KRW", 0),
            ("CLP", 0),
            ("XOF", 0),
            ("KWD", 3),
            ("BHD", 3),
            ("TND", 3),
        ] {
            assert_eq!(cur(code).minor_units(), minor, "{code}");
        }
        for unknown in ["usd", "US", "USDX", "XAU", "XXX", "", "ÉUR"] {
            assert_eq!(Currency::from_code(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn amounts_convert_to_and_from_minor_units() {
        assert_eq!(cur("USD").to_minor_units(&d("12.5")), Ok(1250));
        assert_eq!(cur("USD").to_minor_units(&d("12.500")), Ok(1250));
        assert_eq!(
            cur("USD").to_minor_units(&d("12.345")),
            Err(DecimalError::TooPrecise)
        );
        assert_eq!(cur("JPY").to_minor_units(&d("1250")), Ok(1250));
        assert_eq!(
            cur("JPY").to_minor_units(&d("1250.5")),
            Err(DecimalError::TooPrecise)
        );
        assert_eq!(cur("KWD").to_minor_units(&d("1.25")), Ok(1250));
        assert_eq!(
            cur("USD").from_minor_units(1250).unwrap().to_string(),
            "12.50"
        );
        assert_eq!(
            cur("USD").from_minor_units(-5).unwrap().to_string(),
            "-0.05"
        );
        assert_eq!(
            cur("JPY").from_minor_units(1250).unwrap().to_string(),
            "1250"
        );
        assert_eq!(cur("KWD").from_minor_units(7).unwrap().to_string(), "0.007");
        assert_eq!(
            cur("JPY").from_minor_units(i64::MAX),
            Err(DecimalError::TooLarge)
        );
        assert_eq!(cur("USD").format(125000).unwrap(), "USD 1250.00");
        assert_eq!(cur("JPY").format(1250).unwrap(), "JPY 1250");
    }

    #[test]
    fn totals_are_rounded_half_up_to_the_minor_unit() {
        assert_eq!(cur("USD").round(&d("12.345")).unwrap().to_string(), "12.35");
        assert_eq!(
            cur("USD").round(&d("12.3449")).unwrap().to_string(),
            "12.34"
        );
        assert_eq!(cur("USD").round(&d("12")).unwrap().to_string(), "12.00");
        assert_eq!(cur("JPY").round(&d("1250.5")).unwrap().to_string(), "1251");
        assert_eq!(cur("KWD").round(&d("0.0005")).unwrap().to_string(), "0.001");
        // Three items at 19.99 with a third off, as a formula would compute it.
        let total = d("19.99")
            .checked_mul(&d("3"))
            .unwrap()
            .checked_mul(&d("2"))
            .unwrap()
            .checked_div(&d("3"), 18)
            .unwrap();
        assert_eq!(
            cur("USD").payment_due(&total, 50_000),
            Ok(PaymentDue::Amount(3998))
        );
    }

    #[test]
    fn payment_totals_are_checked() {
        let usd = cur("USD");
        let max = DEFAULT_MAX_PAYMENT_MAJOR_UNITS;
        assert_eq!(usd.payment_due(&d("0"), max), Ok(PaymentDue::Nothing));
        // Below half a cent rounds to nothing due.
        assert_eq!(usd.payment_due(&d("0.004"), max), Ok(PaymentDue::Nothing));
        assert_eq!(usd.payment_due(&d("0.005"), max), Ok(PaymentDue::Amount(1)));
        assert_eq!(
            usd.payment_due(&d("-0.01"), max),
            Err(DecimalError::Negative)
        );
        assert_eq!(usd.payment_due(&d("-0.004"), max), Ok(PaymentDue::Nothing));
        assert_eq!(
            usd.payment_due(&d("50000"), max),
            Ok(PaymentDue::Amount(5_000_000))
        );
        assert_eq!(
            usd.payment_due(&d("50000.01"), max),
            Err(DecimalError::OverMaximum)
        );
        assert_eq!(
            cur("JPY").payment_due(&d("50000"), max),
            Ok(PaymentDue::Amount(50_000))
        );
        assert_eq!(
            usd.payment_due(&d("120000"), 200_000),
            Ok(PaymentDue::Amount(12_000_000))
        );
    }
}
