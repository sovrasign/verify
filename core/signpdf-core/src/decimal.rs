//! Exact decimal numbers for number, formula and payment fields.
//!
//! A field value that is a number is a decimal written as text (`1250.50`), and anything the
//! engine computes from such values (a formula's result, a payment total) must come out the same
//! on every device: in the signer's browser, in a native app and in the verifier that recomputes
//! it. Floating point cannot promise that (`0.1 + 0.2` is not `0.3`), so this module computes
//! with exact decimals: a 128-bit integer mantissa and a count of decimal places.
//!
//! The rules, which any other implementation must follow to get the same results:
//!
//! - **Range**: at most [`MAX_INTEGER_DIGITS`] digits before the decimal point and
//!   [`MAX_SCALE`] after it. A result outside the range is an error ([`DecimalError::TooLarge`]),
//!   never a wrapped or saturated value.
//! - **Exact** addition, subtraction and multiplication. The scale of a sum is the larger of the
//!   two scales; the scale of a product is the sum of the two, and a product with more than
//!   [`MAX_SCALE`] decimal places is rounded to [`MAX_SCALE`].
//! - **Division** takes the number of decimal places the quotient keeps; dividing by zero is an
//!   error, never infinity.
//! - **Rounding** is *half up*, away from zero on a tie, as spreadsheets' `ROUND` does:
//!   `2.345` to two places is `2.35` and `-2.345` is `-2.35`. Every rounding in this module,
//!   including the capped scale of a product, uses it.
//!
//! The canonical text form ([`Decimal::parse`], [`std::fmt::Display`]) is plain ASCII:
//! `-?(0|[1-9][0-9]*)(\.[0-9]+)?`, with no `+`, exponent, spaces, grouping or leading zeros, and
//! no negative zero. It keeps its decimal places (`12.50` stays `12.50`). Reading numbers as
//! people type them in their locale (`1 250,50`) is the host's job; it hands the engine the
//! canonical form. Money amounts and currencies are in [`crate::currency`].

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The most digits a decimal may have after the decimal point.
pub const MAX_SCALE: u8 = 18;

/// The most digits a decimal may have before the decimal point: every value is below 10^18 in
/// absolute value.
pub const MAX_INTEGER_DIGITS: u8 = 18;

/// The longest canonical text [`Decimal::parse`] reads: a sign, every integer and fraction
/// digit, and the decimal point.
pub const MAX_TEXT_LEN: usize = 1 + MAX_INTEGER_DIGITS as usize + 1 + MAX_SCALE as usize;

/// Why a decimal could not be read or computed. [`DecimalError::code`] gives a stable code a host
/// can turn into a message in the signer's language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecimalError {
    /// The text is not a decimal in the canonical form.
    Invalid,
    /// The value has more than [`MAX_INTEGER_DIGITS`] digits before the decimal point.
    TooLarge,
    /// The value has more decimal places than allowed: more than [`MAX_SCALE`], or more than the
    /// currency's minor unit where an amount must be exact.
    TooPrecise,
    /// A division by zero.
    DivisionByZero,
    /// A negative payment total (payments are never negative).
    Negative,
    /// A payment above the maximum allowed for one payment.
    OverMaximum,
}

impl DecimalError {
    /// A stable code for the error, in `snake_case`.
    pub fn code(self) -> &'static str {
        match self {
            DecimalError::Invalid => "invalid_number",
            DecimalError::TooLarge => "number_too_large",
            DecimalError::TooPrecise => "too_many_decimals",
            DecimalError::DivisionByZero => "division_by_zero",
            DecimalError::Negative => "negative_amount",
            DecimalError::OverMaximum => "amount_over_maximum",
        }
    }
}

impl fmt::Display for DecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecimalError::Invalid => "not a decimal number in canonical form",
            DecimalError::TooLarge => "number has more than 18 digits before the decimal point",
            DecimalError::TooPrecise => "number has too many decimal places",
            DecimalError::DivisionByZero => "division by zero",
            DecimalError::Negative => "amount is negative",
            DecimalError::OverMaximum => "amount is above the maximum for one payment",
        })
    }
}

impl std::error::Error for DecimalError {}

/// An exact decimal number: `mantissa × 10^-scale`. Two decimals are equal when their values
/// are (`1.5 == 1.50`), though each keeps its own scale for display.
#[derive(Debug, Clone, Copy)]
pub struct Decimal {
    mantissa: i128,
    scale: u8,
}

/// 10^n for n ≤ 38 (the largest power of ten a `u128` holds).
fn pow10(n: u32) -> u128 {
    10u128.pow(n)
}

impl Decimal {
    /// Zero, with no decimal places.
    pub const ZERO: Decimal = Decimal {
        mantissa: 0,
        scale: 0,
    };
    /// One, with no decimal places.
    pub const ONE: Decimal = Decimal {
        mantissa: 1,
        scale: 0,
    };

    /// `mantissa × 10^-scale`, if it is within the range.
    pub fn new(mantissa: i128, scale: u8) -> Result<Decimal, DecimalError> {
        if scale > MAX_SCALE {
            return Err(DecimalError::TooPrecise);
        }
        Decimal { mantissa, scale }.checked()
    }

    /// The whole number `n`, if it is within the range (an `i64` can reach 9.2 × 10^18).
    pub fn from_int(n: i64) -> Result<Decimal, DecimalError> {
        Decimal {
            mantissa: i128::from(n),
            scale: 0,
        }
        .checked()
    }

    /// Reads the canonical text form (see the module documentation).
    pub fn parse(s: &str) -> Result<Decimal, DecimalError> {
        if s.is_empty() || s.len() > MAX_TEXT_LEN || !s.is_ascii() {
            return Err(DecimalError::Invalid);
        }
        let (negative, unsigned) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let (int_part, frac_part) = match unsigned.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (unsigned, None),
        };
        let all_digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        if !all_digits(int_part) || (int_part.len() > 1 && int_part.starts_with('0')) {
            return Err(DecimalError::Invalid);
        }
        if let Some(f) = frac_part {
            if !all_digits(f) {
                return Err(DecimalError::Invalid);
            }
        }
        if int_part.len() > MAX_INTEGER_DIGITS as usize {
            return Err(DecimalError::TooLarge);
        }
        let frac = frac_part.unwrap_or("");
        if frac.len() > MAX_SCALE as usize {
            return Err(DecimalError::TooPrecise);
        }
        // At most 36 digits: fits an i128 (whose limit is about 1.7 × 10^38).
        let mut mantissa: i128 = 0;
        for b in int_part.bytes().chain(frac.bytes()) {
            mantissa = mantissa * 10 + i128::from(b - b'0');
        }
        if negative {
            if mantissa == 0 {
                // "-0" and "-0.00": zero has one form.
                return Err(DecimalError::Invalid);
            }
            mantissa = -mantissa;
        }
        Ok(Decimal {
            mantissa,
            scale: frac.len() as u8,
        })
    }

    /// The integer mantissa: the value is `mantissa × 10^-scale`.
    pub fn mantissa(&self) -> i128 {
        self.mantissa
    }

    /// The number of decimal places this value is written with.
    pub fn scale(&self) -> u8 {
        self.scale
    }

    /// Whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.mantissa == 0
    }

    /// Whether the value is below zero.
    pub fn is_negative(&self) -> bool {
        self.mantissa < 0
    }

    /// The absolute value.
    pub fn abs(&self) -> Decimal {
        Decimal {
            mantissa: self.mantissa.abs(),
            scale: self.scale,
        }
    }

    /// The same value with no trailing zeros after the decimal point (`12.50` → `12.5`,
    /// `3.00` → `3`).
    pub fn normalized(&self) -> Decimal {
        let mut d = *self;
        while d.scale > 0 && d.mantissa % 10 == 0 {
            d.mantissa /= 10;
            d.scale -= 1;
        }
        d
    }

    /// The number of decimal places the value needs: its scale without trailing zeros
    /// (`12.50` needs 1).
    pub fn decimal_places(&self) -> u8 {
        self.normalized().scale
    }

    /// `self + other`, exactly.
    pub fn checked_add(&self, other: &Decimal) -> Result<Decimal, DecimalError> {
        let scale = self.scale.max(other.scale);
        // Each value is below 10^18, so each aligned mantissa is below 10^36 and the sum fits.
        let a = self.mantissa * pow10(u32::from(scale - self.scale)) as i128;
        let b = other.mantissa * pow10(u32::from(scale - other.scale)) as i128;
        Decimal {
            mantissa: a + b,
            scale,
        }
        .checked()
    }

    /// `self - other`, exactly.
    pub fn checked_sub(&self, other: &Decimal) -> Result<Decimal, DecimalError> {
        self.checked_add(&-*other)
    }

    /// `self × other`: exact, except that a product with more than [`MAX_SCALE`] decimal places
    /// is rounded half up to [`MAX_SCALE`].
    pub fn checked_mul(&self, other: &Decimal) -> Result<Decimal, DecimalError> {
        let product = U256::product(self.mantissa.unsigned_abs(), other.mantissa.unsigned_abs());
        let scale = u32::from(self.scale) + u32::from(other.scale);
        let (magnitude, scale) = if scale > u32::from(MAX_SCALE) {
            let divisor = U256::new(pow10(scale - u32::from(MAX_SCALE)));
            (product.div_round_half_up(&divisor), MAX_SCALE)
        } else {
            (product, scale as u8)
        };
        let negative = self.is_negative() != other.is_negative();
        Decimal::from_magnitude(magnitude, negative, scale)
    }

    /// `self ÷ other`, rounded half up to `scale` decimal places.
    pub fn checked_div(&self, other: &Decimal, scale: u8) -> Result<Decimal, DecimalError> {
        if scale > MAX_SCALE {
            return Err(DecimalError::TooPrecise);
        }
        if other.is_zero() {
            return Err(DecimalError::DivisionByZero);
        }
        // q = self.m × 10^(other.scale + scale − self.scale) / other.m, rounded. The exponent
        // goes on the numerator when it is positive and on the denominator otherwise; either
        // side stays below 2^256 (at most 10^36 × 10^36).
        let exp = i32::from(other.scale) + i32::from(scale) - i32::from(self.scale);
        let (num_pow, den_pow) = if exp >= 0 {
            (exp as u32, 0)
        } else {
            (0, (-exp) as u32)
        };
        let numerator = U256::product(self.mantissa.unsigned_abs(), pow10(num_pow));
        let denominator = U256::product(other.mantissa.unsigned_abs(), pow10(den_pow));
        let magnitude = numerator.div_round_half_up(&denominator);
        let negative = self.is_negative() != other.is_negative();
        Decimal::from_magnitude(magnitude, negative, scale)
    }

    /// The value rounded half up (away from zero on a tie) to `places` decimal places, and
    /// written with exactly that many: `round(2.345, 2)` is `2.35`, `round(2, 2)` is `2.00`.
    pub fn round(&self, places: u8) -> Result<Decimal, DecimalError> {
        if places > MAX_SCALE {
            return Err(DecimalError::TooPrecise);
        }
        if places >= self.scale {
            // Padding with zeros: the value is unchanged and below 10^18, so the mantissa stays
            // below 10^36.
            return Ok(Decimal {
                mantissa: self.mantissa * pow10(u32::from(places - self.scale)) as i128,
                scale: places,
            });
        }
        let divisor = U256::new(pow10(u32::from(self.scale - places)));
        let magnitude = U256::new(self.mantissa.unsigned_abs()).div_round_half_up(&divisor);
        Decimal::from_magnitude(magnitude, self.is_negative(), places)
    }

    /// The value written with exactly `places` decimal places, if that needs no rounding
    /// (`12.5` with 2 places is `12.50`; `12.345` with 2 places is [`DecimalError::TooPrecise`]).
    pub fn with_scale_exact(&self, places: u8) -> Result<Decimal, DecimalError> {
        if self.decimal_places() > places {
            return Err(DecimalError::TooPrecise);
        }
        self.normalized().round(places)
    }

    /// Checks the range: below 10^[`MAX_INTEGER_DIGITS`] in absolute value.
    fn checked(self) -> Result<Decimal, DecimalError> {
        let limit = pow10(u32::from(MAX_INTEGER_DIGITS) + u32::from(self.scale));
        if self.mantissa.unsigned_abs() >= limit {
            return Err(DecimalError::TooLarge);
        }
        Ok(self)
    }

    fn from_magnitude(magnitude: U256, negative: bool, scale: u8) -> Result<Decimal, DecimalError> {
        let limit = pow10(u32::from(MAX_INTEGER_DIGITS) + u32::from(scale));
        let m = magnitude
            .to_u128()
            .filter(|m| *m < limit)
            .ok_or(DecimalError::TooLarge)?;
        // m < 10^36 < i128::MAX.
        let m = m as i128;
        Ok(Decimal {
            mantissa: if negative { -m } else { m },
            scale,
        })
    }

    /// Both mantissas at the larger of the two scales (below 10^36 each, so no overflow).
    fn aligned(&self, other: &Decimal) -> (i128, i128) {
        let scale = self.scale.max(other.scale);
        (
            self.mantissa * pow10(u32::from(scale - self.scale)) as i128,
            other.mantissa * pow10(u32::from(scale - other.scale)) as i128,
        )
    }
}

impl std::ops::Neg for Decimal {
    type Output = Decimal;
    /// The value with the opposite sign (always in range: the range is symmetric).
    fn neg(self) -> Decimal {
        Decimal {
            mantissa: -self.mantissa,
            scale: self.scale,
        }
    }
}

impl PartialEq for Decimal {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = self.aligned(other);
        a == b
    }
}

impl Eq for Decimal {}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        let (a, b) = self.aligned(other);
        a.cmp(&b)
    }
}

impl Hash for Decimal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Equal values have the same normalized form.
        let n = self.normalized();
        n.mantissa.hash(state);
        n.scale.hash(state);
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.mantissa.unsigned_abs().to_string();
        let scale = usize::from(self.scale);
        let sign = if self.mantissa < 0 { "-" } else { "" };
        if scale == 0 {
            return write!(f, "{sign}{digits}");
        }
        let padded = format!("{digits:0>width$}", width = scale + 1);
        let (int_part, frac_part) = padded.split_at(padded.len() - scale);
        write!(f, "{sign}{int_part}.{frac_part}")
    }
}

impl FromStr for Decimal {
    type Err = DecimalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Decimal::parse(s)
    }
}

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Decimal::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// An unsigned 256-bit integer, just enough for exact products and quotients of two mantissas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    const ZERO: U256 = U256 { hi: 0, lo: 0 };

    fn new(n: u128) -> U256 {
        U256 { hi: 0, lo: n }
    }

    /// The full product of two `u128`s.
    fn product(a: u128, b: u128) -> U256 {
        const MASK: u128 = u64::MAX as u128;
        let (a1, a0) = (a >> 64, a & MASK);
        let (b1, b0) = (b >> 64, b & MASK);
        let p00 = a0 * b0;
        let p01 = a0 * b1;
        let p10 = a1 * b0;
        let p11 = a1 * b1;
        // The middle column: the high half of p00 plus the low halves of p01 and p10.
        let mid = (p00 >> 64) + (p01 & MASK) + (p10 & MASK);
        let lo = (p00 & MASK) | (mid << 64);
        let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
        U256 { hi, lo }
    }

    fn to_u128(self) -> Option<u128> {
        (self.hi == 0).then_some(self.lo)
    }

    fn bit(&self, i: u32) -> bool {
        if i >= 128 {
            (self.hi >> (i - 128)) & 1 == 1
        } else {
            (self.lo >> i) & 1 == 1
        }
    }

    fn shl1(self) -> U256 {
        U256 {
            hi: (self.hi << 1) | (self.lo >> 127),
            lo: self.lo << 1,
        }
    }

    fn minus(self, other: U256) -> U256 {
        let (lo, borrow) = self.lo.overflowing_sub(other.lo);
        U256 {
            hi: self.hi - other.hi - u128::from(borrow),
            lo,
        }
    }

    fn add_one(self) -> U256 {
        let (lo, carry) = self.lo.overflowing_add(1);
        U256 {
            hi: self.hi + u128::from(carry),
            lo,
        }
    }

    /// `self ÷ divisor`, rounded half up. `divisor` is non-zero and below 2^255, so twice the
    /// remainder cannot overflow.
    fn div_round_half_up(&self, divisor: &U256) -> U256 {
        debug_assert!(*divisor != U256::ZERO && divisor.hi >> 127 == 0);
        // Binary long division.
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;
        for i in (0..256).rev() {
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.lo |= 1;
            }
            quotient = quotient.shl1();
            if remainder >= *divisor {
                remainder = remainder.minus(*divisor);
                quotient.lo |= 1;
            }
        }
        if remainder.shl1() >= *divisor {
            quotient.add_one()
        } else {
            quotient
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn canonical_text_round_trips() {
        for s in [
            "0",
            "0.00",
            "1",
            "-1",
            "12.50",
            "-0.001",
            "999999999999999999",
            "-999999999999999999.999999999999999999",
            "0.000000000000000001",
        ] {
            assert_eq!(d(s).to_string(), s);
        }
    }

    #[test]
    fn non_canonical_text_is_refused() {
        for s in [
            "", "-", ".5", "5.", "+5", "05", "-05", "1e3", "1,5", " 1", "1 ", "1_000", "-0",
            "-0.00", "0x10", "١", "1.2.3", "--1", "1.-2",
        ] {
            assert_eq!(Decimal::parse(s), Err(DecimalError::Invalid), "{s:?}");
        }
        assert_eq!(
            Decimal::parse("1000000000000000000"),
            Err(DecimalError::TooLarge)
        );
        assert_eq!(
            Decimal::parse("0.0000000000000000001"),
            Err(DecimalError::TooPrecise)
        );
        assert_eq!(
            Decimal::parse(&"9".repeat(MAX_TEXT_LEN + 1)),
            Err(DecimalError::Invalid)
        );
    }

    #[test]
    fn equality_and_order_are_by_value() {
        assert_eq!(d("1.5"), d("1.50"));
        assert_eq!(d("0"), d("0.000"));
        assert!(d("-2") < d("-1.99"));
        assert!(d("10") > d("9.999"));
        assert_eq!(d("2").max(d("2.5")), d("2.50"));
        use std::collections::HashSet;
        let set: HashSet<Decimal> = [d("1.5"), d("1.50"), d("1.500")].into_iter().collect();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn sums_are_exact() {
        // The classic floating-point failure.
        assert_eq!(d("0.1").checked_add(&d("0.2")).unwrap().to_string(), "0.3");
        assert_eq!(d("1.25").checked_add(&d("3")).unwrap().to_string(), "4.25");
        assert_eq!(
            d("1.25").checked_sub(&d("3.5")).unwrap().to_string(),
            "-2.25"
        );
        assert_eq!(d("5").checked_sub(&d("5")).unwrap().to_string(), "0");
        let max = d("999999999999999999.999999999999999999");
        assert_eq!(
            max.checked_add(&d("0.000000000000000001")),
            Err(DecimalError::TooLarge)
        );
        assert_eq!((-max).checked_sub(&d("1")), Err(DecimalError::TooLarge));
    }

    #[test]
    fn products_are_exact_up_to_the_maximum_scale() {
        assert_eq!(
            d("3").checked_mul(&d("19.99")).unwrap().to_string(),
            "59.97"
        );
        assert_eq!(
            d("1.5").checked_mul(&d("-1.5")).unwrap().to_string(),
            "-2.25"
        );
        assert_eq!(d("0").checked_mul(&d("-7.5")).unwrap().to_string(), "0.0");
        // 18 + 18 decimal places are rounded half up to 18.
        let tiny = d("0.000000000000000005");
        assert_eq!(
            tiny.checked_mul(&d("0.1")).unwrap().to_string(),
            "0.000000000000000001"
        );
        assert_eq!(
            tiny.checked_mul(&d("0.09")).unwrap().to_string(),
            "0.000000000000000000"
        );
        assert_eq!(
            (-tiny).checked_mul(&d("0.1")).unwrap().to_string(),
            "-0.000000000000000001"
        );
        // Products of large mantissas go through 256 bits without overflow.
        let big = d("123456789012345678.123456789012345678");
        assert_eq!(
            big.checked_mul(&d("0.000000000000000001"))
                .unwrap()
                .to_string(),
            "0.123456789012345678"
        );
        assert_eq!(
            big.checked_mul(&d("2")).unwrap().to_string(),
            "246913578024691356.246913578024691356"
        );
        assert_eq!(
            d("500000000000000000").checked_mul(&d("2")),
            Err(DecimalError::TooLarge)
        );
        assert_eq!(
            d("999999999.5")
                .checked_mul(&d("1000000000"))
                .unwrap()
                .to_string(),
            "999999999500000000.0"
        );
        assert_eq!(
            d("1000000000").checked_mul(&d("1000000000")),
            Err(DecimalError::TooLarge)
        );
    }

    #[test]
    fn quotients_are_rounded_half_up() {
        assert_eq!(
            d("1").checked_div(&d("3"), 4).unwrap().to_string(),
            "0.3333"
        );
        assert_eq!(
            d("2").checked_div(&d("3"), 4).unwrap().to_string(),
            "0.6667"
        );
        assert_eq!(
            d("-2").checked_div(&d("3"), 2).unwrap().to_string(),
            "-0.67"
        );
        assert_eq!(d("1").checked_div(&d("8"), 2).unwrap().to_string(), "0.13");
        assert_eq!(
            d("-1").checked_div(&d("-8"), 2).unwrap().to_string(),
            "0.13"
        );
        assert_eq!(
            d("1").checked_div(&d("-8"), 2).unwrap().to_string(),
            "-0.13"
        );
        assert_eq!(
            d("100").checked_div(&d("0.25"), 0).unwrap().to_string(),
            "400"
        );
        assert_eq!(
            d("0.0001").checked_div(&d("1000"), 3).unwrap().to_string(),
            "0.000"
        );
        assert_eq!(
            d("1").checked_div(&d("0.000000000000000001"), 18),
            Err(DecimalError::TooLarge)
        );
        assert_eq!(
            d("1").checked_div(&d("0.00"), 2),
            Err(DecimalError::DivisionByZero)
        );
        assert_eq!(
            d("1").checked_div(&d("3"), 19),
            Err(DecimalError::TooPrecise)
        );
        // The full range on both sides.
        let max = d("999999999999999999.999999999999999999");
        assert_eq!(
            max.checked_div(&max, 18).unwrap().to_string(),
            "1.000000000000000000"
        );
        assert_eq!(
            d("0.000000000000000001")
                .checked_div(&max, 18)
                .unwrap()
                .to_string(),
            "0.000000000000000000"
        );
    }

    #[test]
    fn small_quotients_match_a_direct_computation() {
        // Rounded half up, away from zero, computed directly in i128.
        fn reference(n: i128, d: i128) -> i128 {
            let (q, r) = (n.abs() / d.abs(), n.abs() % d.abs());
            let q = if 2 * r >= d.abs() { q + 1 } else { q };
            if (n < 0) != (d < 0) {
                -q
            } else {
                q
            }
        }
        for a in -60i128..=60 {
            for b in (-25i128..=25).filter(|b| *b != 0) {
                for (a_scale, b_scale) in [(0u8, 0u8), (1, 0), (0, 1), (2, 1)] {
                    for places in 0u8..=4 {
                        let x = Decimal::new(a, a_scale).unwrap();
                        let y = Decimal::new(b, b_scale).unwrap();
                        let got = x.checked_div(&y, places).unwrap();
                        // x / y × 10^places = a × 10^(b_scale + places) / (b × 10^a_scale).
                        let n = a * 10i128.pow(u32::from(b_scale + places));
                        let den = b * 10i128.pow(u32::from(a_scale));
                        assert_eq!(got.mantissa(), reference(n, den), "{x} / {y} to {places}");
                        assert_eq!(got.scale(), places);
                    }
                }
            }
        }
    }

    #[test]
    fn rounding_is_half_up_away_from_zero() {
        let cases = [
            ("2.345", 2, "2.35"),
            ("-2.345", 2, "-2.35"),
            ("2.344", 2, "2.34"),
            ("2.5", 0, "3"),
            ("-2.5", 0, "-3"),
            ("0.5", 0, "1"),
            ("0.49", 0, "0"),
            ("-0.4", 0, "0"),
            ("1.005", 2, "1.01"),
            ("2", 2, "2.00"),
            ("12.5", 3, "12.500"),
        ];
        for (value, places, expected) in cases {
            assert_eq!(
                d(value).round(places).unwrap().to_string(),
                expected,
                "{value}"
            );
        }
        assert_eq!(
            d("999999999999999999.5").round(0),
            Err(DecimalError::TooLarge)
        );
        assert_eq!(d("1").round(19), Err(DecimalError::TooPrecise));
    }

    #[test]
    fn exact_rescaling_refuses_lost_digits() {
        assert_eq!(d("12.5").with_scale_exact(2).unwrap().to_string(), "12.50");
        assert_eq!(
            d("12.500").with_scale_exact(2).unwrap().to_string(),
            "12.50"
        );
        assert_eq!(
            d("12.345").with_scale_exact(2),
            Err(DecimalError::TooPrecise)
        );
        assert_eq!(d("12.50").decimal_places(), 1);
        assert_eq!(d("3.00").normalized().to_string(), "3");
    }

    #[test]
    fn constructors_check_the_range() {
        assert_eq!(Decimal::new(1250, 2).unwrap().to_string(), "12.50");
        assert_eq!(Decimal::new(1, 19), Err(DecimalError::TooPrecise));
        assert_eq!(Decimal::new(10i128.pow(18), 0), Err(DecimalError::TooLarge));
        assert_eq!(Decimal::from_int(-42).unwrap().to_string(), "-42");
        assert_eq!(Decimal::from_int(i64::MAX), Err(DecimalError::TooLarge));
    }

    #[test]
    fn serde_uses_the_canonical_text() {
        let v = d("-12.50");
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"-12.50\"");
        assert_eq!(serde_json::from_str::<Decimal>("\"-12.50\"").unwrap(), v);
        assert!(serde_json::from_str::<Decimal>("\"1e2\"").is_err());
        assert!(serde_json::from_str::<Decimal>("12.5").is_err());
    }

    #[test]
    fn wide_arithmetic_matches_u128_where_it_fits() {
        let samples: [u128; 6] = [
            0,
            1,
            7,
            10u128.pow(18) - 1,
            u64::MAX as u128,
            10u128.pow(19) + 3,
        ];
        for &a in &samples {
            for &b in &samples {
                let p = U256::product(a, b);
                if let Some(expected) = a.checked_mul(b) {
                    assert_eq!(p.to_u128(), Some(expected), "{a} × {b}");
                }
                if b != 0 {
                    let q = U256::new(a).div_round_half_up(&U256::new(b));
                    let (fq, r) = (a / b, a % b);
                    let expected = if 2 * r >= b { fq + 1 } else { fq };
                    assert_eq!(q.to_u128(), Some(expected), "{a} ÷ {b}");
                }
            }
        }
        // (2^128 − 1)² = 2^256 − 2^129 + 1.
        let p = U256::product(u128::MAX, u128::MAX);
        assert_eq!(p.lo, 1);
        assert_eq!(p.hi, u128::MAX - 1);
    }
}
