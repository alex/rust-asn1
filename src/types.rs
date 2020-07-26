use core::marker::PhantomData;
use core::mem;

use chrono::{Datelike, TimeZone, Timelike};

use crate::parser::Parser;
use crate::{parse, BitString, ObjectIdentifier, ParseError, ParseResult};

const CONTEXT_SPECIFIC: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;

pub trait Asn1Element<'a>: Sized {
    type ParsedType;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::ParsedType>;
}

pub trait SimpleAsn1Element<'a>: Sized {
    const TAG: u8;
    type ParsedType;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self::ParsedType>;
}

impl<'a, T: SimpleAsn1Element<'a>> Asn1Element<'a> for T {
    type ParsedType = T::ParsedType;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::ParsedType> {
        let tlv = parser.read_tlv()?;
        if tlv.tag != Self::TAG {
            return Err(ParseError::UnexpectedTag { actual: tlv.tag });
        }
        Self::parse_data(tlv.data)
    }
}

impl SimpleAsn1Element<'_> for () {
    const TAG: u8 = 0x05;
    type ParsedType = ();
    fn parse_data(data: &[u8]) -> ParseResult<()> {
        match data {
            b"" => Ok(()),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

impl SimpleAsn1Element<'_> for bool {
    const TAG: u8 = 0x1;
    type ParsedType = bool;
    fn parse_data(data: &[u8]) -> ParseResult<bool> {
        match data {
            b"\x00" => Ok(false),
            b"\xff" => Ok(true),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

impl<'a> SimpleAsn1Element<'a> for &'a [u8] {
    const TAG: u8 = 0x04;
    type ParsedType = &'a [u8];
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        Ok(data)
    }
}

/// Placeholder type for use with `Parser.read_element` for parsing an ASN.1 `PrintableString`.
/// Parsing a `PrintableString` will return an `&str` containing only valid characers.
pub enum PrintableString {}

impl<'a> SimpleAsn1Element<'a> for PrintableString {
    const TAG: u8 = 0x13;
    type ParsedType = &'a str;
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a str> {
        for b in data {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?' => {}
                _ => return Err(ParseError::InvalidValue),
            };
        }
        // TODO: This value is always valid utf-8 because we just verified the contents, but I
        // don't want to call an unsafe function, so we end up validating it twice. If your profile
        // says this is slow, now you know why.
        Ok(core::str::from_utf8(data).unwrap())
    }
}

macro_rules! impl_asn1_element_for_int {
    ($t:ty; $signed:expr) => {
        impl SimpleAsn1Element<'_> for $t {
            const TAG: u8 = 0x02;
            type ParsedType = Self;
            fn parse_data(mut data: &[u8]) -> ParseResult<Self::ParsedType> {
                if data.is_empty() {
                    return Err(ParseError::InvalidValue);
                }
                if data.len() > 1
                    && ((data[0] == 0 && data[1] & 0x80 == 0)
                        || (data[0] == 0xff && data[1] & 0x80 == 0x80))
                {
                    return Err(ParseError::InvalidValue);
                }

                // Reject negatives for unsigned types.
                if !$signed && data[0] & 0x80 == 0x80 {
                    return Err(ParseError::InvalidValue);
                }

                // If we've got something like \x00\xff trim off the first \x00, since it's just
                // there to not mark the value as a negative.
                if data.len() == mem::size_of::<Self>() + 1 && data[0] == 0 {
                    data = &data[1..];
                }
                if data.len() > mem::size_of::<Self>() {
                    return Err(ParseError::IntegerOverflow);
                }

                let mut fixed_data = [0; mem::size_of::<Self>()];
                fixed_data[mem::size_of::<Self>() - data.len()..].copy_from_slice(data);
                let mut ret = Self::from_be_bytes(fixed_data);
                // // Shift up and down in order to sign extend the result.
                ret <<= (8 * mem::size_of::<Self>()) - data.len() * 8;
                ret >>= (8 * mem::size_of::<Self>()) - data.len() * 8;
                Ok(ret)
            }
        }
    };
}

impl_asn1_element_for_int!(i8; true);
impl_asn1_element_for_int!(u8; false);
impl_asn1_element_for_int!(i64; true);
impl_asn1_element_for_int!(u64; false);

impl<'a> SimpleAsn1Element<'a> for ObjectIdentifier<'a> {
    const TAG: u8 = 0x06;
    type ParsedType = ObjectIdentifier<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<ObjectIdentifier<'a>> {
        ObjectIdentifier::from_der(data).ok_or(ParseError::InvalidValue)
    }
}

impl<'a> SimpleAsn1Element<'a> for BitString<'a> {
    const TAG: u8 = 0x03;
    type ParsedType = BitString<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<BitString<'a>> {
        if data.is_empty() {
            return Err(ParseError::InvalidValue);
        }
        BitString::new(&data[1..], data[0]).ok_or(ParseError::InvalidValue)
    }
}

/// Placeholder type for use with `Parser.read_element` for parsing an ASN.1 `UTCTime`. Parsing a
/// `UtcTime` will return a `chrono::DateTime<chrono::Utc>`. Handles all four variants described in
/// ASN.1: with and without explicit seconds, and with either a fixed offset or directly in UTC.
pub enum UtcTime {}

const UTCTIME_WITH_SECONDS_AND_OFFSET: &str = "%y%m%d%H%M%S%z";
const UTCTIME_WITH_SECONDS: &str = "%y%m%d%H%M%SZ";
const UTCTIME_WITH_OFFSET: &str = "%y%m%d%H%M%z";
const UTCTIME: &str = "%y%m%d%H%MZ";

impl SimpleAsn1Element<'_> for UtcTime {
    const TAG: u8 = 0x17;
    type ParsedType = chrono::DateTime<chrono::Utc>;
    fn parse_data(data: &[u8]) -> ParseResult<Self::ParsedType> {
        let data = std::str::from_utf8(data).map_err(|_| ParseError::InvalidValue)?;

        // Try parsing with every combination of "including seconds or not" and "fixed offset or
        // UTC".
        let mut result = None;
        for format in [UTCTIME_WITH_SECONDS, UTCTIME].iter() {
            if let Ok(dt) = chrono::Utc.datetime_from_str(data, format) {
                result = Some(dt);
                break;
            }
        }
        for format in [UTCTIME_WITH_SECONDS_AND_OFFSET, UTCTIME_WITH_OFFSET].iter() {
            if let Ok(dt) = chrono::DateTime::parse_from_str(data, format) {
                result = Some(dt.into());
                break;
            }
        }
        match result {
            Some(mut dt) => {
                // Reject leap seconds, which aren't allowed by ASN.1. chrono encodes them as
                // nanoseconds == 1000000.
                if dt.nanosecond() >= 1_000_000 {
                    return Err(ParseError::InvalidValue);
                }
                // UTCTime only encodes times prior to 2050. We use the X.509 mapping of two-digit
                // year ordinals to full year:
                // https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
                if dt.year() >= 2050 {
                    dt = chrono::Utc
                        .ymd(dt.year() - 100, dt.month(), dt.day())
                        .and_hms(dt.hour(), dt.minute(), dt.second());
                }
                Ok(dt)
            }
            None => Err(ParseError::InvalidValue),
        }
    }
}

impl<'a, T: SimpleAsn1Element<'a>> Asn1Element<'a> for Option<T> {
    type ParsedType = Option<T::ParsedType>;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::ParsedType> {
        let tag = parser.peek_u8();
        if tag == Some(T::TAG) {
            Ok(Some(parser.read_element::<T>()?))
        } else {
            Ok(None)
        }
    }
}

macro_rules! declare_choice {
    ($count:ident => $(($number:ident $name:ident)),*) => {
        /// Represents an ASN.1 `CHOICE` with the provided number of potential types.
        ///
        /// If you need more variants that are provided, please file an issue or submit a pull
        /// request!
        #[derive(Debug, PartialEq)]
        pub enum $count<
            'a,
            $(
                $number: SimpleAsn1Element<'a>,
            )*
        > {
            $(
                $name($number::ParsedType),
            )*
        }

        impl<
            'a,
            $(
                $number: SimpleAsn1Element<'a>,
            )*
        > Asn1Element<'a> for $count<'a, $($number,)*> {
            type ParsedType = Self;

            fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::ParsedType> {
                let tag = parser.peek_u8();
                match tag {
                    $(
                        Some(tag) if tag == $number::TAG => Ok($count::$name(parser.read_element::<$number>()?)),
                    )*
                    Some(tag) => Err(ParseError::UnexpectedTag{actual: tag}),
                    None => Err(ParseError::ShortData),
                }
            }
        }
    }
}

declare_choice!(Choice1 => (T1 ChoiceA));
declare_choice!(Choice2 => (T1 ChoiceA), (T2 ChoiceB));
declare_choice!(Choice3 => (T1 ChoiceA), (T2 ChoiceB), (T3 ChoiceC));

/// Represents an ASN.1 `SEQUENCE`. By itself, this merely indicates a sequence of bytes that are
/// claimed to form an ASN1 sequence. In almost any circumstance, you'll want to immediately call
/// `Sequence.parse` on this value to decode the actual contents therein.
#[derive(Debug, PartialEq)]
pub struct Sequence<'a> {
    data: &'a [u8],
}

impl<'a> Sequence<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Sequence<'a> {
        Sequence { data }
    }

    /// Parses the contents of the `Sequence`. Behaves the same as the module-level `parse`
    /// function.
    pub fn parse<T, F: Fn(&mut Parser) -> ParseResult<T>>(self, f: F) -> ParseResult<T> {
        parse(self.data, f)
    }
}

impl<'a> SimpleAsn1Element<'a> for Sequence<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    type ParsedType = Sequence<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<Sequence<'a>> {
        Ok(Sequence::new(data))
    }
}

/// `Implicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `IMPLICIT`. This will generally be used with `Option` or `Choice`.
pub struct Implicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, T: SimpleAsn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a>
    for Implicit<'a, T, { TAG }>
{
    const TAG: u8 = CONTEXT_SPECIFIC | TAG | (T::TAG & CONSTRUCTED);
    type ParsedType = T::ParsedType;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::ParsedType> {
        T::parse_data(data)
    }
}

/// `Explicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `EXPLICIT`. This will generally be used with `Option` or `Choice`.
pub struct Explicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, T: Asn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a> for Explicit<'a, T, { TAG }> {
    const TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | TAG;
    type ParsedType = T::ParsedType;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::ParsedType> {
        parse(data, |p| p.read_element::<T>())
    }
}
