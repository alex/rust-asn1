use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem;

use chrono::{Datelike, TimeZone, Timelike};

use crate::parser::Parser;
use crate::writer::Writer;
use crate::{parse, BitString, ObjectIdentifier, ParseError, ParseResult};

#[cfg(feature = "const-generics")]
const CONTEXT_SPECIFIC: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;

pub trait Asn1Element<'a>: Sized {
    type ParsedType;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::ParsedType>;
}

pub trait SimpleAsn1Element<'a>: Sized {
    const TAG: u8;
    type ParsedType;
    type WriteType;

    fn parse_data(data: &'a [u8]) -> ParseResult<Self::ParsedType>;
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType);
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

/// A TLV (type, length, value) represented as the tag and bytes content.
/// Generally used for parsing ASN.1 `ANY` values.
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) data: &'a [u8],
}

impl Tlv<'_> {
    pub fn tag(&self) -> u8 {
        self.tag
    }
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> Asn1Element<'a> for Tlv<'a> {
    type ParsedType = Self;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        parser.read_tlv()
    }
}

impl SimpleAsn1Element<'_> for () {
    const TAG: u8 = 0x05;
    type ParsedType = ();
    type WriteType = ();
    #[inline]
    fn parse_data(data: &[u8]) -> ParseResult<()> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(ParseError::InvalidValue)
        }
    }

    fn write_data(_dest: &mut Vec<u8>, _val: ()) {}
}

impl SimpleAsn1Element<'_> for bool {
    const TAG: u8 = 0x1;
    type ParsedType = bool;
    type WriteType = bool;
    fn parse_data(data: &[u8]) -> ParseResult<bool> {
        match data {
            b"\x00" => Ok(false),
            b"\xff" => Ok(true),
            _ => Err(ParseError::InvalidValue),
        }
    }

    fn write_data(dest: &mut Vec<u8>, val: bool) {
        if val {
            dest.push(0xff);
        } else {
            dest.push(0x00);
        }
    }
}

impl<'a> SimpleAsn1Element<'a> for &'a [u8] {
    const TAG: u8 = 0x04;
    type ParsedType = &'a [u8];
    type WriteType = &'a [u8];
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        Ok(data)
    }

    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        dest.extend_from_slice(val);
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `PrintableString`.  Parsing a `PrintableString` will return
/// an `&str` containing only valid characers.
#[derive(Clone)]
pub struct PrintableString<'a>(&'a str);

impl<'a> PrintableString<'a> {
    pub fn new(s: &'a str) -> Option<PrintableString<'a>> {
        if PrintableString::verify(s.as_bytes()) {
            Some(PrintableString(s))
        } else {
            None
        }
    }

    fn verify(data: &[u8]) -> bool {
        for b in data {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b' '
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
                _ => return false,
            };
        }
        true
    }
}

impl<'a> SimpleAsn1Element<'a> for PrintableString<'a> {
    const TAG: u8 = 0x13;
    type ParsedType = &'a str;
    type WriteType = PrintableString<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a str> {
        if !PrintableString::verify(data) {
            return Err(ParseError::InvalidValue);
        }
        // TODO: This value is always valid utf-8 because we just verified the contents, but I
        // don't want to call an unsafe function, so we end up validating it twice. If your profile
        // says this is slow, now you know why.
        Ok(core::str::from_utf8(data).unwrap())
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        dest.extend_from_slice(val.0.as_bytes());
    }
}

macro_rules! impl_asn1_element_for_int {
    ($t:ty; $signed:expr) => {
        impl SimpleAsn1Element<'_> for $t {
            const TAG: u8 = 0x02;
            type ParsedType = Self;
            type WriteType = Self;
            #[inline]
            fn parse_data(mut data: &[u8]) -> ParseResult<Self::ParsedType> {
                if data.is_empty() {
                    return Err(ParseError::InvalidValue);
                }
                // Ensure integer is minimally encoded
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

                let mut fixed_data = [0; mem::size_of::<$t>()];
                fixed_data[mem::size_of::<Self>() - data.len()..].copy_from_slice(data);
                let mut ret = Self::from_be_bytes(fixed_data);
                // Shift up and down in order to sign extend the result.
                ret <<= (8 * mem::size_of::<Self>()) - data.len() * 8;
                ret >>= (8 * mem::size_of::<Self>()) - data.len() * 8;
                Ok(ret)
            }
            fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
                let mut num_bytes = 1;
                let mut v: $t = val;
                #[allow(unused_comparisons)]
                while v > 127 || ($signed && v < (-128i64) as $t) {
                    num_bytes += 1;
                    v = v.checked_shr(8).unwrap_or(0);
                }

                for i in (1..num_bytes + 1).rev() {
                    dest.push((val >> ((i - 1) * 8)) as u8);
                }
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
    type WriteType = ObjectIdentifier<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<ObjectIdentifier<'a>> {
        ObjectIdentifier::from_der(data).ok_or(ParseError::InvalidValue)
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        dest.extend_from_slice(&val.der_encoded);
    }
}

impl<'a> SimpleAsn1Element<'a> for BitString<'a> {
    const TAG: u8 = 0x03;
    type ParsedType = BitString<'a>;
    type WriteType = BitString<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<BitString<'a>> {
        if data.is_empty() {
            return Err(ParseError::InvalidValue);
        }
        BitString::new(&data[1..], data[0]).ok_or(ParseError::InvalidValue)
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        dest.push(val.padding_bits());
        dest.extend_from_slice(val.as_bytes());
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

fn push_two_digits(dest: &mut Vec<u8>, val: u8) {
    dest.push(b'0' + ((val / 10) % 10));
    dest.push(b'0' + (val % 10));
}

impl SimpleAsn1Element<'_> for UtcTime {
    const TAG: u8 = 0x17;
    type ParsedType = chrono::DateTime<chrono::Utc>;
    type WriteType = chrono::DateTime<chrono::Utc>;
    fn parse_data(data: &[u8]) -> ParseResult<Self::ParsedType> {
        let data = core::str::from_utf8(data).map_err(|_| ParseError::InvalidValue)?;

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
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        let year = if 1950 <= val.year() && val.year() < 2000 {
            val.year() - 1900
        } else if 2000 <= val.year() && val.year() < 2050 {
            val.year() - 2000
        } else {
            panic!("Can't write a datetime with a year outside [1950, 2050) as a UTCTIME");
        };
        push_two_digits(dest, year.try_into().unwrap());
        push_two_digits(dest, val.month().try_into().unwrap());
        push_two_digits(dest, val.day().try_into().unwrap());

        push_two_digits(dest, val.hour().try_into().unwrap());
        push_two_digits(dest, val.minute().try_into().unwrap());
        push_two_digits(dest, val.second().try_into().unwrap());

        dest.push(b'Z');
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
        /// If you need more variants than are provided, please file an issue or submit a pull
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
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> Sequence<'a> {
        Sequence { data }
    }

    /// Parses the contents of the `Sequence`. Behaves the same as the module-level `parse`
    /// function.
    pub fn parse<T, E: From<ParseError>, F: Fn(&mut Parser) -> Result<T, E>>(
        self,
        f: F,
    ) -> Result<T, E> {
        parse(self.data, f)
    }
}

impl<'a> SimpleAsn1Element<'a> for Sequence<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    type ParsedType = Sequence<'a>;
    type WriteType = &'a dyn Fn(&mut Writer);
    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Sequence<'a>> {
        Ok(Sequence::new(data))
    }
    #[inline]
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        let mut w = Writer::new(dest);
        val(&mut w);
    }
}

/// Represents an ASN.1 `SEQUENCE OF`. This is an `Iterator` over values that
/// are decoded.
pub struct SequenceOf<'a, T: SimpleAsn1Element<'a>> {
    parser: Parser<'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: SimpleAsn1Element<'a>> SequenceOf<'a, T> {
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> SequenceOf<'a, T> {
        SequenceOf {
            parser: Parser::new(data),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: SimpleAsn1Element<'a> + 'a> SimpleAsn1Element<'a> for SequenceOf<'a, T>
where
    T::WriteType: Copy,
{
    const TAG: u8 = 0x10 | CONSTRUCTED;
    type ParsedType = SequenceOf<'a, T>;
    type WriteType = &'a [T::WriteType];

    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self::ParsedType> {
        Ok(SequenceOf::new(data))
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        let mut w = Writer::new(dest);
        for el in val {
            w.write_element_with_type::<T>(*el);
        }
    }
}

impl<'a, T: SimpleAsn1Element<'a>> Iterator for SequenceOf<'a, T> {
    type Item = ParseResult<T::ParsedType>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            return None;
        }
        Some(self.parser.read_element::<T>())
    }
}

pub struct SetOf<'a, T: SimpleAsn1Element<'a>> {
    parser: Parser<'a>,
    last_element: Option<Tlv<'a>>,
    _phantom: PhantomData<T>,
}

impl<'a, T: SimpleAsn1Element<'a>> SetOf<'a, T> {
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> SetOf<'a, T> {
        SetOf {
            parser: Parser::new(data),
            last_element: None,
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: SimpleAsn1Element<'a> + 'a> SimpleAsn1Element<'a> for SetOf<'a, T>
where
    T::WriteType: Copy,
{
    const TAG: u8 = 0x17 | CONSTRUCTED;
    type ParsedType = SetOf<'a, T>;
    type WriteType = &'a [T::WriteType];

    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self::ParsedType> {
        Ok(SetOf::new(data))
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        if val.is_empty() {
            return;
        } else if val.len() == 1 {
            let mut w = Writer::new(dest);
            w.write_element_with_type::<T>(val[0]);
            return;
        }

        // Optimization: use the dest storage as scratch, then truncate.
        let mut data = vec![];
        let mut w = Writer::new(&mut data);
        // Optimization opportunity: use a SmallVec here.
        let mut spans = vec![];

        let mut pos = 0;
        for el in val {
            w.write_element_with_type::<T>(*el);
            let l = w.data.len();
            spans.push(pos..l);
            pos = l;
        }
        spans.sort_by_key(|v| &data[v.clone()]);
        for span in spans {
            dest.extend_from_slice(&data[span]);
        }
    }
}

impl<'a, T: SimpleAsn1Element<'a>> Iterator for SetOf<'a, T> {
    type Item = ParseResult<T::ParsedType>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            return None;
        }
        let el = match self.parser.read_tlv() {
            Ok(tlv) => tlv,
            Err(e) => return Some(Err(e)),
        };
        if let Some(last_el) = self.last_element {
            if el < last_el {
                return Some(Err(ParseError::InvalidSetOrdering));
            }
        }
        self.last_element = Some(el);
        if el.tag != T::TAG {
            return Some(Err(ParseError::UnexpectedTag { actual: el.tag }));
        }
        Some(T::parse_data(el.data))
    }
}

/// `Implicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `IMPLICIT`. This will generally be used with `Option` or `Choice`.
#[cfg(feature = "const-generics")]
pub struct Implicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg(feature = "const-generics")]
impl<'a, T: SimpleAsn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a>
    for Implicit<'a, T, { TAG }>
{
    const TAG: u8 = CONTEXT_SPECIFIC | TAG | (T::TAG & CONSTRUCTED);
    type ParsedType = T::ParsedType;
    type WriteType = T::WriteType;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::ParsedType> {
        T::parse_data(data)
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        T::write_data(dest, val);
    }
}

/// `Explicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `EXPLICIT`. This will generally be used with `Option` or `Choice`.
#[cfg(feature = "const-generics")]
pub struct Explicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg(feature = "const-generics")]
impl<'a, T: SimpleAsn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a>
    for Explicit<'a, T, { TAG }>
{
    const TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | TAG;
    type ParsedType = T::ParsedType;
    type WriteType = T::WriteType;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::ParsedType> {
        parse(data, |p| p.read_element::<T>())
    }
    fn write_data(dest: &mut Vec<u8>, val: Self::WriteType) {
        Writer::new(dest).write_element_with_type::<T>(val);
    }
}

#[cfg(test)]
mod tests {
    use crate::PrintableString;

    #[test]
    fn test_printable_string_new() {
        assert!(PrintableString::new("abc").is_some());
        assert!(PrintableString::new("").is_some());
        assert!(PrintableString::new(" ").is_some());
        assert!(PrintableString::new("%").is_none());
        assert!(PrintableString::new("\x00").is_none());
    }
}
