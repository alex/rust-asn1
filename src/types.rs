use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem;

use chrono::{Datelike, TimeZone, Timelike};

use crate::writer::Writer;
use crate::{parse, parse_single, BitString, ObjectIdentifier, ParseError, ParseResult, Parser};

pub(crate) const CONTEXT_SPECIFIC: u8 = 0x80;
pub(crate) const CONSTRUCTED: u8 = 0x20;

/// Any type that can be parsed as DER ASN.1.
pub trait Asn1Readable<'a>: Sized {
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self>;
    fn can_parse(tag: u8) -> bool;
}

/// Types with a fixed-tag that can be parsed as DER ASN.1
pub trait SimpleAsn1Readable<'a>: Sized {
    const TAG: u8;

    fn parse_data(data: &'a [u8]) -> ParseResult<Self>;
}

impl<'a, T: SimpleAsn1Readable<'a>> Asn1Readable<'a> for T {
    #[inline]
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let tlv = parser.read_tlv()?;
        if !Self::can_parse(tlv.tag) {
            return Err(ParseError::UnexpectedTag { actual: tlv.tag });
        }
        Self::parse_data(tlv.data)
    }

    #[inline]
    fn can_parse(tag: u8) -> bool {
        tag == Self::TAG
    }
}

/// Any type that can be written as DER ASN.1.
pub trait Asn1Writable<'a>: Sized {
    fn write(&self, dest: &mut Writer);
}

// Types with a fixed-tag that can be written as DER ASN.1.
pub trait SimpleAsn1Writable<'a>: Sized {
    const TAG: u8;

    fn write_data(&self, dest: &mut Vec<u8>);
}

impl<'a, T: SimpleAsn1Writable<'a>> Asn1Writable<'a> for T {
    fn write(&self, w: &mut Writer) {
        w.write_tlv(Self::TAG, move |dest| self.write_data(dest));
    }
}

impl<'a, T: SimpleAsn1Writable<'a>> SimpleAsn1Writable<'a> for &T {
    const TAG: u8 = T::TAG;
    fn write_data(&self, dest: &mut Vec<u8>) {
        T::write_data(self, dest)
    }
}

/// A TLV (type, length, value) represented as the tag and bytes content.
/// Generally used for parsing ASN.1 `ANY` values.
#[derive(Debug, PartialEq, PartialOrd, Hash, Clone, Copy)]
pub struct Tlv<'a> {
    pub(crate) tag: u8,
    // `data` is the value of a TLV
    pub(crate) data: &'a [u8],
    // `full_data` contains the encoded type and length, in addition to the
    // value
    pub(crate) full_data: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// The tag portion of a TLV.
    pub fn tag(&self) -> u8 {
        self.tag
    }
    /// The value portion of the TLV.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
    /// The full DER encoded TLV.
    pub fn full_data(&self) -> &'a [u8] {
        self.full_data
    }
    /// Parse this TLV as a given type.
    pub fn parse<T: Asn1Readable<'a>>(&self) -> ParseResult<T> {
        parse_single::<T>(self.full_data)
    }
}

impl<'a> Asn1Readable<'a> for Tlv<'a> {
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        parser.read_tlv()
    }

    fn can_parse(_tag: u8) -> bool {
        true
    }
}
impl<'a> Asn1Writable<'a> for Tlv<'a> {
    fn write(&self, w: &mut Writer) {
        w.write_tlv(self.tag, move |dest| dest.extend_from_slice(self.data))
    }
}

impl SimpleAsn1Readable<'_> for () {
    const TAG: u8 = 0x05;
    #[inline]
    fn parse_data(data: &[u8]) -> ParseResult<()> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(ParseError::InvalidValue)
        }
    }
}

impl SimpleAsn1Writable<'_> for () {
    const TAG: u8 = 0x05;
    #[inline]
    fn write_data(&self, _dest: &mut Vec<u8>) {}
}

impl SimpleAsn1Readable<'_> for bool {
    const TAG: u8 = 0x1;
    fn parse_data(data: &[u8]) -> ParseResult<bool> {
        match data {
            b"\x00" => Ok(false),
            b"\xff" => Ok(true),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

impl SimpleAsn1Writable<'_> for bool {
    const TAG: u8 = 0x1;
    fn write_data(&self, dest: &mut Vec<u8>) {
        if *self {
            dest.push(0xff);
        } else {
            dest.push(0x00);
        }
    }
}

impl<'a> SimpleAsn1Readable<'a> for &'a [u8] {
    const TAG: u8 = 0x04;
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        Ok(data)
    }
}

impl<'a> SimpleAsn1Writable<'a> for &'a [u8] {
    const TAG: u8 = 0x04;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self);
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `PrintableString`.  A `PrintableString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq)]
pub struct PrintableString<'a>(&'a str);

impl<'a> PrintableString<'a> {
    pub fn new(s: &'a str) -> Option<PrintableString<'a>> {
        if PrintableString::verify(s.as_bytes()) {
            Some(PrintableString(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<PrintableString<'a>> {
        if PrintableString::verify(s) {
            // TODO: This value is always valid utf-8 because we just verified
            // the contents, but I don't want to call an unsafe function, so we
            // end up validating it twice. If your profile says this is slow,
            // now you know why.
            Some(PrintableString(core::str::from_utf8(s).unwrap()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'a str {
        self.0
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

impl<'a> SimpleAsn1Readable<'a> for PrintableString<'a> {
    const TAG: u8 = 0x13;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        PrintableString::new_from_bytes(data).ok_or(ParseError::InvalidValue)
    }
}

impl<'a> SimpleAsn1Writable<'a> for PrintableString<'a> {
    const TAG: u8 = 0x13;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.0.as_bytes());
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `IA5String`.  An `IA5String` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq)]
pub struct IA5String<'a>(&'a str);

impl<'a> IA5String<'a> {
    pub fn new(s: &'a str) -> Option<IA5String<'a>> {
        if IA5String::verify(s.as_bytes()) {
            Some(IA5String(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<IA5String> {
        if IA5String::verify(s) {
            // TODO: This value is always valid utf-8 because we just verified
            // the contents, but I don't want to call an unsafe function, so we
            // end up validating it twice. If your profile says this is slow,
            // now you know why.
            Some(IA5String(core::str::from_utf8(s).unwrap()))
        } else {
            None
        }
    }

    fn verify(s: &[u8]) -> bool {
        s.is_ascii()
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for IA5String<'a> {
    const TAG: u8 = 0x16;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        IA5String::new_from_bytes(data).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for IA5String<'a> {
    const TAG: u8 = 0x16;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.0.as_bytes());
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `UTF8String`.
#[derive(Clone, Debug, PartialEq)]
pub struct Utf8String<'a>(&'a str);

impl<'a> Utf8String<'a> {
    pub fn new(s: &'a str) -> Utf8String<'a> {
        Utf8String(s)
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<Utf8String> {
        Some(Utf8String(core::str::from_utf8(s).ok()?))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for Utf8String<'a> {
    const TAG: u8 = 0x0c;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Utf8String::new_from_bytes(data).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for Utf8String<'a> {
    const TAG: u8 = 0x0c;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.0.as_bytes());
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `VisibleString`.  An `VisibleString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq)]
pub struct VisibleString<'a>(&'a str);

impl<'a> VisibleString<'a> {
    pub fn new(s: &'a str) -> Option<VisibleString<'a>> {
        if VisibleString::verify(s.as_bytes()) {
            Some(VisibleString(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<VisibleString> {
        if VisibleString::verify(s) {
            // TODO: This value is always valid utf-8 because we just verified
            // the contents, but I don't want to call an unsafe function, so we
            // end up validating it twice. If your profile says this is slow,
            // now you know why.
            Some(VisibleString(core::str::from_utf8(s).unwrap()))
        } else {
            None
        }
    }

    fn verify(s: &[u8]) -> bool {
        for b in s {
            if !(b.is_ascii_graphic() || *b == b' ') {
                return false;
            }
        }
        true
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for VisibleString<'a> {
    const TAG: u8 = 0x1a;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        VisibleString::new_from_bytes(data).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for VisibleString<'a> {
    const TAG: u8 = 0x1a;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.0.as_bytes());
    }
}

fn validate_integer(data: &[u8], signed: bool) -> ParseResult<()> {
    if data.is_empty() {
        return Err(ParseError::InvalidValue);
    }
    // Ensure integer is minimally encoded
    if data.len() > 1
        && ((data[0] == 0 && data[1] & 0x80 == 0) || (data[0] == 0xff && data[1] & 0x80 == 0x80))
    {
        return Err(ParseError::InvalidValue);
    }

    // Reject negatives for unsigned types.
    if !signed && data[0] & 0x80 == 0x80 {
        return Err(ParseError::InvalidValue);
    }

    Ok(())
}

macro_rules! impl_asn1_element_for_int {
    ($t:ty; $signed:expr) => {
        impl SimpleAsn1Readable<'_> for $t {
            const TAG: u8 = 0x02;
            #[inline]
            fn parse_data(mut data: &[u8]) -> ParseResult<Self> {
                validate_integer(data, $signed)?;

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
        }
        impl SimpleAsn1Writable<'_> for $t {
            const TAG: u8 = 0x02;
            fn write_data(&self, dest: &mut Vec<u8>) {
                let mut num_bytes = 1;
                let mut v: $t = *self;
                #[allow(unused_comparisons)]
                while v > 127 || ($signed && v < (-128i64) as $t) {
                    num_bytes += 1;
                    v = v.checked_shr(8).unwrap_or(0);
                }

                for i in (1..num_bytes + 1).rev() {
                    dest.push((self >> ((i - 1) * 8)) as u8);
                }
            }
        }
    };
}

impl_asn1_element_for_int!(i8; true);
impl_asn1_element_for_int!(u8; false);
impl_asn1_element_for_int!(i32; false);
impl_asn1_element_for_int!(u32; false);
impl_asn1_element_for_int!(i64; true);
impl_asn1_element_for_int!(u64; false);

/// Arbitrary sized unsigned integer. Contents may be accessed as `&[u8]` of
/// big-endian data. Its contents always match the DER encoding of a value
/// (i.e. they are minimal)
#[derive(PartialEq, Clone, Copy, Debug, Hash)]
pub struct BigUint<'a> {
    data: &'a [u8],
}

impl<'a> BigUint<'a> {
    /// Create a new BigUint from already encoded data. `data` must be encoded
    /// as required by DER: minimally and if the high bit would be set in the
    /// first octet, a leading \x00 should be prepended (to disambiguate from
    /// negative values).
    pub fn new(data: &'a [u8]) -> Option<Self> {
        validate_integer(data, false).ok()?;
        Some(BigUint { data })
    }

    /// Returns the contents of the integer as big-endian bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> SimpleAsn1Readable<'a> for BigUint<'a> {
    const TAG: u8 = 0x02;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        BigUint::new(data).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for BigUint<'a> {
    const TAG: u8 = 0x02;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(self.data);
    }
}

impl<'a> SimpleAsn1Readable<'a> for ObjectIdentifier<'a> {
    const TAG: u8 = 0x06;
    fn parse_data(data: &'a [u8]) -> ParseResult<ObjectIdentifier<'a>> {
        ObjectIdentifier::from_der(data).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for ObjectIdentifier<'a> {
    const TAG: u8 = 0x06;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.der_encoded);
    }
}

impl<'a> SimpleAsn1Readable<'a> for BitString<'a> {
    const TAG: u8 = 0x03;
    fn parse_data(data: &'a [u8]) -> ParseResult<BitString<'a>> {
        if data.is_empty() {
            return Err(ParseError::InvalidValue);
        }
        BitString::new(&data[1..], data[0]).ok_or(ParseError::InvalidValue)
    }
}
impl<'a> SimpleAsn1Writable<'a> for BitString<'a> {
    const TAG: u8 = 0x03;
    fn write_data(&self, dest: &mut Vec<u8>) {
        dest.push(self.padding_bits());
        dest.extend_from_slice(self.as_bytes());
    }
}

/// Used for parsing and writing ASN.1 `UTC TIME` values. Wraps a
/// `chrono::DateTime<Utc>`.
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct UtcTime(chrono::DateTime<chrono::Utc>);

impl UtcTime {
    pub fn new(v: chrono::DateTime<chrono::Utc>) -> Option<UtcTime> {
        if v.year() > 2050 || v.year() <= 1950 {
            return None;
        }
        Some(UtcTime(v))
    }

    pub fn as_chrono(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.0
    }
}

const UTCTIME_WITH_SECONDS_AND_OFFSET: &str = "%y%m%d%H%M%S%z";
const UTCTIME_WITH_SECONDS: &str = "%y%m%d%H%M%SZ";
const UTCTIME_WITH_OFFSET: &str = "%y%m%d%H%M%z";
const UTCTIME: &str = "%y%m%d%H%MZ";

impl SimpleAsn1Readable<'_> for UtcTime {
    const TAG: u8 = 0x17;
    fn parse_data(data: &[u8]) -> ParseResult<Self> {
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
                Ok(UtcTime(dt))
            }
            None => Err(ParseError::InvalidValue),
        }
    }
}

fn push_two_digits(dest: &mut Vec<u8>, val: u8) {
    dest.push(b'0' + ((val / 10) % 10));
    dest.push(b'0' + (val % 10));
}

fn push_four_digits(dest: &mut Vec<u8>, val: u16) {
    dest.push(b'0' + ((val / 1000) % 10) as u8);
    dest.push(b'0' + ((val / 100) % 10) as u8);
    dest.push(b'0' + ((val / 10) % 10) as u8);
    dest.push(b'0' + (val % 10) as u8);
}

impl SimpleAsn1Writable<'_> for UtcTime {
    const TAG: u8 = 0x17;
    fn write_data(&self, dest: &mut Vec<u8>) {
        let year = if 1950 <= self.0.year() && self.0.year() < 2000 {
            self.0.year() - 1900
        } else if 2000 <= self.0.year() && self.0.year() < 2050 {
            self.0.year() - 2000
        } else {
            unreachable!()
        };
        push_two_digits(dest, year.try_into().unwrap());
        push_two_digits(dest, self.0.month().try_into().unwrap());
        push_two_digits(dest, self.0.day().try_into().unwrap());

        push_two_digits(dest, self.0.hour().try_into().unwrap());
        push_two_digits(dest, self.0.minute().try_into().unwrap());
        push_two_digits(dest, self.0.second().try_into().unwrap());

        dest.push(b'Z');
    }
}

/// Used for parsing and writing ASN.1 `GENERALIZED TIME` values. Wraps a
/// `chrono::DateTime<Utc>`.
#[derive(Debug, PartialEq, Hash)]
pub struct GeneralizedTime(chrono::DateTime<chrono::Utc>);

impl GeneralizedTime {
    pub fn new(v: chrono::DateTime<chrono::Utc>) -> GeneralizedTime {
        GeneralizedTime(v)
    }

    pub fn as_chrono(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.0
    }
}

impl SimpleAsn1Readable<'_> for GeneralizedTime {
    const TAG: u8 = 0x18;
    fn parse_data(data: &[u8]) -> ParseResult<GeneralizedTime> {
        let data = core::str::from_utf8(data).map_err(|_| ParseError::InvalidValue)?;
        if let Ok(v) = chrono::Utc.datetime_from_str(data, "%Y%m%d%H%M%SZ") {
            return Ok(GeneralizedTime::new(v));
        }
        if let Ok(v) = chrono::DateTime::parse_from_str(data, "%Y%m%d%H%M%S%z") {
            return Ok(GeneralizedTime::new(v.into()));
        }

        Err(ParseError::InvalidValue)
    }
}

impl SimpleAsn1Writable<'_> for GeneralizedTime {
    const TAG: u8 = 0x18;
    fn write_data(&self, dest: &mut Vec<u8>) {
        push_four_digits(dest, self.0.year().try_into().unwrap());
        push_two_digits(dest, self.0.month().try_into().unwrap());
        push_two_digits(dest, self.0.day().try_into().unwrap());

        push_two_digits(dest, self.0.hour().try_into().unwrap());
        push_two_digits(dest, self.0.minute().try_into().unwrap());
        push_two_digits(dest, self.0.second().try_into().unwrap());

        dest.push(b'Z');
    }
}

/// An ASN.1 `ENUMERATED` value.
#[derive(Debug, PartialEq)]
pub struct Enumerated(u32);

impl Enumerated {
    pub fn new(v: u32) -> Enumerated {
        Enumerated(v)
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for Enumerated {
    const TAG: u8 = 0xa;

    fn parse_data(data: &'a [u8]) -> ParseResult<Enumerated> {
        Ok(Enumerated::new(u32::parse_data(data)?))
    }
}

impl<'a> SimpleAsn1Writable<'a> for Enumerated {
    const TAG: u8 = 0xa;

    fn write_data(&self, dest: &mut Vec<u8>) {
        u32::write_data(&self.0, dest)
    }
}

impl<'a, T: Asn1Readable<'a>> Asn1Readable<'a> for Option<T> {
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        match parser.peek_u8() {
            Some(tag) if T::can_parse(tag) => Ok(Some(parser.read_element::<T>()?)),
            Some(_) | None => Ok(None),
        }
    }

    fn can_parse(tag: u8) -> bool {
        T::can_parse(tag)
    }
}

impl<'a, T: Asn1Writable<'a>> Asn1Writable<'a> for Option<T> {
    fn write(&self, w: &mut Writer) {
        if let Some(v) = self {
            w.write_element(v);
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
            $($number,)*
        > {
            $(
                $name($number),
            )*
        }

        impl<
            'a,
            $(
                $number: Asn1Readable<'a>,
            )*
        > Asn1Readable<'a> for $count<$($number,)*> {
            fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
                let tlv = parser.read_tlv()?;
                $(
                    if $number::can_parse(tlv.tag()) {
                        return Ok($count::$name(tlv.parse::<$number>()?));
                    }
                )*
                Err(ParseError::UnexpectedTag{actual: tlv.tag()})
            }

            fn can_parse(tag: u8) -> bool {
                $(
                    if $number::can_parse(tag) {
                        return true;
                    }
                )*
                false
            }
        }

        impl<
            'a,
            $(
                $number: Asn1Writable<'a>,
            )*
        > Asn1Writable<'a> for $count<$($number,)*> {
            fn write(&self, w: &mut Writer) {
                match self {
                    $(
                        $count::$name(v) => w.write_element(v),
                    )*
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
    pub fn parse<T, E: From<ParseError>, F: Fn(&mut Parser<'a>) -> Result<T, E>>(
        self,
        f: F,
    ) -> Result<T, E> {
        parse(self.data, f)
    }
}

impl<'a> SimpleAsn1Readable<'a> for Sequence<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Sequence<'a>> {
        Ok(Sequence::new(data))
    }
}
impl<'a> SimpleAsn1Writable<'a> for Sequence<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    #[inline]
    fn write_data(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(self.data);
    }
}

/// Writes an ASN.1 `SEQUENCE` using a callback that writes the inner
/// elements.
pub struct SequenceWriter<'a> {
    f: &'a dyn Fn(&mut Writer),
}

impl<'a> SequenceWriter<'a> {
    #[inline]
    pub fn new(f: &'a dyn Fn(&mut Writer)) -> Self {
        SequenceWriter { f }
    }
}

impl<'a> SimpleAsn1Writable<'a> for SequenceWriter<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    #[inline]
    fn write_data(&self, dest: &mut Vec<u8>) {
        (self.f)(&mut Writer::new(dest))
    }
}

/// Represents an ASN.1 `SEQUENCE OF`. This is an `Iterator` over values that
/// are decoded.
pub struct SequenceOf<'a, T: Asn1Readable<'a>> {
    parser: Parser<'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: Asn1Readable<'a>> SequenceOf<'a, T> {
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> SequenceOf<'a, T> {
        SequenceOf {
            parser: Parser::new(data),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: Asn1Readable<'a>> Clone for SequenceOf<'a, T> {
    fn clone(&self) -> SequenceOf<'a, T> {
        SequenceOf {
            parser: self.parser.clone_internal(),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: Asn1Readable<'a> + PartialEq> PartialEq for SequenceOf<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        let mut it1 = self.clone();
        let mut it2 = other.clone();
        loop {
            match (it1.next(), it2.next()) {
                (Some(v1), Some(v2)) => {
                    if v1 != v2 {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a, T: Asn1Readable<'a> + Hash> Hash for SequenceOf<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for val in self.clone() {
            val.hash(state);
        }
    }
}

impl<'a, T: Asn1Readable<'a> + 'a> SimpleAsn1Readable<'a> for SequenceOf<'a, T> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        parse(data, |p| {
            while !p.is_empty() {
                p.read_element::<T>()?;
            }
            Ok(())
        })?;
        Ok(SequenceOf::new(data))
    }
}

impl<'a, T: Asn1Readable<'a>> Iterator for SequenceOf<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            return None;
        }
        Some(
            self.parser
                .read_element::<T>()
                .expect("Should always succeed"),
        )
    }
}

impl<'a, T: Asn1Readable<'a> + Asn1Writable<'a>> SimpleAsn1Writable<'a> for SequenceOf<'a, T> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    fn write_data(&self, dest: &mut Vec<u8>) {
        let mut w = Writer::new(dest);
        for el in self.clone() {
            w.write_element(&el);
        }
    }
}

/// Writes a `SEQUENCE OF` ASN.1 structure from a slice of `T`.
pub struct SequenceOfWriter<'a, T: Asn1Writable<'a>> {
    vals: &'a [T],
}

impl<'a, T: Asn1Writable<'a>> SequenceOfWriter<'a, T> {
    pub fn new(vals: &'a [T]) -> Self {
        SequenceOfWriter { vals }
    }
}

impl<'a, T: Asn1Writable<'a>> SimpleAsn1Writable<'a> for SequenceOfWriter<'a, T> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    fn write_data(&self, dest: &mut Vec<u8>) {
        let mut w = Writer::new(dest);
        for el in self.vals {
            w.write_element(el);
        }
    }
}

/// Represents an ASN.1 `SET OF`. This is an `Iterator` over values that
/// are decoded.
pub struct SetOf<'a, T: Asn1Readable<'a>> {
    parser: Parser<'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: Asn1Readable<'a>> SetOf<'a, T> {
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> SetOf<'a, T> {
        SetOf {
            parser: Parser::new(data),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: Asn1Readable<'a>> Clone for SetOf<'a, T> {
    fn clone(&self) -> SetOf<'a, T> {
        SetOf {
            parser: self.parser.clone_internal(),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: Asn1Readable<'a> + PartialEq> PartialEq for SetOf<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        let mut it1 = self.clone();
        let mut it2 = other.clone();
        loop {
            match (it1.next(), it2.next()) {
                (Some(v1), Some(v2)) => {
                    if v1 != v2 {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a, T: Asn1Readable<'a> + Hash> Hash for SetOf<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for val in self.clone() {
            val.hash(state);
        }
    }
}

impl<'a, T: Asn1Readable<'a> + 'a> SimpleAsn1Readable<'a> for SetOf<'a, T> {
    const TAG: u8 = 0x11 | CONSTRUCTED;

    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        parse(data, |p| {
            let mut last_element: Option<Tlv> = None;
            while !p.is_empty() {
                let el = p.read_tlv()?;
                if let Some(last_el) = last_element {
                    if el.full_data < last_el.full_data {
                        return Err(ParseError::InvalidSetOrdering);
                    }
                }
                last_element = Some(el);
                el.parse::<T>()?;
            }
            Ok(())
        })?;
        Ok(SetOf::new(data))
    }
}

impl<'a, T: Asn1Readable<'a>> Iterator for SetOf<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            return None;
        }
        Some(
            self.parser
                .read_element::<T>()
                .expect("Should always succeed"),
        )
    }
}

impl<'a, T: Asn1Readable<'a> + Asn1Writable<'a>> SimpleAsn1Writable<'a> for SetOf<'a, T> {
    const TAG: u8 = 0x11 | CONSTRUCTED;
    fn write_data(&self, dest: &mut Vec<u8>) {
        let mut w = Writer::new(dest);
        // We are known to be ordered correctly because that's an invariant for
        // `self`, so we don't need to sort here.
        for el in self.clone() {
            w.write_element(&el);
        }
    }
}

/// Writes an ASN.1 `SET OF` whose contents is a slice of `T`. This type is
/// responsible for ensure the values are properly ordered when written as DER.
pub struct SetOfWriter<'a, T: Asn1Writable<'a>> {
    vals: &'a [T],
}

impl<'a, T: Asn1Writable<'a>> SetOfWriter<'a, T> {
    pub fn new(vals: &'a [T]) -> Self {
        SetOfWriter { vals }
    }
}

impl<'a, T: Asn1Writable<'a>> SimpleAsn1Writable<'a> for SetOfWriter<'a, T> {
    const TAG: u8 = 0x11 | CONSTRUCTED;
    fn write_data(&self, dest: &mut Vec<u8>) {
        if self.vals.is_empty() {
            return;
        } else if self.vals.len() == 1 {
            let mut w = Writer::new(dest);
            w.write_element(&self.vals[0]);
            return;
        }

        // Optimization: use the dest storage as scratch, then truncate.
        let mut data = vec![];
        let mut w = Writer::new(&mut data);
        // Optimization opportunity: use a SmallVec here.
        let mut spans = vec![];

        let mut pos = 0;
        for el in self.vals {
            w.write_element(el);
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

/// `Implicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `IMPLICIT`. This will generally be used with `Option` or `Choice`.
///
/// Requires the `const-generics` feature and Rust 1.51 or greater. For users
/// on older Rust versions, `Parser::read_optional_implicit_element` may be
/// used.
#[cfg(feature = "const-generics")]
#[derive(PartialEq, Debug)]
pub struct Implicit<'a, T, const TAG: u8> {
    inner: T,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg(feature = "const-generics")]
impl<'a, T, const TAG: u8> Implicit<'a, T, { TAG }> {
    pub fn new(v: T) -> Self {
        Implicit {
            inner: v,
            _lifetime: PhantomData,
        }
    }

    pub fn as_inner(&self) -> &T {
        &self.inner
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T, const TAG: u8> From<T> for Implicit<'a, T, { TAG }> {
    fn from(v: T) -> Self {
        Implicit::new(v)
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T: SimpleAsn1Readable<'a>, const TAG: u8> SimpleAsn1Readable<'a>
    for Implicit<'a, T, { TAG }>
{
    const TAG: u8 = crate::implicit_tag(TAG, T::TAG);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(Implicit::new(T::parse_data(data)?))
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T: SimpleAsn1Writable<'a>, const TAG: u8> SimpleAsn1Writable<'a>
    for Implicit<'a, T, { TAG }>
{
    const TAG: u8 = crate::implicit_tag(TAG, T::TAG);

    fn write_data(&self, dest: &mut Vec<u8>) {
        self.inner.write_data(dest);
    }
}

/// `Explicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `EXPLICIT`. This will generally be used with `Option` or `Choice`.
///
/// Requires the `const-generics` feature and Rust 1.51 or greater. For users
/// on older Rust versions, `Parser::read_optional_explicit_element` may be
/// used.
#[cfg(feature = "const-generics")]
#[derive(PartialEq, Debug)]
pub struct Explicit<'a, T, const TAG: u8> {
    inner: T,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg(feature = "const-generics")]
impl<'a, T, const TAG: u8> Explicit<'a, T, { TAG }> {
    pub fn new(v: T) -> Self {
        Explicit {
            inner: v,
            _lifetime: PhantomData,
        }
    }

    pub fn as_inner(&self) -> &T {
        &self.inner
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T, const TAG: u8> From<T> for Explicit<'a, T, { TAG }> {
    fn from(v: T) -> Self {
        Explicit::new(v)
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T: Asn1Readable<'a>, const TAG: u8> SimpleAsn1Readable<'a> for Explicit<'a, T, { TAG }> {
    const TAG: u8 = crate::explicit_tag(TAG);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(Explicit::new(parse(data, |p| p.read_element::<T>())?))
    }
}

#[cfg(feature = "const-generics")]
impl<'a, T: Asn1Writable<'a>, const TAG: u8> SimpleAsn1Writable<'a> for Explicit<'a, T, { TAG }> {
    const TAG: u8 = crate::explicit_tag(TAG);
    fn write_data(&self, dest: &mut Vec<u8>) {
        Writer::new(dest).write_element(&self.inner);
    }
}

#[cfg(test)]
mod tests {
    use crate::{parse_single, IA5String, ParseError, PrintableString, SequenceOf, SetOf, Tlv};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn test_printable_string_new() {
        assert!(PrintableString::new("abc").is_some());
        assert!(PrintableString::new("").is_some());
        assert!(PrintableString::new(" ").is_some());
        assert!(PrintableString::new("%").is_none());
        assert!(PrintableString::new("\x00").is_none());
    }

    #[test]
    fn test_ia5string_new() {
        assert!(IA5String::new("abc").is_some());
        assert!(IA5String::new("").is_some());
        assert!(IA5String::new(" ").is_some());
        assert!(IA5String::new("%").is_some());
        assert!(IA5String::new("😄").is_none());
    }

    #[test]
    fn test_tlv_parse() {
        let tlv = Tlv {
            tag: 0x2,
            data: b"\x03",
            full_data: b"\x02\x01\x03",
        };
        assert_eq!(tlv.parse::<u64>(), Ok(3));
        assert_eq!(
            tlv.parse::<&[u8]>(),
            Err(ParseError::UnexpectedTag { actual: 0x2 })
        );
    }

    #[test]
    fn test_sequence_of_clone() {
        let mut seq1 =
            parse_single::<SequenceOf<u64>>(b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03")
                .unwrap();
        assert_eq!(seq1.next(), Some(1));
        let seq2 = seq1.clone();
        assert_eq!(seq1.collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(seq2.collect::<Vec<_>>(), vec![2, 3]);
    }

    fn hash<T: Hash>(v: &T) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_set_of_eq_hash() {
        let s1 = SetOf::<bool>::new(b"");
        let s2 = SetOf::<bool>::new(b"");
        let s3 = SetOf::<bool>::new(b"\x01\x01\x00");

        assert!(s1 == s2);
        assert_eq!(hash(&s1), hash(&s2));

        assert!(s2 != s3);
        assert_ne!(hash(&s2), hash(&s3));
    }

    #[test]
    fn test_sequence_of_eq_hash() {
        let s1 = SequenceOf::<bool>::new(b"");
        let s2 = SequenceOf::<bool>::new(b"");
        let s3 = SequenceOf::<bool>::new(b"\x01\x01\x00");

        assert!(s1 == s2);
        assert_eq!(hash(&s1), hash(&s2));

        assert!(s2 != s3);
        assert_ne!(hash(&s2), hash(&s3));
    }
}
