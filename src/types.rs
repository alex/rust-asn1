#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem;

use crate::writer::Writer;
use crate::{
    parse, parse_single, BitString, ObjectIdentifier, OwnedBitString, ParseError, ParseErrorKind,
    ParseLocation, ParseResult, Parser, Tag, WriteBuf, WriteResult,
};

/// Any type that can be parsed as DER ASN.1.
pub trait Asn1Readable<'a>: Sized {
    /// Parse a value from the given parser.
    ///
    /// This method should read exactly one ASN.1 TLV from the parser,
    /// consuming the appropriate bytes and returning the parsed value.
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self>;

    /// Returns whether this type can parse values with the given tag.
    fn can_parse(tag: Tag) -> bool;
}

/// Types with a fixed-tag that can be parsed as DER ASN.1
pub trait SimpleAsn1Readable<'a>: Sized {
    /// The ASN.1 tag that this type expects when parsing.
    const TAG: Tag;

    /// Parse the value from the given data bytes.
    ///
    /// This method receives the value portion of a TLV (without the tag or
    /// length) and should parse it into the appropriate type.
    fn parse_data(data: &'a [u8]) -> ParseResult<Self>;
}

impl<'a, T: SimpleAsn1Readable<'a>> Asn1Readable<'a> for T {
    #[inline]
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let tlv = parser.read_tlv()?;
        if !Self::can_parse(tlv.tag) {
            return Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: tlv.tag,
            }));
        }
        Self::parse_data(tlv.data)
    }

    #[inline]
    fn can_parse(tag: Tag) -> bool {
        tag == Self::TAG
    }
}

impl<'a, T: SimpleAsn1Readable<'a>> SimpleAsn1Readable<'a> for Box<T> {
    const TAG: Tag = T::TAG;

    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(Box::new(T::parse_data(data)?))
    }
}

/// Any type that can be written as DER ASN.1.
pub trait Asn1Writable: Sized {
    /// Write this value to the given writer.
    ///
    /// This method should write the complete ASN.1 encoding of this value,
    /// including the tag, length, and content bytes.
    fn write(&self, dest: &mut Writer<'_>) -> WriteResult;

    /// Get the complete encoded length (tag + length + content), if it can be
    /// calculated efficiently.
    ///
    /// It is always safe to return `None`, which indicates the length is
    /// unknown. Returning `Some(...)` from this method reduces the number of
    /// re-allocations required in writing.
    fn encoded_length(&self) -> Option<usize>;
}

/// Types with a fixed-tag that can be written as DER ASN.1.
pub trait SimpleAsn1Writable: Sized {
    /// The ASN.1 tag that this type uses when writing.
    const TAG: Tag;

    /// Write the value's data to the given buffer.
    ///
    /// This method should write only the value bytes (without the tag and
    /// length) to the buffer.
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult;

    /// Get the length of the data content (without tag and length bytes) if it
    /// can be calculated efficiently.
    ///
    /// It is always safe to return `None`, which indicates the length is
    /// unknown. Returning `Some(...)` from this method reduces the number of
    /// re-allocations required in writing.
    fn data_length(&self) -> Option<usize>;
}

/// A trait for types that can be parsed based on a `DEFINED BY` value.
///
/// `T` is the type of the `DEFINED BY` field (nearly always `ObjectIdentifier`).
pub trait Asn1DefinedByReadable<'a, T: Asn1Readable<'a>>: Sized {
    /// Parse a value based on the previously parsed item.
    ///
    /// The `item` parameter contains the value that determines how to parse
    /// the current value from the parser.
    fn parse(item: T, parser: &mut Parser<'a>) -> ParseResult<Self>;
}

/// A trait for types that can be written based on a `DEFINED BY` value.
///
/// `T` is the type of the `DEFINED BY` field (nearly always `ObjectIdentifier`).
pub trait Asn1DefinedByWritable<T: Asn1Writable>: Sized {
    /// Get a reference to the `DEFINED BY` value.
    fn item(&self) -> &T;

    /// Write this value to the given writer.
    fn write(&self, dest: &mut Writer<'_>) -> WriteResult;

    /// Get the complete encoded length (tag + length + content), if it can be
    /// calculated efficiently.
    ///
    /// It is always safe to return `None`, which indicates the length is
    /// unknown. Returning `Some(...)` from this method reduces the number of
    /// re-allocations required in writing.
    fn encoded_length(&self) -> Option<usize>;
}

impl<T: SimpleAsn1Writable> Asn1Writable for T {
    #[inline]
    fn write(&self, w: &mut Writer<'_>) -> WriteResult {
        w.write_tlv(Self::TAG, self.data_length(), move |dest| {
            self.write_data(dest)
        })
    }

    fn encoded_length(&self) -> Option<usize> {
        Some(Tlv::full_length(Self::TAG, self.data_length()?))
    }
}

impl<T: SimpleAsn1Writable> SimpleAsn1Writable for &T {
    const TAG: Tag = T::TAG;
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        T::write_data(self, dest)
    }

    fn data_length(&self) -> Option<usize> {
        T::data_length(self)
    }
}

impl<T: SimpleAsn1Writable> SimpleAsn1Writable for Box<T> {
    const TAG: Tag = T::TAG;
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        T::write_data(self, dest)
    }

    fn data_length(&self) -> Option<usize> {
        T::data_length(self)
    }
}

/// A TLV (type, length, value) represented as the tag and bytes content.
/// Generally used for parsing ASN.1 `ANY` values.
#[derive(Debug, PartialEq, Hash, Clone, Copy, Eq)]
pub struct Tlv<'a> {
    pub(crate) tag: Tag,
    // `data` is the value of a TLV
    pub(crate) data: &'a [u8],
    // `full_data` contains the encoded type and length, in addition to the
    // value
    pub(crate) full_data: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub(crate) fn full_length(t: Tag, inner_length: usize) -> usize {
        t.encoded_length() + crate::writer::length_encoding_size(inner_length) + inner_length
    }

    /// The tag portion of a TLV.
    pub fn tag(&self) -> Tag {
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
    #[inline]
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        parser.read_tlv()
    }

    #[inline]
    fn can_parse(_tag: Tag) -> bool {
        true
    }
}
impl Asn1Writable for Tlv<'_> {
    #[inline]
    fn write(&self, w: &mut Writer<'_>) -> WriteResult {
        w.write_tlv(self.tag, Some(self.data.len()), move |dest| {
            dest.push_slice(self.data)
        })
    }

    fn encoded_length(&self) -> Option<usize> {
        Some(Tlv::full_length(self.tag, self.data.len()))
    }
}

impl Asn1Writable for &Tlv<'_> {
    #[inline]
    fn write(&self, w: &mut Writer<'_>) -> WriteResult {
        Tlv::write(self, w)
    }

    fn encoded_length(&self) -> Option<usize> {
        Tlv::encoded_length(self)
    }
}

/// The ASN.1 NULL type, for use with `Parser.read_element` and
/// `Writer.write_element`.
pub type Null = ();

impl SimpleAsn1Readable<'_> for Null {
    const TAG: Tag = Tag::primitive(0x05);
    #[inline]
    fn parse_data(data: &[u8]) -> ParseResult<Null> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(ParseError::new(ParseErrorKind::InvalidValue))
        }
    }
}

impl SimpleAsn1Writable for Null {
    const TAG: Tag = Tag::primitive(0x05);
    #[inline]
    fn write_data(&self, _dest: &mut WriteBuf) -> WriteResult {
        Ok(())
    }

    fn data_length(&self) -> Option<usize> {
        Some(0)
    }
}

impl SimpleAsn1Readable<'_> for bool {
    const TAG: Tag = Tag::primitive(0x1);
    fn parse_data(data: &[u8]) -> ParseResult<bool> {
        match data {
            b"\x00" => Ok(false),
            b"\xff" => Ok(true),
            _ => Err(ParseError::new(ParseErrorKind::InvalidValue)),
        }
    }
}

impl SimpleAsn1Writable for bool {
    const TAG: Tag = Tag::primitive(0x1);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        if *self {
            dest.push_byte(0xff)
        } else {
            dest.push_byte(0x00)
        }
    }

    fn data_length(&self) -> Option<usize> {
        Some(1)
    }
}

impl<'a> SimpleAsn1Readable<'a> for &'a [u8] {
    const TAG: Tag = Tag::primitive(0x04);
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        Ok(data)
    }
}

impl SimpleAsn1Writable for &[u8] {
    const TAG: Tag = Tag::primitive(0x04);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self)
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl<const N: usize> SimpleAsn1Readable<'_> for [u8; N] {
    const TAG: Tag = Tag::primitive(0x04);
    fn parse_data(data: &[u8]) -> ParseResult<[u8; N]> {
        data.try_into()
            .map_err(|_| ParseError::new(ParseErrorKind::InvalidValue))
    }
}

impl<const N: usize> SimpleAsn1Writable for [u8; N] {
    const TAG: Tag = Tag::primitive(0x04);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self)
    }

    fn data_length(&self) -> Option<usize> {
        Some(N)
    }
}

/// Represents values that are encoded as an `OCTET STRING` containing an
/// encoded TLV, of type `T`.
#[derive(PartialEq, Eq, Debug)]
pub struct OctetStringEncoded<T>(T);

impl<T> OctetStringEncoded<T> {
    pub fn new(v: T) -> OctetStringEncoded<T> {
        OctetStringEncoded(v)
    }

    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'a, T: Asn1Readable<'a>> SimpleAsn1Readable<'a> for OctetStringEncoded<T> {
    const TAG: Tag = Tag::primitive(0x04);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(OctetStringEncoded::new(parse_single(data)?))
    }
}

impl<T: Asn1Writable> SimpleAsn1Writable for OctetStringEncoded<T> {
    const TAG: Tag = Tag::primitive(0x04);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        self.0.write(&mut Writer::new(dest))
    }

    fn data_length(&self) -> Option<usize> {
        self.0.encoded_length()
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `PrintableString`.  A `PrintableString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    const TAG: Tag = Tag::primitive(0x13);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        PrintableString::new_from_bytes(data)
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}

impl SimpleAsn1Writable for PrintableString<'_> {
    const TAG: Tag = Tag::primitive(0x13);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `IA5String`.  An `IA5String` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IA5String<'a>(&'a str);

impl<'a> IA5String<'a> {
    pub fn new(s: &'a str) -> Option<IA5String<'a>> {
        if IA5String::verify(s.as_bytes()) {
            Some(IA5String(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<IA5String<'a>> {
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
    const TAG: Tag = Tag::primitive(0x16);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        IA5String::new_from_bytes(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for IA5String<'_> {
    const TAG: Tag = Tag::primitive(0x16);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `UTF8String`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Utf8String<'a>(&'a str);

impl<'a> Utf8String<'a> {
    pub fn new(s: &'a str) -> Utf8String<'a> {
        Utf8String(s)
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<Utf8String<'a>> {
        Some(Utf8String(core::str::from_utf8(s).ok()?))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for Utf8String<'a> {
    const TAG: Tag = Tag::primitive(0x0c);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Utf8String::new_from_bytes(data)
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for Utf8String<'_> {
    const TAG: Tag = Tag::primitive(0x0c);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `VisibleString`.  An `VisibleString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleString<'a>(&'a str);

impl<'a> VisibleString<'a> {
    pub fn new(s: &'a str) -> Option<VisibleString<'a>> {
        if VisibleString::verify(s.as_bytes()) {
            Some(VisibleString(s))
        } else {
            None
        }
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<VisibleString<'a>> {
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
    const TAG: Tag = Tag::primitive(0x1a);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        VisibleString::new_from_bytes(data)
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for VisibleString<'_> {
    const TAG: Tag = Tag::primitive(0x1a);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `BMPString`. A `BMPString` contains encoded (UTF-16-BE)
/// bytes which are known to be valid.
#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct BMPString<'a>(&'a [u8]);

impl<'a> BMPString<'a> {
    pub fn new(b: &'a [u8]) -> Option<BMPString<'a>> {
        if BMPString::verify(b) {
            Some(BMPString(b))
        } else {
            None
        }
    }

    fn verify(b: &[u8]) -> bool {
        if b.len() % 2 == 1 {
            return false;
        }

        for r in core::char::decode_utf16(
            b.chunks_exact(2)
                .map(|v| u16::from_be_bytes(v.try_into().unwrap())),
        ) {
            if r.is_err() {
                return false;
            }
        }

        true
    }

    pub fn as_utf16_be_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for BMPString<'a> {
    const TAG: Tag = Tag::primitive(0x1e);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        BMPString::new(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for BMPString<'_> {
    const TAG: Tag = Tag::primitive(0x1e);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_utf16_be_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_utf16_be_bytes().len())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `UniversalString`. A `UniversalString` contains encoded
/// (UTF-32-BE) bytes which are known to be valid.
#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct UniversalString<'a>(&'a [u8]);

impl<'a> UniversalString<'a> {
    pub fn new(b: &'a [u8]) -> Option<UniversalString<'a>> {
        if UniversalString::verify(b) {
            Some(UniversalString(b))
        } else {
            None
        }
    }

    fn verify(b: &[u8]) -> bool {
        if b.len() % 4 != 0 {
            return false;
        }

        for r in b
            .chunks_exact(4)
            .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
        {
            if core::char::from_u32(r).is_none() {
                return false;
            }
        }

        true
    }

    pub fn as_utf32_be_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for UniversalString<'a> {
    const TAG: Tag = Tag::primitive(0x1c);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        UniversalString::new(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for UniversalString<'_> {
    const TAG: Tag = Tag::primitive(0x1c);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_utf32_be_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_utf32_be_bytes().len())
    }
}

const fn validate_integer(data: &[u8], signed: bool) -> ParseResult<()> {
    if data.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }
    // Ensure integer is minimally encoded
    if data.len() > 1
        && ((data[0] == 0 && data[1] & 0x80 == 0) || (data[0] == 0xff && data[1] & 0x80 == 0x80))
    {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }

    // Reject negatives for unsigned types.
    if !signed && data[0] & 0x80 == 0x80 {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }

    Ok(())
}

macro_rules! impl_asn1_element_for_int {
    ($t:ty; $signed:expr) => {
        impl SimpleAsn1Readable<'_> for $t {
            const TAG: Tag = Tag::primitive(0x02);
            #[inline]
            fn parse_data(mut data: &[u8]) -> ParseResult<Self> {
                validate_integer(data, $signed)?;

                // If we've got something like \x00\xff trim off the first \x00, since it's just
                // there to not mark the value as a negative.
                if !$signed && data.len() == mem::size_of::<Self>() + 1 && data[0] == 0 {
                    data = &data[1..];
                }
                if data.len() > mem::size_of::<Self>() {
                    return Err(ParseError::new(ParseErrorKind::IntegerOverflow));
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
        impl SimpleAsn1Writable for $t {
            const TAG: Tag = Tag::primitive(0x02);
            fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
                let num_bytes = self.data_length().unwrap() as u32;

                for i in (1..=num_bytes).rev() {
                    let digit = self.checked_shr((i - 1) * 8).unwrap_or(0);
                    dest.push_byte(digit as u8)?;
                }
                Ok(())
            }

            fn data_length(&self) -> Option<usize> {
                let mut num_bytes = 1;
                let mut v: $t = *self;
                #[allow(unused_comparisons)]
                while v > 127 || ($signed && v < (-128i64) as $t) {
                    num_bytes += 1;
                    v = v.checked_shr(8).unwrap_or(0);
                }
                Some(num_bytes)
            }
        }
    };
}

impl_asn1_element_for_int!(i8; true);
impl_asn1_element_for_int!(u8; false);
impl_asn1_element_for_int!(i16; true);
impl_asn1_element_for_int!(u16; false);
impl_asn1_element_for_int!(i32; true);
impl_asn1_element_for_int!(u32; false);
impl_asn1_element_for_int!(i64; true);
impl_asn1_element_for_int!(u64; false);

/// Arbitrary sized unsigned integer. Contents may be accessed as `&[u8]` of
/// big-endian data. Its contents always match the DER encoding of a value
/// (i.e. they are minimal)
#[derive(PartialEq, Clone, Copy, Debug, Hash, Eq)]
pub struct BigUint<'a> {
    data: &'a [u8],
}

impl<'a> BigUint<'a> {
    /// Create a new `BigUint` from already encoded data. `data` must be encoded
    /// as required by DER: minimally and if the high bit would be set in the
    /// first octet, a leading `\x00` should be prepended (to disambiguate from
    /// negative values).
    pub const fn new(data: &'a [u8]) -> Option<Self> {
        match validate_integer(data, false) {
            Ok(()) => Some(BigUint { data }),
            Err(_) => None,
        }
    }

    /// Returns the contents of the integer as big-endian bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> SimpleAsn1Readable<'a> for BigUint<'a> {
    const TAG: Tag = Tag::primitive(0x02);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        BigUint::new(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for BigUint<'_> {
    const TAG: Tag = Tag::primitive(0x02);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_bytes().len())
    }
}

/// Arbitrary sized unsigned integer which owns its data. Contents may be
/// accessed as `&[u8]` of big-endian data. Its contents always match the DER
/// encoding of a value (i.e. they are minimal)
#[derive(PartialEq, Clone, Debug, Hash, Eq)]
pub struct OwnedBigUint {
    data: Vec<u8>,
}

impl OwnedBigUint {
    /// Create a new `OwnedBigUint` from already encoded data. `data` must be
    /// encoded as required by DER: minimally and if the high bit would be set
    /// in the first octet, a leading `\x00` should be prepended (to
    /// disambiguate from negative values).
    pub fn new(data: Vec<u8>) -> Option<Self> {
        validate_integer(&data, false).ok()?;
        Some(OwnedBigUint { data })
    }

    /// Returns the contents of the integer as big-endian bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl SimpleAsn1Readable<'_> for OwnedBigUint {
    const TAG: Tag = Tag::primitive(0x02);
    fn parse_data(data: &[u8]) -> ParseResult<Self> {
        OwnedBigUint::new(data.to_vec())
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for OwnedBigUint {
    const TAG: Tag = Tag::primitive(0x02);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_bytes().len())
    }
}

/// Arbitrary sized signed integer. Contents may be accessed as `&[u8]` of
/// big-endian data. Its contents always match the DER encoding of a value
/// (i.e. they are minimal)
#[derive(PartialEq, Clone, Copy, Debug, Hash, Eq)]
pub struct BigInt<'a> {
    data: &'a [u8],
}

impl<'a> BigInt<'a> {
    /// Create a new `BigInt` from already encoded data. `data` must be encoded
    /// as required by DER: minimally and if the high bit would be set in the
    /// first octet, a leading `\x00` should be prepended (to disambiguate from
    /// negative values).
    pub const fn new(data: &'a [u8]) -> Option<Self> {
        match validate_integer(data, true) {
            Ok(()) => Some(BigInt { data }),
            Err(_) => None,
        }
    }

    /// Returns the contents of the integer as big-endian bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns a boolean indicating whether the integer is negative.
    pub fn is_negative(&self) -> bool {
        self.data[0] & 0x80 == 0x80
    }
}

impl<'a> SimpleAsn1Readable<'a> for BigInt<'a> {
    const TAG: Tag = Tag::primitive(0x02);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        BigInt::new(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for BigInt<'_> {
    const TAG: Tag = Tag::primitive(0x02);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_bytes().len())
    }
}

/// Arbitrary sized signed integer which owns its contents. Contents may be
/// accessed as `&[u8]` of big-endian data. Its contents always match the DER
/// encoding of a value (i.e. they are minimal)
#[derive(PartialEq, Clone, Debug, Hash, Eq)]
pub struct OwnedBigInt {
    data: Vec<u8>,
}

impl OwnedBigInt {
    /// Create a new `OwnedBigInt` from already encoded data. `data` must be
    /// encoded as required by DER: minimally and if the high bit would be set
    /// in the first octet, a leading `\x00` should be prepended (to
    /// disambiguate from negative values).
    pub fn new(data: Vec<u8>) -> Option<Self> {
        validate_integer(&data, true).ok()?;
        Some(OwnedBigInt { data })
    }

    /// Returns the contents of the integer as big-endian bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns a boolean indicating whether the integer is negative.
    pub fn is_negative(&self) -> bool {
        self.data[0] & 0x80 == 0x80
    }
}

impl SimpleAsn1Readable<'_> for OwnedBigInt {
    const TAG: Tag = Tag::primitive(0x02);
    fn parse_data(data: &[u8]) -> ParseResult<Self> {
        OwnedBigInt::new(data.to_vec()).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for OwnedBigInt {
    const TAG: Tag = Tag::primitive(0x02);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.as_bytes().len())
    }
}

impl<'a> SimpleAsn1Readable<'a> for ObjectIdentifier {
    const TAG: Tag = Tag::primitive(0x06);
    fn parse_data(data: &'a [u8]) -> ParseResult<ObjectIdentifier> {
        ObjectIdentifier::from_der(data)
    }
}
impl SimpleAsn1Writable for ObjectIdentifier {
    const TAG: Tag = Tag::primitive(0x06);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.as_der())
    }
    fn data_length(&self) -> Option<usize> {
        Some(self.as_der().len())
    }
}

impl<'a> SimpleAsn1Readable<'a> for BitString<'a> {
    const TAG: Tag = Tag::primitive(0x03);
    fn parse_data(data: &'a [u8]) -> ParseResult<BitString<'a>> {
        if data.is_empty() {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        BitString::new(&data[1..], data[0])
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}
impl SimpleAsn1Writable for BitString<'_> {
    const TAG: Tag = Tag::primitive(0x03);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_byte(self.padding_bits())?;
        dest.push_slice(self.as_bytes())
    }

    fn data_length(&self) -> Option<usize> {
        Some(1 + self.as_bytes().len())
    }
}
impl<'a> SimpleAsn1Readable<'a> for OwnedBitString {
    const TAG: Tag = Tag::primitive(0x03);
    fn parse_data(data: &'a [u8]) -> ParseResult<OwnedBitString> {
        let bs = BitString::parse_data(data)?;
        Ok(OwnedBitString::new(bs.as_bytes().to_vec(), bs.padding_bits()).unwrap())
    }
}
impl SimpleAsn1Writable for OwnedBitString {
    const TAG: Tag = Tag::primitive(0x03);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        self.as_bitstring().write_data(dest)
    }

    fn data_length(&self) -> Option<usize> {
        self.as_bitstring().data_length()
    }
}

fn read_byte(data: &mut &[u8]) -> ParseResult<u8> {
    if data.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }
    let result = Ok(data[0]);
    *data = &data[1..];
    result
}

fn read_digit(data: &mut &[u8]) -> ParseResult<u8> {
    let b = read_byte(data)?;
    if !b.is_ascii_digit() {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }
    Ok(b - b'0')
}

fn read_2_digits(data: &mut &[u8]) -> ParseResult<u8> {
    Ok(read_digit(data)? * 10 + read_digit(data)?)
}

fn read_4_digits(data: &mut &[u8]) -> ParseResult<u16> {
    Ok(u16::from(read_digit(data)?) * 1000
        + u16::from(read_digit(data)?) * 100
        + u16::from(read_digit(data)?) * 10
        + u16::from(read_digit(data)?))
}

const fn validate_date(year: u16, month: u8, day: u8) -> ParseResult<()> {
    if day < 1 {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => return Err(ParseError::new(ParseErrorKind::InvalidValue)),
    };
    if day > days_in_month {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }

    Ok(())
}

fn read_tz_and_finish(data: &mut &[u8]) -> ParseResult<()> {
    if read_byte(data)? != b'Z' {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }

    if !data.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidValue));
    }
    Ok(())
}

fn push_two_digits(dest: &mut WriteBuf, val: u8) -> WriteResult {
    dest.push_byte(b'0' + ((val / 10) % 10))?;
    dest.push_byte(b'0' + (val % 10))
}

fn push_four_digits(dest: &mut WriteBuf, val: u16) -> WriteResult {
    dest.push_byte(b'0' + ((val / 1000) % 10) as u8)?;
    dest.push_byte(b'0' + ((val / 100) % 10) as u8)?;
    dest.push_byte(b'0' + ((val / 10) % 10) as u8)?;
    dest.push_byte(b'0' + (val % 10) as u8)
}

/// A structure representing a (UTC timezone) date and time.
/// Wrapped by `UtcTime` and `X509GeneralizedTime` and used in
/// `GeneralizedTime`.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd)]
pub struct DateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl DateTime {
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> ParseResult<DateTime> {
        if hour > 23 || minute > 59 || second > 59 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        match validate_date(year, month, day) {
            Ok(()) => Ok(DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
            }),
            Err(e) => Err(e),
        }
    }

    /// The calendar year.
    pub fn year(&self) -> u16 {
        self.year
    }

    /// The calendar month (1 to 12).
    pub fn month(&self) -> u8 {
        self.month
    }

    /// The calendar day (1 to 31).
    pub fn day(&self) -> u8 {
        self.day
    }

    /// The clock hour (0 to 23).
    pub fn hour(&self) -> u8 {
        self.hour
    }

    /// The clock minute (0 to 59).
    pub fn minute(&self) -> u8 {
        self.minute
    }

    /// The clock second (0 to 59).
    pub fn second(&self) -> u8 {
        self.second
    }
}

/// Used for parsing and writing ASN.1 `UTC TIME` values. Wraps a
/// `DateTime`.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct UtcTime(DateTime);

impl UtcTime {
    pub fn new(dt: DateTime) -> ParseResult<UtcTime> {
        if dt.year() < 1950 || dt.year() >= 2050 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        Ok(UtcTime(dt))
    }

    pub fn as_datetime(&self) -> &DateTime {
        &self.0
    }
}

impl SimpleAsn1Readable<'_> for UtcTime {
    const TAG: Tag = Tag::primitive(0x17);
    fn parse_data(mut data: &[u8]) -> ParseResult<Self> {
        let year = u16::from(read_2_digits(&mut data)?);
        let month = read_2_digits(&mut data)?;
        let day = read_2_digits(&mut data)?;
        // UTCTime only encodes times prior to 2050. We use the X.509 mapping of two-digit
        // year ordinals to full year:
        // https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
        let year = if year >= 50 { 1900 + year } else { 2000 + year };
        let hour = read_2_digits(&mut data)?;
        let minute = read_2_digits(&mut data)?;
        let second = read_2_digits(&mut data)?;

        read_tz_and_finish(&mut data)?;

        UtcTime::new(DateTime::new(year, month, day, hour, minute, second)?)
    }
}

impl SimpleAsn1Writable for UtcTime {
    const TAG: Tag = Tag::primitive(0x17);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let dt = self.as_datetime();
        let year = if 1950 <= dt.year() && dt.year() < 2000 {
            dt.year() - 1900
        } else {
            assert!(2000 <= dt.year() && dt.year() < 2050);
            dt.year() - 2000
        };
        push_two_digits(dest, year.try_into().unwrap())?;
        push_two_digits(dest, dt.month())?;
        push_two_digits(dest, dt.day())?;

        push_two_digits(dest, dt.hour())?;
        push_two_digits(dest, dt.minute())?;
        push_two_digits(dest, dt.second())?;

        dest.push_byte(b'Z')
    }

    fn data_length(&self) -> Option<usize> {
        Some(13)
    }
}

/// Used for parsing and writing ASN.1 `GENERALIZED TIME` values used in X.509.
/// Wraps a `DateTime`.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct X509GeneralizedTime(DateTime);

impl X509GeneralizedTime {
    pub fn new(dt: DateTime) -> ParseResult<X509GeneralizedTime> {
        Ok(X509GeneralizedTime(dt))
    }

    pub fn as_datetime(&self) -> &DateTime {
        &self.0
    }
}

impl SimpleAsn1Readable<'_> for X509GeneralizedTime {
    const TAG: Tag = Tag::primitive(0x18);
    fn parse_data(mut data: &[u8]) -> ParseResult<X509GeneralizedTime> {
        let year = read_4_digits(&mut data)?;
        let month = read_2_digits(&mut data)?;
        let day = read_2_digits(&mut data)?;
        let hour = read_2_digits(&mut data)?;
        let minute = read_2_digits(&mut data)?;
        let second = read_2_digits(&mut data)?;

        // Fractionals are forbidden (RFC5280)

        read_tz_and_finish(&mut data)?;

        X509GeneralizedTime::new(DateTime::new(year, month, day, hour, minute, second)?)
    }
}

impl SimpleAsn1Writable for X509GeneralizedTime {
    const TAG: Tag = Tag::primitive(0x18);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let dt = self.as_datetime();
        push_four_digits(dest, dt.year())?;
        push_two_digits(dest, dt.month())?;
        push_two_digits(dest, dt.day())?;

        push_two_digits(dest, dt.hour())?;
        push_two_digits(dest, dt.minute())?;
        push_two_digits(dest, dt.second())?;

        dest.push_byte(b'Z')
    }

    fn data_length(&self) -> Option<usize> {
        Some(15) // YYYYMMDDHHMMSSZ
    }
}

/// Used for parsing and writing ASN.1 `GENERALIZED TIME` values,
/// including values with fractional seconds of up to nanosecond
/// precision.
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Eq)]
pub struct GeneralizedTime {
    datetime: DateTime,
    nanoseconds: Option<u32>,
}

impl GeneralizedTime {
    pub fn new(dt: DateTime, nanoseconds: Option<u32>) -> ParseResult<GeneralizedTime> {
        if let Some(val) = nanoseconds {
            if val < 1 || val >= 1e9 as u32 {
                return Err(ParseError::new(ParseErrorKind::InvalidValue));
            }
        }

        Ok(GeneralizedTime {
            datetime: dt,
            nanoseconds,
        })
    }

    pub fn as_datetime(&self) -> &DateTime {
        &self.datetime
    }

    pub fn nanoseconds(&self) -> Option<u32> {
        self.nanoseconds
    }
}

fn read_fractional_time(data: &mut &[u8]) -> ParseResult<Option<u32>> {
    // We cannot use read_byte here because it will advance the pointer
    // However, we know that the is suffixed by 'Z' so reading into an empty
    // data should lead to an error.
    if data.first() == Some(&b'.') {
        *data = &data[1..];

        let mut fraction = 0u32;
        let mut digits = 0;
        // Read up to 9 digits
        for b in data.iter().take(9) {
            if !b.is_ascii_digit() {
                if digits == 0 {
                    // We must have at least one digit
                    return Err(ParseError::new(ParseErrorKind::InvalidValue));
                }
                break;
            }
            fraction = fraction * 10 + (b - b'0') as u32;
            digits += 1;
        }
        *data = &data[digits..];

        // No trailing zero
        if fraction % 10 == 0 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }

        // Now let scale up in nanoseconds
        let nanoseconds: u32 = fraction * 10u32.pow(9 - digits as u32);
        Ok(Some(nanoseconds))
    } else {
        Ok(None)
    }
}

impl SimpleAsn1Readable<'_> for GeneralizedTime {
    const TAG: Tag = Tag::primitive(0x18);
    fn parse_data(mut data: &[u8]) -> ParseResult<GeneralizedTime> {
        let year = read_4_digits(&mut data)?;
        let month = read_2_digits(&mut data)?;
        let day = read_2_digits(&mut data)?;
        let hour = read_2_digits(&mut data)?;
        let minute = read_2_digits(&mut data)?;
        let second = read_2_digits(&mut data)?;

        let fraction = read_fractional_time(&mut data)?;
        read_tz_and_finish(&mut data)?;

        GeneralizedTime::new(
            DateTime::new(year, month, day, hour, minute, second)?,
            fraction,
        )
    }
}

impl SimpleAsn1Writable for GeneralizedTime {
    const TAG: Tag = Tag::primitive(0x18);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let dt = self.as_datetime();
        push_four_digits(dest, dt.year())?;
        push_two_digits(dest, dt.month())?;
        push_two_digits(dest, dt.day())?;

        push_two_digits(dest, dt.hour())?;
        push_two_digits(dest, dt.minute())?;
        push_two_digits(dest, dt.second())?;

        if let Some(nanoseconds) = self.nanoseconds() {
            dest.push_byte(b'.')?;

            let mut buf = itoa::Buffer::new();
            let nanos = buf.format(nanoseconds);
            let pad = 9 - nanos.len();
            let nanos = nanos.trim_end_matches('0');

            for _ in 0..pad {
                dest.push_byte(b'0')?;
            }

            dest.push_slice(nanos.as_bytes())?;
        }

        dest.push_byte(b'Z')
    }

    fn data_length(&self) -> Option<usize> {
        let base_len = 15; // YYYYMMDDHHMMSSZ
        if let Some(nanoseconds) = self.nanoseconds() {
            let mut buf = itoa::Buffer::new();
            let nanos = buf.format(nanoseconds);
            let pad = 9 - nanos.len();
            let nanos = nanos.trim_end_matches('0');
            Some(base_len + 1 + pad + nanos.len()) // . + padded nanos
        } else {
            Some(base_len)
        }
    }
}

/// An ASN.1 `ENUMERATED` value.
#[derive(Debug, PartialEq, Eq)]
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
    const TAG: Tag = Tag::primitive(0xa);

    fn parse_data(data: &'a [u8]) -> ParseResult<Enumerated> {
        Ok(Enumerated::new(u32::parse_data(data)?))
    }
}

impl SimpleAsn1Writable for Enumerated {
    const TAG: Tag = Tag::primitive(0xa);

    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        u32::write_data(&self.value(), dest)
    }

    fn data_length(&self) -> Option<usize> {
        self.value().data_length()
    }
}

impl<'a, T: Asn1Readable<'a>> Asn1Readable<'a> for Option<T> {
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        match parser.peek_tag() {
            Some(tag) if Self::can_parse(tag) => Ok(Some(parser.read_element::<T>()?)),
            Some(_) | None => Ok(None),
        }
    }

    #[inline]
    fn can_parse(tag: Tag) -> bool {
        T::can_parse(tag)
    }
}

impl<T: Asn1Writable> Asn1Writable for Option<T> {
    #[inline]
    fn write(&self, w: &mut Writer<'_>) -> WriteResult {
        if let Some(v) = self {
            w.write_element(v)
        } else {
            Ok(())
        }
    }

    fn encoded_length(&self) -> Option<usize> {
        match self {
            Some(v) => v.encoded_length(),
            None => Some(0),
        }
    }
}

macro_rules! declare_choice {
    ($count:ident => $(($number:ident $name:ident)),+) => {
        /// Represents an ASN.1 `CHOICE` with the provided number of potential
        /// types.
        ///
        /// If you need more variants than are provided, please file an issue
        /// or submit a pull request! Arbitrary numbers of variants are
        /// supported by the `#[derive(asn1::Asn1Read)]` and
        /// `#[derive(asn1::Asn1Write)]` APIs.
        #[derive(Debug, PartialEq, Eq)]
        pub enum $count<
            $($number,)+
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
        > Asn1Readable<'a> for $count<$($number,)+> {
            fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
                let tlv = parser.read_tlv()?;
                $(
                    if $number::can_parse(tlv.tag()) {
                        return Ok($count::$name(tlv.parse::<$number>()?));
                    }
                )+
                Err(ParseError::new(ParseErrorKind::UnexpectedTag{actual: tlv.tag()}))
            }

            fn can_parse(tag: Tag) -> bool {
                $(
                    if $number::can_parse(tag) {
                        return true;
                    }
                )+
                false
            }
        }

        impl<
            $(
                $number: Asn1Writable,
            )+
        > Asn1Writable for $count<$($number,)+> {
            fn write(&self, w: &mut Writer<'_>) -> WriteResult {
                match self {
                    $(
                        $count::$name(v) => w.write_element(v),
                    )+
                }
            }

            fn encoded_length(&self) -> Option<usize> {
                match self {
                    $(
                        $count::$name(v) => Asn1Writable::encoded_length(v),
                    )+
                }
            }
        }
    }
}

declare_choice!(Choice1 => (T1 ChoiceA));
declare_choice!(Choice2 => (T1 ChoiceA), (T2 ChoiceB));
declare_choice!(Choice3 => (T1 ChoiceA), (T2 ChoiceB), (T3 ChoiceC));

/// Represents an ASN.1 `SEQUENCE`.
///
/// By itself, this merely indicates a sequence of bytes that are claimed to
// form an ASN1 sequence. In almost any circumstance, you'll want to
/// immediately call `Sequence.parse` on this value to decode the actual
/// contents therein.
#[derive(Debug, PartialEq, Hash, Clone, Eq)]
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
    const TAG: Tag = Tag::constructed(0x10);
    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Sequence<'a>> {
        Ok(Sequence::new(data))
    }
}
impl SimpleAsn1Writable for Sequence<'_> {
    const TAG: Tag = Tag::constructed(0x10);
    #[inline]
    fn write_data(&self, data: &mut WriteBuf) -> WriteResult {
        data.push_slice(self.data)
    }

    fn data_length(&self) -> Option<usize> {
        Some(self.data.len())
    }
}

/// Writes an ASN.1 `SEQUENCE` using a callback that writes the inner
/// elements.
pub struct SequenceWriter<'a> {
    f: &'a dyn Fn(&mut Writer<'_>) -> WriteResult,
}

impl<'a> SequenceWriter<'a> {
    #[inline]
    pub fn new(f: &'a dyn Fn(&mut Writer<'_>) -> WriteResult) -> Self {
        SequenceWriter { f }
    }
}

impl SimpleAsn1Writable for SequenceWriter<'_> {
    const TAG: Tag = Tag::constructed(0x10);
    #[inline]
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        (self.f)(&mut Writer::new(dest))
    }

    fn data_length(&self) -> Option<usize> {
        None
    }
}

/// Represents an ASN.1 `SEQUENCE OF`. This is an `Iterator` over values that
/// are decoded.
pub struct SequenceOf<
    'a,
    T,
    const MINIMUM_LEN: usize = 0,
    const MAXIMUM_LEN: usize = { usize::MAX },
> {
    parser: Parser<'a>,
    length: usize,
    _phantom: PhantomData<T>,
}

impl<'a, T: Asn1Readable<'a>, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize>
    SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> ParseResult<SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>> {
        let length = parse(data, |p| {
            let mut i = 0;
            while !p.is_empty() {
                p.read_element::<T>()
                    .map_err(|e| e.add_location(ParseLocation::Index(i)))?;
                i += 1;
            }
            Ok(i)
        })?;

        if length < MINIMUM_LEN || length > MAXIMUM_LEN {
            return Err(ParseError::new(ParseErrorKind::InvalidSize {
                min: MINIMUM_LEN,
                max: MAXIMUM_LEN,
                actual: length,
            }));
        }

        Ok(Self {
            length,
            parser: Parser::new(data),
            _phantom: PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a, T: Asn1Readable<'a>, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize> Clone
    for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    fn clone(&self) -> SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN> {
        SequenceOf {
            parser: self.parser.clone_internal(),
            length: self.length,
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: Asn1Readable<'a> + PartialEq, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize>
    PartialEq for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
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

impl<'a, T: Asn1Readable<'a> + Eq, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize> Eq
    for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
}

impl<'a, T: Asn1Readable<'a> + Hash, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize> Hash
    for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        for val in self.clone() {
            val.hash(state);
        }
    }
}

impl<'a, T: Asn1Readable<'a> + 'a, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize>
    SimpleAsn1Readable<'a> for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    const TAG: Tag = Tag::constructed(0x10);
    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        SequenceOf::new(data)
    }
}

impl<'a, T: Asn1Readable<'a>, const MINIMUM_LEN: usize, const MAXIMUM_LEN: usize> Iterator
    for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.parser.is_empty() {
            return None;
        }
        self.length -= 1;
        Some(
            self.parser
                .read_element::<T>()
                .expect("Should always succeed"),
        )
    }
}

impl<
        'a,
        T: Asn1Readable<'a> + Asn1Writable,
        const MINIMUM_LEN: usize,
        const MAXIMUM_LEN: usize,
    > SimpleAsn1Writable for SequenceOf<'a, T, MINIMUM_LEN, MAXIMUM_LEN>
{
    const TAG: Tag = Tag::constructed(0x10);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let mut w = Writer::new(dest);
        for el in self.clone() {
            w.write_element(&el)?;
        }

        Ok(())
    }

    fn data_length(&self) -> Option<usize> {
        let iter = self.clone();
        iter.map(|el| el.encoded_length()).sum()
    }
}

/// Writes a `SEQUENCE OF` ASN.1 structure from a slice of `T`.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SequenceOfWriter<'a, T, V: Borrow<[T]> = &'a [T]> {
    vals: V,
    _phantom: PhantomData<&'a T>,
}

impl<T, V: Borrow<[T]>> SequenceOfWriter<'_, T, V> {
    pub fn new(vals: V) -> Self {
        SequenceOfWriter {
            vals,
            _phantom: PhantomData,
        }
    }
}

impl<T: Asn1Writable, V: Borrow<[T]>> SimpleAsn1Writable for SequenceOfWriter<'_, T, V> {
    const TAG: Tag = Tag::constructed(0x10);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let mut w = Writer::new(dest);
        for el in self.vals.borrow() {
            w.write_element(el)?;
        }

        Ok(())
    }

    fn data_length(&self) -> Option<usize> {
        let vals = self.vals.borrow();
        vals.iter().map(|v| v.encoded_length()).sum()
    }
}

/// Represents an ASN.1 `SET OF`. This is an `Iterator` over values that
/// are decoded.
pub struct SetOf<'a, T> {
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

impl<'a, T: Asn1Readable<'a> + Eq> Eq for SetOf<'a, T> {}

impl<'a, T: Asn1Readable<'a> + Hash> Hash for SetOf<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for val in self.clone() {
            val.hash(state);
        }
    }
}

impl<'a, T: Asn1Readable<'a> + 'a> SimpleAsn1Readable<'a> for SetOf<'a, T> {
    const TAG: Tag = Tag::constructed(0x11);

    #[inline]
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        parse(data, |p| {
            let mut last_element: Option<Tlv<'a>> = None;
            let mut i = 0;
            while !p.is_empty() {
                let el = p
                    .read_tlv()
                    .map_err(|e| e.add_location(ParseLocation::Index(i)))?;
                if let Some(last_el) = last_element {
                    if el.full_data < last_el.full_data {
                        return Err(ParseError::new(ParseErrorKind::InvalidSetOrdering)
                            .add_location(ParseLocation::Index(i)));
                    }
                }
                last_element = Some(el);
                el.parse::<T>()
                    .map_err(|e| e.add_location(ParseLocation::Index(i)))?;
                i += 1;
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

impl<'a, T: Asn1Readable<'a> + Asn1Writable> SimpleAsn1Writable for SetOf<'a, T> {
    const TAG: Tag = Tag::constructed(0x11);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let mut w = Writer::new(dest);
        // We are known to be ordered correctly because that's an invariant for
        // `self`, so we don't need to sort here.
        for el in self.clone() {
            w.write_element(&el)?;
        }

        Ok(())
    }
    fn data_length(&self) -> Option<usize> {
        let iter = self.clone();
        iter.map(|el| el.encoded_length()).sum()
    }
}

/// Writes an ASN.1 `SET OF` whose contents is a slice of `T`. This type handles
/// ensuring that the values are properly ordered when written as DER.
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SetOfWriter<'a, T, V: Borrow<[T]> = &'a [T]> {
    vals: V,
    _phantom: PhantomData<&'a T>,
}

impl<T: Asn1Writable, V: Borrow<[T]>> SetOfWriter<'_, T, V> {
    pub fn new(vals: V) -> Self {
        SetOfWriter {
            vals,
            _phantom: PhantomData,
        }
    }
}

impl<T: Asn1Writable, V: Borrow<[T]>> SimpleAsn1Writable for SetOfWriter<'_, T, V> {
    const TAG: Tag = Tag::constructed(0x11);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        let vals = self.vals.borrow();
        if vals.is_empty() {
            return Ok(());
        } else if vals.len() == 1 {
            let mut w = Writer::new(dest);
            w.write_element(&vals[0])?;
            return Ok(());
        }

        // Optimization: use the dest storage as scratch, then truncate.
        let mut data = WriteBuf::new(vec![]);
        let mut w = Writer::new(&mut data);
        // Optimization opportunity: use a SmallVec here.
        let mut spans = vec![];

        let mut pos = 0;
        for el in vals {
            w.write_element(el)?;
            let l = w.buf.len();
            spans.push(pos..l);
            pos = l;
        }
        let data = data.as_slice();
        spans.sort_by_key(|v| &data[v.clone()]);
        for span in spans {
            dest.push_slice(&data[span])?;
        }

        Ok(())
    }

    fn data_length(&self) -> Option<usize> {
        let vals = self.vals.borrow();
        vals.iter().map(|v| v.encoded_length()).sum()
    }
}

/// `Implicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `IMPLICIT`. This will generally be used with `Option` or `Choice`.
#[derive(PartialEq, Eq, Debug)]
pub struct Implicit<T, const TAG: u32> {
    inner: T,
}

impl<T, const TAG: u32> Implicit<T, { TAG }> {
    pub fn new(v: T) -> Self {
        Implicit { inner: v }
    }

    pub fn as_inner(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T, const TAG: u32> From<T> for Implicit<T, { TAG }> {
    fn from(v: T) -> Self {
        Implicit::new(v)
    }
}

impl<'a, T: SimpleAsn1Readable<'a>, const TAG: u32> SimpleAsn1Readable<'a>
    for Implicit<T, { TAG }>
{
    const TAG: Tag = crate::implicit_tag(TAG, T::TAG);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(Implicit::new(T::parse_data(data)?))
    }
}

impl<T: SimpleAsn1Writable, const TAG: u32> SimpleAsn1Writable for Implicit<T, { TAG }> {
    const TAG: Tag = crate::implicit_tag(TAG, T::TAG);

    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        self.inner.write_data(dest)
    }

    fn data_length(&self) -> Option<usize> {
        self.inner.data_length()
    }
}

/// `Explicit` is a type which wraps another ASN.1 type, indicating that the tag is an ASN.1
/// `EXPLICIT`. This will generally be used with `Option` or `Choice`.
#[derive(PartialEq, Eq, Debug)]
pub struct Explicit<T, const TAG: u32> {
    inner: T,
}

impl<T, const TAG: u32> Explicit<T, { TAG }> {
    pub fn new(v: T) -> Self {
        Explicit { inner: v }
    }

    pub fn as_inner(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T, const TAG: u32> From<T> for Explicit<T, { TAG }> {
    fn from(v: T) -> Self {
        Explicit::new(v)
    }
}

impl<'a, T: Asn1Readable<'a>, const TAG: u32> SimpleAsn1Readable<'a> for Explicit<T, { TAG }> {
    const TAG: Tag = crate::explicit_tag(TAG);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        Ok(Explicit::new(parse(data, Parser::read_element::<T>)?))
    }
}

impl<T: Asn1Writable, const TAG: u32> SimpleAsn1Writable for Explicit<T, { TAG }> {
    const TAG: Tag = crate::explicit_tag(TAG);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        Writer::new(dest).write_element(&self.inner)
    }
    fn data_length(&self) -> Option<usize> {
        self.inner.encoded_length()
    }
}

impl<'a, T: Asn1Readable<'a>, U: Asn1DefinedByReadable<'a, T>, const TAG: u32>
    Asn1DefinedByReadable<'a, T> for Explicit<U, { TAG }>
{
    fn parse(item: T, parser: &mut Parser<'a>) -> ParseResult<Self> {
        let tlv = parser.read_element::<Explicit<Tlv<'_>, TAG>>()?;
        Ok(Explicit::new(parse(tlv.as_inner().full_data(), |p| {
            U::parse(item, p)
        })?))
    }
}

impl<T: Asn1Writable, U: Asn1DefinedByWritable<T>, const TAG: u32> Asn1DefinedByWritable<T>
    for Explicit<U, { TAG }>
{
    fn item(&self) -> &T {
        self.as_inner().item()
    }
    fn write(&self, dest: &mut Writer<'_>) -> WriteResult {
        dest.write_tlv(
            crate::explicit_tag(TAG),
            self.as_inner().encoded_length(),
            |dest| self.as_inner().write(&mut Writer::new(dest)),
        )
    }
    fn encoded_length(&self) -> Option<usize> {
        let inner_len = self.as_inner().encoded_length()?;
        Some(Tlv::full_length(crate::explicit_tag(TAG), inner_len))
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct DefinedByMarker<T>(core::marker::PhantomData<T>);

impl<T> DefinedByMarker<T> {
    pub const fn marker() -> DefinedByMarker<T> {
        DefinedByMarker(core::marker::PhantomData)
    }
}

impl<'a, T: Asn1Readable<'a>> Asn1Readable<'a> for DefinedByMarker<T> {
    fn parse(_: &mut Parser<'a>) -> ParseResult<Self> {
        panic!("parse() should never be called on a DefinedByMarker")
    }
    fn can_parse(_: Tag) -> bool {
        panic!("can_parse() should never be called on a DefinedByMarker")
    }
}

impl<T: Asn1Writable> Asn1Writable for DefinedByMarker<T> {
    fn write(&self, _: &mut Writer<'_>) -> WriteResult {
        panic!("write() should never be called on a DefinedByMarker")
    }

    fn encoded_length(&self) -> Option<usize> {
        panic!("encoded_length() shoudl never be called on a DefinedByMarker")
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        parse_single, Asn1Readable, Asn1Writable, BigInt, BigUint, DateTime, DefinedByMarker,
        Enumerated, GeneralizedTime, IA5String, ObjectIdentifier, OctetStringEncoded, OwnedBigInt,
        OwnedBigUint, ParseError, ParseErrorKind, PrintableString, SequenceOf, SequenceOfWriter,
        SetOf, SetOfWriter, Tag, Tlv, UtcTime, Utf8String, VisibleString, X509GeneralizedTime,
    };
    use crate::{Explicit, Implicit};
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use core::hash::{Hash, Hasher};
    #[cfg(feature = "std")]
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn test_octet_string_encoded() {
        assert_eq!(OctetStringEncoded::new(12).get(), &12);
        assert_eq!(OctetStringEncoded::new(12).into_inner(), 12);
    }

    #[test]
    fn test_printable_string_new() {
        assert!(PrintableString::new("abc").is_some());
        assert!(PrintableString::new("").is_some());
        assert!(PrintableString::new(" ").is_some());
        assert!(PrintableString::new("%").is_none());
        assert!(PrintableString::new("\x00").is_none());
    }

    #[test]
    fn test_printable_string_as_str() {
        assert_eq!(PrintableString::new("abc").unwrap().as_str(), "abc");
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
    fn test_ia5string_as_str() {
        assert_eq!(IA5String::new("abc").unwrap().as_str(), "abc");
    }

    #[test]
    fn test_utf8string_as_str() {
        assert_eq!(Utf8String::new("abc").as_str(), "abc");
    }

    #[test]
    fn test_visiblestring_new() {
        assert!(VisibleString::new("").is_some());
        assert!(VisibleString::new("abc").is_some());
        assert!(VisibleString::new("\n").is_none());
    }

    #[test]
    fn test_visiblestring_as_str() {
        assert_eq!(VisibleString::new("abc").unwrap().as_str(), "abc");
    }

    #[test]
    fn test_tlv_data() {
        let tlv = parse_single::<Tlv<'_>>(b"\x01\x03abc").unwrap();
        assert_eq!(tlv.data(), b"abc");
    }

    #[test]
    fn test_tlv_full_data() {
        let tlv = parse_single::<Tlv<'_>>(b"\x01\x03abc").unwrap();
        assert_eq!(tlv.full_data(), b"\x01\x03abc");
    }

    #[test]
    fn test_tlv_parse() {
        let tlv = Tlv {
            tag: Tag::primitive(0x2),
            data: b"\x03",
            full_data: b"\x02\x01\x03",
        };
        assert_eq!(tlv.parse::<u64>(), Ok(3));
        assert_eq!(
            tlv.parse::<&[u8]>(),
            Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: Tag::primitive(0x2)
            }))
        );
    }

    #[test]
    fn test_biguint_as_bytes() {
        assert_eq!(BigUint::new(b"\x01").unwrap().as_bytes(), b"\x01");
        assert_eq!(
            OwnedBigUint::new(b"\x01".to_vec()).unwrap().as_bytes(),
            b"\x01"
        );
    }

    #[test]
    fn test_bigint_as_bytes() {
        assert_eq!(BigInt::new(b"\x01").unwrap().as_bytes(), b"\x01");
        assert_eq!(
            OwnedBigInt::new(b"\x01".to_vec()).unwrap().as_bytes(),
            b"\x01"
        );
    }

    #[test]
    fn test_bigint_is_negative() {
        assert!(!BigInt::new(b"\x01").unwrap().is_negative()); // 1
        assert!(!BigInt::new(b"\x00").unwrap().is_negative()); // 0
        assert!(BigInt::new(b"\xff").unwrap().is_negative()); // -1

        assert!(!OwnedBigInt::new(b"\x01".to_vec()).unwrap().is_negative()); // 1
        assert!(!OwnedBigInt::new(b"\x00".to_vec()).unwrap().is_negative()); // 0
        assert!(OwnedBigInt::new(b"\xff".to_vec()).unwrap().is_negative()); // -1
    }

    #[test]
    fn test_sequence_of_clone() {
        let mut seq1 =
            parse_single::<SequenceOf<'_, u64>>(b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03")
                .unwrap();
        assert_eq!(seq1.next(), Some(1));
        let seq2 = seq1.clone();
        assert_eq!(seq1.collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(seq2.collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn test_sequence_of_len() {
        let mut seq1 =
            parse_single::<SequenceOf<'_, u64>>(b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03")
                .unwrap();
        let seq2 = seq1.clone();

        assert_eq!(seq1.len(), 3);
        assert!(seq1.next().is_some());
        assert_eq!(seq1.len(), 2);
        assert_eq!(seq2.len(), 3);
        assert!(seq1.next().is_some());
        assert!(seq1.next().is_some());
        assert_eq!(seq1.len(), 0);
        assert!(seq1.next().is_none());
        assert_eq!(seq1.len(), 0);
        assert!(seq1.is_empty());
        assert_eq!(seq2.len(), 3);
        assert!(!seq2.is_empty());
    }

    #[cfg(feature = "std")]
    fn hash<T: Hash>(v: &T) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_set_of_eq() {
        let s1 = SetOf::<bool>::new(b"");
        let s2 = SetOf::<bool>::new(b"");
        let s3 = SetOf::<bool>::new(b"\x01\x01\x00");
        let s4 = SetOf::<bool>::new(b"\x01\x01\xff");

        assert!(s1 == s2);

        assert!(s2 != s3);

        assert!(s3 == s3);

        assert!(s3 != s4);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_set_of_hash() {
        let s1 = SetOf::<bool>::new(b"");
        let s2 = SetOf::<bool>::new(b"");
        let s3 = SetOf::<bool>::new(b"\x01\x01\x00");
        let s4 = SetOf::<bool>::new(b"\x01\x01\xff");

        assert_eq!(hash(&s1), hash(&s2));

        assert_ne!(hash(&s2), hash(&s3));

        assert_ne!(hash(&s3), hash(&s4));
    }

    #[test]
    fn test_sequence_of_eq() {
        let s1 = SequenceOf::<bool>::new(b"").unwrap();
        let s2 = SequenceOf::<bool>::new(b"").unwrap();
        let s3 = SequenceOf::<bool>::new(b"\x01\x01\x00").unwrap();
        let s4 = SequenceOf::<bool>::new(b"\x01\x01\xff").unwrap();

        assert!(s1 == s2);

        assert!(s2 != s3);

        assert!(s3 == s3);

        assert!(s3 != s4);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_sequence_of_hash() {
        let s1 = SequenceOf::<bool>::new(b"").unwrap();
        let s2 = SequenceOf::<bool>::new(b"").unwrap();
        let s3 = SequenceOf::<bool>::new(b"\x01\x01\x00").unwrap();
        let s4 = SequenceOf::<bool>::new(b"\x01\x01\xff").unwrap();

        assert_eq!(hash(&s1), hash(&s2));

        assert_ne!(hash(&s2), hash(&s3));

        assert_ne!(hash(&s3), hash(&s4));
    }

    #[test]
    fn test_sequence_of_writer_clone() {
        let s1 = SequenceOfWriter::new([1, 2, 3]);
        let s2 = s1.clone();

        assert!(s1 == s2);
    }

    #[test]
    fn test_set_of_writer_clone() {
        let s1 = SetOfWriter::new([1, 2, 3]);
        let s2 = s1.clone();

        assert!(s1 == s2);
    }

    #[test]
    fn test_datetime_new() {
        assert!(DateTime::new(2038, 13, 1, 12, 0, 0).is_err());
        assert!(DateTime::new(2000, 1, 1, 12, 60, 0).is_err());
        assert!(DateTime::new(2000, 1, 1, 12, 0, 60).is_err());
        assert!(DateTime::new(2000, 1, 1, 24, 0, 0).is_err());
    }

    #[test]
    fn test_datetime_partialord() {
        let point = DateTime::new(2023, 6, 15, 14, 26, 5).unwrap();

        assert!(point < DateTime::new(2023, 6, 15, 14, 26, 6).unwrap());
        assert!(point < DateTime::new(2023, 6, 15, 14, 27, 5).unwrap());
        assert!(point < DateTime::new(2023, 6, 15, 15, 26, 5).unwrap());
        assert!(point < DateTime::new(2023, 6, 16, 14, 26, 5).unwrap());
        assert!(point < DateTime::new(2023, 7, 15, 14, 26, 5).unwrap());
        assert!(point < DateTime::new(2024, 6, 15, 14, 26, 5).unwrap());

        assert!(point > DateTime::new(2023, 6, 15, 14, 26, 4).unwrap());
        assert!(point > DateTime::new(2023, 6, 15, 14, 25, 5).unwrap());
        assert!(point > DateTime::new(2023, 6, 15, 13, 26, 5).unwrap());
        assert!(point > DateTime::new(2023, 6, 14, 14, 26, 5).unwrap());
        assert!(point > DateTime::new(2023, 5, 15, 14, 26, 5).unwrap());
        assert!(point > DateTime::new(2022, 6, 15, 14, 26, 5).unwrap());
    }

    #[test]
    fn test_utctime_new() {
        assert!(UtcTime::new(DateTime::new(1950, 1, 1, 12, 0, 0).unwrap()).is_ok());
        assert!(UtcTime::new(DateTime::new(1949, 1, 1, 12, 0, 0).unwrap()).is_err());
        assert!(UtcTime::new(DateTime::new(2050, 1, 1, 12, 0, 0).unwrap()).is_err());
        assert!(UtcTime::new(DateTime::new(2100, 1, 1, 12, 0, 0).unwrap()).is_err());
    }

    #[test]
    fn test_x509_generalizedtime_new() {
        assert!(X509GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap()).is_ok());
    }

    #[test]
    fn test_generalized_time_new() {
        assert!(
            GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(), Some(1234))
                .is_ok()
        );
        assert!(
            GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(), None).is_ok()
        );
        // Maximum fractional time is 999,999,999 nanos.
        assert!(GeneralizedTime::new(
            DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(),
            Some(999_999_999_u32)
        )
        .is_ok());
        assert!(GeneralizedTime::new(
            DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(),
            Some(1e9 as u32)
        )
        .is_err());
        assert!(GeneralizedTime::new(
            DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(),
            Some(1e9 as u32 + 1)
        )
        .is_err());
    }

    #[test]
    fn test_generalized_time_partial_ord() {
        let point =
            GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(), Some(1234))
                .unwrap();
        assert!(
            point
                < GeneralizedTime::new(DateTime::new(2023, 6, 30, 23, 59, 59).unwrap(), Some(1234))
                    .unwrap()
        );
        assert!(
            point
                < GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(), Some(1235))
                    .unwrap()
        );
        assert!(
            point
                > GeneralizedTime::new(DateTime::new(2015, 6, 30, 23, 59, 59).unwrap(), None)
                    .unwrap()
        );
    }

    #[test]
    fn test_enumerated_value() {
        assert_eq!(Enumerated::new(4).value(), 4);
    }

    #[test]
    fn test_implicit_as_inner() {
        assert_eq!(Implicit::<i32, 0>::new(12).as_inner(), &12);
    }

    #[test]
    fn test_explicit_as_inner() {
        assert_eq!(Explicit::<i32, 0>::new(12).as_inner(), &12);
    }

    #[test]
    fn test_const() {
        const _: DefinedByMarker<ObjectIdentifier> = DefinedByMarker::marker();
    }

    #[test]
    #[should_panic]
    fn test_defined_by_marker_parse() {
        crate::parse(b"", DefinedByMarker::<ObjectIdentifier>::parse).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_defined_by_marker_can_parse() {
        DefinedByMarker::<ObjectIdentifier>::can_parse(Tag::primitive(2));
    }

    #[test]
    #[should_panic]
    fn test_defined_by_marker_write() {
        crate::write(|w| DefinedByMarker::<ObjectIdentifier>::marker().write(w)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_defined_by_marker_encoded_length() {
        DefinedByMarker::<ObjectIdentifier>::marker().encoded_length();
    }
}
