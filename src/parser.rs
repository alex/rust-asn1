use crate::types::{Asn1Readable, SimpleAsn1Readable, Tlv};
use crate::Tag;
use core::fmt;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ParseErrorKind {
    /// Something about the value was invalid.
    InvalidValue,
    /// Something about the tag was invalid. This refers to a syntax error,
    /// not a tag's value being unexpected.
    InvalidTag,
    /// Something about the length was invalid. This can mean either a invalid
    /// encoding, or that a TLV was longer than 4GB, which is the maximum
    /// length that rust-asn1 supports.
    InvalidLength,
    /// A container's size was invalid. This typically indicates an empty
    /// or oversized structure.
    InvalidSize {
        min: usize,
        max: usize,
        actual: usize,
    },
    /// An unexpected tag was encountered.
    UnexpectedTag { actual: Tag },
    /// There was not enough data available to complete parsing. `needed`
    /// indicates the amount of data required to advance the parse.
    ///
    /// Note that providing `needed` additional bytes of data does not ensure
    /// that `parse` will succeed -- it is the amount of data required to
    /// satisfy the `read` operation that failed, and there may be subsequent
    /// `read` operations that require additional data.
    ShortData { needed: usize },
    /// An internal computation would have overflowed.
    IntegerOverflow,
    /// There was extraneous data in the input.
    ExtraData,
    /// Elements of a set were not lexicographically sorted.
    InvalidSetOrdering,
    /// An OPTIONAL DEFAULT was written with a default value.
    EncodedDefault,
    /// OID value is longer than the maximum size rust-asn1 can store. This is
    /// a limitation of rust-asn1.
    OidTooLong,
    /// A `DEFINED BY` value received an value for which there was no known
    /// variant.
    UnknownDefinedBy,
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ParseLocation {
    Field(&'static str),
    Index(usize),
}

/// `ParseError` are returned when there is an error parsing the ASN.1 data.
#[derive(PartialEq, Eq)]
pub struct ParseError {
    kind: ParseErrorKind,
    parse_locations: [Option<ParseLocation>; 4],
    parse_depth: u8,
}

impl ParseError {
    pub const fn new(kind: ParseErrorKind) -> ParseError {
        ParseError {
            kind,
            parse_locations: [None, None, None, None],
            parse_depth: 0,
        }
    }

    pub fn kind(&self) -> ParseErrorKind {
        self.kind
    }

    #[doc(hidden)]
    #[must_use]
    pub fn add_location(mut self, loc: ParseLocation) -> Self {
        if (self.parse_depth as usize) < self.parse_locations.len() {
            self.parse_locations[self.parse_depth as usize] = Some(loc);
            self.parse_depth += 1;
        }
        self
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

// Wraps an `Option<T>`, but `fmt::Debug` will only render `Some` values and
// panics on others.
struct SomeFmtOption<T>(Option<T>);

impl<T: fmt::Debug> fmt::Debug for SomeFmtOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_ref().unwrap().fmt(f)
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("ParseError");
        f.field("kind", &self.kind);
        if self.parse_depth > 0 {
            let mut locations = [
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
                SomeFmtOption(None),
            ];
            for (i, location) in self.parse_locations[..self.parse_depth as usize]
                .iter()
                .rev()
                .enumerate()
            {
                locations[i] = match location.as_ref().unwrap() {
                    ParseLocation::Field(f) => SomeFmtOption(Some(f as &dyn fmt::Debug)),
                    ParseLocation::Index(i) => SomeFmtOption(Some(i as &dyn fmt::Debug)),
                }
            }

            f.field("location", &&locations[..self.parse_depth as usize]);
        }
        f.finish()
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ASN.1 parsing error: ")?;
        match self.kind {
            ParseErrorKind::InvalidValue => write!(f, "invalid value"),
            ParseErrorKind::InvalidTag => write!(f, "invalid tag"),
            ParseErrorKind::InvalidLength => write!(f, "invalid length"),
            ParseErrorKind::InvalidSize { min, max, actual } => {
                write!(
                    f,
                    "invalid container size (expected between {min} and {max}, got {actual})"
                )
            }
            ParseErrorKind::UnexpectedTag { actual } => {
                write!(f, "unexpected tag (got {actual:?})")
            }
            ParseErrorKind::ShortData { needed } => {
                write!(f, "short data (needed at least {needed} additional bytes)")
            }
            ParseErrorKind::IntegerOverflow => write!(f, "integer overflow"),
            ParseErrorKind::ExtraData => write!(f, "extra data"),
            ParseErrorKind::InvalidSetOrdering => write!(f, "SET value was ordered incorrectly"),
            ParseErrorKind::EncodedDefault => write!(f, "DEFAULT value was explicitly encoded"),
            ParseErrorKind::OidTooLong => write!(
                f,
                "OBJECT IDENTIFIER was too large to be stored in rust-asn1's buffer"
            ),
            ParseErrorKind::UnknownDefinedBy => write!(f, "DEFINED BY with unknown value"),
        }
    }
}

/// The result of a `parse`. Either a successful value or a `ParseError`.
pub type ParseResult<T> = Result<T, ParseError>;

/// Parse takes a sequence of bytes of DER encoded ASN.1 data, constructs a
/// parser, and invokes a callback to read elements from the ASN.1 parser.
pub fn parse<'a, T, E: From<ParseError>, F: FnOnce(&mut Parser<'a>) -> Result<T, E>>(
    data: &'a [u8],
    f: F,
) -> Result<T, E> {
    let mut p = Parser::new(data);
    let result = f(&mut p)?;
    p.finish()?;
    Ok(result)
}

/// Parses a single top-level ASN.1 element from `data` (does not allow
/// trailing data). Most often this will be used where `T` is a type with
/// `#[derive(asn1::Asn1Read)]`.
pub fn parse_single<'a, T: Asn1Readable<'a>>(data: &'a [u8]) -> ParseResult<T> {
    parse(data, Parser::read_element::<T>)
}

/// Attempts to parse the `Tlv` at the start of `data` (allows trailing data).
/// If successful, the `Tlv` and the trailing data after it are returned, if
/// unsuccessful a `ParseError` is returned.
///
/// This can be useful where you have a file or stream format that relies on
/// ASN.1 TLVs for framing.
///
/// When parsing a stream, if an error is returned, if its `kind` is
/// `ParseErrorKind::ShortData`, this indicates that `data` did not contain
/// sufficient data to parse an entire `Tlv`, and thus adding more data may
/// resolve this. All other errors are "fatal" and cannot be resolved with
/// additional data.
pub fn strip_tlv(data: &[u8]) -> ParseResult<(Tlv<'_>, &[u8])> {
    let mut p = Parser::new(data);
    let tlv = p.read_element::<Tlv<'_>>()?;
    Ok((tlv, p.data))
}

/// Encapsulates an ongoing parse. For almost all use-cases the correct
/// entry-point is [`parse`] or [`parse_single`].
pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> Parser<'a> {
        Parser { data }
    }

    #[inline]
    fn finish(self) -> ParseResult<()> {
        if !self.is_empty() {
            return Err(ParseError::new(ParseErrorKind::ExtraData));
        }
        Ok(())
    }

    pub(crate) fn clone_internal(&self) -> Parser<'a> {
        Parser::new(self.data)
    }

    /// Returns the tag of the next element, without consuming it.
    pub fn peek_tag(&mut self) -> Option<Tag> {
        let (tag, _) = Tag::from_bytes(self.data).ok()?;
        Some(tag)
    }

    pub(crate) fn read_tag(&mut self) -> ParseResult<Tag> {
        let (tag, data) = Tag::from_bytes(self.data)?;
        self.data = data;
        Ok(tag)
    }

    #[inline]
    fn read_u8(&mut self) -> ParseResult<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    #[inline]
    fn read_bytes(&mut self, length: usize) -> ParseResult<&'a [u8]> {
        if length > self.data.len() {
            return Err(ParseError::new(ParseErrorKind::ShortData {
                needed: length - self.data.len(),
            }));
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length(&mut self) -> ParseResult<usize> {
        match self.read_u8()? {
            n if (n & 0x80) == 0 => Ok(usize::from(n)),
            0x81 => {
                let length = usize::from(self.read_u8()?);
                // Do not allow values <0x80 to be encoded using the long form
                if length < 0x80 {
                    return Err(ParseError::new(ParseErrorKind::InvalidLength));
                }
                Ok(length)
            }
            0x82 => {
                let length_bytes = self.read_bytes(2)?;
                let length = (usize::from(length_bytes[0]) << 8) | usize::from(length_bytes[1]);
                // Enforce that we're not using long form for values <0x80,
                // and that the first byte of the length is not zero (i.e.
                // that we're minimally encoded)
                if length < 0x100 {
                    return Err(ParseError::new(ParseErrorKind::InvalidLength));
                }
                Ok(length)
            }
            0x83 => {
                let length_bytes = self.read_bytes(3)?;
                let length = (usize::from(length_bytes[0]) << 16)
                    | (usize::from(length_bytes[1]) << 8)
                    | usize::from(length_bytes[2]);
                // Same thing as the 0x82 case
                if length < 0x10000 {
                    return Err(ParseError::new(ParseErrorKind::InvalidLength));
                }
                Ok(length)
            }
            0x84 => {
                let length_bytes = self.read_bytes(4)?;
                let length = (usize::from(length_bytes[0]) << 24)
                    | (usize::from(length_bytes[1]) << 16)
                    | (usize::from(length_bytes[2]) << 8)
                    | usize::from(length_bytes[3]);
                // Same thing as the 0x82 case
                if length < 0x1000000 {
                    return Err(ParseError::new(ParseErrorKind::InvalidLength));
                }
                Ok(length)
            }
            // We only support four-byte lengths
            _ => Err(ParseError::new(ParseErrorKind::InvalidLength)),
        }
    }

    #[inline]
    pub(crate) fn read_tlv(&mut self) -> ParseResult<Tlv<'a>> {
        let initial_data = self.data;

        let tag = self.read_tag()?;
        let length = self.read_length()?;
        let data = self.read_bytes(length)?;

        let full_data = &initial_data[..initial_data.len() - self.data.len()];
        Ok(Tlv {
            tag,
            data,
            full_data,
        })
    }

    /// Tests whether there is any data remaining in the Parser. Generally
    /// useful when parsing a `SEQUENCE OF`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a single ASN.1 element from the parser. Which type you are reading is determined by
    /// the type parameter `T`.
    #[inline]
    pub fn read_element<T: Asn1Readable<'a>>(&mut self) -> ParseResult<T> {
        T::parse(self)
    }

    /// This is an alias for `read_element::<Explicit<T, tag>>` for use when
    /// the tag is not known at compile time.
    pub fn read_explicit_element<T: Asn1Readable<'a>>(&mut self, tag: u32) -> ParseResult<T> {
        let expected_tag = crate::explicit_tag(tag);
        let tlv = self.read_tlv()?;
        if tlv.tag != expected_tag {
            return Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: tlv.tag,
            }));
        }
        parse_single(tlv.data())
    }

    /// This is an alias for `read_element::<Implicit<T, tag>>` for use when
    /// the tag is not known at compile time.
    pub fn read_implicit_element<T: SimpleAsn1Readable<'a>>(&mut self, tag: u32) -> ParseResult<T> {
        let expected_tag = crate::implicit_tag(tag, T::TAG);
        let tlv = self.read_tlv()?;
        if tlv.tag != expected_tag {
            return Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: tlv.tag,
            }));
        }
        T::parse_data(tlv.data())
    }
}

#[cfg(test)]
mod tests {
    use super::Parser;
    use crate::tag::TagClass;
    use crate::types::Asn1Readable;
    use crate::{
        BMPString, BigInt, BigUint, BitString, Choice1, Choice2, Choice3, DateTime, Enumerated,
        Explicit, GeneralizedTime, IA5String, Implicit, ObjectIdentifier, OctetStringEncoded,
        OwnedBigInt, OwnedBigUint, OwnedBitString, ParseError, ParseErrorKind, ParseLocation,
        ParseResult, PrintableString, Sequence, SequenceOf, SetOf, Tag, Tlv, UniversalString,
        UtcTime, Utf8String, VisibleString, X509GeneralizedTime,
    };
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    use alloc::{format, vec};
    use core::fmt;

    #[test]
    fn test_lifetimes() {
        // Explicit 'static OCTET_STRING
        let result = crate::parse(b"\x04\x01\x00", |p| p.read_element::<&'static [u8]>()).unwrap();
        assert_eq!(result, b"\x00");

        // Explicit 'static SEQUENCE containing an explicit 'static OCTET_STRING
        let result = crate::parse(b"\x30\x03\x04\x01\x00", |p| {
            p.read_element::<Sequence<'static>>()?
                .parse(|p| p.read_element::<&'static [u8]>())
        })
        .unwrap();
        assert_eq!(result, b"\x00");

        // Automatic 'static OCTET_STRING
        let result = crate::parse(b"\x04\x01\x00", |p| p.read_element::<&[u8]>()).unwrap();
        assert_eq!(result, b"\x00");

        // Automatic 'static SEQUENCE containing an automatic 'static
        // OCTET_STRING
        let result = crate::parse(b"\x30\x03\x04\x01\x00", |p| {
            p.read_element::<Sequence<'_>>()?
                .parse(|p| p.read_element::<&[u8]>())
        })
        .unwrap();
        assert_eq!(result, b"\x00");

        // BIT_STRING
        let result = crate::parse::<_, ParseError, _>(b"\x03\x02\x00\x00", |p| {
            Ok(p.read_element::<BitString<'_>>()?.as_bytes())
        })
        .unwrap();
        assert_eq!(result, b"\x00");
    }

    #[test]
    fn test_parse_error_debug() {
        for (e, expected) in &[
            (
                ParseError::new(ParseErrorKind::InvalidValue),
                "ParseError { kind: InvalidValue }",
            ),
            (
                ParseError::new(ParseErrorKind::InvalidValue)
                    .add_location(ParseLocation::Field("Abc::123")),
                "ParseError { kind: InvalidValue, location: [\"Abc::123\"] }",
            ),
            (
                ParseError::new(ParseErrorKind::InvalidValue)
                    .add_location(ParseLocation::Index(12))
                    .add_location(ParseLocation::Field("Abc::123")),
                "ParseError { kind: InvalidValue, location: [\"Abc::123\", 12] }",
            ),
        ] {
            assert_eq!(&format!("{e:?}"), expected);
        }
    }

    #[test]
    fn test_parse_error_display() {
        for (e, expected) in &[
            (
                ParseError::new(ParseErrorKind::InvalidValue),
                "ASN.1 parsing error: invalid value",
            ),
            (
                ParseError::new(ParseErrorKind::InvalidTag),
                "ASN.1 parsing error: invalid tag"
            ),
            (
                ParseError::new(ParseErrorKind::InvalidLength),
                "ASN.1 parsing error: invalid length"
            ),
            (
                ParseError::new(ParseErrorKind::InvalidSize { min: 1, max: 5, actual: 0 }),
                "ASN.1 parsing error: invalid container size (expected between 1 and 5, got 0)",
            ),
            (
                ParseError::new(ParseErrorKind::IntegerOverflow),
                "ASN.1 parsing error: integer overflow"
            ),
            (
                ParseError::new(ParseErrorKind::ExtraData),
                "ASN.1 parsing error: extra data"
            ),
            (
                ParseError::new(ParseErrorKind::InvalidSetOrdering),
                "ASN.1 parsing error: SET value was ordered incorrectly"
            ),
            (
                ParseError::new(ParseErrorKind::EncodedDefault),
                "ASN.1 parsing error: DEFAULT value was explicitly encoded"
            ),
            (
                ParseError::new(ParseErrorKind::OidTooLong),
                "ASN.1 parsing error: OBJECT IDENTIFIER was too large to be stored in rust-asn1's buffer"
            ),
            (
                ParseError::new(ParseErrorKind::UnknownDefinedBy),
                "ASN.1 parsing error: DEFINED BY with unknown value"
            ),
            (
                ParseError::new(ParseErrorKind::ShortData{needed: 7})
                    .add_location(ParseLocation::Field("Abc::123")),
                "ASN.1 parsing error: short data (needed at least 7 additional bytes)",
            ),
            (
                ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(12),
                })
                .add_location(ParseLocation::Index(12))
                .add_location(ParseLocation::Field("Abc::123")),
                "ASN.1 parsing error: unexpected tag (got Tag { value: 12, constructed: false, class: Universal })",
            ),
        ]
        {
            assert_eq!(&format!("{e}"), expected);
        }
    }

    #[test]
    fn test_parse_error_kind() {
        let e = ParseError::new(ParseErrorKind::EncodedDefault);
        assert_eq!(e.kind(), ParseErrorKind::EncodedDefault);
    }

    #[test]
    fn test_strip_tlv() {
        for (der_bytes, expected) in [
            (
                b"" as &[u8],
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
            ),
            (
                b"\x04",
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
            ),
            (
                b"\x04\x82",
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 2 })),
            ),
            (
                b"\x04\x03",
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 3 })),
            ),
            (
                b"\x04\x03ab",
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
            ),
            (
                b"\x04\x03abc",
                Ok((
                    Tlv {
                        tag: Tag::primitive(0x04),
                        data: b"abc",
                        full_data: b"\x04\x03abc",
                    },
                    b"" as &[u8],
                )),
            ),
            (
                b"\x04\x03abc\x00\x00\x00",
                Ok((
                    Tlv {
                        tag: Tag::primitive(0x04),
                        data: b"abc",
                        full_data: b"\x04\x03abc",
                    },
                    b"\x00\x00\x00",
                )),
            ),
        ] {
            let result = crate::strip_tlv(der_bytes);
            assert_eq!(result, expected);
        }
    }

    fn assert_parses_cb<
        'a,
        T: fmt::Debug + PartialEq,
        E: From<ParseError> + fmt::Debug + PartialEq,
        F: Fn(&mut Parser<'a>) -> Result<T, E>,
    >(
        data: &[(Result<T, E>, &'a [u8])],
        f: F,
    ) {
        for (expected, der_bytes) in data {
            let result = crate::parse(der_bytes, &f);
            assert_eq!(&result, expected);
        }
    }

    fn assert_parses<'a, T>(data: &[(ParseResult<T>, &'a [u8])])
    where
        T: Asn1Readable<'a> + fmt::Debug + PartialEq,
    {
        assert_parses_cb(data, |p| p.read_element::<T>());
    }

    #[test]
    fn test_parse_extra_data() {
        let result = crate::parse(b"\x00", |_| Ok(()));
        assert_eq!(result, Err(ParseError::new(ParseErrorKind::ExtraData)));
    }

    #[test]
    fn test_peek_tag() {
        let result = crate::parse(b"\x02\x01\x7f", |p| {
            assert_eq!(p.peek_tag(), Some(Tag::primitive(0x02)));
            p.read_element::<u8>()
        });
        assert_eq!(result, Ok(127));
    }

    #[test]
    fn test_errors() {
        #[derive(Debug, PartialEq, Eq)]
        enum E {
            X(u64),
            P(ParseError),
        }

        impl From<ParseError> for E {
            fn from(e: ParseError) -> E {
                E::P(e)
            }
        }

        assert_parses_cb(
            &[
                (Ok(8), b"\x02\x01\x08"),
                (
                    Err(E::P(ParseError::new(ParseErrorKind::ShortData {
                        needed: 1,
                    }))),
                    b"\x02\x01",
                ),
                (Err(E::X(7)), b"\x02\x01\x07"),
            ],
            |p| {
                let val = p.read_element::<u64>()?;
                if val % 2 == 0 {
                    Ok(val)
                } else {
                    Err(E::X(val))
                }
            },
        );
    }

    #[test]
    fn test_parse_tlv() {
        assert_parses::<Tlv<'_>>(&[
            (
                Ok(Tlv {
                    tag: Tag::primitive(0x4),
                    data: b"abc",
                    full_data: b"\x04\x03abc",
                }),
                b"\x04\x03abc",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 2 })),
                b"\x04\x03a",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x04",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
            // Long form tags
            (
                Ok(Tlv {
                    tag: Tag::new(31, TagClass::Universal, false),
                    data: b"",
                    full_data: b"\x1f\x1f\x00",
                }),
                b"\x1f\x1f\x00",
            ),
            (
                Ok(Tlv {
                    tag: Tag::new(128, TagClass::Universal, false),
                    data: b"",
                    full_data: b"\x1f\x81\x00\x00",
                }),
                b"\x1f\x81\x00\x00",
            ),
            (
                Ok(Tlv {
                    tag: Tag::new(0x4001, TagClass::Universal, false),
                    data: b"",
                    full_data: b"\x1f\x81\x80\x01\x00",
                }),
                b"\x1f\x81\x80\x01\x00",
            ),
            (
                Ok(Tlv {
                    tag: Tag::new(0x01, TagClass::Application, false),
                    data: b"",
                    full_data: b"\x41\x00",
                }),
                b"\x41\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x1f",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x1f\x85",
            ),
            // Overflow u32 for the tag number.
            (
                Err(ParseError::new(ParseErrorKind::InvalidTag)),
                b"\x1f\x88\x80\x80\x80\x80\x00",
            ),
            // Long form tag for value that fits in a short form
            (
                Err(ParseError::new(ParseErrorKind::InvalidTag)),
                b"\x1f\x1e\x00",
            ),
            (
                // base128 integer with leading 0
                Err(ParseError::new(ParseErrorKind::InvalidTag)),
                b"\xff\x80\x84\x01\x01\xa9",
            ),
        ]);
    }

    #[test]
    fn test_parse_null() {
        assert_parses::<()>(&[
            (Ok(()), b"\x05\x00"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x05\x01\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_bool() {
        assert_parses::<bool>(&[
            (Ok(true), b"\x01\x01\xff"),
            (Ok(false), b"\x01\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x01\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x01\x01\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x01\x02\x00\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x01\x02\xff\x01",
            ),
        ]);
    }

    #[test]
    fn test_parse_octet_string() {
        let long_value = vec![b'a'; 70_000];
        let really_long_value = vec![b'a'; 20_000_000];

        assert_parses::<&[u8]>(&[
            (Ok(b""), b"\x04\x00"),
            (Ok(b"\x01\x02\x03"), b"\x04\x03\x01\x02\x03"),
            (
                Ok(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                b"\x04\x81\x81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            (
                Ok(long_value.as_slice()),
                [b"\x04\x83\x01\x11\x70", long_value.as_slice()].concat().as_slice()
            ),
            (
                Ok(really_long_value.as_slice()),
                [b"\x04\x84\x01\x31\x2d\x00", really_long_value.as_slice()].concat().as_slice()
            ),
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x80"),
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x81\x00"),
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x81\x01\x09"),
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x82\x00\x80"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidLength)),
                b"\x04\x89\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData{needed: 1})), b"\x04\x03\x01\x02"),
            (Err(ParseError::new(ParseErrorKind::ShortData{needed: 65531})), b"\x04\x82\xff\xff\xff\xff\xff\xff"),
            // 3 byte length form with leading 0.
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x83\x00\xff\xff"),
            // 4 byte length form with leading 0.
            (Err(ParseError::new(ParseErrorKind::InvalidLength)), b"\x04\x84\x00\xff\xff\xff"),
        ]);

        assert_parses::<[u8; 0]>(&[
            (Ok([]), b"\x04\x00"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x04\x02\x01\x02",
            ),
        ]);

        assert_parses::<[u8; 1]>(&[
            (Ok([2]), b"\x04\x01\x02"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x04\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x04\x02\x01\x02",
            ),
        ]);
    }

    #[test]
    fn test_octet_string_encoded() {
        assert_parses::<OctetStringEncoded<bool>>(&[
            (Ok(OctetStringEncoded::new(true)), b"\x04\x03\x01\x01\xff"),
            (Ok(OctetStringEncoded::new(false)), b"\x04\x03\x01\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x03),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x02),
                })),
                b"\x04\x02\x02\x00",
            ),
        ])
    }

    #[test]
    fn test_parse_int_i64() {
        assert_parses::<i64>(&[
            (Ok(0), b"\x02\x01\x00"),
            (Ok(127), b"\x02\x01\x7f"),
            (Ok(128), b"\x02\x02\x00\x80"),
            (Ok(256), b"\x02\x02\x01\x00"),
            (Ok(-128), b"\x02\x01\x80"),
            (Ok(-129), b"\x02\x02\xff\x7f"),
            (Ok(-256), b"\x02\x02\xff\x00"),
            (Ok(i64::MAX), b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x3),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x02\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x02",
            ),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x05\x00\x00\x00\x00\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\x80",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x09\x00\xD0\x07\x04\x00\x03\x31\x31\x00",
            ),
        ]);
    }

    #[test]
    fn parse_int_u64() {
        assert_parses::<u64>(&[
            (
                Ok(u64::MAX),
                b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_int_i32() {
        assert_parses::<i32>(&[
            (Ok(0), b"\x02\x01\x00"),
            (Ok(127), b"\x02\x01\x7f"),
            (Ok(128), b"\x02\x02\x00\x80"),
            (Ok(256), b"\x02\x02\x01\x00"),
            (Ok(-128), b"\x02\x01\x80"),
            (Ok(-129), b"\x02\x02\xff\x7f"),
            (Ok(-256), b"\x02\x02\xff\x00"),
            (Ok(i32::MAX), b"\x02\x04\x7f\xff\xff\xff"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x3),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x02\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x02",
            ),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x05\x00\x00\x00\x00\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\x80",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_int_u16() {
        assert_parses::<u16>(&[
            (Ok(0), b"\x02\x01\x00"),
            (Ok(1), b"\x02\x01\x01"),
            (Ok(256), b"\x02\x02\x01\x00"),
            (Ok(65535), b"\x02\x03\x00\xff\xff"),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x03\x01\x00\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_int_i16() {
        assert_parses::<i16>(&[
            (Ok(0), b"\x02\x01\x00"),
            (Ok(1), b"\x02\x01\x01"),
            (Ok(-256), b"\x02\x02\xff\x00"),
            (Ok(-1), b"\x02\x01\xff"),
            (Ok(-32768), b"\x02\x02\x80\x00"),
            (Ok(32767), b"\x02\x02\x7f\xff"),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x03\x80\x00\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_int_i8() {
        assert_parses::<i8>(&[
            (Ok(0i8), b"\x02\x01\x00"),
            (Ok(127i8), b"\x02\x01\x7f"),
            (Ok(-128i8), b"\x02\x01\x80"),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x02\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_int_u8() {
        assert_parses::<u8>(&[
            (Ok(0u8), b"\x02\x01\x00"),
            (Ok(127u8), b"\x02\x01\x7f"),
            (Ok(255u8), b"\x02\x02\x00\xff"),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x02\x02\x01\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x01\x80",
            ),
        ]);
    }

    #[test]
    fn test_parse_biguint() {
        assert_parses::<BigUint<'_>>(&[
            (Ok(BigUint::new(b"\x00").unwrap()), b"\x02\x01\x00"),
            (Ok(BigUint::new(b"\x00\xff").unwrap()), b"\x02\x02\x00\xff"),
            (
                Ok(BigUint::new(b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").unwrap()),
                b"\x02\x0d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x01\x80",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\x80",
            ),
        ]);
    }

    #[test]
    fn test_parse_ownedbiguint() {
        assert_parses::<OwnedBigUint>(&[
            (
                Ok(OwnedBigUint::new(b"\x00".to_vec()).unwrap()),
                b"\x02\x01\x00",
            ),
            (
                Ok(OwnedBigUint::new(b"\x00\xff".to_vec()).unwrap()),
                b"\x02\x02\x00\xff",
            ),
            (
                Ok(OwnedBigUint::new(
                    b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".to_vec(),
                )
                .unwrap()),
                b"\x02\x0d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x01\x80",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\x80",
            ),
        ]);
    }

    #[test]
    fn test_parse_bigint() {
        assert_parses::<BigInt<'_>>(&[
            (Ok(BigInt::new(b"\x80").unwrap()), b"\x02\x01\x80"),
            (Ok(BigInt::new(b"\xff").unwrap()), b"\x02\x01\xff"),
            (
                Ok(BigInt::new(b"\x00\xff\xff").unwrap()),
                b"\x02\x03\x00\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\xff",
            ),
            (
                Ok(BigInt::new(b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").unwrap()),
                b"\x02\x0c\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_owned_bigint() {
        assert_parses::<OwnedBigInt>(&[
            (
                Ok(OwnedBigInt::new(b"\x80".to_vec()).unwrap()),
                b"\x02\x01\x80",
            ),
            (
                Ok(OwnedBigInt::new(b"\xff".to_vec()).unwrap()),
                b"\x02\x01\xff",
            ),
            (
                Ok(OwnedBigInt::new(b"\x00\xff\xff".to_vec()).unwrap()),
                b"\x02\x03\x00\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x02\xff\xff",
            ),
            (
                Ok(
                    OwnedBigInt::new(b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".to_vec())
                        .unwrap(),
                ),
                b"\x02\x0c\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x02\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_object_identifier() {
        assert_parses::<ObjectIdentifier>(&[
            (
                Ok(ObjectIdentifier::from_string("2.5").unwrap()),
                b"\x06\x01\x55",
            ),
            (
                Ok(ObjectIdentifier::from_string("2.5.2").unwrap()),
                b"\x06\x02\x55\x02",
            ),
            (
                Ok(ObjectIdentifier::from_string("1.2.840.113549").unwrap()),
                b"\x06\x06\x2a\x86\x48\x86\xf7\x0d",
            ),
            (
                Ok(ObjectIdentifier::from_string("1.2.3.4").unwrap()),
                b"\x06\x03\x2a\x03\x04",
            ),
            (
                Ok(ObjectIdentifier::from_string("1.2.840.133549.1.1.5").unwrap()),
                b"\x06\x09\x2a\x86\x48\x88\x93\x2d\x01\x01\x05",
            ),
            (
                Ok(ObjectIdentifier::from_string("2.100.3").unwrap()),
                b"\x06\x03\x81\x34\x03",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x06\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x06\x07\x55\x02\xc0\x80\x80\x80\x80",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x06\x02\x2a\x86",
            ),
        ]);
    }

    #[test]
    fn test_parse_bit_string() {
        assert_parses::<BitString<'_>>(&[
            (Ok(BitString::new(b"", 0).unwrap()), b"\x03\x01\x00"),
            (Ok(BitString::new(b"\x00", 7).unwrap()), b"\x03\x02\x07\x00"),
            (Ok(BitString::new(b"\x80", 7).unwrap()), b"\x03\x02\x07\x80"),
            (
                Ok(BitString::new(b"\x81\xf0", 4).unwrap()),
                b"\x03\x03\x04\x81\xf0",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x07\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x07\x40",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x08\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_owned_bit_string() {
        assert_parses::<OwnedBitString>(&[
            (Ok(OwnedBitString::new(vec![], 0).unwrap()), b"\x03\x01\x00"),
            (
                Ok(OwnedBitString::new(vec![0x00], 7).unwrap()),
                b"\x03\x02\x07\x00",
            ),
            (
                Ok(OwnedBitString::new(vec![0x80], 7).unwrap()),
                b"\x03\x02\x07\x80",
            ),
            (
                Ok(OwnedBitString::new(vec![0x81, 0xf0], 4).unwrap()),
                b"\x03\x03\x04\x81\xf0",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x07\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x07\x40",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x03\x02\x08\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_printable_string() {
        assert_parses::<PrintableString<'_>>(&[
            (Ok(PrintableString::new("abc").unwrap()), b"\x13\x03abc"),
            (Ok(PrintableString::new(")").unwrap()), b"\x13\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x13\x03ab\x00",
            ),
        ]);
    }

    #[test]
    fn test_parse_ia5string() {
        assert_parses::<IA5String<'_>>(&[
            (Ok(IA5String::new("abc").unwrap()), b"\x16\x03abc"),
            (Ok(IA5String::new(")").unwrap()), b"\x16\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x16\x03ab\xff",
            ),
        ]);
    }

    #[test]
    fn test_parse_utf8string() {
        assert_parses::<Utf8String<'_>>(&[
            (Ok(Utf8String::new("abc")), b"\x0c\x03abc"),
            (Ok(Utf8String::new(")")), b"\x0c\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x0c\x01\xff",
            ),
        ]);
    }

    #[test]
    fn test_parse_visiblestring() {
        assert_parses::<VisibleString<'_>>(&[
            (Ok(VisibleString::new("abc").unwrap()), b"\x1a\x03abc"),
            (Ok(VisibleString::new(")").unwrap()), b"\x1a\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1a\x01\n",
            ),
        ]);
    }

    #[test]
    fn test_parse_bmpstring() {
        assert_parses::<BMPString<'_>>(&[
            (
                Ok(BMPString::new(b"\x00a\x00b\x00c").unwrap()),
                b"\x1e\x06\x00a\x00b\x00c",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1e\x01a",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1e\x04\xde|X@",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1e\x02\xdeX",
            ),
        ]);
    }

    #[test]
    fn test_parse_universalstring() {
        assert_parses::<UniversalString<'_>>(&[
            (
                Ok(UniversalString::new(b"\x00\x00\x00a\x00\x00\x00b\x00\x00\x00c").unwrap()),
                b"\x1c\x0c\x00\x00\x00a\x00\x00\x00b\x00\x00\x00c",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1c\x01a",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1c\x02ab",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1c\x03abc",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1c\x03abc",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1c\x04\x96\x8c\xeaU",
            ),
        ]);
    }

    #[test]
    fn test_parse_utctime() {
        assert_parses::<UtcTime>(&[
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x11910506164540-0700",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x11910506164540+0730",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0f5105062345+0000",
            ),
            (
                Ok(UtcTime::new(DateTime::new(1991, 5, 6, 23, 45, 40).unwrap()).unwrap()),
                b"\x17\x0d910506234540Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0b9105062345Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0b5105062345Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0da10506234540Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d91a506234540Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d9105a6234540Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d910506a34540Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d910506334a40Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d91050633444aZ",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d910506334461Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e910506334400Za",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d000100000000Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d101302030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100002030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100100030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100132030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100231030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100102240405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100102036005Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0d100102030460Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e-100102030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e10-0102030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e10-0002030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e1001-02030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e100102-030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e10010203-0410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0e1001020304-10Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0c18102813516Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x1018102813516+0730",
            ),
            (
                // 2049 year with a negative UTC-offset, so actually a 2050
                // date. UTCTime doesn't support those.
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x17\x0f4912311047-2026",
            ),
        ]);
    }

    #[test]
    fn test_x509_generalizedtime() {
        assert_parses::<X509GeneralizedTime>(&[
            (
                Ok(X509GeneralizedTime::new(DateTime::new(2010, 1, 2, 3, 4, 5).unwrap()).unwrap()),
                b"\x18\x0f20100102030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1320100102030405+0607",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1320100102030405-0607",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1320100602030405-0607",
            ),
            (
                // 29th of February (Leap Year)
                Ok(X509GeneralizedTime::new(DateTime::new(2000, 2, 29, 3, 4, 5).unwrap()).unwrap()),
                b"\x18\x0f20000229030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100102030405",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e00000100000000Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20101302030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100002030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100100030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100132030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100231030405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100102240405Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100102036005Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0e20100102030460Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f-20100102030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f2010-0102030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f2010-0002030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f201001-02030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f20100102-030410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f2010010203-0410Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f201001020304-10Z",
            ),
            (
                // 31st of June
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1320100631030405-0607",
            ),
            (
                // 30th of February (Leap Year)
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1320000230030405-0607",
            ),
            (
                // 29th of February (non-Leap Year)
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1319000229030405-0607",
            ),
            (
                // Invalid timezone-offset hours
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1319000228030405-3007",
            ),
            (
                // Invalid timezone-offset minutes
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1319000228030405-2367",
            ),
            (
                // Trailing data
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1019000228030405Z ",
            ),
            // Tests for fractional seconds, which we currently don't support
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1620100102030405.123456Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1520100102030405.123456",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1020100102030405.Z",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0f20100102030405.",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x11-1\n110723459+1002",
            ),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x0d0 1204000060Z",
            ),
        ]);
    }

    #[test]
    fn test_generalized_time() {
        assert_parses::<GeneralizedTime>(&[
            (
                // General case
                Ok(GeneralizedTime::new(
                    DateTime::new(2010, 1, 2, 3, 4, 5).unwrap(),
                    Some(123_456_000),
                )
                .unwrap()),
                b"\x18\x1620100102030405.123456Z",
            ),
            (
                // No fractional time
                Ok(
                    GeneralizedTime::new(DateTime::new(2010, 1, 2, 3, 4, 5).unwrap(), None)
                        .unwrap(),
                ),
                b"\x18\x0f20100102030405Z",
            ),
            (
                // Starting with 0 is ok
                Ok(GeneralizedTime::new(
                    DateTime::new(2010, 1, 2, 3, 4, 5).unwrap(),
                    Some(12_375_600),
                )
                .unwrap()),
                b"\x18\x1720100102030405.0123756Z",
            ),
            (
                // But ending with 0 is not OK
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1220100102030405.10Z",
            ),
            (
                // Too many digits
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1a20100102030405.0123456789Z",
            ),
            (
                // Missing timezone
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1520100102030405.123456",
            ),
            (
                // Invalid fractional second
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x18\x1020100102030405.Z",
            ),
        ])
    }

    #[test]
    fn test_enumerated() {
        assert_parses::<Enumerated>(&[
            (Ok(Enumerated::new(12)), b"\x0a\x01\x0c"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x0a\x09\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
        ]);
    }

    #[test]
    fn test_parse_sequence() {
        assert_parses::<Sequence<'_>>(&[
            (
                Ok(Sequence::new(b"\x02\x01\x01\x02\x01\x02")),
                b"\x30\x06\x02\x01\x01\x02\x01\x02",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x30\x04\x02\x01\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ExtraData)),
                b"\x30\x06\x02\x01\x01\x02\x01\x02\x00",
            ),
        ]);
    }

    #[test]
    fn test_sequence_parse() {
        assert_parses_cb(
            &[
                (Ok((1, 2)), b"\x30\x06\x02\x01\x01\x02\x01\x02"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"\x30\x03\x02\x01\x01",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x30\x07\x02\x01\x01\x02\x01\x02\x00",
                ),
            ],
            |p| {
                p.read_element::<Sequence<'_>>()?
                    .parse(|p| Ok((p.read_element::<i64>()?, p.read_element::<i64>()?)))
            },
        );
    }

    #[test]
    fn test_parse_is_empty() {
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (Ok(vec![]), b"\x30\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"\x30\x02\x02\x01",
                ),
            ],
            |p| {
                p.read_element::<Sequence<'_>>()?.parse(|p| {
                    let mut result = vec![];
                    while !p.is_empty() {
                        result.push(p.read_element::<i64>()?);
                    }
                    Ok(result)
                })
            },
        );
    }

    #[test]
    fn test_parse_sequence_of() {
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (Ok(vec![]), b"\x30\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })
                        .add_location(ParseLocation::Index(0))),
                    b"\x30\x02\x02\x01",
                ),
            ],
            |p| Ok(p.read_element::<SequenceOf<'_, i64>>()?.collect()),
        );
    }

    #[test]
    fn test_sequence_of_constrained_lengths() {
        // Minimum only.
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::InvalidSize {
                        min: 1,
                        max: usize::MAX,
                        actual: 0,
                    })),
                    b"\x30\x00",
                ),
            ],
            |p| Ok(p.read_element::<SequenceOf<'_, i64, 1>>()?.collect()),
        );

        // Minimum and maximum.
        assert_parses_cb(
            &[
                (
                    Err(ParseError::new(ParseErrorKind::InvalidSize {
                        min: 1,
                        max: 2,
                        actual: 3,
                    })),
                    b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::InvalidSize {
                        min: 1,
                        max: 2,
                        actual: 0,
                    })),
                    b"\x30\x00",
                ),
                (Ok(vec![3, 1]), b"\x30\x06\x02\x01\x03\x02\x01\x01"),
            ],
            |p| Ok(p.read_element::<SequenceOf<'_, i64, 1, 2>>()?.collect()),
        );
    }

    #[test]
    fn parse_set_of() {
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x31\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (Ok(vec![]), b"\x31\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::InvalidSetOrdering)
                        .add_location(ParseLocation::Index(1))),
                    b"\x31\x06\x02\x01\x03\x02\x01\x01",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })
                        .add_location(ParseLocation::Index(0))),
                    b"\x31\x01\x02",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x1),
                    })
                    .add_location(ParseLocation::Index(0))),
                    b"\x31\x02\x01\x00",
                ),
            ],
            |p| Ok(p.read_element::<SetOf<'_, u64>>()?.collect()),
        );
    }

    #[test]
    fn test_parse_optional() {
        assert_parses_cb(
            &[
                (Ok((Some(true), None)), b"\x01\x01\xff"),
                (Ok((Some(false), None)), b"\x01\x01\x00"),
                (Ok((None, Some(18))), b"\x02\x01\x12"),
                (Ok((Some(true), Some(18))), b"\x01\x01\xff\x02\x01\x12"),
                (Ok((None, None)), b""),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"\x01",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"\x02",
                ),
            ],
            |p| {
                Ok((
                    p.read_element::<Option<bool>>()?,
                    p.read_element::<Option<i64>>()?,
                ))
            },
        );

        assert_parses::<Option<Tlv<'_>>>(&[
            (
                Ok(Some(Tlv {
                    tag: Tag::primitive(0x4),
                    data: b"abc",
                    full_data: b"\x04\x03abc",
                })),
                b"\x04\x03abc",
            ),
            (Ok(None), b""),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"\x04",
            ),
        ]);

        assert_parses::<Option<Choice2<u64, bool>>>(&[
            (Ok(None), b""),
            (Ok(Some(Choice2::ChoiceA(17))), b"\x02\x01\x11"),
            (Ok(Some(Choice2::ChoiceB(true))), b"\x01\x01\xff"),
            (Err(ParseError::new(ParseErrorKind::ExtraData)), b"\x03\x00"),
        ]);
    }

    #[test]
    fn test_choice1() {
        assert_parses::<Choice1<bool>>(&[
            (Ok(Choice1::ChoiceA(true)), b"\x01\x01\xff"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x03),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
        ]);
    }

    #[test]
    fn test_choice2() {
        assert_parses::<Choice2<bool, i64>>(&[
            (Ok(Choice2::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice2::ChoiceB(18)), b"\x02\x01\x12"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x03),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
        ]);
    }

    #[test]
    fn test_choice3() {
        assert_parses::<Choice3<bool, i64, ()>>(&[
            (Ok(Choice3::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice3::ChoiceB(18)), b"\x02\x01\x12"),
            (Ok(Choice3::ChoiceC(())), b"\x05\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x03),
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
        ]);
    }

    #[test]
    fn test_parse_implicit() {
        assert_parses::<Implicit<bool, 2>>(&[
            (Ok(Implicit::new(true)), b"\x82\x01\xff"),
            (Ok(Implicit::new(false)), b"\x82\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x01),
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x02),
                })),
                b"\x02\x01\xff",
            ),
        ]);
        assert_parses::<Implicit<Sequence<'_>, 2>>(&[
            (Ok(Implicit::new(Sequence::new(b"abc"))), b"\xa2\x03abc"),
            (Ok(Implicit::new(Sequence::new(b""))), b"\xa2\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x01),
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x02),
                })),
                b"\x02\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                b"",
            ),
        ]);
        assert_parses_cb(
            &[
                (Ok(true), b"\x82\x01\xff"),
                (Ok(false), b"\x82\x01\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x01),
                    })),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x02),
                    })),
                    b"\x02\x01\xff",
                ),
            ],
            |p| p.read_implicit_element::<bool>(2),
        );
        assert_parses_cb(
            &[
                (Ok(Sequence::new(b"abc")), b"\xa2\x03abc"),
                (Ok(Sequence::new(b"")), b"\xa2\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x01),
                    })),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x02),
                    })),
                    b"\x02\x01\xff",
                ),
            ],
            |p| p.read_implicit_element::<Sequence<'_>>(2),
        );
    }

    #[test]
    fn test_parse_explicit() {
        assert_parses::<Explicit<bool, 2>>(&[
            (Ok(Explicit::new(true)), b"\xa2\x03\x01\x01\xff"),
            (Ok(Explicit::new(false)), b"\xa2\x03\x01\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x01),
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x02),
                })),
                b"\x02\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: Tag::primitive(0x03),
                })),
                b"\xa2\x03\x03\x01\xff",
            ),
        ]);
        assert_parses_cb(
            &[
                (Ok(true), b"\xa2\x03\x01\x01\xff"),
                (Ok(false), b"\xa2\x03\x01\x01\x00"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
                    b"",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x01),
                    })),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: Tag::primitive(0x03),
                    })),
                    b"\xa2\x03\x03\x01\xff",
                ),
            ],
            |p| p.read_explicit_element::<bool>(2),
        );
    }

    #[test]
    fn test_parse_box() {
        assert_parses::<Box<u8>>(&[
            (Ok(Box::new(12u8)), b"\x02\x01\x0c"),
            (Ok(Box::new(0)), b"\x02\x01\x00"),
        ]);
    }
}
