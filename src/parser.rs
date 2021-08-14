use crate::types::{Asn1Readable, SimpleAsn1Readable, Tlv};
use core::fmt;

/// ParseError are returned when there is an error parsing the ASN.1 data.
#[derive(Debug, PartialEq)]
pub enum ParseErrorKind {
    /// Something about the value was invalid.
    InvalidValue,
    /// An unexpected tag was encountered.
    UnexpectedTag { actual: u8 },
    /// There was not enough data available to complete parsing.
    ShortData,
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
}

#[derive(Debug, PartialEq)]
#[doc(hidden)]
pub enum ParseLocation {
    Field(&'static str),
    Index(usize),
}

#[derive(PartialEq)]
pub struct ParseError {
    kind: ParseErrorKind,
    parse_locations: [Option<ParseLocation>; 8],
    parse_depth: u8,
}

impl ParseError {
    pub fn new(kind: ParseErrorKind) -> ParseError {
        ParseError {
            kind,
            parse_locations: [None, None, None, None, None, None, None, None],
            parse_depth: 0,
        }
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.as_ref().unwrap().fmt(f)
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
                    ParseLocation::Field(ref f) => SomeFmtOption(Some(f as &dyn fmt::Debug)),
                    ParseLocation::Index(ref i) => SomeFmtOption(Some(i as &dyn fmt::Debug)),
                }
            }

            f.field("location", &&locations[..self.parse_depth as usize]);
        }
        f.finish()
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ASN.1 parsing error: ")?;
        match self.kind {
            ParseErrorKind::InvalidValue => write!(f, "invalid value"),
            ParseErrorKind::UnexpectedTag { actual } => {
                write!(f, "unexpected tag (got {})", actual)
            }
            ParseErrorKind::ShortData => write!(f, "short data"),
            ParseErrorKind::IntegerOverflow => write!(f, "integer overflow"),
            ParseErrorKind::ExtraData => write!(f, "extra data"),
            ParseErrorKind::InvalidSetOrdering => write!(f, "SET value was ordered incorrectly"),
            ParseErrorKind::EncodedDefault => write!(f, "DEFAULT value was explicitly encoded"),
        }
    }
}

/// The result of a `parse`. Either a successful value or a `ParseError`.
pub type ParseResult<T> = Result<T, ParseError>;

/// Parse takes a sequence of bytes of DER encoded ASN.1 data, constructs a
/// parser, and invokes a callback to read elements from the ASN.1 parser.
pub fn parse<'a, T, E: From<ParseError>, F: Fn(&mut Parser<'a>) -> Result<T, E>>(
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
    parse(data, |p| p.read_element::<T>())
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

    pub(crate) fn peek_u8(&mut self) -> Option<u8> {
        self.data.get(0).copied()
    }

    #[inline]
    fn read_u8(&mut self) -> ParseResult<u8> {
        if self.data.is_empty() {
            return Err(ParseError::new(ParseErrorKind::ShortData));
        }
        let (val, data) = self.data.split_at(1);
        self.data = data;
        Ok(val[0])
    }

    #[inline]
    fn read_bytes(&mut self, length: usize) -> ParseResult<&'a [u8]> {
        if length > self.data.len() {
            return Err(ParseError::new(ParseErrorKind::ShortData));
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length(&mut self) -> ParseResult<usize> {
        let b = self.read_u8()?;
        if b & 0x80 == 0 {
            return Ok(b as usize);
        }
        let num_bytes = b & 0x7f;
        // Indefinite length form is not valid DER
        if num_bytes == 0 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }

        let mut length = 0;
        for _ in 0..num_bytes {
            let b = self.read_u8()?;
            if length > (usize::max_value() >> 8) {
                return Err(ParseError::new(ParseErrorKind::IntegerOverflow));
            }
            length <<= 8;
            length |= b as usize;
            // Disallow leading 0s
            if length == 0 {
                return Err(ParseError::new(ParseErrorKind::InvalidValue));
            }
        }
        // Do not allow values <0x80 to be encoded using the long form
        if length < 0x80 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        Ok(length)
    }

    #[inline]
    pub(crate) fn read_tlv(&mut self) -> ParseResult<Tlv<'a>> {
        let initial_data = self.data;

        let tag = self.read_u8()?;
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
    /// MSRV is < 1.51.
    pub fn read_explicit_element<T: Asn1Readable<'a>>(&mut self, tag: u8) -> ParseResult<T> {
        let expected_tag = crate::explicit_tag(tag);
        let tlv = self.read_tlv()?;
        if tlv.tag != expected_tag {
            return Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: tlv.tag,
            }));
        }
        parse_single(tlv.data())
    }

    /// This is an alias for `read_element::<Option<Explicit<T, tag>>>` for use
    /// when MSRV is <1.51.
    pub fn read_optional_explicit_element<T: Asn1Readable<'a>>(
        &mut self,
        tag: u8,
    ) -> ParseResult<Option<T>> {
        let expected_tag = crate::explicit_tag(tag);
        if self.peek_u8() != Some(expected_tag) {
            return Ok(None);
        }
        let tlv = self.read_tlv()?;
        Ok(Some(parse_single::<T>(tlv.data())?))
    }

    /// This is an alias for `read_element::<Implicit<T, tag>>` for use when
    /// MSRV is <1.51.
    pub fn read_implicit_element<T: SimpleAsn1Readable<'a>>(&mut self, tag: u8) -> ParseResult<T> {
        let expected_tag = crate::implicit_tag(tag, T::TAG);
        let tlv = self.read_tlv()?;
        if tlv.tag != expected_tag {
            return Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                actual: tlv.tag,
            }));
        }
        T::parse_data(tlv.data())
    }

    /// This is an alias for `read_element::<Option<Implicit<T, tag>>>` for use
    /// when MSRV is <1.51.
    pub fn read_optional_implicit_element<T: SimpleAsn1Readable<'a>>(
        &mut self,
        tag: u8,
    ) -> ParseResult<Option<T>> {
        let expected_tag = crate::implicit_tag(tag, T::TAG);
        if self.peek_u8() != Some(expected_tag) {
            return Ok(None);
        }
        let tlv = self.read_tlv()?;
        Ok(Some(T::parse_data(tlv.data())?))
    }
}

#[cfg(test)]
mod tests {
    use super::Parser;
    use crate::types::Asn1Readable;
    use crate::{
        BMPString, BigInt, BigUint, BitString, Choice1, Choice2, Choice3, Enumerated,
        GeneralizedTime, IA5String, ObjectIdentifier, ParseError, ParseErrorKind, ParseLocation,
        ParseResult, PrintableString, Sequence, SequenceOf, SetOf, Tlv, UniversalString, UtcTime,
        Utf8String, VisibleString,
    };
    #[cfg(feature = "const-generics")]
    use crate::{Explicit, Implicit};
    use alloc::vec;
    use chrono::{FixedOffset, TimeZone, Utc};
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
            p.read_element::<Sequence>()?
                .parse(|p| p.read_element::<&[u8]>())
        })
        .unwrap();
        assert_eq!(result, b"\x00");

        // BIT_STRING
        let result = crate::parse::<_, ParseError, _>(b"\x03\x02\x00\x00", |p| {
            Ok(p.read_element::<BitString>()?.as_bytes())
        })
        .unwrap();
        assert_eq!(result, b"\x00");
    }

    #[test]
    fn test_parse_error_debug() {
        for (e, expected) in [
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
        ]
        .iter()
        {
            assert_eq!(&format!("{:?}", e), expected)
        }
    }

    #[test]
    fn test_parse_error_display() {
        for (e, expected) in [
            (
                ParseError::new(ParseErrorKind::InvalidValue),
                "ASN.1 parsing error: invalid value",
            ),
            (
                ParseError::new(ParseErrorKind::ShortData)
                    .add_location(ParseLocation::Field("Abc::123")),
                "ASN.1 parsing error: short data",
            ),
            (
                ParseError::new(ParseErrorKind::UnexpectedTag { actual: 12 })
                    .add_location(ParseLocation::Index(12))
                    .add_location(ParseLocation::Field("Abc::123")),
                "ASN.1 parsing error: unexpected tag (got 12)",
            ),
        ]
        .iter()
        {
            assert_eq!(&format!("{}", e), expected)
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
    fn test_errors() {
        #[derive(Debug, PartialEq)]
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
                    Err(E::P(ParseError::new(ParseErrorKind::ShortData))),
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
        assert_parses::<Tlv>(&[
            (
                Ok(Tlv {
                    tag: 0x4,
                    data: b"abc",
                    full_data: b"\x04\x03abc",
                }),
                b"\x04\x03abc",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData)),
                b"\x04\x03a",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x04"),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
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
        assert_parses::<&[u8]>(&[
            (Ok(b""), b"\x04\x00"),
            (Ok(b"\x01\x02\x03"), b"\x04\x03\x01\x02\x03"),
            (
                Ok(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                b"\x04\x81\x81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            (Err(ParseError::new(ParseErrorKind::InvalidValue)), b"\x04\x80"),
            (Err(ParseError::new(ParseErrorKind::InvalidValue)), b"\x04\x81\x00"),
            (Err(ParseError::new(ParseErrorKind::InvalidValue)), b"\x04\x81\x01\x09"),
            (
                Err(ParseError::new(ParseErrorKind::IntegerOverflow)),
                b"\x04\x89\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x04\x03\x01\x02"),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x04\x83\xff\xff\xff\xff\xff\xff"),
        ]);
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
            (
                Ok(core::i64::MAX),
                b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x3,
                })),
                b"\x03\x00",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ShortData)),
                b"\x02\x02\x00",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x02"),
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
        ])
    }

    #[test]
    fn parse_int_u64() {
        assert_parses::<u64>(&[
            (
                Ok(core::u64::MAX),
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
        ])
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
        ])
    }

    #[test]
    fn test_parse_biguint() {
        assert_parses::<BigUint>(&[
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
    fn test_parse_bigint() {
        assert_parses::<BigInt>(&[
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
        ])
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
    fn test_parse_printable_string() {
        assert_parses::<PrintableString>(&[
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
        assert_parses::<IA5String>(&[
            (Ok(IA5String::new("abc").unwrap()), b"\x16\x03abc"),
            (Ok(IA5String::new(")").unwrap()), b"\x16\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x16\x03ab\xff",
            ),
        ])
    }

    #[test]
    fn test_parse_utf8string() {
        assert_parses::<Utf8String>(&[
            (Ok(Utf8String::new("abc")), b"\x0c\x03abc"),
            (Ok(Utf8String::new(")")), b"\x0c\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x0c\x01\xff",
            ),
        ])
    }

    #[test]
    fn test_parse_visiblestring() {
        assert_parses::<VisibleString>(&[
            (Ok(VisibleString::new("abc").unwrap()), b"\x1a\x03abc"),
            (Ok(VisibleString::new(")").unwrap()), b"\x1a\x01)"),
            (
                Err(ParseError::new(ParseErrorKind::InvalidValue)),
                b"\x1a\x01\n",
            ),
        ])
    }

    #[test]
    fn test_parse_bmpstring() {
        assert_parses::<BMPString>(&[
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
        assert_parses::<UniversalString>(&[
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
                Ok(UtcTime::new(
                    FixedOffset::west(7 * 60 * 60)
                        .ymd(1991, 5, 6)
                        .and_hms(16, 45, 40)
                        .into(),
                )
                .unwrap()),
                b"\x17\x11910506164540-0700",
            ),
            (
                Ok(UtcTime::new(
                    FixedOffset::east(7 * 60 * 60 + 30 * 60)
                        .ymd(1991, 5, 6)
                        .and_hms(16, 45, 40)
                        .into(),
                )
                .unwrap()),
                b"\x17\x11910506164540+0730",
            ),
            (
                Ok(UtcTime::new(Utc.ymd(1991, 5, 6).and_hms(23, 45, 40)).unwrap()),
                b"\x17\x0d910506234540Z",
            ),
            (
                Ok(UtcTime::new(Utc.ymd(1991, 5, 6).and_hms(23, 45, 0)).unwrap()),
                b"\x17\x0b9105062345Z",
            ),
            (
                Ok(UtcTime::new(Utc.ymd(1951, 5, 6).and_hms(23, 45, 0)).unwrap()),
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
        ]);
    }

    #[test]
    fn test_generalizedtime() {
        assert_parses::<GeneralizedTime>(&[
            (
                Ok(GeneralizedTime::new(Utc.ymd(2010, 1, 2).and_hms(3, 4, 5))),
                b"\x18\x0f20100102030405Z",
            ),
            (
                Ok(GeneralizedTime::new(
                    FixedOffset::east(6 * 60 * 60 + 7 * 60)
                        .ymd(2010, 1, 2)
                        .and_hms(3, 4, 5)
                        .into(),
                )),
                b"\x18\x1320100102030405+0607",
            ),
            (
                Ok(GeneralizedTime::new(
                    FixedOffset::west(6 * 60 * 60 + 7 * 60)
                        .ymd(2010, 1, 2)
                        .and_hms(3, 4, 5)
                        .into(),
                )),
                b"\x18\x1320100102030405-0607",
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
        ]);
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
                Err(ParseError::new(ParseErrorKind::ShortData)),
                b"\x30\x04\x02\x01\x01",
            ),
            (
                Err(ParseError::new(ParseErrorKind::ExtraData)),
                b"\x30\x06\x02\x01\x01\x02\x01\x02\x00",
            ),
        ])
    }

    #[test]
    fn test_sequence_parse() {
        assert_parses_cb(
            &[
                (Ok((1, 2)), b"\x30\x06\x02\x01\x01\x02\x01\x02"),
                (
                    Err(ParseError::new(ParseErrorKind::ShortData)),
                    b"\x30\x03\x02\x01\x01",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x30\x07\x02\x01\x01\x02\x01\x02\x00",
                ),
            ],
            |p| {
                p.read_element::<Sequence>()?
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
                    Err(ParseError::new(ParseErrorKind::ShortData)),
                    b"\x30\x02\x02\x01",
                ),
            ],
            |p| {
                p.read_element::<Sequence>()?.parse(|p| {
                    let mut result = vec![];
                    while !p.is_empty() {
                        result.push(p.read_element::<i64>()?);
                    }
                    Ok(result)
                })
            },
        )
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
                    Err(ParseError::new(ParseErrorKind::ShortData)
                        .add_location(ParseLocation::Index(0))),
                    b"\x30\x02\x02\x01",
                ),
            ],
            |p| Ok(p.read_element::<SequenceOf<i64>>()?.collect()),
        )
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
                    Err(ParseError::new(ParseErrorKind::ShortData)
                        .add_location(ParseLocation::Index(0))),
                    b"\x31\x01\x02",
                ),
                (
                    Err(
                        ParseError::new(ParseErrorKind::UnexpectedTag { actual: 0x1 })
                            .add_location(ParseLocation::Index(0)),
                    ),
                    b"\x31\x02\x01\x00",
                ),
            ],
            |p| Ok(p.read_element::<SetOf<u64>>()?.collect()),
        )
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
                (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x01"),
                (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x02"),
            ],
            |p| {
                Ok((
                    p.read_element::<Option<bool>>()?,
                    p.read_element::<Option<i64>>()?,
                ))
            },
        );

        assert_parses::<Option<Tlv>>(&[
            (
                Ok(Some(Tlv {
                    tag: 0x4,
                    data: b"abc",
                    full_data: b"\x04\x03abc",
                })),
                b"\x04\x03abc",
            ),
            (Ok(None), b""),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b"\x04"),
        ]);

        assert_parses::<Option<Choice2<u64, bool>>>(&[
            (Ok(None), b""),
            (Ok(Some(Choice2::ChoiceA(17))), b"\x02\x01\x11"),
            (Ok(Some(Choice2::ChoiceB(true))), b"\x01\x01\xff"),
        ]);
    }

    #[test]
    fn test_choice1() {
        assert_parses::<Choice1<bool>>(&[
            (Ok(Choice1::ChoiceA(true)), b"\x01\x01\xff"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x03,
                })),
                b"\x03\x00",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
        ]);
    }

    #[test]
    fn test_choice2() {
        assert_parses::<Choice2<bool, i64>>(&[
            (Ok(Choice2::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice2::ChoiceB(18)), b"\x02\x01\x12"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x03,
                })),
                b"\x03\x00",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
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
                    actual: 0x03,
                })),
                b"\x03\x00",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
        ]);
    }

    #[test]
    fn test_parse_implicit() {
        #[cfg(feature = "const-generics")]
        assert_parses::<Implicit<bool, 2>>(&[
            (Ok(Implicit::new(true)), b"\x82\x01\xff"),
            (Ok(Implicit::new(false)), b"\x82\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x01,
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x02,
                })),
                b"\x02\x01\xff",
            ),
        ]);
        #[cfg(feature = "const-generics")]
        assert_parses::<Implicit<Sequence, 2>>(&[
            (Ok(Implicit::new(Sequence::new(b"abc"))), b"\xa2\x03abc"),
            (Ok(Implicit::new(Sequence::new(b""))), b"\xa2\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x01,
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x02,
                })),
                b"\x02\x01\xff",
            ),
            (Err(ParseError::new(ParseErrorKind::ShortData)), b""),
        ]);

        assert_parses_cb(
            &[
                (Ok(Some(true)), b"\x82\x01\xff"),
                (Ok(Some(false)), b"\x82\x01\x00"),
                (Ok(None), b""),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x02\x01\xff",
                ),
            ],
            |p| p.read_optional_implicit_element::<bool>(2),
        );
        assert_parses_cb(
            &[
                (Ok(Some(Sequence::new(b"abc"))), b"\xa2\x03abc"),
                (Ok(Some(Sequence::new(b""))), b"\xa2\x00"),
                (Ok(None), b""),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x02\x01\xff",
                ),
            ],
            |p| p.read_optional_implicit_element::<Sequence>(2),
        );
    }

    #[test]
    fn test_parse_explicit() {
        #[cfg(feature = "const-generics")]
        assert_parses::<Explicit<bool, 2>>(&[
            (Ok(Explicit::new(true)), b"\xa2\x03\x01\x01\xff"),
            (Ok(Explicit::new(false)), b"\xa2\x03\x01\x01\x00"),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x01,
                })),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x02,
                })),
                b"\x02\x01\xff",
            ),
            (
                Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                    actual: 0x03,
                })),
                b"\xa2\x03\x03\x01\xff",
            ),
        ]);

        assert_parses_cb(
            &[
                (Ok(Some(true)), b"\xa2\x03\x01\x01\xff"),
                (Ok(Some(false)), b"\xa2\x03\x01\x01\x00"),
                (Ok(None), b""),
                (
                    Err(ParseError::new(ParseErrorKind::ExtraData)),
                    b"\x01\x01\xff",
                ),
                (
                    Err(ParseError::new(ParseErrorKind::UnexpectedTag {
                        actual: 0x03,
                    })),
                    b"\xa2\x03\x03\x01\xff",
                ),
            ],
            |p| p.read_optional_explicit_element::<bool>(2),
        );
    }
}
