use crate::types::{Asn1Element, Tlv};

/// ParseError are returned when there is an error parsing the ASN.1 data.
#[derive(Debug, PartialEq)]
pub enum ParseError {
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
    /// Elements of a set were not lexicographically sorted
    InvalidSetOrdering,
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
            return Err(ParseError::ExtraData);
        }
        Ok(())
    }

    pub(crate) fn peek_u8(&mut self) -> Option<u8> {
        self.data.get(0).copied()
    }

    #[inline]
    fn read_u8(&mut self) -> ParseResult<u8> {
        if self.data.is_empty() {
            return Err(ParseError::ShortData);
        }
        let (val, data) = self.data.split_at(1);
        self.data = data;
        Ok(val[0])
    }

    #[inline]
    fn read_bytes(&mut self, length: usize) -> ParseResult<&'a [u8]> {
        if length > self.data.len() {
            return Err(ParseError::ShortData);
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
            return Err(ParseError::InvalidValue);
        }

        let mut length = 0;
        for _ in 0..num_bytes {
            let b = self.read_u8()?;
            if length > (usize::max_value() >> 8) {
                return Err(ParseError::IntegerOverflow);
            }
            length <<= 8;
            length |= b as usize;
            // Disallow leading 0s
            if length == 0 {
                return Err(ParseError::InvalidValue);
            }
        }
        // Do not allow values <0x80 to be encoded using the long form
        if length < 0x80 {
            return Err(ParseError::InvalidValue);
        }
        Ok(length)
    }

    #[inline]
    pub(crate) fn read_tlv(&mut self) -> ParseResult<Tlv<'a>> {
        let tag = self.read_u8()?;
        let length = self.read_length()?;
        Ok(Tlv {
            tag,
            data: self.read_bytes(length)?,
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
    pub fn read_element<T: Asn1Element<'a>>(&mut self) -> ParseResult<T::ParsedType> {
        T::parse(self)
    }
}

#[cfg(test)]
mod tests {
    use super::Parser;
    use crate::types::Asn1Element;
    use crate::{
        BitString, Choice1, Choice2, Choice3, ObjectIdentifier, ParseError, ParseResult,
        PrintableString, Sequence, SequenceOf, SetOf, Tlv, UtcTime,
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
            assert_eq!(&result, expected)
        }
    }

    fn assert_parses<'a, T>(data: &[(ParseResult<T::ParsedType>, &'a [u8])])
    where
        T: Asn1Element<'a>,
        T::ParsedType: fmt::Debug + PartialEq,
    {
        assert_parses_cb(data, |p| p.read_element::<T>());
    }

    #[test]
    fn test_parse_extra_data() {
        let result = crate::parse(b"\x00", |_| Ok(()));
        assert_eq!(result, Err(ParseError::ExtraData));
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
                (Err(E::P(ParseError::ShortData)), b"\x02\x01"),
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
                }),
                b"\x04\x03abc",
            ),
            (Err(ParseError::ShortData), b"\x04\x03a"),
            (Err(ParseError::ShortData), b"\x04"),
            (Err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_parse_null() {
        assert_parses::<()>(&[
            (Ok(()), b"\x05\x00"),
            (Err(ParseError::InvalidValue), b"\x05\x01\x00"),
        ]);
    }

    #[test]
    fn test_parse_bool() {
        assert_parses::<bool>(&[
            (Ok(true), b"\x01\x01\xff"),
            (Ok(false), b"\x01\x01\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x01\x01"),
            (Err(ParseError::InvalidValue), b"\x01\x02\x00\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x02\xff\x01"),
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
            (Err(ParseError::InvalidValue), b"\x04\x80"),
            (Err(ParseError::InvalidValue), b"\x04\x81\x00"),
            (Err(ParseError::InvalidValue), b"\x04\x81\x01\x09"),
            (
                Err(ParseError::IntegerOverflow),
                b"\x04\x89\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            (Err(ParseError::ShortData), b"\x04\x03\x01\x02"),
            (Err(ParseError::ShortData), b"\x04\x86\xff\xff\xff\xff\xff\xff"),
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
            (Err(ParseError::UnexpectedTag { actual: 0x3 }), b"\x03\x00"),
            (Err(ParseError::ShortData), b"\x02\x02\x00"),
            (Err(ParseError::ShortData), b""),
            (Err(ParseError::ShortData), b"\x02"),
            (
                Err(ParseError::IntegerOverflow),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                Err(ParseError::InvalidValue),
                b"\x02\x05\x00\x00\x00\x00\x01",
            ),
            (Err(ParseError::InvalidValue), b"\x02\x02\xff\x80"),
            (Err(ParseError::InvalidValue), b"\x02\x00"),
        ])
    }

    #[test]
    fn parse_int_u64() {
        assert_parses::<u64>(&[
            (
                Ok(core::u64::MAX),
                b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (Err(ParseError::InvalidValue), b"\x02\x01\xff"),
            (
                Err(ParseError::IntegerOverflow),
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
            (Err(ParseError::IntegerOverflow), b"\x02\x02\x02\x00"),
            (Err(ParseError::InvalidValue), b"\x02\x00"),
        ])
    }

    #[test]
    fn test_parse_int_u8() {
        assert_parses::<u8>(&[
            (Ok(0u8), b"\x02\x01\x00"),
            (Ok(127u8), b"\x02\x01\x7f"),
            (Ok(255u8), b"\x02\x02\x00\xff"),
            (Err(ParseError::IntegerOverflow), b"\x02\x02\x01\x00"),
            (Err(ParseError::InvalidValue), b"\x02\x01\x80"),
        ])
    }

    #[test]
    fn test_parse_object_identitifer() {
        assert_parses::<ObjectIdentifier<'_>>(&[
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
            (Err(ParseError::InvalidValue), b"\x06\x00"),
            (
                Err(ParseError::InvalidValue),
                b"\x06\x07\x55\x02\xc0\x80\x80\x80\x80",
            ),
            (Err(ParseError::InvalidValue), b"\x06\x02\x2a\x86"),
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
            (Err(ParseError::InvalidValue), b"\x03\x00"),
            (Err(ParseError::InvalidValue), b"\x03\x02\x07\x01"),
            (Err(ParseError::InvalidValue), b"\x03\x02\x07\x40"),
            (Err(ParseError::InvalidValue), b"\x03\x02\x08\x00"),
        ]);
    }

    #[test]
    fn test_parse_printable_string() {
        assert_parses::<PrintableString>(&[
            (Ok("abc"), b"\x13\x03abc"),
            (Ok(")"), b"\x13\x01)"),
            (Err(ParseError::InvalidValue), b"\x13\x03ab\x00"),
        ]);
    }

    #[test]
    fn test_parse_utctime() {
        assert_parses::<UtcTime>(&[
            (
                Ok(FixedOffset::west(7 * 60 * 60)
                    .ymd(1991, 5, 6)
                    .and_hms(16, 45, 40)
                    .into()),
                b"\x17\x11910506164540-0700",
            ),
            (
                Ok(FixedOffset::east(7 * 60 * 60 + 30 * 60)
                    .ymd(1991, 5, 6)
                    .and_hms(16, 45, 40)
                    .into()),
                b"\x17\x11910506164540+0730",
            ),
            (
                Ok(Utc.ymd(1991, 5, 6).and_hms(23, 45, 40)),
                b"\x17\x0d910506234540Z",
            ),
            (
                Ok(Utc.ymd(1991, 5, 6).and_hms(23, 45, 0)),
                b"\x17\x0b9105062345Z",
            ),
            (
                Ok(Utc.ymd(1951, 5, 6).and_hms(23, 45, 0)),
                b"\x17\x0b5105062345Z",
            ),
            (Err(ParseError::InvalidValue), b"\x17\x0da10506234540Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d91a506234540Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d9105a6234540Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d910506a34540Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d910506334a40Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d91050633444aZ"),
            (Err(ParseError::InvalidValue), b"\x17\x0d910506334461Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e910506334400Za"),
            (Err(ParseError::InvalidValue), b"\x17\x0d000100000000Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d101302030405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100002030405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100100030405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100132030405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100231030405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100102240405Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100102036005Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0d100102030460Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e-100102030410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e10-0102030410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e10-0002030410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e1001-02030410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e100102-030410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e10010203-0410Z"),
            (Err(ParseError::InvalidValue), b"\x17\x0e1001020304-10Z"),
        ]);
    }

    #[test]
    fn test_parse_sequence() {
        assert_parses::<Sequence<'_>>(&[
            (
                Ok(Sequence::new(b"\x02\x01\x01\x02\x01\x02")),
                b"\x30\x06\x02\x01\x01\x02\x01\x02",
            ),
            (Err(ParseError::ShortData), b"\x30\x04\x02\x01\x01"),
            (
                Err(ParseError::ExtraData),
                b"\x30\x06\x02\x01\x01\x02\x01\x02\x00",
            ),
        ])
    }

    #[test]
    fn test_sequence_parse() {
        assert_parses_cb(
            &[
                (Ok((1, 2)), b"\x30\x06\x02\x01\x01\x02\x01\x02"),
                (Err(ParseError::ShortData), b"\x30\x03\x02\x01\x01"),
                (
                    Err(ParseError::ExtraData),
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
                (Err(ParseError::ShortData), b"\x30\x02\x02\x01"),
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
                (Err(ParseError::ShortData), b"\x30\x02\x02\x01"),
            ],
            |p| p.read_element::<SequenceOf<i64>>()?.collect(),
        )
    }

    #[test]
    fn parse_set_of() {
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x37\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (Ok(vec![]), b"\x37\x00"),
                (
                    Err(ParseError::InvalidSetOrdering),
                    b"\x37\x06\x02\x01\x03\x02\x01\x01",
                ),
                (Err(ParseError::ShortData), b"\x37\x01\x02"),
                (
                    Err(ParseError::UnexpectedTag { actual: 0x1 }),
                    b"\x37\x02\x01\x00",
                ),
            ],
            |p| p.read_element::<SetOf<u64>>()?.collect(),
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
                (Err(ParseError::ShortData), b"\x01"),
                (Err(ParseError::ShortData), b"\x02"),
            ],
            |p| {
                Ok((
                    p.read_element::<Option<bool>>()?,
                    p.read_element::<Option<i64>>()?,
                ))
            },
        )
    }

    #[test]
    fn test_choice1() {
        assert_parses::<Choice1<bool>>(&[
            (Ok(Choice1::ChoiceA(true)), b"\x01\x01\xff"),
            (Err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (Err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_choice2() {
        assert_parses::<Choice2<bool, i64>>(&[
            (Ok(Choice2::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice2::ChoiceB(18)), b"\x02\x01\x12"),
            (Err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (Err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_choice3() {
        assert_parses::<Choice3<bool, i64, ()>>(&[
            (Ok(Choice3::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice3::ChoiceB(18)), b"\x02\x01\x12"),
            (Ok(Choice3::ChoiceC(())), b"\x05\x00"),
            (Err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (Err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    #[cfg(feature = "const-generics")]
    fn test_parse_implicit() {
        assert_parses::<Implicit<bool, 2>>(&[
            (Ok(true), b"\x82\x01\xff"),
            (Ok(false), b"\x82\x01\x00"),
            (
                Err(ParseError::UnexpectedTag { actual: 0x01 }),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::UnexpectedTag { actual: 0x02 }),
                b"\x02\x01\xff",
            ),
        ]);
        assert_parses::<Implicit<Sequence, 2>>(&[
            (Ok(Sequence::new(b"abc")), b"\xa2\x03abc"),
            (Ok(Sequence::new(b"")), b"\xa2\x00"),
            (
                Err(ParseError::UnexpectedTag { actual: 0x01 }),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::UnexpectedTag { actual: 0x02 }),
                b"\x02\x01\xff",
            ),
            (Err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    #[cfg(feature = "const-generics")]
    fn test_parse_explicit() {
        assert_parses::<Explicit<bool, 2>>(&[
            (Ok(true), b"\xa2\x03\x01\x01\xff"),
            (Ok(false), b"\xa2\x03\x01\x01\x00"),
            (
                Err(ParseError::UnexpectedTag { actual: 0x01 }),
                b"\x01\x01\xff",
            ),
            (
                Err(ParseError::UnexpectedTag { actual: 0x02 }),
                b"\x02\x01\xff",
            ),
            (
                Err(ParseError::UnexpectedTag { actual: 0x03 }),
                b"\xa2\x03\x03\x01\xff",
            ),
        ]);
    }
}
