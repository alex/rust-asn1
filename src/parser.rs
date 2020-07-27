use crate::types::Asn1Element;

/// ParseError are returned when there is an error parsing the ASN.1 data.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParseError {
    /// Something about the value was invalid.
    #[error("invalid value")]
    InvalidValue,
    /// An unexpected tag was encountered.
    #[error("unexpected tag")]
    UnexpectedTag { actual: u8 },
    /// There was not enough data available to complete parsing.
    #[error("not enough data")]
    ShortData,
    /// An internal computation would have overflowed.
    #[error("integer overflow")]
    IntegerOverflow,
    /// There was extraneous data in the input.
    #[error("extra data in the TLV")]
    ExtraData,
}

pub(crate) fn err<T>(v: ParseError) -> anyhow::Result<T> {
    Err(anyhow::Error::new(v))
}

/// Parse takes a sequence of bytes of DER encoded ASN.1 data, constructs a parser, and invokes a
/// callback to read elements from the ASN.1 parser.
pub fn parse<'a, T, F: Fn(&mut Parser<'a>) -> anyhow::Result<T>>(
    data: &'a [u8],
    f: F,
) -> anyhow::Result<T> {
    let mut p = Parser::new(data);
    let result = f(&mut p)?;
    p.finish()?;
    Ok(result)
}

pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Parser<'a> {
        Parser { data }
    }

    fn finish(self) -> anyhow::Result<()> {
        if !self.data.is_empty() {
            return err(ParseError::ExtraData);
        }
        Ok(())
    }

    pub(crate) fn peek_u8(&mut self) -> Option<u8> {
        self.data.get(0).copied()
    }

    fn read_u8(&mut self) -> anyhow::Result<u8> {
        if self.data.is_empty() {
            return err(ParseError::ShortData);
        }
        let (val, data) = self.data.split_at(1);
        self.data = data;
        Ok(val[0])
    }

    fn read_bytes(&mut self, length: usize) -> anyhow::Result<&'a [u8]> {
        if length > self.data.len() {
            return err(ParseError::ShortData);
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length(&mut self) -> anyhow::Result<usize> {
        let b = self.read_u8()?;
        if b & 0x80 == 0 {
            return Ok(b as usize);
        }
        let num_bytes = b & 0x7f;
        // Indefinite length form is not valid DER
        if num_bytes == 0 {
            return err(ParseError::InvalidValue);
        }

        let mut length = 0;
        for _ in 0..num_bytes {
            let b = self.read_u8()?;
            if length > (usize::max_value() >> 8) {
                return err(ParseError::IntegerOverflow);
            }
            length <<= 8;
            length |= b as usize;
            // Disallow leading 0s
            if length == 0 {
                return err(ParseError::InvalidValue);
            }
        }
        // Do not allow values <0x80 to be encoded using the long form
        if length < 0x80 {
            return err(ParseError::InvalidValue);
        }
        Ok(length)
    }

    pub(crate) fn read_tlv(&mut self) -> anyhow::Result<Tlv<'a>> {
        let tag = self.read_u8()?;
        let length = self.read_length()?;
        Ok(Tlv {
            tag,
            data: self.read_bytes(length)?,
        })
    }

    /// Tests whether there is any data remaining in the Parser. Generally
    /// useful when parsing a `SEQUENCE OF`.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a single ASN.1 element from the parser. Which type you are reading is determined by
    /// the type parameter `T`.
    pub fn read_element<T: Asn1Element<'a>>(&mut self) -> anyhow::Result<T::ParsedType> {
        T::parse(self)
    }
}

pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) data: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::{err, Parser};
    use crate::types::Asn1Element;
    use crate::{
        BitString, Choice1, Choice2, Choice3, Explicit, Implicit, ObjectIdentifier, ParseError,
        PrintableString, Sequence, UtcTime,
    };
    use chrono::{FixedOffset, TimeZone, Utc};
    use core::fmt;

    fn assert_result_eq<T: fmt::Debug + PartialEq>(
        result: &anyhow::Result<T>,
        expected: &anyhow::Result<T>,
    ) {
        match (result, expected) {
            (Ok(r), Ok(e)) => assert_eq!(r, e),
            (Err(r), Err(e)) => {
                assert_eq!(format!("{:?}", r), format!("{:?}", e));
            }
            (_, _) => {
                panic!(format!(
                    "Unexpected result. Got: {:?}, expected: {:?}",
                    result, expected
                ));
            }
        }
    }

    fn assert_parses_cb<
        'a,
        T: fmt::Debug + PartialEq,
        F: Fn(&mut Parser<'a>) -> anyhow::Result<T>,
    >(
        data: &[(anyhow::Result<T>, &'a [u8])],
        f: F,
    ) {
        for (expected, der_bytes) in data {
            let result = crate::parse(der_bytes, &f);
            assert_result_eq(&result, expected);
        }
    }

    fn assert_parses<'a, T>(data: &[(anyhow::Result<T::ParsedType>, &'a [u8])])
    where
        T: Asn1Element<'a>,
        T::ParsedType: fmt::Debug + PartialEq,
    {
        assert_parses_cb(data, |p| p.read_element::<T>());
    }

    #[test]
    fn test_parse_extra_data() {
        let result = crate::parse(b"\x00", |_| Ok(()));
        assert_result_eq(&result, &err(ParseError::ExtraData));
    }

    #[test]
    fn test_errors() {
        #[derive(Debug, thiserror::Error)]
        enum E {
            #[error("X happened")]
            X(u64),
        }

        assert_parses_cb(
            &[
                (Ok(8), b"\x02\x01\x08"),
                (err(ParseError::ShortData), b"\x02\x01"),
                (Err(anyhow::Error::new(E::X(7))), b"\x02\x01\x07"),
            ],
            |p| {
                let val = p.read_element::<u64>()?;
                if val % 2 == 0 {
                    Ok(val)
                } else {
                    Err(anyhow::Error::new(E::X(val)))
                }
            },
        );
    }

    #[test]
    fn test_parse_null() {
        assert_parses::<()>(&[
            (Ok(()), b"\x05\x00"),
            (err(ParseError::InvalidValue), b"\x05\x01\x00"),
        ]);
    }

    #[test]
    fn test_parse_bool() {
        assert_parses::<bool>(&[
            (Ok(true), b"\x01\x01\xff"),
            (Ok(false), b"\x01\x01\x00"),
            (err(ParseError::InvalidValue), b"\x01\x00"),
            (err(ParseError::InvalidValue), b"\x01\x01\x01"),
            (err(ParseError::InvalidValue), b"\x01\x02\x00\x00"),
            (err(ParseError::InvalidValue), b"\x01\x02\xff\x01"),
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
            (err(ParseError::InvalidValue), b"\x04\x80"),
            (err(ParseError::InvalidValue), b"\x04\x81\x00"),
            (err(ParseError::InvalidValue), b"\x04\x81\x01\x09"),
            (
                err(ParseError::IntegerOverflow),
                b"\x04\x89\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
            (err(ParseError::ShortData), b"\x04\x03\x01\x02"),
            (err(ParseError::ShortData), b"\x04\x86\xff\xff\xff\xff\xff\xff"),
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
            (err(ParseError::UnexpectedTag { actual: 0x3 }), b"\x03\x00"),
            (err(ParseError::ShortData), b"\x02\x02\x00"),
            (err(ParseError::ShortData), b""),
            (err(ParseError::ShortData), b"\x02"),
            (
                err(ParseError::IntegerOverflow),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                err(ParseError::InvalidValue),
                b"\x02\x05\x00\x00\x00\x00\x01",
            ),
            (err(ParseError::InvalidValue), b"\x02\x02\xff\x80"),
            (err(ParseError::InvalidValue), b"\x02\x00"),
        ])
    }

    #[test]
    fn parse_int_u64() {
        assert_parses::<u64>(&[
            (
                Ok(core::u64::MAX),
                b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
            (err(ParseError::InvalidValue), b"\x02\x01\xff"),
            (
                err(ParseError::IntegerOverflow),
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
            (err(ParseError::IntegerOverflow), b"\x02\x02\x02\x00"),
            (err(ParseError::InvalidValue), b"\x02\x00"),
        ])
    }

    #[test]
    fn test_parse_int_u8() {
        assert_parses::<u8>(&[
            (Ok(0u8), b"\x02\x01\x00"),
            (Ok(127u8), b"\x02\x01\x7f"),
            (Ok(255u8), b"\x02\x02\x00\xff"),
            (err(ParseError::IntegerOverflow), b"\x02\x02\x01\x00"),
            (err(ParseError::InvalidValue), b"\x02\x01\x80"),
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
            (err(ParseError::InvalidValue), b"\x06\x00"),
            (
                err(ParseError::InvalidValue),
                b"\x06\x07\x55\x02\xc0\x80\x80\x80\x80",
            ),
            (err(ParseError::InvalidValue), b"\x06\x02\x2a\x86"),
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
            (err(ParseError::InvalidValue), b"\x03\x00"),
            (err(ParseError::InvalidValue), b"\x03\x02\x07\x01"),
            (err(ParseError::InvalidValue), b"\x03\x02\x07\x40"),
            (err(ParseError::InvalidValue), b"\x03\x02\x08\x00"),
        ]);
    }

    #[test]
    fn test_parse_printable_string() {
        assert_parses::<PrintableString>(&[
            (Ok("abc"), b"\x13\x03abc"),
            (Ok(")"), b"\x13\x01)"),
            (err(ParseError::InvalidValue), b"\x13\x03ab\x00"),
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
            (err(ParseError::InvalidValue), b"\x17\x0da10506234540Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d91a506234540Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d9105a6234540Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d910506a34540Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d910506334a40Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d91050633444aZ"),
            (err(ParseError::InvalidValue), b"\x17\x0d910506334461Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e910506334400Za"),
            (err(ParseError::InvalidValue), b"\x17\x0d000100000000Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d101302030405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100002030405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100100030405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100132030405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100231030405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100102240405Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100102036005Z"),
            (err(ParseError::InvalidValue), b"\x17\x0d100102030460Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e-100102030410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e10-0102030410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e10-0002030410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e1001-02030410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e100102-030410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e10010203-0410Z"),
            (err(ParseError::InvalidValue), b"\x17\x0e1001020304-10Z"),
        ]);
    }

    #[test]
    fn test_parse_sequence() {
        assert_parses::<Sequence<'_>>(&[
            (
                Ok(Sequence::new(b"\x02\x01\x01\x02\x01\x02")),
                b"\x30\x06\x02\x01\x01\x02\x01\x02",
            ),
            (err(ParseError::ShortData), b"\x30\x04\x02\x01\x01"),
            (
                err(ParseError::ExtraData),
                b"\x30\x06\x02\x01\x01\x02\x01\x02\x00",
            ),
        ])
    }

    #[test]
    fn test_sequence_parse() {
        assert_parses_cb(
            &[
                (Ok((1, 2)), b"\x30\x06\x02\x01\x01\x02\x01\x02"),
                (err(ParseError::ShortData), b"\x30\x03\x02\x01\x01"),
                (
                    err(ParseError::ExtraData),
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
    fn test_parse_sequence_of() {
        assert_parses_cb(
            &[
                (
                    Ok(vec![1, 2, 3]),
                    b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
                ),
                (Ok(vec![]), b"\x30\x00"),
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
    fn test_parse_optional() {
        assert_parses_cb(
            &[
                (Ok((Some(true), None)), b"\x01\x01\xff"),
                (Ok((Some(false), None)), b"\x01\x01\x00"),
                (Ok((None, Some(18))), b"\x02\x01\x12"),
                (Ok((Some(true), Some(18))), b"\x01\x01\xff\x02\x01\x12"),
                (Ok((None, None)), b""),
                (err(ParseError::ShortData), b"\x01"),
                (err(ParseError::ShortData), b"\x02"),
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
            (err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_choice2() {
        assert_parses::<Choice2<bool, i64>>(&[
            (Ok(Choice2::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice2::ChoiceB(18)), b"\x02\x01\x12"),
            (err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_choice3() {
        assert_parses::<Choice3<bool, i64, ()>>(&[
            (Ok(Choice3::ChoiceA(true)), b"\x01\x01\xff"),
            (Ok(Choice3::ChoiceB(18)), b"\x02\x01\x12"),
            (Ok(Choice3::ChoiceC(())), b"\x05\x00"),
            (err(ParseError::UnexpectedTag { actual: 0x03 }), b"\x03"),
            (err(ParseError::ShortData), b""),
        ]);
    }

    #[test]
    fn test_parse_implicit() {
        assert_parses::<Implicit<bool, 2>>(&[
            (Ok(true), b"\x82\x01\xff"),
            (Ok(false), b"\x82\x01\x00"),
            (
                err(ParseError::UnexpectedTag { actual: 0x01 }),
                b"\x01\x01\xff",
            ),
            (
                err(ParseError::UnexpectedTag { actual: 0x02 }),
                b"\x02\x01\xff",
            ),
        ]);
    }

    #[test]
    fn test_parse_explicit() {
        assert_parses::<Explicit<bool, 2>>(&[
            (Ok(true), b"\xa2\x03\x01\x01\xff"),
            (Ok(false), b"\xa2\x03\x01\x01\x00"),
            (
                err(ParseError::UnexpectedTag { actual: 0x01 }),
                b"\x01\x01\xff",
            ),
            (
                err(ParseError::UnexpectedTag { actual: 0x02 }),
                b"\x02\x01\xff",
            ),
            (
                err(ParseError::UnexpectedTag { actual: 0x03 }),
                b"\xa2\x03\x03\x01\xff",
            ),
        ]);
    }
}
