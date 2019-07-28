use std::mem;

use crate::ObjectIdentifier;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidValue,
    UnexpectedTag { expected: u8, actual: u8 },
    ShortData,
    IntegerOverflow,
    ExtraData,
}

pub type ParseResult<T> = Result<T, ParseError>;

pub fn parse<'a, T, F: Fn(&mut Parser<'a>) -> Result<T, ParseError>>(
    data: &'a [u8],
    f: F,
) -> ParseResult<T> {
    let mut p = Parser::new(data);
    let result = f(&mut p)?;
    p.finish()?;
    return Ok(result);
}

pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Parser<'a> {
        return Parser { data };
    }

    fn finish(self) -> ParseResult<()> {
        if !self.data.is_empty() {
            return Err(ParseError::ExtraData);
        }
        return Ok(());
    }

    fn read_u8(&mut self) -> ParseResult<u8> {
        if self.data.is_empty() {
            return Err(ParseError::ShortData);
        }
        let (val, data) = self.data.split_at(1);
        self.data = data;
        return Ok(val[0]);
    }

    fn read_bytes(&mut self, length: usize) -> ParseResult<&'a [u8]> {
        if length > self.data.len() {
            return Err(ParseError::ShortData);
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        return Ok(result);
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
        return Ok(length);
    }

    fn read_tlv(&mut self) -> ParseResult<Tlv<'a>> {
        let tag = self.read_u8()?;
        let length = self.read_length()?;
        return Ok(Tlv {
            tag: tag,
            data: self.read_bytes(length)?,
        });
    }

    pub fn read_element<T: Asn1Element<'a>>(&mut self) -> ParseResult<T> {
        let tlv = self.read_tlv()?;
        if tlv.tag != T::TAG {
            return Err(ParseError::UnexpectedTag {
                expected: T::TAG,
                actual: tlv.tag,
            });
        }
        return T::parse(tlv.data);
    }
}

struct Tlv<'a> {
    tag: u8,
    data: &'a [u8],
}

pub trait Asn1Element<'a>: Sized {
    const TAG: u8;
    fn parse(tlv: &'a [u8]) -> ParseResult<Self>;
}

impl Asn1Element<'_> for bool {
    const TAG: u8 = 0x1;
    fn parse(data: &[u8]) -> ParseResult<bool> {
        match data {
            b"\x00" => Ok(false),
            b"\xff" => Ok(true),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

impl<'a> Asn1Element<'a> for &'a [u8] {
    const TAG: u8 = 0x04;
    fn parse(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        return Ok(data);
    }
}

impl Asn1Element<'_> for i64 {
    const TAG: u8 = 0x02;
    fn parse(data: &[u8]) -> ParseResult<i64> {
        if data.is_empty() {
            return Err(ParseError::InvalidValue);
        }
        if data.len() > 1 {
            if (data[0] == 0 && data[1] & 0x80 == 0) || (data[0] == 0xff && data[1] & 0x80 == 0x80)
            {
                return Err(ParseError::InvalidValue);
            }
        }

        if data.len() > mem::size_of::<Self>() {
            return Err(ParseError::IntegerOverflow);
        }

        let mut ret = 0;
        for b in data {
            ret <<= 8;
            ret |= *b as Self;
        }
        // Shift up and down in order to sign extend the result.
        ret <<= 64 - data.len() * 8;
        ret >>= 64 - data.len() * 8;
        return Ok(ret);
    }
}

impl<'a> Asn1Element<'a> for ObjectIdentifier<'a> {
    const TAG: u8 = 0x06;
    fn parse(data: &'a [u8]) -> ParseResult<ObjectIdentifier<'a>> {
        return ObjectIdentifier::from_der(data).ok_or(ParseError::InvalidValue);
    }
}

#[cfg(test)]
mod tests {
    use super::Asn1Element;
    use crate::{ObjectIdentifier, ParseError, ParseResult};
    use std::fmt;

    fn assert_parses<'a, T: Asn1Element<'a> + fmt::Debug + PartialEq>(
        data: &[(ParseResult<T>, &'a [u8])],
    ) {
        for (expected, der_bytes) in data {
            let result = crate::parse(der_bytes, |p| p.read_element::<T>());
            assert_eq!(&result, expected);
        }
    }

    #[test]
    fn test_read_extra_data() {
        let result = crate::parse(b"\x00", |_| Ok(()));
        assert_eq!(result, Err(ParseError::ExtraData));
    }

    #[test]
    fn test_parse_bool() {
        assert_parses(&[
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
        assert_parses(&[
            (Ok(0), b"\x02\x01\x00"),
            (Ok(127), b"\x02\x01\x7f"),
            (Ok(128), b"\x02\x02\x00\x80"),
            (Ok(256), b"\x02\x02\x01\x00"),
            (Ok(-128), b"\x02\x01\x80"),
            (Ok(-129), b"\x02\x02\xff\x7f"),
            (Ok(-256), b"\x02\x02\xff\x00"),
            (
                Ok(std::i64::MAX),
                b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff",
            ),
            (
                Err(ParseError::UnexpectedTag {
                    expected: 0x2,
                    actual: 0x3,
                }),
                b"\x03\x00",
            ),
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
    fn test_parse_object_identitifer() {
        assert_parses(&[
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
}
