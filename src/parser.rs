use core::marker::PhantomData;
use core::mem;

use crate::{BitString, ObjectIdentifier};

const CONTEXT_SPECIFIC: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidValue,
    UnexpectedTag { actual: u8 },
    ShortData,
    IntegerOverflow,
    ExtraData,
}

pub type ParseResult<T> = Result<T, ParseError>;

pub fn parse<'a, T, F: Fn(&mut Parser<'a>) -> ParseResult<T>>(
    data: &'a [u8],
    f: F,
) -> ParseResult<T> {
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

    fn finish(self) -> ParseResult<()> {
        if !self.data.is_empty() {
            return Err(ParseError::ExtraData);
        }
        Ok(())
    }

    fn peek_u8(&mut self) -> Option<u8> {
        self.data.get(0).copied()
    }

    fn read_u8(&mut self) -> ParseResult<u8> {
        if self.data.is_empty() {
            return Err(ParseError::ShortData);
        }
        let (val, data) = self.data.split_at(1);
        self.data = data;
        Ok(val[0])
    }

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

    fn read_tlv(&mut self) -> ParseResult<Tlv<'a>> {
        let tag = self.read_u8()?;
        let length = self.read_length()?;
        Ok(Tlv {
            tag,
            data: self.read_bytes(length)?,
        })
    }

    pub fn read_element<T: Asn1Element<'a>>(&mut self) -> ParseResult<T::Output> {
        T::parse(self)
    }
}

struct Tlv<'a> {
    tag: u8,
    data: &'a [u8],
}

pub trait Asn1Element<'a>: Sized {
    type Output;
    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::Output>;
}

pub trait SimpleAsn1Element<'a>: Sized {
    const TAG: u8;
    type Output;
    fn parse_data(data: &'a [u8]) -> ParseResult<Self::Output>;
}

impl<'a, T: SimpleAsn1Element<'a>> Asn1Element<'a> for T {
    type Output = T::Output;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::Output> {
        let tlv = parser.read_tlv()?;
        if tlv.tag != Self::TAG {
            return Err(ParseError::UnexpectedTag { actual: tlv.tag });
        }
        Self::parse_data(tlv.data)
    }
}

impl SimpleAsn1Element<'_> for () {
    const TAG: u8 = 0x05;
    type Output = ();
    fn parse_data(data: &[u8]) -> ParseResult<()> {
        match data {
            b"" => Ok(()),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

impl SimpleAsn1Element<'_> for bool {
    const TAG: u8 = 0x1;
    type Output = bool;
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
    type Output = &'a [u8];
    fn parse_data(data: &'a [u8]) -> ParseResult<&'a [u8]> {
        Ok(data)
    }
}

pub enum PrintableString {}

impl<'a> SimpleAsn1Element<'a> for PrintableString {
    const TAG: u8 = 0x13;
    type Output = &'a str;
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
    ($t:ty) => {
        impl SimpleAsn1Element<'_> for $t {
            const TAG: u8 = 0x02;
            type Output = Self;
            fn parse_data(data: &[u8]) -> ParseResult<Self::Output> {
                if data.is_empty() {
                    return Err(ParseError::InvalidValue);
                }
                if data.len() > 1
                    && ((data[0] == 0 && data[1] & 0x80 == 0)
                        || (data[0] == 0xff && data[1] & 0x80 == 0x80))
                {
                    return Err(ParseError::InvalidValue);
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

impl_asn1_element_for_int!(i8);
impl_asn1_element_for_int!(i64);

impl<'a> SimpleAsn1Element<'a> for ObjectIdentifier<'a> {
    const TAG: u8 = 0x06;
    type Output = ObjectIdentifier<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<ObjectIdentifier<'a>> {
        ObjectIdentifier::from_der(data).ok_or(ParseError::InvalidValue)
    }
}

impl<'a> SimpleAsn1Element<'a> for BitString<'a> {
    const TAG: u8 = 0x03;
    type Output = BitString<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<BitString<'a>> {
        if data.is_empty() {
            return Err(ParseError::InvalidValue);
        }
        BitString::new(&data[1..], data[0]).ok_or(ParseError::InvalidValue)
    }
}

impl<'a, T: SimpleAsn1Element<'a>> Asn1Element<'a> for Option<T> {
    type Output = Option<T::Output>;

    fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::Output> {
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
        #[derive(Debug, PartialEq)]
        pub enum $count<
            'a,
            $(
                $number: SimpleAsn1Element<'a>,
            )*
        > {
            $(
                $name($number::Output),
            )*
        }

        impl<
            'a,
            $(
                $number: SimpleAsn1Element<'a>,
            )*
        > Asn1Element<'a> for $count<'a, $($number,)*> {
            type Output = Self;

            fn parse(parser: &mut Parser<'a>) -> ParseResult<Self::Output> {
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

#[derive(Debug, PartialEq)]
pub struct Sequence<'a> {
    data: &'a [u8],
}

impl<'a> Sequence<'a> {
    fn new(data: &'a [u8]) -> Sequence<'a> {
        Sequence { data }
    }

    pub fn parse<T, F: Fn(&mut Parser) -> ParseResult<T>>(self, f: F) -> ParseResult<T> {
        parse(self.data, f)
    }
}

impl<'a> SimpleAsn1Element<'a> for Sequence<'a> {
    const TAG: u8 = 0x10 | CONSTRUCTED;
    type Output = Sequence<'a>;
    fn parse_data(data: &'a [u8]) -> ParseResult<Sequence<'a>> {
        Ok(Sequence::new(data))
    }
}

pub struct Implicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, T: SimpleAsn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a>
    for Implicit<'a, T, { TAG }>
{
    const TAG: u8 = CONTEXT_SPECIFIC | TAG | (T::TAG & CONSTRUCTED);
    type Output = T::Output;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::Output> {
        T::parse_data(data)
    }
}

pub struct Explicit<'a, T: Asn1Element<'a>, const TAG: u8> {
    _inner: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, T: Asn1Element<'a>, const TAG: u8> SimpleAsn1Element<'a> for Explicit<'a, T, { TAG }> {
    const TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | TAG;
    type Output = T::Output;
    fn parse_data(data: &'a [u8]) -> ParseResult<T::Output> {
        parse(data, |p| p.read_element::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::{Asn1Element, Parser};
    use crate::{
        BitString, Choice1, Choice2, Choice3, Explicit, Implicit, ObjectIdentifier, ParseError,
        ParseResult, PrintableString, Sequence,
    };
    use core::fmt;

    fn assert_parses_cb<'a, T: fmt::Debug + PartialEq, F: Fn(&mut Parser<'a>) -> ParseResult<T>>(
        data: &[(ParseResult<T>, &'a [u8])],
        f: F,
    ) {
        for (expected, der_bytes) in data {
            let result = crate::parse(der_bytes, &f);
            assert_eq!(&result, expected)
        }
    }

    fn assert_parses<'a, T>(data: &[(ParseResult<T::Output>, &'a [u8])])
    where
        T: Asn1Element<'a>,
        T::Output: fmt::Debug + PartialEq,
    {
        assert_parses_cb(data, |p| p.read_element::<T>());
    }

    #[test]
    fn test_parse_extra_data() {
        let result = crate::parse(b"\x00", |_| Ok(()));
        assert_eq!(result, Err(ParseError::ExtraData));
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
    fn test_printable_string() {
        assert_parses::<PrintableString>(&[
            (Ok("abc"), b"\x13\x03abc"),
            (Ok(")"), b"\x13\x01)"),
            (Err(ParseError::InvalidValue), b"\x13\x03ab\x00"),
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
    }

    #[test]
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
