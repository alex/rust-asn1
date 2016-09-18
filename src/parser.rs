use std::{convert, mem};
use std::io::{self, BufRead, Cursor};
use std::marker::{PhantomData};

use byteorder::{ReadBytesExt};



#[derive(Debug, PartialEq)]
pub enum ParseError {
    ExtraData,
    InvalidValue,
    IntegerOverflow,
    ShortData,
    UnexpectedTag{expected: u8, actual: u8},
}


impl convert::From<io::Error> for ParseError {
    fn from(e: io::Error) -> ParseError {
        return match e.kind() {
            io::ErrorKind::UnexpectedEof => ParseError::ShortData,
            _ => panic!("Unexpected error!"),
        }
    }
}

pub type ParseResult<T> = Result<T, ParseError>;

pub struct Parser<'a> {
    reader: Cursor<&'a [u8]>,
}

pub trait Asn1Element {
    type Result;
    const TAG: u8;

    fn parse(&[u8]) -> ParseResult<Self::Result>;
}

struct Boolean {}

impl Asn1Element for Boolean {
    type Result = bool;
    const TAG: u8 = 0x1;

    fn parse(data: &[u8]) -> ParseResult<bool> {
        if data == b"\x00" {
            return Ok(false);
        } else if data == b"\xff" {
            return Ok(true)
        } else {
            return Err(ParseError::InvalidValue);
        }
    }
}

trait Asn1Integer: Sized {
    fn parse(&[u8]) -> ParseResult<Self>;
}

struct Integer<T> where T: Asn1Integer {
    integer_type: PhantomData<T>,
}

impl<T> Asn1Element for Integer<T> where T: Asn1Integer {
    type Result = T;
    const TAG: u8 = 0x2;

    fn parse(data: &[u8]) -> ParseResult<T> {
        if data.len() > 1 {
            match (data[0], data[1] & 0x80) {
                (0xff, 0x80) | (0x00, 0x00) => return Err(ParseError::InvalidValue),
                _ => {},
            }
        }
        T::parse(data)
    }
}

macro_rules! primitive_integer {
    ($Int:ident) => {
        impl Asn1Integer for $Int {
            fn parse(data: &[u8]) -> ParseResult<$Int> {
                if data.len() > mem::size_of::<$Int>() {
                    return Err(ParseError::IntegerOverflow);
                } else if data.is_empty() {
                    return Err(ParseError::InvalidValue);
                }

                let mut ret = 0;
                for b in data.iter() {
                    ret <<= 8;
                    ret |= *b as i64;
                }
                // Shift up and down in order to sign extend the result.
                ret <<= 64 - data.len() * 8;
                ret >>= 64 - data.len() * 8;
                return Ok(ret as $Int);
            }
        }
    }
}

primitive_integer!(i8);
primitive_integer!(i32);
primitive_integer!(i64);

struct TLV {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl<'a> Parser<'a> {
    pub fn new(data: &[u8]) -> Parser {
        return Parser{reader: Cursor::new(data)};
    }

    fn read_length(&mut self) -> ParseResult<usize> {
        let b = try!(self.reader.read_u8());
        if b&0x80 == 0 {
            return Ok((b & 0x7f) as usize);
        }
        let num_bytes = b & 0x7f;
        // Indefinite lengths are not valid DER.
        if num_bytes == 0 {
            return Err(ParseError::InvalidValue);
        }
        let mut length = 0;
        for _ in 0..num_bytes {
            let b = try!(self.reader.read_u8());
            // Handle overflows
            if length > (usize::max_value() >> 8) {
                return Err(ParseError::IntegerOverflow);
            }
            length <<= 8;
            length |= b as usize;
            // Disallow leading 0s.
            if length == 0 {
                return Err(ParseError::InvalidValue);
            }
        }
        // Do not allow values <127 to be encoded using the long form
        if length < 128 {
            return Err(ParseError::InvalidValue);
        }
        return Ok(length);
    }

    fn read_tlv(&mut self) -> ParseResult<TLV> {
        let tag = try!(self.reader.read_u8());
        let length = try!(self.read_length());
        let value = {
            let buf = self.reader.fill_buf().unwrap();
            if buf.len() < length {
                return Err(ParseError::ShortData);
            }
            buf[..length].to_vec()
        };
        self.reader.consume(length);
        return Ok(TLV{tag: tag, value: value});
    }

    pub fn read<T>(&mut self) -> ParseResult<T::Result> where T: Asn1Element {
        let tlv = try!(self.read_tlv());
        if tlv.tag != T::TAG {
            return Err(ParseError::UnexpectedTag{expected: T::TAG, actual: tlv.tag});
        }
        return T::parse(&tlv.value);
    }

    pub fn finish(&mut self) -> ParseResult<()> {
        if self.reader.position() as usize != self.reader.get_ref().len() {
            return Err(ParseError::ExtraData);
        }
        return Ok(());
    }
}


fn parse<T, F>(data: &[u8], f: F) -> ParseResult<T>
        where F: Fn(&mut Parser) -> ParseResult<T> {
    let mut parser = Parser::new(data);
    let result = try!(f(&mut parser));
    try!(parser.finish());
    return Ok(result);
}

#[cfg(test)]
mod tests {
    use std::{self, fmt};

    use super::{parse, Parser, ParseError, ParseResult};

    fn assert_parses<T, F>(values: Vec<(ParseResult<T>, &[u8])>, f: F)
            where T: Eq + fmt::Debug, F: Fn(&mut Parser) -> ParseResult<T> {
        for (expected, value) in values {
            let result = parse(value, &f);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_read_extra_data() {
        assert_parses(vec![
            (Err(ParseError::ExtraData), b"\x00"),
        ], |_| {
            return Ok(());
        });
    }

    #[test]
    fn test_read_bool() {
        assert_parses(vec![
            (Ok(true), b"\x01\x01\xff"),
            (Ok(false), b"\x01\x01\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x01\x01"),
            (Err(ParseError::InvalidValue), b"\x01\x02\x00\x00"),
            (Err(ParseError::InvalidValue), b"\x01\x02\xff\x01"),
        ], |p| {
            p.read::<super::Boolean>()
        });
    }


    #[test]
    fn test_read_int_i64() {
        assert_parses(vec![
            (Ok(0), b"\x02\x01\x00"),
            (Ok(127), b"\x02\x01\x7f"),
            (Ok(128), b"\x02\x02\x00\x80"),
            (Ok(256), b"\x02\x02\x01\x00"),
            (Ok(-128), b"\x02\x01\x80"),
            (Ok(-129), b"\x02\x02\xff\x7f"),
            (Ok(-256), b"\x02\x02\xff\x00"),
            (Ok(std::i64::MAX), b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff"),
            (Err(ParseError::UnexpectedTag{expected: 0x2, actual: 0x3}), b"\x03\x00"),
            (Err(ParseError::ShortData), b"\x02\x02\x00"),
            (Err(ParseError::ShortData), b""),
            (Err(ParseError::ShortData), b"\x02"),
            (
                Err(ParseError::IntegerOverflow),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            (Err(ParseError::InvalidValue), b"\x02\x05\x00\x00\x00\x00\x01"),
            (Err(ParseError::InvalidValue), b"\x02\x02\xff\x80"),
            (Err(ParseError::InvalidValue), b"\x02\x00"),
        ], |p| {
            p.read::<super::Integer<_>>()
        });
    }

    #[test]
    fn test_read_int_i32() {
        assert_parses(vec![
            (Ok(0i32), b"\x02\x01\x00"),
            (Ok(127i32), b"\x02\x01\x7f"),
            (Ok(128i32), b"\x02\x02\x00\x80"),
            (Ok(256i32), b"\x02\x02\x01\x00"),
            (Ok(-128i32), b"\x02\x01\x80"),
            (Ok(-129i32), b"\x02\x02\xff\x7f"),
            (Ok(-256i32), b"\x02\x02\xff\x00"),
            (Ok(std::i32::MAX), b"\x02\x04\x7f\xff\xff\xff"),
            (Err(ParseError::IntegerOverflow), b"\x02\x05\x02\x00\x00\x00\x00"),
            (Err(ParseError::InvalidValue), b"\x02\x00"),
        ], |p| {
            return p.read::<super::Integer<_>>();
        });
    }

    #[test]
    fn test_read_int_i8() {
        assert_parses(vec![
            (Ok(0i8), b"\x02\x01\x00"),
            (Ok(127i8), b"\x02\x01\x7f"),
            (Ok(-128i8), b"\x02\x01\x80"),
            (Err(ParseError::IntegerOverflow), b"\x02\x02\x02\x00"),
            (Err(ParseError::InvalidValue), b"\x02\x00"),
        ], |p| {
            return p.read::<super::Integer<_>>();
        });
    }
}
