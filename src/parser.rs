use std::{convert};
use std::io::{self, BufRead, Cursor};

use byteorder::{ReadBytesExt};



#[derive(Debug, PartialEq)]
pub enum ParseError {
    ExtraData,
    InvalidValue,
    IntegerOverflow,
    ShortData,
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

trait Asn1Element {
    type Result;

    fn parse(&[u8]) -> ParseResult<Self::Result>;
}

struct Boolean {}

impl Asn1Element for Boolean {
    type Result = bool;

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
    use std::{fmt};

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
}
