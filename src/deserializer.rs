use std::{convert};
use std::io::{Cursor, Read};

use byteorder::{self, ReadBytesExt};


#[derive(Debug, PartialEq, Eq)]
pub enum DeserializationError {
    UnexpectedTag,
    ShortData,
    ExtraData,
    IntegerOverflow,
    InvalidValue,
}

impl convert::From<byteorder::Error> for DeserializationError {
    fn from(e: byteorder::Error) -> DeserializationError {
        return match e {
            byteorder::Error::UnexpectedEOF => DeserializationError::ShortData,
            _ => panic!("Unexpected error!"),
        }
    }
}

pub type DeserializationResult<T> = Result<T, DeserializationError>;

pub struct Deserializer {
    reader: Cursor<Vec<u8>>,
}

impl Deserializer {
    pub fn new(data: Vec<u8>) -> Deserializer {
        return Deserializer{
            reader: Cursor::new(data),
        }
    }

    fn _read_length(&mut self) -> DeserializationResult<usize> {
        let b = try!(self.reader.read_u8());
        // TODO: handle lengths greater than 128
        assert!(b & 0x80 == 0);
        return Ok((b & 0x7f) as usize);
    }

    fn _read_with_tag<T, F>(&mut self, expected_tag: u8, body: F) -> DeserializationResult<T>
            where F: Fn(Vec<u8>) -> DeserializationResult<T> {
        let tag = try!(self.reader.read_u8());
        // TODO: only some of the bits in the first byte are for the tag
        if tag != expected_tag {
            return Err(DeserializationError::UnexpectedTag);
        }
        let length = try!(self._read_length());
        let mut data = vec![0; length];
        let n = self.reader.read(&mut data).unwrap();
        if n != length {
            return Err(DeserializationError::ShortData);
        }
        return body(data);
    }

    pub fn finish(self) -> DeserializationResult<()> {
        if self.reader.position() as usize != self.reader.get_ref().len() {
            return Err(DeserializationError::ExtraData);
        }
        return Ok(());
    }

    pub fn read_bool(&mut self) -> DeserializationResult<bool> {
        return self._read_with_tag(1, |data| {
            if data == b"\x00" {
                return Ok(false);
            } else if data == b"\xff" {
                return Ok(true)
            } else {
                return Err(DeserializationError::InvalidValue);
            }
        });
    }

    pub fn read_int(&mut self) -> DeserializationResult<i64> {
        return self._read_with_tag(2, |data| {
            if data.len() > 8 {
                return Err(DeserializationError::IntegerOverflow);
            }
            if data.len() > 1 {
                match (data[0], data[1] & 0x80) {
                    (0xff, 0x80) | (0x00, 0x00) => return Err(DeserializationError::InvalidValue),
                    _ => {},
                }
            }
            let mut ret = 0;
            for b in data.iter() {
                ret <<= 8;
                ret |= *b as i64;
            }
            // Shift up and down in order to sign extend the result.
            ret <<= 64 - data.len() * 8;
            ret >>= 64 - data.len() * 8;
            return Ok(ret);
        });
    }
}

pub fn from_vec<F, T>(data: Vec<u8>, f: F) -> DeserializationResult<T>
        where F: Fn(&mut Deserializer) -> DeserializationResult<T> {
    let mut deserializer = Deserializer::new(data);
    let result = try!(f(&mut deserializer));
    try!(deserializer.finish());
    return Ok(result);
}

#[cfg(test)]
mod tests {
    use std::{fmt};

    use super::{Deserializer, DeserializationError, DeserializationResult, from_vec};

    fn assert_deserializes<T, F>(values: Vec<(DeserializationResult<T>, Vec<u8>)>, f: F)
            where T: Eq + fmt::Debug, F: Fn(&mut Deserializer) -> DeserializationResult<T> {
        for (expected, value) in values {
            let result = from_vec(value, &f);
            assert_eq!(result, expected);
        }
    }
    #[test]
    fn test_read_extra_data() {
        assert_deserializes(vec![
            (Err(DeserializationError::ExtraData), b"\x00".to_vec()),
        ], |_| {
            return Ok(());
        });
    }

    #[test]
    fn test_read_bool() {
        assert_deserializes(vec![
            (Ok(true), b"\x01\x01\xff".to_vec()),
            (Ok(false), b"\x01\x01\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x01\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x01\x01\x01".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x01\x02\x01\x01".to_vec()),
        ], |deserializer| {
            return deserializer.read_bool();
        });
    }

    #[test]
    fn test_read_int() {
        assert_deserializes(vec![
            (Ok(0), b"\x02\x01\x00".to_vec()),
            (Ok(127), b"\x02\x01\x7f".to_vec()),
            (Ok(128), b"\x02\x02\x00\x80".to_vec()),
            (Ok(256), b"\x02\x02\x01\x00".to_vec()),
            (Ok(-128), b"\x02\x01\x80".to_vec()),
            (Ok(-129), b"\x02\x02\xff\x7f".to_vec()),
            (Ok(-256), b"\x02\x02\xff\x00".to_vec()),
            (Err(DeserializationError::UnexpectedTag), b"\x03".to_vec()),
            (Err(DeserializationError::ShortData), b"\x02\x02\x00".to_vec()),
            (Err(DeserializationError::ShortData), b"".to_vec()),
            (Err(DeserializationError::ShortData), b"\x02".to_vec()),
            (
                Err(DeserializationError::IntegerOverflow),
                b"\x02\x09\x02\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()
            ),
            (Err(DeserializationError::InvalidValue), b"\x02\x05\x00\x00\x00\x00\x01".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x02\x02\xff\x80".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }
}
