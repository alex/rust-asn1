use std::{convert};
use std::io::{Cursor, Read};

use byteorder::{self, ReadBytesExt};

use utils::{BitString, Integer, ObjectIdentifier};


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

fn _read_base128_int(reader: &mut Cursor<Vec<u8>>) -> DeserializationResult<u32> {
    let mut ret = 0u32;
    for _ in 0..4 {
        let b = try!(reader.read_u8());
        ret <<= 7;
        ret |= (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            return Ok(ret);
        }
    }
    return Err(DeserializationError::InvalidValue);
}

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

    pub fn read_int<T>(&mut self) -> DeserializationResult<T> where T: Integer {
        return self._read_with_tag(2, |data| {
            if data.len() > 1 {
                match (data[0], data[1] & 0x80) {
                    (0xff, 0x80) | (0x00, 0x00) => return Err(DeserializationError::InvalidValue),
                    _ => {},
                }
            }
            return T::decode(data);
        });
    }

    pub fn read_octet_string(&mut self) -> DeserializationResult<Vec<u8>> {
        return self._read_with_tag(4, |data| {
            return Ok(data);
        });
    }

    pub fn read_bit_string(&mut self) -> DeserializationResult<BitString> {
        return self._read_with_tag(3, |data| {
            let padding_bits = match data.get(0) {
                Some(&bits) => bits,
                None => return Err(DeserializationError::InvalidValue),
            };

            if padding_bits > 7 ||
                (data.len() == 1 && padding_bits > 0) ||
                ((data[data.len() - 1] & ((1 << padding_bits) - 1)) != 0) {

                return Err(DeserializationError::InvalidValue);
            }

            return Ok(BitString::new(
                data[1..].to_vec(),
                (data.len() - 1) * 8 - (padding_bits as usize),
            ).unwrap());
        });
    }

    pub fn read_object_identifier(&mut self) -> DeserializationResult<ObjectIdentifier> {
        return self._read_with_tag(6, |data| {
            if data.is_empty() {
                return Err(DeserializationError::InvalidValue);
            }
            let mut reader = Cursor::new(data);
            let mut s = vec![];
            let v = try!(_read_base128_int(&mut reader));

            if v < 80 {
                s.push(v / 40);
                s.push(v % 40);
            } else {
                s.push(2);
                s.push(v - 80);
            }

            while (reader.position() as usize) < reader.get_ref().len() {
                s.push(try!(_read_base128_int(&mut reader)));
            }

            return Ok(ObjectIdentifier::new(s).unwrap());
        });
    }

    pub fn read_sequence<F, T>(&mut self, v: F) -> DeserializationResult<T>
            where F: Fn(&mut Deserializer) -> DeserializationResult<T> {
        return self._read_with_tag(48, |data| {
            return from_vec(data, &v);
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
    use std;
    use std::{fmt};

    use num::{BigInt, FromPrimitive, One};

    use utils::{BitString, ObjectIdentifier};
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
            (Err(DeserializationError::InvalidValue), b"\x01\x02\x00\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x01\x02\xff\x01".to_vec()),
        ], |deserializer| {
            return deserializer.read_bool();
        });
    }

    #[test]
    fn test_read_int_i64() {
        assert_deserializes(vec![
            (Ok(0), b"\x02\x01\x00".to_vec()),
            (Ok(127), b"\x02\x01\x7f".to_vec()),
            (Ok(128), b"\x02\x02\x00\x80".to_vec()),
            (Ok(256), b"\x02\x02\x01\x00".to_vec()),
            (Ok(-128), b"\x02\x01\x80".to_vec()),
            (Ok(-129), b"\x02\x02\xff\x7f".to_vec()),
            (Ok(-256), b"\x02\x02\xff\x00".to_vec()),
            (Ok(std::i64::MAX), b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff".to_vec()),
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
            (Err(DeserializationError::InvalidValue), b"\x02\x00".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }

    #[test]
    fn test_read_int_i32() {
        assert_deserializes(vec![
            (Ok(0i32), b"\x02\x01\x00".to_vec()),
            (Ok(127i32), b"\x02\x01\x7f".to_vec()),
            (Ok(128i32), b"\x02\x02\x00\x80".to_vec()),
            (Ok(256i32), b"\x02\x02\x01\x00".to_vec()),
            (Ok(-128i32), b"\x02\x01\x80".to_vec()),
            (Ok(-129i32), b"\x02\x02\xff\x7f".to_vec()),
            (Ok(-256i32), b"\x02\x02\xff\x00".to_vec()),
            (Ok(std::i32::MAX), b"\x02\x04\x7f\xff\xff\xff".to_vec()),
            (Err(DeserializationError::IntegerOverflow), b"\x02\x05\x02\x00\x00\x00\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x02\x00".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }

    #[test]
    fn test_read_int_i8() {
        assert_deserializes(vec![
            (Ok(0i8), b"\x02\x01\x00".to_vec()),
            (Ok(127i8), b"\x02\x01\x7f".to_vec()),
            (Ok(-128i8), b"\x02\x01\x80".to_vec()),
            (Err(DeserializationError::IntegerOverflow), b"\x02\x02\x02\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x02\x00".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }

    #[test]
    fn test_read_int_bigint() {
        assert_deserializes(vec![
            (Ok(BigInt::from_i64(0).unwrap()), b"\x02\x01\x00".to_vec()),
            (Ok(BigInt::from_i64(127).unwrap()), b"\x02\x01\x7f".to_vec()),
            (Ok(BigInt::from_i64(128).unwrap()), b"\x02\x02\x00\x80".to_vec()),
            (Ok(BigInt::from_i64(256).unwrap()), b"\x02\x02\x01\x00".to_vec()),
            (Ok(BigInt::from_i64(-128).unwrap()), b"\x02\x01\x80".to_vec()),
            (Ok(BigInt::from_i64(-129).unwrap()), b"\x02\x02\xff\x7f".to_vec()),
            (Ok(BigInt::from_i64(-256).unwrap()), b"\x02\x02\xff\x00".to_vec()),
            (
                Ok(BigInt::from_i64(std::i64::MAX).unwrap()),
                b"\x02\x08\x7f\xff\xff\xff\xff\xff\xff\xff".to_vec()
            ),
            (
                Ok(BigInt::from_i64(std::i64::MAX).unwrap() + BigInt::one()),
                b"\x02\x09\x00\x80\x00\x00\x00\x00\x00\x00\x00".to_vec()
            ),
            (Err(DeserializationError::InvalidValue), b"\x02\x00".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }

    #[test]
    fn test_read_octet_string() {
        assert_deserializes(vec![
            (Ok(b"".to_vec()), b"\x04\x00".to_vec()),
            (Ok(b"\x01\x02\x03".to_vec()), b"\x04\x03\x01\x02\x03".to_vec()),
            (Err(DeserializationError::ShortData), b"\x04\x03\x01\x02".to_vec()),
        ], |deserializer| {
            return deserializer.read_octet_string();
        });
    }

    #[test]
    fn test_read_bit_string() {
        assert_deserializes(vec![
            (Ok(BitString::new(b"".to_vec(), 0).unwrap()), b"\x03\x01\x00".to_vec()),
            (Ok(BitString::new(b"\x00".to_vec(), 1).unwrap()), b"\x03\x02\x07\x00".to_vec()),
            (Ok(BitString::new(b"\x80".to_vec(), 1).unwrap()), b"\x03\x02\x07\x80".to_vec()),
            (
                Ok(BitString::new(b"\x81\xf0".to_vec(), 12).unwrap()),
                b"\x03\x03\x04\x81\xf0".to_vec()
            ),
            (Err(DeserializationError::InvalidValue), b"\x03\x00".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x03\x02\x07\x01".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x03\x02\x07\x40".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x03\x02\x08\x00".to_vec()),
        ], |deserializer| {
            return deserializer.read_bit_string();
        })
    }

    #[test]
    fn test_read_object_identifier() {
        assert_deserializes(vec![
            (Ok(ObjectIdentifier::new(vec![2, 5]).unwrap()), b"\x06\x01\x55".to_vec()),
            (Ok(ObjectIdentifier::new(vec![2, 5, 2]).unwrap()), b"\x06\x02\x55\x02".to_vec()),
            (
                Ok(ObjectIdentifier::new(vec![1, 2, 840, 113549]).unwrap()),
                b"\x06\x06\x2a\x86\x48\x86\xf7\x0d".to_vec()
            ),
            (
                Ok(ObjectIdentifier::new(vec![1, 2, 3, 4]).unwrap()),
                b"\x06\x03\x2a\x03\x04".to_vec(),
            ),
            (
                Ok(ObjectIdentifier::new(vec![1, 2, 840, 133549, 1, 1, 5]).unwrap()),
                b"\x06\x09\x2a\x86\x48\x88\x93\x2d\x01\x01\x05".to_vec(),
            ),
            (
                Ok(ObjectIdentifier::new(vec![2, 100, 3]).unwrap()),
                b"\x06\x03\x81\x34\x03".to_vec(),
            ),
            (Err(DeserializationError::InvalidValue), b"\x06\x00".to_vec()),
            (
                Err(DeserializationError::InvalidValue),
                b"\x06\x07\x55\x02\xc0\x80\x80\x80\x80".to_vec()
            ),
            (Err(DeserializationError::ShortData), b"\x06\x02\x2a\x86".to_vec()),
        ], |deserializer| {
            return deserializer.read_object_identifier();
        });
    }

    #[test]
    fn test_read_sequence() {
        assert_deserializes(vec![
            (Ok((1, 2)), b"\x30\x06\x02\x01\x01\x02\x01\x02".to_vec()),
            (Err(DeserializationError::ShortData), b"\x30\x03\x02\x01\x01".to_vec()),
            (
                Err(DeserializationError::ExtraData),
                b"\x30\x07\x02\x01\x01\x02\x01\x02\x00".to_vec()
            ),
        ], |deserializer| {
            return deserializer.read_sequence(|deserializer| {
                return Ok((
                    try!(deserializer.read_int()),
                    try!(deserializer.read_int())
                ));
            });
        });
    }
}
