extern crate byteorder;
extern crate chrono;

use std::ascii::{AsciiExt};
use std::io::{Cursor, Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};

use chrono::{DateTime, UTC};


#[derive(Clone)]
pub struct ObjectIdentifier {
    data: Vec<u8>
}

fn encode_base128_int(data: &mut Vec<u8>, n: u32) {
    if n == 0 {
        data.push(0);
        return;
    }
    let mut l = 0;
    let mut i = n;
    while i > 0 {
        l += 1;
        i >>= 7;
    }

    for i in (0..l).rev() {
        let mut o = (n >> (i * 7)) as u8;
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        data.push(o);
    }
}

impl ObjectIdentifier {
    pub fn new(oid: Vec<u32>) -> Option<ObjectIdentifier> {
        if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
            return None;
        }

        let mut data = Vec::new();
        encode_base128_int(&mut data, 40 * oid[0] + oid[1]);
        for el in oid.iter().skip(2) {
            encode_base128_int(&mut data, *el);
        }
        return Some(ObjectIdentifier {
            data: data
        });
    }
}


pub struct Serializer<'a> {
    writer: &'a mut Vec<u8>
}

impl<'a> Serializer<'a> {
    pub fn new(writer: &'a mut Vec<u8>) -> Serializer<'a> {
        return Serializer {
            writer: writer,
        }
    }

    fn _length_length(&self, length: usize) -> u8 {
        let mut i = length;
        let mut num_bytes = 1;
        while i > 255 {
            num_bytes += 1;
            i >>= 8;
        }
        return num_bytes;
    }

    fn _write_length(&mut self, length: usize) {
        if length >= 128 {
            let n = self._length_length(length);
            self.writer.write_u8(0x80 | n).unwrap();
            for i in (1..n+1).rev() {
                self.writer.write_u8((length >> ((i - 1) * 8)) as u8).unwrap();
            }
        } else {
            self.writer.write_u8(length as u8).unwrap();
        }
    }

    fn _write_with_tag<F>(&mut self, tag: u8, body: F) where F: Fn() -> Vec<u8> {
        self.writer.write_u8(tag).unwrap();
        let body = body();
        self._write_length(body.len());
        self.writer.write_all(&body).unwrap();
    }

    pub fn write_bool(&mut self, v: bool) {
        return self._write_with_tag(1, || {
            if v {
                return b"\xff".to_vec();
            } else {
                return b"\x00".to_vec();
            }
        })
    }

    fn _int_length(&self, v: i64) -> usize {
        let mut num_bytes = 1;
        let mut i = v;

        while i > 127 || i < -128 {
            num_bytes += 1;
            i >>= 8;
        }
        return num_bytes;
    }

    pub fn write_int(&mut self, v: i64) {
        let n = self._int_length(v);
        return self._write_with_tag(2, || {
            let mut result = Vec::with_capacity(n);
            for i in (1..n+1).rev() {
                result.push((v >> ((i - 1) * 8)) as u8);
            }
            return result;
        })
    }

    pub fn write_octet_string(&mut self, v: &Vec<u8>) {
        return self._write_with_tag(4, || {
            return v.to_vec();
        })
    }

    pub fn write_printable_string(&mut self, v: String) {
        for c in v.chars() {
            if !c.is_ascii() || (
                !c.is_uppercase() &&
                !c.is_lowercase() &&
                !c.is_digit(10) &&
                ![' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?'].contains(&c)
            ) {
                panic!("Non-printable characters.")
            }
        }
        return self._write_with_tag(19, || {
            return v.as_bytes().to_vec();
        });
    }

    pub fn write_object_identifier(&mut self, v: ObjectIdentifier) {
        return self._write_with_tag(6, || {
            return v.data.to_vec();
        })
    }

    pub fn write_utctime(&mut self, v: DateTime<UTC>) {
        return self._write_with_tag(23, || {
            return format!("{}", v.format("%y%m%d%H%M%SZ")).into_bytes();
        });
    }

    pub fn write_sequence<F>(&mut self, v: F) where F: Fn(&mut Serializer) {
        return self._write_with_tag(48, || {
            return to_vec(&v);
        });
    }
}

pub fn to_vec<F>(f: F) -> Vec<u8> where F: Fn(&mut Serializer) {
    let mut out = Vec::new();
    {
        let mut serializer = Serializer::new(&mut out);
        f(&mut serializer);
    }
    return out;
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeserializationError {
    UnexpectedTag,
    ShortData,
    ExtraData,
    Overflow,
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

    fn _read_length(&mut self) -> Result<usize, DeserializationError> {
        let b = self.reader.read_u8().unwrap();
        // TODO: handle lengths greater than 128
        assert!(b & 0x80 == 0);
        return Ok((b & 0x7f) as usize);
    }

    fn _read_with_tag<T, F>(&mut self, expected_tag: u8, body: F) -> Result<T, DeserializationError>
            where F: Fn(Vec<u8>) -> Result<T, DeserializationError> {
        // TODO: only some of the bits in the first byte are for the tag
        let tag = self.reader.read_u8().unwrap();
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

    pub fn finish(self) -> Result<(), DeserializationError> {
        if self.reader.position() as usize != self.reader.get_ref().len() {
            return Err(DeserializationError::ExtraData);
        }
        return Ok(());
    }

    pub fn read_int(&mut self) -> Result<i64, DeserializationError> {
        return self._read_with_tag(2, |data| {
            if data.len() > 8 {
                return Err(DeserializationError::Overflow);
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

pub fn from_vec<F, T>(data: Vec<u8>, f: F) -> Result<T, DeserializationError>
        where F: Fn(&mut Deserializer) -> Result<T, DeserializationError> {
    let mut deserializer = Deserializer::new(data);
    let result = try!(f(&mut deserializer));
    try!(deserializer.finish());
    return Ok(result);
}


#[cfg(test)]
mod tests {
    use std::{fmt};

    use chrono::{TimeZone, UTC};

    use super::{ObjectIdentifier, Serializer, Deserializer, DeserializationError, to_vec, from_vec};

    fn assert_serializes<T, F>(values: Vec<(T, Vec<u8>)>, f: F)
            where T: Clone,  F: Fn(&mut Serializer, T) {
        for (value, expected) in values {
            let out = to_vec(|s| f(s, value.clone()));
            assert_eq!(out, expected);
        }
    }

    fn assert_deserializes<T, F>(values: Vec<(Result<T, DeserializationError>, Vec<u8>)>, f: F)
            where T: Eq + fmt::Debug, F: Fn(&mut Deserializer) -> Result<T, DeserializationError> {
        for (expected, value) in values {
            let result = from_vec(value, &f);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_write_bool() {
        assert_serializes(vec![
            (true, b"\x01\x01\xff".to_vec()),
            (false, b"\x01\x01\x00".to_vec()),
        ], |serializer, v| {
            serializer.write_bool(v);
        });
    }

    #[test]
    fn test_write_int() {
        assert_serializes(vec![
            (0, b"\x02\x01\x00".to_vec()),
            (127, b"\x02\x01\x7f".to_vec()),
            (128, b"\x02\x02\x00\x80".to_vec()),
            (256, b"\x02\x02\x01\x00".to_vec()),
            (-128, b"\x02\x01\x80".to_vec()),
            (-129, b"\x02\x02\xff\x7f".to_vec()),
        ], |serializer, v| {
            serializer.write_int(v);
        })
    }

    #[test]
    fn test_write_octet_string() {
        assert_serializes(vec![
            (b"\x01\x02\x03".to_vec(), b"\x04\x03\x01\x02\x03".to_vec()),
        ], |serializer, v| {
            serializer.write_octet_string(&v);
        })
    }

    #[test]
    fn test_write_printable_string() {
        assert_serializes(vec![
            (
                "Test User 1".to_string(),
                b"\x13\x0b\x54\x65\x73\x74\x20\x55\x73\x65\x72\x20\x31".to_vec()
            ),
            (
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
                b"\x13\x81\x80\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78".to_vec()
            ),
        ], |serializer, v| {
            serializer.write_printable_string(v);
        })
    }

    #[test]
    fn test_write_object_identifier() {
        assert_serializes(vec![
            (
                ObjectIdentifier::new(vec![1, 2, 840, 113549]).unwrap(),
                b"\x06\x06\x2a\x86\x48\x86\xf7\x0d".to_vec()
            ),
            (
                ObjectIdentifier::new(vec![1, 2, 3, 4]).unwrap(),
                b"\x06\x03\x2a\x03\x04".to_vec(),
            ),
            (
                ObjectIdentifier::new(vec![1, 2, 840, 133549, 1, 1, 5]).unwrap(),
                b"\x06\x09\x2a\x86\x48\x88\x93\x2d\x01\x01\x05".to_vec(),
            ),
            (
                ObjectIdentifier::new(vec![2, 100, 3]).unwrap(),
                b"\x06\x03\x81\x34\x03".to_vec(),
            ),
        ], |serializer, oid| {
            serializer.write_object_identifier(oid);
        })
    }

    #[test]
    fn test_write_utctime() {
        assert_serializes(vec![
            (
                UTC.ymd(1991, 5, 6).and_hms(23, 45, 40),
                b"\x17\x0d\x39\x31\x30\x35\x30\x36\x32\x33\x34\x35\x34\x30\x5a".to_vec(),
            ),
            (
                UTC.timestamp(0, 0),
                b"\x17\x0d\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a".to_vec(),
            ),
            (
                UTC.timestamp(1258325776, 0),
                b"\x17\x0d\x30\x39\x31\x31\x31\x35\x32\x32\x35\x36\x31\x36\x5a".to_vec(),
            ),
        ], |serializer, v| {
            serializer.write_utctime(v);
        });
    }

    #[test]
    fn test_write_sequence() {
        assert_serializes(vec![
            ((1, 2), b"\x30\x06\x02\x01\x01\x02\x01\x02".to_vec()),
        ], |serializer, (x, y)| {
            serializer.write_sequence(|s| {
                s.write_int(x);
                s.write_int(y);
            });
        })
    }

    #[test]
    fn test_object_identifier_new() {
        assert!(ObjectIdentifier::new(vec![]).is_none());
        assert!(ObjectIdentifier::new(vec![3, 10]).is_none());
        assert!(ObjectIdentifier::new(vec![1, 50]).is_none());
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
    fn test_read_int() {
        assert_deserializes(vec![
            (Ok(0), b"\x02\x01\x00".to_vec()),
            (Ok(127), b"\x02\x01\x7f".to_vec()),
            (Ok(128), b"\x02\x02\x00\x80".to_vec()),
            (Ok(256), b"\x02\x02\x01\x00".to_vec()),
            (Ok(-128), b"\x02\x01\x80".to_vec()),
            (Ok(-129), b"\x02\x02\xff\x7f".to_vec()),
            (Err(DeserializationError::UnexpectedTag), b"\x03".to_vec()),
        ], |deserializer| {
            return deserializer.read_int();
        });
    }
}
