extern crate byteorder;

use std::io;

use byteorder::{WriteBytesExt};


pub struct Serializer<T> where T: io::Write {
    writer: T
}

impl<T> Serializer<T> where T: io::Write {
    pub fn new(writer: T) -> Serializer<T> {
        return Serializer {
            writer: writer,
        }
    }

    fn _write_length(&mut self, length: usize) -> Result<(), io::Error> {
        assert!(length < 128);
        try!(self.writer.write_u8(length as u8));
        return Ok(());
    }

    fn _write_with_tag<F>(&mut self, tag: u8, body: F) -> Result<(), io::Error>
            where F: Fn() -> Vec<u8> {
        try!(self.writer.write_u8(tag));
        let body = body();
        try!(self._write_length(body.len()));
        try!(self.writer.write_all(&body));
        return Ok(());
    }

    pub fn write_bool(&mut self, v: bool) -> Result<(), io::Error> {
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

    pub fn write_int(&mut self, v: i64) -> Result<(), io::Error> {
        let n = self._int_length(v);
        return self._write_with_tag(2, || {
            let mut result = Vec::with_capacity(n);
            for i in (1..n+1).rev() {
                result.push((v >> ((i - 1) * 8)) as u8);
            }
            return result;
        })
    }

    pub fn write_octet_string(&mut self, v: &Vec<u8>) -> Result<(), io::Error> {
        return self._write_with_tag(4, || {
            return v.to_vec();
        })
    }
}


#[cfg(test)]
mod tests {
    use super::{Serializer};

    fn assert_serializes<T, F>(values: Vec<(T, Vec<u8>)>, f: F)
            where F: Fn(&mut Serializer<&mut Vec<u8>>, T) {
        for (value, expected) in values {
            let mut out = Vec::new();
            {
                let mut serializer = Serializer::new(&mut out);
                f(&mut serializer, value);
            }
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn test_write_bool() {
        assert_serializes(vec![
            (true, b"\x01\x01\xff".to_vec()),
            (false, b"\x01\x01\x00".to_vec()),
        ], |serializer, v| {
            serializer.write_bool(v).unwrap();
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
            serializer.write_int(v).unwrap();
        })
    }

    #[test]
    fn test_write_octet_string() {
        assert_serializes(vec![
            (b"\x01\x02\x03".to_vec(), b"\x04\x03\x01\x02\x03".to_vec()),
        ], |serializer, v| {
            serializer.write_octet_string(&v).unwrap();
        })
    }
}
