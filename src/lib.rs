extern crate byteorder;
extern crate serde;

use std::io;

use byteorder::{WriteBytesExt};


pub struct Serializer<W> {
    writer: W,
}

impl<W> Serializer<W> where W: io::Write {
    pub fn new(writer: W) -> Self {
        return Serializer {
            writer: writer,
        }
    }

    fn _write_length(&mut self, length: usize) -> Result<(), io::Error> {
        assert!(length < 128);
        try!(self.writer.write_u8(length as u8));
        return Ok(());
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

    fn _write_with_tag<F>(&mut self, tag: u8, body: F) -> Result<(), io::Error>
            where F: Fn() -> Vec<u8> {
        try!(self.writer.write_u8(tag));

        let body = body();
        try!(self._write_length(body.len()));
        try!(self.writer.write_all(&body));
        return Ok(());
    }
}

impl<W> serde::Serializer for Serializer<W> where W: io::Write {
    type Error = io::Error;

    fn visit_bool(&mut self, v: bool) -> Result<(), Self::Error> {
        return self._write_with_tag(1, || {
            if v {
                return b"\xff".to_vec();
            } else {
                return b"\x00".to_vec();
            }
        })
    }

    fn visit_i64(&mut self, v: i64) -> Result<(), Self::Error> {
        let n = self._int_length(v);
        return self._write_with_tag(2, || {
            let mut result = Vec::with_capacity(n);
            for i in (1..n+1).rev() {
                result.push((v >> ((i - 1) * 8)) as u8);
            }
            return result;
        });
    }

    #[allow(unused_variables)]
    fn visit_u64(&mut self, v: u64) -> Result<(), Self::Error> {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_f64(&mut self, v: f64) -> Result<(), Self::Error> {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_str(&mut self, value: &str) -> Result<(), Self::Error> {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_unit(&mut self) -> Result<(), Self::Error> {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_none(&mut self) -> Result<(), Self::Error> {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_some<V>(&mut self, value: V) -> Result<(), Self::Error> where V: serde::Serialize {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_seq<V>(&mut self, visitor: V) -> Result<(), Self::Error>
        where V: serde::ser::SeqVisitor {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_seq_elt<T>(&mut self, value: T) -> Result<(), Self::Error> where T: serde::Serialize {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_map<V>(&mut self, visitor: V) -> Result<(), Self::Error>
            where V: serde::ser::MapVisitor {
        panic!("not implemented");
    }

    #[allow(unused_variables)]
    fn visit_map_elt<K, V>(&mut self, key: K, value: V) -> Result<(), Self::Error>
            where K: serde::Serialize, V: serde::Serialize {
        panic!("not implemented");
    }
}


pub fn to_writer<W, T>(writer: &mut W, value: &T) -> io::Result<()>
        where W: io::Write, T: serde::Serialize {
    let mut ser = Serializer::new(writer);
    try!(value.serialize(&mut ser));
    return Ok(());
}

pub fn to_vec<T>(value: &T) -> Vec<u8> where T: serde::Serialize {
    let mut writer = Vec::new();
    to_writer(&mut writer, value).unwrap();
    return writer;
}


#[cfg(test)]
mod tests {
    use serde;

    use super::{to_vec};

    fn assert_serializes<T>(values: Vec<(T, Vec<u8>)>) where T: serde::Serialize {
        for (value, expected) in values {
            let result = to_vec(&value);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_serialize_bool() {
        assert_serializes(vec![
            (true, b"\x01\x01\xff".to_vec()),
            (false, b"\x01\x01\x00".to_vec()),
        ]);
    }

    #[test]
    fn test_serialize_int() {
        assert_serializes(vec![
            (0, b"\x02\x01\x00".to_vec()),
            (127, b"\x02\x01\x7f".to_vec()),
            (128, b"\x02\x02\x00\x80".to_vec()),
            (256, b"\x02\x02\x01\x00".to_vec()),
            (-128, b"\x02\x01\x80".to_vec()),
            (-129, b"\x02\x02\xff\x7f".to_vec()),
        ])
    }
}
