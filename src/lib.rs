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

    fn _write_length(&mut self, length: isize) -> Result<(), io::Error> {
        assert!(length < 128);
        try!(self.writer.write_u8(length as u8));
        return Ok(());
    }

    fn _int_length(&self, v: i64) -> isize {
        let mut num_bytes = 1;
        let mut i = v;

        while i > 127 || i < -128 {
            num_bytes += 1;
            i >>= 8;
        }
        return num_bytes;
    }
}

impl<W> serde::Serializer for Serializer<W> where W: io::Write {
    type Error = io::Error;

    fn visit_bool(&mut self, v: bool) -> Result<(), Self::Error> {
        if v {
            try!(self.writer.write_all(b"\xff"));
        } else {
            try!(self.writer.write_all(b"\x00"));
        }
        return Ok(());
    }

    fn visit_i64(&mut self, v: i64) -> Result<(), Self::Error> {
        try!(self.writer.write_all(b"\x02"));

        let n = self._int_length(v);
        try!(self._write_length(n));
        for i in (1..n+1).rev() {
            try!(self.writer.write_u8((v >> ((i - 1) * 8)) as u8))
        }

        return Ok(());
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
            (true, b"\xff".to_vec()),
            (false, b"\x00".to_vec()),
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
