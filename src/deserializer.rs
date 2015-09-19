use std::{convert};
use std::io::{Cursor, Read};

use byteorder::{self, ReadBytesExt};

use chrono::{DateTime, UTC, TimeZone, Timelike};

use utils::{ObjectIdentifier};


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

    pub fn read_octet_string(&mut self) -> DeserializationResult<Vec<u8>> {
        return self._read_with_tag(4, |data| {
            return Ok(data);
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

    pub fn read_utctime(&mut self) -> DeserializationResult<DateTime<UTC>> {
        return self._read_with_tag(23, |data| {
            let s = match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => return Err(DeserializationError::InvalidValue),
            };
            match UTC.datetime_from_str(&s, "%y%m%d%H%M%SZ") {
                Ok(d) => {
                    // Chrono allows leap seconds, but ASN.1 does not. Chrono represents leap
                    // seconds as `d.second() == 59 && d.nanosecond() == 1000000`. There's no other
                    // way for us to get a nanosecond besides in a seconds=60 case, so we just
                    // check for their presence.
                    if d.second() >= 59 && d.nanosecond() > 0 {
                        return Err(DeserializationError::InvalidValue);
                    } else {
                        return Ok(d)
                    }
                },
                Err(_) => return Err(DeserializationError::InvalidValue),
            };
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
    use std::{self, fmt};

    use chrono::{TimeZone, UTC};

    use utils::{ObjectIdentifier};
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
    fn test_read_int() {
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
    fn test_read_utctime() {
        assert_deserializes(vec![
            (
                Ok(UTC.ymd(1991, 5, 6).and_hms(23, 45, 40)),
                b"\x17\x0d\x39\x31\x30\x35\x30\x36\x32\x33\x34\x35\x34\x30\x5a".to_vec(),
            ),
            (
                Ok(UTC.timestamp(0, 0)),
                b"\x17\x0d\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a".to_vec(),
            ),
            (
                Ok(UTC.timestamp(1258325776, 0)),
                b"\x17\x0d\x30\x39\x31\x31\x31\x35\x32\x32\x35\x36\x31\x36\x5a".to_vec(),
            ),
            (Err(DeserializationError::InvalidValue), b"\x17\x01\xff".to_vec()),
            // TODO: correct hex formatting
            (Err(DeserializationError::InvalidValue), b"\x17\x0da10506234540Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d91a506234540Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d9105a6234540Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d910506a34540Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d910506334a40Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d91050633444aZ".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d910506334461Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e910506334400Za".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d000100000000Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d101302030405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100002030405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100100030405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100132030405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100231030405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100102240405Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100102036005Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0d100102030460Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e-100102030410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e10-0102030410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e10-0002030410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e1001-02030410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e100102-030410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e10010203-0410Z".to_vec()),
            (Err(DeserializationError::InvalidValue), b"\x17\x0e1001020304-10Z".to_vec()),

        ], |deserializer| {
            return deserializer.read_utctime();
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
