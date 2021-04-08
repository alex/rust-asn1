use alloc::vec;
use alloc::vec::Vec;

fn _length_length(length: usize) -> u8 {
    let mut i = length;
    let mut num_bytes = 1;
    while i > 255 {
        num_bytes += 1;
        i >>= 8;
    }
    num_bytes
}
fn _insert_at_position(vec: &mut Vec<u8>, pos: usize, data: &[u8]) {
    for _ in 0..data.len() {
        vec.push(0);
    }
    let src_range = pos..vec.len() - data.len();
    vec.copy_within(src_range, pos + data.len());
    vec[pos..pos + data.len()].copy_from_slice(data);
}

pub struct Writer<'a> {
    pub(crate) data: &'a mut Vec<u8>,
}

impl Writer<'_> {
    #[inline]
    pub(crate) fn new(data: &mut Vec<u8>) -> Writer {
        Writer { data }
    }

    #[inline]
    pub fn write_element<'a, T>(&mut self, val: T)
    where
        T: crate::types::SimpleAsn1Element<'a, WriteType = T>,
    {
        self.write_element_with_type::<T>(val);
    }

    #[inline]
    pub fn write_element_with_type<'a, T>(&mut self, val: T::WriteType)
    where
        T: crate::types::SimpleAsn1Element<'a>,
    {
        self.data.push(T::TAG);
        // Push a 0-byte placeholder for the length. Needing only a single byte
        // for the element is probably the most common case.
        self.data.push(0);
        let start_len = self.data.len();
        T::write_data(self.data, val);
        let added_len = self.data.len() - start_len;
        if added_len >= 128 {
            let n = _length_length(added_len);
            self.data[start_len - 1] = 0x80 | n;
            let mut length_buf = [0u8; 8];
            for (pos, i) in (1..n + 1).rev().enumerate() {
                length_buf[pos] = (added_len >> ((i - 1) * 8)) as u8;
            }
            _insert_at_position(self.data, start_len, &length_buf[..n as usize]);
        } else {
            self.data[start_len - 1] = added_len as u8;
        }
    }
}

/// Constructs a writer and invokes a callback which writes ASN.1 elements into
/// the writer, then returns the generated DER bytes.
#[inline]
pub fn write<F: Fn(&mut Writer)>(f: F) -> Vec<u8> {
    let mut v = vec![];
    let mut w = Writer::new(&mut v);
    f(&mut w);
    v
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use chrono::{TimeZone, Utc};

    use super::{_insert_at_position, write, Writer};
    use crate::types::SimpleAsn1Element;
    use crate::{
        BitString, ObjectIdentifier, PrintableString, Sequence, SequenceOf, SetOf, UtcTime,
    };
    #[cfg(feature = "const-generics")]
    use crate::{Explicit, Implicit};

    fn assert_writes<'a, T>(data: &[(T::WriteType, &[u8])])
    where
        T: SimpleAsn1Element<'a>,
        T::WriteType: Clone,
    {
        for (val, expected) in data {
            let result = write(|w| {
                w.write_element_with_type::<T>(val.clone());
            });
            assert_eq!(&result, expected);
        }
    }

    #[test]
    fn test_insert_at_position() {
        let mut v = vec![1, 2, 3, 4];
        _insert_at_position(&mut v, 2, &[5, 6]);
        assert_eq!(&v, &[1, 2, 5, 6, 3, 4]);
    }

    #[test]
    fn test_write_element() {
        assert_eq!(write(|w| w.write_element(())), b"\x05\x00");
    }

    #[test]
    fn test_write_null() {
        assert_writes::<()>(&[((), b"\x05\x00")]);
    }

    #[test]
    fn test_write_bool() {
        assert_writes::<bool>(&[(false, b"\x01\x01\x00"), (true, b"\x01\x01\xff")]);
    }

    #[test]
    fn test_write_octet_string() {
        assert_writes::<&[u8]>(&[
            (b"", b"\x04\x00"),
            (b"\x01\x02\x03", b"\x04\x03\x01\x02\x03"),
            (b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b"\x04\x81\x81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ])
    }

    #[test]
    fn test_write_printable_string() {
        assert_writes::<PrintableString>(&[
            (
                PrintableString::new("Test User 1").unwrap(),
                b"\x13\x0bTest User 1",
            ),
            (
                PrintableString::new("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap(),
                b"\x13\x81\x80xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ),
        ]);
    }

    #[test]
    fn test_write_i64() {
        assert_writes::<i64>(&[
            (0, b"\x02\x01\x00"),
            (127, b"\x02\x01\x7f"),
            (128, b"\x02\x02\x00\x80"),
            (255, b"\x02\x02\x00\xff"),
            (256, b"\x02\x02\x01\x00"),
            (-1, b"\x02\x01\xff"),
            (-128, b"\x02\x01\x80"),
            (-129, b"\x02\x02\xff\x7f"),
        ]);
    }

    #[test]
    fn test_write_i8() {
        assert_writes::<i8>(&[
            (0, b"\x02\x01\x00"),
            (127, b"\x02\x01\x7f"),
            (-1, b"\x02\x01\xff"),
            (-128, b"\x02\x01\x80"),
        ]);
    }

    #[test]
    fn test_write_object_identifier() {
        assert_writes::<ObjectIdentifier>(&[
            (
                ObjectIdentifier::from_string("1.2.840.113549").unwrap(),
                b"\x06\x06\x2a\x86\x48\x86\xf7\x0d",
            ),
            (
                ObjectIdentifier::from_string("1.2.3.4").unwrap(),
                b"\x06\x03\x2a\x03\x04",
            ),
            (
                ObjectIdentifier::from_string("1.2.840.133549.1.1.5").unwrap(),
                b"\x06\x09\x2a\x86\x48\x88\x93\x2d\x01\x01\x05",
            ),
            (
                ObjectIdentifier::from_string("2.100.3").unwrap(),
                b"\x06\x03\x81\x34\x03",
            ),
        ]);
    }

    #[test]
    fn test_write_bit_string() {
        assert_writes::<BitString>(&[
            (BitString::new(b"", 0).unwrap(), b"\x03\x01\x00"),
            (BitString::new(b"\x80", 7).unwrap(), b"\x03\x02\x07\x80"),
            (
                BitString::new(b"\x81\xf0", 4).unwrap(),
                b"\x03\x03\x04\x81\xf0",
            ),
        ]);
    }

    #[test]
    fn test_write_utctime() {
        assert_writes::<UtcTime>(&[
            (
                Utc.ymd(1991, 5, 6).and_hms(23, 45, 40),
                b"\x17\x0d910506234540Z",
            ),
            (Utc.timestamp(0, 0), b"\x17\x0d700101000000Z"),
            (Utc.timestamp(1258325776, 0), b"\x17\x0d091115225616Z"),
        ]);
    }

    #[test]
    fn test_write_sequence() {
        assert_eq!(
            write(|w| {
                w.write_element_with_type::<Sequence>(&|w: &mut Writer| w.write_element(()))
            }),
            b"\x30\x02\x05\x00"
        );
        assert_eq!(
            write(|w| {
                w.write_element_with_type::<Sequence>(&|w: &mut Writer| w.write_element(true))
            }),
            b"\x30\x03\x01\x01\xff"
        );
    }

    #[test]
    fn test_write_sequence_of() {
        assert_writes::<SequenceOf<u64>>(&[
            (&[], b"\x30\x00"),
            (&[1, 2, 3], b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03"),
        ]);
        assert_writes::<SequenceOf<Sequence>>(&[
            (&[], b"\x30\x00"),
            (&[&|_w| ()], b"\x30\x02\x30\x00"),
            (
                &[&|w| w.write_element(1u64)],
                b"\x30\x05\x30\x03\x02\x01\x01",
            ),
        ]);
    }

    #[test]
    fn test_write_set_of() {
        assert_writes::<SetOf<u64>>(&[
            (&[], b"\x37\x00"),
            (&[1], b"\x37\x03\x02\x01\x01"),
            (&[1, 2, 3], b"\x37\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03"),
            (&[3, 2, 1], b"\x37\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03"),
        ]);
    }

    #[test]
    #[cfg(feature = "const-generics")]
    fn test_write_implicit() {
        assert_writes::<Implicit<bool, 2>>(&[(true, b"\x82\x01\xff"), (false, b"\x82\x01\x00")]);
    }

    #[test]
    #[cfg(feature = "const-generics")]
    fn test_write_explicit() {
        assert_writes::<Explicit<bool, 2>>(&[
            (true, b"\xa2\x03\x01\x01\xff"),
            (false, b"\xa2\x03\x01\x01\x00"),
        ]);
    }
}
