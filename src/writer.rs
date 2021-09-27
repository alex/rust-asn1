use crate::types::{Asn1Writable, SimpleAsn1Writable};
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

/// Encapsulates an ongoing write. For almost all use-cases the correct
/// entrypoint is [`write()`] or [`write_single()`].
pub struct Writer<'a> {
    pub(crate) data: &'a mut Vec<u8>,
}

impl Writer<'_> {
    #[inline]
    #[doc(hidden)]
    pub fn new(data: &mut Vec<u8>) -> Writer {
        Writer { data }
    }

    /// Writes a single element to the output.
    pub fn write_element<'a, T: Asn1Writable<'a>>(&mut self, val: &T) {
        val.write(self);
    }

    /// This is an alias for `write_element::<Option<Explicit<T, tag>>>` for
    /// use when MSRV is <1.51.
    pub fn write_optional_explicit_element<'a, T: Asn1Writable<'a>>(
        &mut self,
        val: &Option<T>,
        tag: u8,
    ) {
        if let Some(v) = val {
            let tag = crate::explicit_tag(tag);
            self.write_tlv(tag, |dest| Writer::new(dest).write_element(v));
        }
    }

    /// This is an alias for `write_element::<Implicit<T, tag>>` for use when
    /// MSRV is <1.51.
    pub fn write_implicit_element<'a, T: SimpleAsn1Writable<'a>>(&mut self, val: &T, tag: u8) {
        let tag = crate::implicit_tag(tag, T::TAG);
        self.write_tlv(tag, |dest| val.write_data(dest));
    }

    /// This is an alias for `write_element::<Option<Implicit<T, tag>>>` for
    /// use when MSRV is <1.51.
    pub fn write_optional_implicit_element<'a, T: SimpleAsn1Writable<'a>>(
        &mut self,
        val: &Option<T>,
        tag: u8,
    ) {
        if let Some(v) = val {
            let tag = crate::implicit_tag(tag, T::TAG);
            self.write_tlv(tag, |dest| v.write_data(dest));
        }
    }

    #[inline]
    pub(crate) fn write_tlv<F: FnOnce(&mut Vec<u8>)>(&mut self, tag: u8, body: F) {
        self.data.push(tag);
        // Push a 0-byte placeholder for the length. Needing only a single byte
        // for the element is probably the most common case.
        self.data.push(0);
        let start_len = self.data.len();
        body(self.data);
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

/// Writes a single top-level ASN.1 element, returning the generated DER bytes.
/// Most often this will be used where `T` is a type with
/// `#[derive(asn1::Asn1Write)]`.
pub fn write_single<'a, T: Asn1Writable<'a>>(v: &T) -> Vec<u8> {
    write(|w| {
        w.write_element(v);
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use chrono::{TimeZone, Utc};

    use super::{_insert_at_position, write, write_single, Writer};
    use crate::types::Asn1Writable;
    use crate::{
        parse_single, BigUint, BitString, Choice1, Choice2, Choice3, Enumerated, GeneralizedTime,
        IA5String, ObjectIdentifier, PrintableString, Sequence, SequenceOf, SequenceOfWriter,
        SequenceWriter, SetOf, SetOfWriter, Tlv, UtcTime, Utf8String, VisibleString,
    };
    #[cfg(feature = "const-generics")]
    use crate::{Explicit, Implicit};

    fn assert_writes<'a, T>(data: &[(T, &[u8])])
    where
        T: Asn1Writable<'a>,
    {
        for (val, expected) in data {
            let result = write_single(val);
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
        assert_eq!(write(|w| w.write_element(&())), b"\x05\x00");
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
    fn test_write_ia5string() {
        assert_writes::<IA5String>(&[
            (
                IA5String::new("Test User 1").unwrap(),
                b"\x16\x0bTest User 1",
            ),
            (
                IA5String::new("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap(),
                b"\x16\x81\x80xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ),
        ]);
    }

    #[test]
    fn test_write_utf8string() {
        assert_writes::<Utf8String>(&[
            (
                Utf8String::new("Test User 1"),
                b"\x0c\x0bTest User 1",
            ),
            (
                Utf8String::new("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
                b"\x0c\x81\x80xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ),
        ]);
    }

    #[test]
    fn test_write_visiblestring() {
        assert_writes::<VisibleString>(&[
            (
                VisibleString::new("Test User 1").unwrap(),
                b"\x1a\x0bTest User 1",
            ),
            (
                VisibleString::new("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap(),
                b"\x1a\x81\x80xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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
    fn test_write_biguint() {
        assert_writes::<BigUint>(&[
            (BigUint::new(b"\x00\xff").unwrap(), b"\x02\x02\x00\xff"),
            (
                BigUint::new(b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").unwrap(),
                b"\x02\x0d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
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
                UtcTime::new(Utc.ymd(1991, 5, 6).and_hms(23, 45, 40)).unwrap(),
                b"\x17\x0d910506234540Z",
            ),
            (
                UtcTime::new(Utc.timestamp(0, 0)).unwrap(),
                b"\x17\x0d700101000000Z",
            ),
            (
                UtcTime::new(Utc.timestamp(1258325776, 0)).unwrap(),
                b"\x17\x0d091115225616Z",
            ),
        ]);
    }

    #[test]
    fn test_write_generalizedtime() {
        assert_writes(&[
            (
                GeneralizedTime::new(Utc.ymd(1991, 5, 6).and_hms(23, 45, 40)),
                b"\x18\x0f19910506234540Z",
            ),
            (
                GeneralizedTime::new(Utc.timestamp(0, 0)),
                b"\x18\x0f19700101000000Z",
            ),
            (
                GeneralizedTime::new(Utc.timestamp(1258325776, 0)),
                b"\x18\x0f20091115225616Z",
            ),
        ]);
    }

    #[test]
    fn test_write_enumerated() {
        assert_writes::<Enumerated>(&[
            (Enumerated::new(0), b"\x0a\x01\x00"),
            (Enumerated::new(12), b"\x0a\x01\x0c"),
        ]);
    }

    #[test]
    fn test_write_sequence() {
        assert_eq!(
            write(|w| {
                w.write_element(&SequenceWriter::new(&|w: &mut Writer| w.write_element(&())))
            }),
            b"\x30\x02\x05\x00"
        );
        assert_eq!(
            write(|w| {
                w.write_element(&SequenceWriter::new(&|w: &mut Writer| {
                    w.write_element(&true)
                }))
            }),
            b"\x30\x03\x01\x01\xff"
        );

        assert_writes(&[(
            parse_single::<Sequence>(b"\x30\x06\x01\x01\xff\x02\x01\x06").unwrap(),
            b"\x30\x06\x01\x01\xff\x02\x01\x06",
        )]);
    }

    #[test]
    fn test_write_sequence_of() {
        assert_writes(&[
            (SequenceOfWriter::new(&[]), b"\x30\x00"),
            (
                SequenceOfWriter::new(&[1u8, 2, 3]),
                b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
        ]);
        assert_writes(&[
            (SequenceOfWriter::new(&[]), b"\x30\x00"),
            (
                SequenceOfWriter::new(&[SequenceWriter::new(&|_w| ())]),
                b"\x30\x02\x30\x00",
            ),
            (
                SequenceOfWriter::new(&[SequenceWriter::new(&|w: &mut Writer| {
                    w.write_element(&1u64)
                })]),
                b"\x30\x05\x30\x03\x02\x01\x01",
            ),
        ]);

        assert_writes(&[(
            parse_single::<SequenceOf<u64>>(b"\x30\x06\x02\x01\x05\x02\x01\x07").unwrap(),
            b"\x30\x06\x02\x01\x05\x02\x01\x07",
        )]);
    }

    #[test]
    fn test_write_set_of() {
        assert_writes(&[
            (SetOfWriter::new(&[]), b"\x31\x00"),
            (SetOfWriter::new(&[1u8]), b"\x31\x03\x02\x01\x01"),
            (
                SetOfWriter::new(&[1, 2, 3]),
                b"\x31\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
            (
                SetOfWriter::new(&[3, 2, 1]),
                b"\x31\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
        ]);

        assert_writes(&[(
            parse_single::<SetOf<u64>>(b"\x31\x06\x02\x01\x05\x02\x01\x07").unwrap(),
            b"\x31\x06\x02\x01\x05\x02\x01\x07",
        )]);
    }

    #[test]
    fn test_write_implicit() {
        #[cfg(feature = "const-generics")]
        assert_writes::<Implicit<bool, 2>>(&[
            (Implicit::new(true), b"\x82\x01\xff"),
            (Implicit::new(false), b"\x82\x01\x00"),
        ]);

        assert_eq!(
            write(|w| { w.write_optional_implicit_element(&Some(true), 2) }),
            b"\x82\x01\xff"
        );
        assert_eq!(
            write(|w| { w.write_optional_explicit_element::<u8>(&None, 2) }),
            b""
        );

        assert_eq!(
            write(|w| {
                w.write_optional_implicit_element(&Some(SequenceWriter::new(&|_w| {})), 2)
            }),
            b"\xa2\x00"
        );
        assert_eq!(
            write(|w| { w.write_optional_explicit_element::<SequenceWriter>(&None, 2) }),
            b""
        );
    }

    #[test]
    fn test_write_explicit() {
        #[cfg(feature = "const-generics")]
        assert_writes::<Explicit<bool, 2>>(&[
            (Explicit::new(true), b"\xa2\x03\x01\x01\xff"),
            (Explicit::new(false), b"\xa2\x03\x01\x01\x00"),
        ]);

        assert_eq!(
            write(|w| { w.write_optional_explicit_element(&Some(true), 2) }),
            b"\xa2\x03\x01\x01\xff"
        );
        assert_eq!(
            write(|w| { w.write_optional_explicit_element::<u8>(&None, 2) }),
            b""
        );
    }

    #[test]
    fn test_write_option() {
        assert_writes::<Option<bool>>(&[
            (Some(true), b"\x01\x01\xff"),
            (Some(false), b"\x01\x01\x00"),
            (None, b""),
        ]);
    }

    #[test]
    fn test_write_choice() {
        assert_writes::<Choice1<bool>>(&[(Choice1::ChoiceA(true), b"\x01\x01\xff")]);

        assert_writes::<Choice2<bool, i64>>(&[
            (Choice2::ChoiceA(true), b"\x01\x01\xff"),
            (Choice2::ChoiceB(18), b"\x02\x01\x12"),
        ]);

        assert_writes::<Choice3<bool, i64, ()>>(&[
            (Choice3::ChoiceA(true), b"\x01\x01\xff"),
            (Choice3::ChoiceB(18), b"\x02\x01\x12"),
            (Choice3::ChoiceC(()), b"\x05\x00"),
        ]);
    }

    #[test]
    fn test_write_tlv() {
        assert_writes(&[(
            parse_single::<Tlv>(b"\x01\x01\x00").unwrap(),
            b"\x01\x01\x00",
        )]);
    }
}
