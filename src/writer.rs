use crate::types::Asn1Writable;
use crate::Tag;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use alloc::{fmt, vec};

/// `WriteError` are returned when there is an error writing the ASN.1 data.
#[derive(PartialEq, Eq, Debug)]
pub enum WriteError {
    AllocationError,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::AllocationError => write!(f, "allocation error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WriteError {}

pub type WriteResult<T = ()> = Result<T, WriteError>;

pub struct WriteBuf(Vec<u8>);

impl WriteBuf {
    #[inline]
    pub(crate) fn new(data: Vec<u8>) -> WriteBuf {
        WriteBuf(data)
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    // Reserve space for up to `len` additional bytes.
    #[inline]
    pub fn reserve_additional(&mut self, len: usize) -> WriteResult {
        self.0
            .try_reserve(len)
            .map_err(|_| WriteError::AllocationError)?;

        Ok(())
    }

    #[inline]
    pub fn push_byte(&mut self, b: u8) -> WriteResult {
        self.reserve_additional(1)?;
        self.0.push(b);
        Ok(())
    }

    #[inline]
    pub fn push_slice(&mut self, data: &[u8]) -> WriteResult {
        self.reserve_additional(data.len())?;

        self.0.extend_from_slice(data);
        Ok(())
    }
}

fn _length_length(length: usize) -> u8 {
    let mut i = length;
    let mut num_bytes = 1;
    while i > 255 {
        num_bytes += 1;
        i >>= 8;
    }
    num_bytes
}

/// Calculate the number of bytes needed to encode a length field for the given content length.
/// This includes the length-of-length byte for lengths >= 128.
pub(crate) fn length_encoding_size(content_length: usize) -> usize {
    if content_length < 128 {
        1
    } else {
        1 + _length_length(content_length) as usize
    }
}

fn _insert_at_position(buf: &mut WriteBuf, pos: usize, data: &[u8]) -> WriteResult {
    for _ in 0..data.len() {
        buf.push_byte(0)?;
    }
    let src_range = pos..buf.len() - data.len();
    buf.as_mut_slice().copy_within(src_range, pos + data.len());
    buf.as_mut_slice()[pos..pos + data.len()].copy_from_slice(data);

    Ok(())
}

/// Encapsulates an ongoing write. For almost all use-cases the correct
/// entrypoint is [`write()`] or [`write_single()`].
pub struct Writer<'a> {
    pub(crate) buf: &'a mut WriteBuf,
}

impl Writer<'_> {
    #[inline]
    #[doc(hidden)]
    pub fn new(buf: &mut WriteBuf) -> Writer<'_> {
        Writer { buf }
    }

    /// Writes a single element to the output.
    #[inline]
    pub fn write_element<T: Asn1Writable>(&mut self, val: &T) -> WriteResult {
        if let Some(len) = val.encoded_length() {
            self.buf.reserve_additional(len)?;
        }
        val.write(self)
    }

    /// Writes a TLV with the specified tag where the value is any bytes
    /// written to the `Vec` in the callback. The length portion of the
    /// TLV is automatically computed.
    ///
    /// If `content_length` is provided, it reduces the number of
    /// re-allocations required.
    #[inline]
    pub fn write_tlv<F: FnOnce(&mut WriteBuf) -> WriteResult>(
        &mut self,
        tag: Tag,
        content_length: Option<usize>,
        body: F,
    ) -> WriteResult {
        tag.write_bytes(self.buf)?;

        match content_length {
            Some(len) => {
                // Optimized path: write the correct length encoding upfront
                if len < 128 {
                    self.buf.push_byte(len as u8)?;
                } else {
                    let num_length_bytes = _length_length(len);
                    self.buf.push_byte(0x80 | num_length_bytes)?;
                    for i in (1..=num_length_bytes).rev() {
                        self.buf.push_byte((len >> ((i - 1) * 8)) as u8)?;
                    }
                }
                let start_len = self.buf.len();
                body(self.buf)?;
                assert_eq!(len, self.buf.len() - start_len);
                Ok(())
            }
            None => {
                // Write a placeholder and then fix the length up later as
                // required.
                self.buf.push_byte(0)?;
                let start_len = self.buf.len();
                body(self.buf)?;
                self.insert_length(start_len)
            }
        }
    }

    #[inline]
    fn insert_length(&mut self, start_len: usize) -> WriteResult {
        let added_len = self.buf.len() - start_len;
        if added_len >= 128 {
            let n = _length_length(added_len);
            self.buf.as_mut_slice()[start_len - 1] = 0x80 | n;
            let mut length_buf = [0u8; 8];
            for (pos, i) in (1..=n).rev().enumerate() {
                length_buf[pos] = (added_len >> ((i - 1) * 8)) as u8;
            }
            _insert_at_position(self.buf, start_len, &length_buf[..n as usize])?;
        } else {
            self.buf.as_mut_slice()[start_len - 1] = added_len as u8;
        }

        Ok(())
    }
}

/// Constructs a writer and invokes a callback which writes ASN.1 elements into
/// the writer, then returns the generated DER bytes.
#[inline]
pub fn write<F: Fn(&mut Writer<'_>) -> WriteResult>(f: F) -> WriteResult<Vec<u8>> {
    let mut v = WriteBuf::new(vec![]);
    let mut w = Writer::new(&mut v);
    f(&mut w)?;
    Ok(v.0)
}

/// Writes a single top-level ASN.1 element, returning the generated DER bytes.
/// Most often this will be used where `T` is a type with
/// `#[derive(asn1::Asn1Write)]`.
pub fn write_single<T: Asn1Writable>(v: &T) -> WriteResult<Vec<u8>> {
    write(|w| w.write_element(v))
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    use super::{_insert_at_position, write, write_single, WriteBuf, Writer};
    use crate::types::Asn1Writable;
    use crate::{
        parse_single, BMPString, BigInt, BigUint, BitString, Choice1, Choice2, Choice3, DateTime,
        Enumerated, Explicit, GeneralizedTime, IA5String, Implicit, ObjectIdentifier,
        OctetStringEncoded, OwnedBigInt, OwnedBigUint, OwnedBitString, PrintableString, Sequence,
        SequenceOf, SequenceOfWriter, SequenceWriter, SetOf, SetOfWriter, Tlv, UniversalString,
        UtcTime, Utf8String, VisibleString, WriteError, X509GeneralizedTime,
    };
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    fn assert_writes<T>(data: &[(T, &[u8])])
    where
        T: Asn1Writable,
    {
        for (val, expected) in data {
            let result = write_single(val).unwrap();
            assert_eq!(&result, expected);
        }
    }

    #[test]
    fn test_insert_at_position() {
        let mut v = WriteBuf::new(vec![1, 2, 3, 4]);
        _insert_at_position(&mut v, 2, &[5, 6]).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 5, 6, 3, 4]);
    }

    #[test]
    fn test_write_error_eq() {
        let e1 = WriteError::AllocationError;
        let e2 = WriteError::AllocationError;

        assert_eq!(e1, e2);
    }

    #[test]
    fn test_write_element() {
        assert_eq!(write(|w| w.write_element(&())).unwrap(), b"\x05\x00");
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
            (b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b"\x04\x82\x01\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]);

        assert_writes::<[u8; 0]>(&[([], b"\x04\x00")]);
        assert_writes::<[u8; 1]>(&[([1], b"\x04\x01\x01")]);
        assert_writes::<[u8; 2]>(&[([2, 3], b"\x04\x02\x02\x03")]);
    }

    #[test]
    fn test_write_octet_string_encoded() {
        assert_writes::<OctetStringEncoded<bool>>(&[
            (OctetStringEncoded::new(true), b"\x04\x03\x01\x01\xff"),
            (OctetStringEncoded::new(false), b"\x04\x03\x01\x01\x00"),
        ]);
    }

    #[test]
    fn test_write_printable_string() {
        assert_writes::<PrintableString<'_>>(&[
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
        assert_writes::<IA5String<'_>>(&[
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
        assert_writes::<Utf8String<'_>>(&[
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
        assert_writes::<VisibleString<'_>>(&[
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
    fn test_write_bmpstring() {
        assert_writes::<BMPString<'_>>(&[(
            BMPString::new(b"\x00a\x00b\x00c").unwrap(),
            b"\x1e\x06\x00a\x00b\x00c",
        )]);
    }

    #[test]
    fn test_write_universalstring() {
        assert_writes::<UniversalString<'_>>(&[(
            UniversalString::new(b"\x00\x00\x00a\x00\x00\x00b\x00\x00\x00c").unwrap(),
            b"\x1c\x0c\x00\x00\x00a\x00\x00\x00b\x00\x00\x00c",
        )]);
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
    fn test_write_u64() {
        assert_writes::<u64>(&[(
            12356915591483590945,
            b"\x02\x09\x00\xab\x7c\x95\x42\xbd\xdd\x89\x21",
        )]);
    }

    #[test]
    fn test_write_i32() {
        assert_writes::<i32>(&[
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
    fn test_write_u16() {
        assert_writes::<u16>(&[
            (0, b"\x02\x01\x00"),
            (1, b"\x02\x01\x01"),
            (256, b"\x02\x02\x01\x00"),
            (65535, b"\x02\x03\x00\xff\xff"),
        ]);
    }

    #[test]
    fn test_write_i16() {
        assert_writes::<i16>(&[
            (0, b"\x02\x01\x00"),
            (1, b"\x02\x01\x01"),
            (-256, b"\x02\x02\xff\x00"),
            (-1, b"\x02\x01\xff"),
            (-32768, b"\x02\x02\x80\x00"),
            (32767, b"\x02\x02\x7f\xff"),
        ]);
    }

    #[test]
    fn test_write_u8() {
        assert_writes::<u8>(&[
            (0, b"\x02\x01\x00"),
            (127, b"\x02\x01\x7f"),
            (128, b"\x02\x02\x00\x80"),
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
        assert_writes::<BigUint<'_>>(&[
            (BigUint::new(b"\x00\xff").unwrap(), b"\x02\x02\x00\xff"),
            (
                BigUint::new(b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").unwrap(),
                b"\x02\x0d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
        ]);
    }

    #[test]
    fn test_write_ownedbiguint() {
        assert_writes::<OwnedBigUint>(&[
            (
                OwnedBigUint::new(b"\x00\xff".to_vec()).unwrap(),
                b"\x02\x02\x00\xff",
            ),
            (
                OwnedBigUint::new(b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".to_vec())
                    .unwrap(),
                b"\x02\x0d\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
        ]);
    }

    #[test]
    fn test_write_bigint() {
        assert_writes::<BigInt<'_>>(&[
            (BigInt::new(b"\xff").unwrap(), b"\x02\x01\xff"),
            (
                BigInt::new(b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").unwrap(),
                b"\x02\x0c\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ),
        ]);
    }

    #[test]
    fn test_write_ownedbigint() {
        assert_writes::<OwnedBigInt>(&[
            (OwnedBigInt::new(b"\xff".to_vec()).unwrap(), b"\x02\x01\xff"),
            (
                OwnedBigInt::new(b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".to_vec())
                    .unwrap(),
                b"\x02\x0c\xff\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
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
            (
                ObjectIdentifier::from_string("2.4.0").unwrap(),
                b"\x06\x02\x54\x00",
            ),
        ]);
    }

    #[test]
    fn test_write_bit_string() {
        assert_writes::<BitString<'_>>(&[
            (BitString::new(b"", 0).unwrap(), b"\x03\x01\x00"),
            (BitString::new(b"\x80", 7).unwrap(), b"\x03\x02\x07\x80"),
            (
                BitString::new(b"\x81\xf0", 4).unwrap(),
                b"\x03\x03\x04\x81\xf0",
            ),
        ]);

        assert_writes::<OwnedBitString>(&[
            (OwnedBitString::new(vec![], 0).unwrap(), b"\x03\x01\x00"),
            (
                OwnedBitString::new(vec![0x80], 7).unwrap(),
                b"\x03\x02\x07\x80",
            ),
            (
                OwnedBitString::new(vec![0x81, 0xf0], 4).unwrap(),
                b"\x03\x03\x04\x81\xf0",
            ),
        ]);
    }

    #[test]
    fn test_write_utctime() {
        assert_writes::<UtcTime>(&[
            (
                UtcTime::new(DateTime::new(1991, 5, 6, 23, 45, 40).unwrap()).unwrap(),
                b"\x17\x0d910506234540Z",
            ),
            (
                UtcTime::new(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap()).unwrap(),
                b"\x17\x0d700101000000Z",
            ),
            (
                UtcTime::new(DateTime::new(2009, 11, 15, 22, 56, 16).unwrap()).unwrap(),
                b"\x17\x0d091115225616Z",
            ),
        ]);
    }

    #[test]
    fn test_write_x509_generalizedtime() {
        assert_writes(&[
            (
                X509GeneralizedTime::new(DateTime::new(1991, 5, 6, 23, 45, 40).unwrap()).unwrap(),
                b"\x18\x0f19910506234540Z",
            ),
            (
                X509GeneralizedTime::new(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap()).unwrap(),
                b"\x18\x0f19700101000000Z",
            ),
            (
                X509GeneralizedTime::new(DateTime::new(2009, 11, 15, 22, 56, 16).unwrap()).unwrap(),
                b"\x18\x0f20091115225616Z",
            ),
        ]);
    }

    #[test]
    fn test_write_generalizedtime() {
        assert_writes(&[
            (
                GeneralizedTime::new(DateTime::new(1991, 5, 6, 23, 45, 40).unwrap(), Some(1_234))
                    .unwrap(),
                b"\x18\x1919910506234540.000001234Z",
            ),
            (
                GeneralizedTime::new(DateTime::new(1991, 5, 6, 23, 45, 40).unwrap(), Some(1))
                    .unwrap(),
                b"\x18\x1919910506234540.000000001Z",
            ),
            (
                GeneralizedTime::new(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap(), None).unwrap(),
                b"\x18\x0f19700101000000Z",
            ),
            (
                GeneralizedTime::new(
                    DateTime::new(2009, 11, 15, 22, 56, 16).unwrap(),
                    Some(100_000_000),
                )
                .unwrap(),
                b"\x18\x1120091115225616.1Z",
            ),
            (
                GeneralizedTime::new(
                    DateTime::new(2009, 11, 15, 22, 56, 16).unwrap(),
                    Some(999_999_999),
                )
                .unwrap(),
                b"\x18\x1920091115225616.999999999Z",
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
                w.write_element(&SequenceWriter::new(&|w: &mut Writer<'_>| {
                    w.write_element(&())
                }))
            })
            .unwrap(),
            b"\x30\x02\x05\x00"
        );
        assert_eq!(
            write(|w| {
                w.write_element(&SequenceWriter::new(&|w: &mut Writer<'_>| {
                    w.write_element(&true)
                }))
            })
            .unwrap(),
            b"\x30\x03\x01\x01\xff"
        );
        assert_eq!(
            write(|w| {
                w.write_element(&SequenceWriter::new(&|w: &mut Writer<'_>| {
                    w.write_element(&b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                }))
            }).unwrap(),
            b"\x30\x81\x84\x04\x81\x81aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        assert_writes(&[(
            parse_single::<Sequence<'_>>(b"\x30\x06\x01\x01\xff\x02\x01\x06").unwrap(),
            b"\x30\x06\x01\x01\xff\x02\x01\x06",
        )]);
    }

    #[test]
    fn test_write_sequence_of() {
        assert_writes::<SequenceOfWriter<'_, u8, &[u8]>>(&[
            (SequenceOfWriter::new(&[]), b"\x30\x00"),
            (
                SequenceOfWriter::new(&[1u8, 2, 3]),
                b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
        ]);
        assert_writes::<SequenceOfWriter<'_, u8, Vec<u8>>>(&[
            (SequenceOfWriter::new(vec![]), b"\x30\x00"),
            (
                SequenceOfWriter::new(vec![1u8, 2, 3]),
                b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
        ]);
        assert_writes::<SequenceOfWriter<'_, SequenceWriter<'_>, &[SequenceWriter<'_>]>>(&[
            (SequenceOfWriter::new(&[]), b"\x30\x00"),
            (
                SequenceOfWriter::new(&[SequenceWriter::new(&|_w| Ok(()))]),
                b"\x30\x02\x30\x00",
            ),
            (
                SequenceOfWriter::new(&[SequenceWriter::new(&|w: &mut Writer<'_>| {
                    w.write_element(&1u64)
                })]),
                b"\x30\x05\x30\x03\x02\x01\x01",
            ),
        ]);

        assert_writes(&[(
            parse_single::<SequenceOf<'_, u64>>(b"\x30\x06\x02\x01\x05\x02\x01\x07").unwrap(),
            b"\x30\x06\x02\x01\x05\x02\x01\x07",
        )]);
    }

    #[test]
    fn test_write_set_of() {
        assert_writes::<SetOfWriter<'_, u8, &[u8]>>(&[
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
        assert_writes(&[
            (SetOfWriter::new(vec![]), b"\x31\x00"),
            (SetOfWriter::new(vec![1u8]), b"\x31\x03\x02\x01\x01"),
            (
                SetOfWriter::new(vec![1, 2, 3]),
                b"\x31\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
            (
                SetOfWriter::new(vec![3, 2, 1]),
                b"\x31\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03",
            ),
        ]);

        assert_writes(&[(
            parse_single::<SetOf<'_, u64>>(b"\x31\x06\x02\x01\x05\x02\x01\x07").unwrap(),
            b"\x31\x06\x02\x01\x05\x02\x01\x07",
        )]);
    }

    #[test]
    fn test_write_implicit() {
        assert_writes::<Implicit<bool, 2>>(&[
            (Implicit::new(true), b"\x82\x01\xff"),
            (Implicit::new(false), b"\x82\x01\x00"),
        ]);
    }

    #[test]
    fn test_write_explicit() {
        assert_writes::<Explicit<bool, 2>>(&[
            (Explicit::new(true), b"\xa2\x03\x01\x01\xff"),
            (Explicit::new(false), b"\xa2\x03\x01\x01\x00"),
        ]);
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
        assert_writes(&[
            (
                parse_single::<Tlv<'_>>(b"\x01\x01\x00").unwrap(),
                b"\x01\x01\x00",
            ),
            (
                parse_single::<Tlv<'_>>(b"\x1f\x81\x80\x01\x00").unwrap(),
                b"\x1f\x81\x80\x01\x00",
            ),
            (
                parse_single::<Tlv<'_>>(b"\x1f\x1f\x00").unwrap(),
                b"\x1f\x1f\x00",
            ),
        ]);
    }

    #[test]
    fn test_write_box() {
        assert_writes(&[
            (Box::new(12u8), b"\x02\x01\x0c"),
            (Box::new(0), b"\x02\x01\x00"),
        ]);
    }

    #[test]
    fn test_write_error_display() {
        use alloc::string::ToString;
        assert_eq!(&WriteError::AllocationError.to_string(), "allocation error");
    }
}
