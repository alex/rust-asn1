fn assert_roundtrips<T>(i: T)
where
    for<'a> T: asn1::Asn1Writable + asn1::Asn1Readable<'a> + std::fmt::Debug + PartialEq,
{
    let result = asn1::write_single::<T>(&i).unwrap();
    let parsed = asn1::parse_single::<T>(&result).unwrap();
    assert_eq!(parsed, i);
}

#[test]
fn test_u8() {
    for i in u8::MIN..=u8::MAX {
        assert_roundtrips::<u8>(i);
    }
}

#[test]
fn test_i8() {
    for i in i8::MIN..=i8::MAX {
        assert_roundtrips::<i8>(i);
    }
}

#[test]
fn test_u16() {
    for i in u16::MIN..=u16::MAX {
        assert_roundtrips::<u16>(i);
    }
}

#[test]
fn test_i16() {
    for i in i16::MIN..=i16::MAX {
        assert_roundtrips::<i16>(i);
    }
}

#[test]
fn test_u64() {
    for v in [0, 12356915591483590945, u64::MAX] {
        assert_roundtrips::<u64>(v);
    }
}
