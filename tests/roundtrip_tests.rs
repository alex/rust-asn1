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
