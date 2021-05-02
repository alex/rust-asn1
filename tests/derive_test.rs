#![cfg(feature = "derive")]

use std::fmt;

fn assert_roundtrips<
    'a,
    T: asn1::Asn1Readable<'a> + asn1::Asn1Writable<'a> + PartialEq + fmt::Debug,
>(
    data: &[(asn1::ParseResult<T>, &'a [u8])],
) {
    for (value, der_bytes) in data {
        let parsed = asn1::parse_single::<T>(der_bytes);
        assert_eq!(value, &parsed);
        if let Ok(v) = value {
            let result = asn1::write_single(v);
            assert_eq!(&result, der_bytes);
        }
    }
}

#[test]
fn test_struct_no_fields() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct NoFields;

    assert_roundtrips(&[
        (Ok(NoFields), b"\x30\x00"),
        (Err(asn1::ParseError::ExtraData), b"\x30\x01\x00"),
    ])
}

#[test]
fn test_struct_simple_fields() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct SimpleFields {
        a: u64,
        b: u64,
    }
    assert_roundtrips(&[(
        Ok(SimpleFields { a: 2, b: 3 }),
        b"\x30\x06\x02\x01\x02\x02\x01\x03",
    )]);
}

#[test]
fn test_tuple_struct_simple_fields() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct SimpleFields(u8, u8);

    assert_roundtrips(&[(Ok(SimpleFields(2, 3)), b"\x30\x06\x02\x01\x02\x02\x01\x03")]);
}

#[test]
fn test_struct_lifetime() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct Lifetimes<'a> {
        a: &'a [u8],
    }

    assert_roundtrips(&[(Ok(Lifetimes { a: b"abc" }), b"\x30\x05\x04\x03abc")]);
}

#[test]
fn test_optional() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct OptionalFields {
        zzz: Option<u8>,
    }

    assert_roundtrips(&[
        (Ok(OptionalFields { zzz: None }), b"\x30\x00"),
        (Ok(OptionalFields { zzz: Some(8) }), b"\x30\x03\x02\x01\x08"),
        (Err(asn1::ParseError::ExtraData), b"\x30\x03\x04\x00\x00"),
    ]);
}

#[test]
fn test_explicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct EmptySequence;

    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct ExplicitFields {
        #[explicit(5)]
        a: Option<u8>,
        #[explicit(7)]
        b: Option<EmptySequence>,
    }

    assert_roundtrips(&[
        (
            Ok(ExplicitFields {
                a: Some(3),
                b: Some(EmptySequence),
            }),
            b"\x30\x09\xa5\x03\x02\x01\x03\xa7\x02\x30\x00",
        ),
        (
            Ok(ExplicitFields {
                a: None,
                b: Some(EmptySequence),
            }),
            b"\x30\x04\xa7\x02\x30\x00",
        ),
        (
            Ok(ExplicitFields {
                a: Some(3),
                b: None,
            }),
            b"\x30\x05\xa5\x03\x02\x01\x03",
        ),
        (Ok(ExplicitFields { a: None, b: None }), b"\x30\x00"),
    ]);
}

#[test]
fn test_implicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct EmptySequence;

    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq)]
    struct ImplicitFields {
        #[implicit(5)]
        a: Option<u8>,
        #[implicit(7)]
        b: Option<EmptySequence>,
    }

    assert_roundtrips(&[
        (
            Ok(ImplicitFields {
                a: Some(3),
                b: Some(EmptySequence),
            }),
            b"\x30\x05\x85\x01\x03\xa7\x00",
        ),
        (
            Ok(ImplicitFields {
                a: None,
                b: Some(EmptySequence),
            }),
            b"\x30\x02\xa7\x00",
        ),
        (
            Ok(ImplicitFields {
                a: Some(3),
                b: None,
            }),
            b"\x30\x03\x85\x01\x03",
        ),
        (Ok(ImplicitFields { a: None, b: None }), b"\x30\x00"),
    ]);
}
