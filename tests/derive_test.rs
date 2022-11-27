use std::fmt;

fn assert_roundtrips<
    'a,
    T: asn1::Asn1Readable<'a> + asn1::Asn1Writable + PartialEq + fmt::Debug,
>(
    data: &[(asn1::ParseResult<T>, &'a [u8])],
) {
    for (value, der_bytes) in data {
        let parsed = asn1::parse_single::<T>(der_bytes);
        assert_eq!(value, &parsed);
        if let Ok(v) = value {
            let result = asn1::write_single(v).unwrap();
            assert_eq!(&result, der_bytes);
        }
    }
}

#[test]
fn test_struct_no_fields() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct NoFields;

    assert_roundtrips(&[
        (Ok(NoFields), b"\x30\x00"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::ExtraData)),
            b"\x30\x01\x00",
        ),
    ]);
}

#[test]
fn test_struct_simple_fields() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
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
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct SimpleFields(u8, u8);

    assert_roundtrips(&[(Ok(SimpleFields(2, 3)), b"\x30\x06\x02\x01\x02\x02\x01\x03")]);
}

#[test]
fn test_struct_lifetime() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct Lifetimes<'a> {
        a: &'a [u8],
    }

    assert_roundtrips(&[(Ok(Lifetimes { a: b"abc" }), b"\x30\x05\x04\x03abc")]);
}

#[test]
fn test_optional() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct OptionalFields {
        zzz: Option<u8>,
    }

    assert_roundtrips(&[
        (Ok(OptionalFields { zzz: None }), b"\x30\x00"),
        (Ok(OptionalFields { zzz: Some(8) }), b"\x30\x03\x02\x01\x08"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::ExtraData)),
            b"\x30\x03\x04\x00\x00",
        ),
    ]);
}

#[test]
fn test_explicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct EmptySequence;

    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
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
    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
    struct EmptySequence;

    #[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Eq)]
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

#[test]
fn test_default() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct DefaultFields {
        #[default(13)]
        a: u8,
        #[default(15)]
        #[explicit(1)]
        b: u8,
        #[default(17)]
        #[implicit(5)]
        c: u8,
    }

    assert_roundtrips(&[
        (
            Ok(DefaultFields {
                a: 13,
                b: 15,
                c: 17,
            }),
            b"\x30\x00",
        ),
        (
            Ok(DefaultFields { a: 3, b: 15, c: 17 }),
            b"\x30\x03\x02\x01\x03",
        ),
        (
            Ok(DefaultFields { a: 13, b: 5, c: 17 }),
            b"\x30\x05\xa1\x03\x02\x01\x05",
        ),
        (
            Ok(DefaultFields { a: 13, b: 15, c: 7 }),
            b"\x30\x03\x85\x01\x07",
        ),
        (
            Ok(DefaultFields { a: 3, b: 5, c: 7 }),
            b"\x30\x0b\x02\x01\x03\xa1\x03\x02\x01\x05\x85\x01\x07",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultFields::a"))),
            b"\x30\x03\x02\x01\x0d",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultFields::b"))),
            b"\x30\x05\xa1\x03\x02\x01\x0f",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultFields::c"))),
            b"\x30\x03\x85\x01\x11",
        ),
    ]);
}

#[test]
#[cfg(feature = "const-generics")]
fn test_default_const_generics() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug)]
    struct DefaultFields<'a> {
        #[default(15)]
        a: asn1::Explicit<'a, u8, 1>,
        #[default(17)]
        b: asn1::Implicit<'a, u8, 5>,
    }

    assert_roundtrips(&[
        (
            Ok(DefaultFields {
                a: asn1::Explicit::new(15),
                b: asn1::Implicit::new(17),
            }),
            b"\x30\x00",
        ),
        (
            Ok(DefaultFields {
                a: asn1::Explicit::new(5),
                b: asn1::Implicit::new(17),
            }),
            b"\x30\x05\xa1\x03\x02\x01\x05",
        ),
        (
            Ok(DefaultFields {
                a: asn1::Explicit::new(15),
                b: asn1::Implicit::new(7),
            }),
            b"\x30\x03\x85\x01\x07",
        ),
        (
            Ok(DefaultFields {
                a: asn1::Explicit::new(5),
                b: asn1::Implicit::new(7),
            }),
            b"\x30\x08\xa1\x03\x02\x01\x05\x85\x01\x07",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultFields::a"))),
            b"\x30\x05\xa1\x03\x02\x01\x0f",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultFields::b"))),
            b"\x30\x03\x85\x01\x11",
        ),
    ]);
}

#[test]
fn test_default_bool() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct DefaultField {
        #[default(false)]
        a: bool,
    }

    assert_roundtrips(&[
        (Ok(DefaultField { a: true }), b"\x30\x03\x01\x01\xff"),
        (Ok(DefaultField { a: false }), b"\x30\x00"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::EncodedDefault)
                .add_location(asn1::ParseLocation::Field("DefaultField::a"))),
            b"\x30\x03\x01\x01\x00",
        ),
    ]);
}

#[test]
fn test_enum() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    enum BasicChoice {
        A(u64),
        B(()),
    }

    assert_roundtrips(&[
        (Ok(BasicChoice::A(17)), b"\x02\x01\x11"),
        (Ok(BasicChoice::B(())), b"\x05\x00"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(4),
            })),
            b"\x04\x00",
        ),
    ]);

    assert_roundtrips(&[
        (Ok(Some(BasicChoice::A(17))), b"\x02\x01\x11"),
        (Ok(Some(BasicChoice::B(()))), b"\x05\x00"),
        (Ok(None), b""),
    ]);
}

#[test]
fn test_enum_lifetimes() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    enum LifetimesChoice<'a> {
        A(u64),
        B(&'a [u8]),
    }

    assert_roundtrips(&[
        (Ok(LifetimesChoice::A(17)), b"\x02\x01\x11"),
        (Ok(LifetimesChoice::B(b"lol")), b"\x04\x03lol"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(5),
            })),
            b"\x05\x00",
        ),
    ]);

    assert_roundtrips(&[
        (Ok(Some(LifetimesChoice::A(17))), b"\x02\x01\x11"),
        (Ok(Some(LifetimesChoice::B(b"lol"))), b"\x04\x03lol"),
        (Ok(None), b""),
    ]);
}

#[test]
fn test_enum_explicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    enum ExplicitChoice<'a> {
        #[explicit(5)]
        A(u64),
        B(&'a [u8]),
    }

    assert_roundtrips(&[
        (Ok(ExplicitChoice::A(17)), b"\xa5\x03\x02\x01\x11"),
        (Ok(ExplicitChoice::B(b"lol")), b"\x04\x03lol"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(5),
            })),
            b"\x05\x00",
        ),
    ]);

    assert_roundtrips(&[
        (Ok(Some(ExplicitChoice::A(17))), b"\xa5\x03\x02\x01\x11"),
        (Ok(Some(ExplicitChoice::B(b"lol"))), b"\x04\x03lol"),
        (Ok(None), b""),
    ]);
}

#[test]
fn test_enum_implicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct EmptySequence;

    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    enum ImplicitChoice<'a> {
        #[implicit(5)]
        A(u64),
        #[implicit(7)]
        B(EmptySequence),
        C(&'a [u8]),
    }

    assert_roundtrips(&[
        (Ok(ImplicitChoice::A(17)), b"\x85\x01\x11"),
        (Ok(ImplicitChoice::B(EmptySequence)), b"\xa7\x00"),
        (Ok(ImplicitChoice::C(b"lol")), b"\x04\x03lol"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(5),
            })),
            b"\x05\x00",
        ),
    ]);

    assert_roundtrips(&[
        (Ok(Some(ImplicitChoice::A(17))), b"\x85\x01\x11"),
        (Ok(Some(ImplicitChoice::B(EmptySequence))), b"\xa7\x00"),
        (Ok(Some(ImplicitChoice::C(b"lol"))), b"\x04\x03lol"),
        (Ok(None), b""),
    ]);
}

#[test]
fn test_error_parse_location() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct InnerSeq(u64);

    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    enum InnerEnum {
        Int(u64),
    }

    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct OuterSeq {
        inner: InnerSeq,
        inner_enum: Option<InnerEnum>,
    }

    assert_roundtrips::<OuterSeq>(&[
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue)
                .add_location(asn1::ParseLocation::Field("InnerSeq::0"))
                .add_location(asn1::ParseLocation::Field("OuterSeq::inner"))),
            b"\x30\x04\x30\x02\x02\x00",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue)
                .add_location(asn1::ParseLocation::Field("InnerEnum::Int"))
                .add_location(asn1::ParseLocation::Field("OuterSeq::inner_enum"))),
            b"\x30\x07\x30\x03\x02\x01\x01\x02\x00",
        ),
    ]);
}

#[test]
fn test_required_implicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct RequiredImplicit {
        #[implicit(0, required)]
        value: u8,
    }

    assert_roundtrips::<RequiredImplicit>(&[
        (Ok(RequiredImplicit { value: 8 }), b"\x30\x03\x80\x01\x08"),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::ShortData)
                .add_location(asn1::ParseLocation::Field("RequiredImplicit::value"))),
            b"\x30\x00",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(11),
            })
            .add_location(asn1::ParseLocation::Field("RequiredImplicit::value"))),
            b"\x30\x03\x0b\x01\x00",
        ),
    ]);
}

#[test]
fn test_required_explicit() {
    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct RequiredExplicit {
        #[explicit(0, required)]
        value: u8,
    }

    assert_roundtrips::<RequiredExplicit>(&[
        (
            Ok(RequiredExplicit { value: 8 }),
            b"\x30\x05\xa0\x03\x02\x01\x08",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::ShortData)
                .add_location(asn1::ParseLocation::Field("RequiredExplicit::value"))),
            b"\x30\x00",
        ),
        (
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: asn1::Tag::primitive(11),
            })
            .add_location(asn1::ParseLocation::Field("RequiredExplicit::value"))),
            b"\x30\x03\x0b\x01\x00",
        ),
    ]);
}

#[test]
fn test_defined_by() {
    const OID1: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3);
    const OID2: asn1::ObjectIdentifier = asn1::oid!(1, 2, 5);

    #[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Debug, Eq)]
    struct S<'a> {
        oid: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
        #[defined_by(oid)]
        value: Value<'a>,
    }

    #[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite, PartialEq, Debug, Eq)]
    enum Value<'a> {
        #[defined_by(OID1)]
        OctetString(&'a [u8]),
        #[defined_by(OID2)]
        Integer(u32),
    }

    assert_roundtrips::<S>(&[
        (
            Ok(S {
                oid: asn1::DefinedByMarker::marker(),
                value: Value::OctetString(b"abc"),
            }),
            b"\x30\x09\x06\x02\x2a\x03\x04\x03abc",
        ),
        (
            Ok(S {
                oid: asn1::DefinedByMarker::marker(),
                value: Value::Integer(17),
            }),
            b"\x30\x07\x06\x02\x2a\x05\x02\x01\x11",
        ),
        (
            Err(
                asn1::ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy)
                    .add_location(asn1::ParseLocation::Field("S::value")),
            ),
            b"\x30\x04\x06\x02\x2a\x07",
        ),
    ]);
}
