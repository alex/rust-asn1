#![no_main]
use libfuzzer_sys::fuzz_target;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq)]
enum Data<'a> {
    Null(()),
    Bool(bool),

    OctetString(&'a [u8]),
    PrintableString(asn1::PrintableString<'a>),
    BMPString(asn1::BMPString<'a>),
    UniversalString(asn1::UniversalString<'a>),
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    VisibleString(asn1::VisibleString<'a>),

    ObjectIdentifier(asn1::ObjectIdentifier),

    UtcTime(asn1::UtcTime),
    GeneralizedTime(asn1::GeneralizedTime),

    Enumerated(asn1::Enumerated),

    SetOf(asn1::SetOf<'a, i64>),

    #[explicit(0)]
    I8(i8),
    #[explicit(1)]
    U8(u8),
    #[explicit(2)]
    I64(i64),
    #[explicit(3)]
    U64(u64),
    #[explicit(4)]
    BigInt(asn1::BigInt<'a>),
    #[explicit(5)]
    BigUint(asn1::BigUint<'a>),

    #[explicit(6)]
    BitString(asn1::BitString<'a>),
    #[explicit(7)]
    OwnedBitString(asn1::OwnedBitString),

    #[explicit(8)]
    Sequence(asn1::Sequence<'a>),
    #[explicit(9)]
    SequenceOf(asn1::SequenceOf<'a, i64>),
    #[explicit(10)]
    Struct(StructData<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq)]
struct StructData<'a> {
    f1: Option<()>,
    f2: asn1::Choice2<bool, i64>,

    #[implicit(3)]
    f3: Option<u32>,
    #[implicit(4)]
    f4: Option<u32>,

    #[implicit(5)]
    #[default(7)]
    f5: i32,
    #[implicit(6)]
    #[default(8)]
    f6: i32,

    f7: asn1::Implicit<'a, u32, 7>,
    f8: asn1::Explicit<'a, u32, 8>,

    #[explicit(9)]
    f9: Option<asn1::Tlv<'a>>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = asn1::parse_single::<Data>(data) {
        let written = asn1::write_single(&parsed).unwrap();
        assert_eq!(written, data);
    }
});
