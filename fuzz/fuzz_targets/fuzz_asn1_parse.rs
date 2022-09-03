#![no_main]
use libfuzzer_sys::fuzz_target;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq)]
struct Data<'a> {
    f1: (),
    f2: bool,

    f3: i8,
    f4: u8,
    f5: i64,
    f6: u64,
    f7: asn1::BigUint<'a>,
    f8: asn1::BigInt<'a>,

    f9: &'a [u8],

    f10: asn1::PrintableString<'a>,
    f11: asn1::BMPString<'a>,
    f12: asn1::UniversalString<'a>,
    f13: asn1::IA5String<'a>,
    f14: asn1::Utf8String<'a>,
    f15: asn1::VisibleString<'a>,

    f16: asn1::BitString<'a>,
    f17: asn1::OwnedBitString,

    f18: asn1::ObjectIdentifier,

    f19: asn1::UtcTime,
    f20: asn1::GeneralizedTime,

    f21: asn1::Enumerated,

    f22: Option<()>,
    f23: asn1::Choice2<bool, i64>,

    f24: asn1::Sequence<'a>,
    f25: asn1::SequenceOf<'a, i64>,
    f26: asn1::SetOf<'a, i64>,

    #[implicit(3)]
    f27: Option<u32>,
    #[implicit(4)]
    f28: Option<u32>,

    #[implicit(3)]
    #[default(7)]
    f29: i32,
    #[implicit(4)]
    #[default(8)]
    f30: i32,

    #[cfg(feature = "const-generics")]
    f31: asn1::Implicit<u32, 3>,
    #[cfg(feature = "const-generics")]
    f32: asn1::Explicit<u32, 3>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = asn1::parse_single::<Data>(data) {
        let written = asn1::write_single(&parsed).unwrap();
        assert_eq!(written, data);
    }
});
