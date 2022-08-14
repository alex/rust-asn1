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
    f13: asn1::BitString<'a>,

    f14: asn1::ObjectIdentifier,

    f15: asn1::UtcTime,
    f16: asn1::GeneralizedTime,

    f17: Option<()>,
    f18: asn1::Choice2<bool, i64>,

    f19: asn1::SequenceOf<'a, i64>,
    f20: asn1::SetOf<'a, i64>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = asn1::parse_single::<Data>(data) {
        // I'd like to test that the result of `write_single` is the same
        // as `data`, which should hold in general... but it doesn't hold
        // for our UtcTime/GeneralizedTime types. Those types can parse
        // several formats, but always serialize to the same one.
        let written = asn1::write_single(&parsed).unwrap();
        let reparsed = asn1::parse_single::<Data>(&written).unwrap();
        assert!(parsed == reparsed);
    }
});
