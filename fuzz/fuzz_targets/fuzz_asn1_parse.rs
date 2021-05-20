#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _: asn1::ParseResult<()> = asn1::parse(data, |d| {
        d.read_element::<()>()?;
        d.read_element::<bool>()?;

        d.read_element::<i8>()?;
        d.read_element::<u8>()?;
        d.read_element::<i64>()?;
        d.read_element::<u64>()?;
        d.read_element::<asn1::BigUint>()?;

        d.read_element::<&[u8]>()?;
        d.read_element::<asn1::PrintableString>()?;
        d.read_element::<asn1::ObjectIdentifier>()?;
        d.read_element::<asn1::BitString>()?;
        d.read_element::<asn1::UtcTime>()?;

        d.read_element::<Option<()>>()?;
        d.read_element::<asn1::Choice2<bool, i64>>()?;

        d.read_element::<asn1::SequenceOf<i64>>()?.collect::<Vec<_>>();
        d.read_element::<asn1::SetOf<i64>>()?.collect::<Vec<_>>();

        Ok(())
    });
});
