#[derive(asn1::Asn1Read)]
pub enum Value<'a> {
    SequenceOf(asn1::SequenceOf<'a, Value<'a>>),
    SetOf(asn1::SetOf<'a, Value<'a>>),
    Integer(asn1::BigInt<'a>),
    Boolean(bool),
    ObjectIdentifier(asn1::ObjectIdentifier),
    Null(asn1::Null),
    PrintableString(asn1::PrintableString<'a>),
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    OctetString(&'a [u8]),
    BitString(asn1::BitString<'a>),
    UtcTime(asn1::UtcTime),

    Fallback(asn1::Tlv<'a>),
}

impl Value<'_> {
    pub fn render(
        &self,
        out: &mut dyn std::io::Write,
        indent: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Value::SequenceOf(v) => {
                writeln!(out, "{}SEQUENCE", " ".repeat(indent))?;
                for el in v.clone() {
                    el.render(out, indent + 2)?;
                }
            }
            Value::SetOf(v) => {
                writeln!(out, "{}SET", " ".repeat(indent))?;
                for el in v.clone() {
                    el.render(out, indent + 2)?;
                }
            }
            Value::Integer(v) => {
                let data = hex::encode(v.as_bytes());
                let mut output = data.trim_start_matches('0');
                if output.is_empty() {
                    output = "0";
                }

                writeln!(
                    out,
                    "{}INTEGER: {}0x{}",
                    " ".repeat(indent),
                    if v.is_negative() { "-" } else { "" },
                    output,
                )?;
            }
            Value::Boolean(v) => {
                writeln!(out, "{}BOOLEAN: {:?}", " ".repeat(indent), v)?;
            }
            Value::ObjectIdentifier(v) => {
                writeln!(out, "{}OBJECT IDENTIFIER: {}", " ".repeat(indent), v)?;
            }
            Value::PrintableString(v) => {
                writeln!(
                    out,
                    "{}PRINTABLE STRING: {:?}",
                    " ".repeat(indent),
                    v.as_str()
                )?;
            }
            Value::IA5String(v) => {
                writeln!(out, "{}IA5 STRING: {:?}", " ".repeat(indent), v.as_str())?;
            }
            Value::Utf8String(v) => {
                writeln!(out, "{}UTF8 STRING: {:?}", " ".repeat(indent), v.as_str())?;
            }
            Value::OctetString(v) => {
                if let Ok(v) = asn1::parse_single::<Value<'_>>(v) {
                    writeln!(out, "{}OCTET STRING", " ".repeat(indent))?;
                    v.render(out, indent + 2)?;
                } else {
                    writeln!(out, "{}OCTET STRING: {:?}", " ".repeat(indent), v)?;
                }
            }
            Value::BitString(v) => {
                writeln!(
                    out,
                    "{}BIT STRING: {:?}",
                    " ".repeat(indent),
                    hex::encode(v.as_bytes())
                )?;
            }
            Value::UtcTime(v) => {
                let dt = v.as_datetime();
                writeln!(
                    out,
                    "{}UTC TIME: {}-{:02}-{:02} {:02}:{:02}:{:02}",
                    " ".repeat(indent),
                    dt.year(),
                    dt.month(),
                    dt.day(),
                    dt.hour(),
                    dt.minute(),
                    dt.second()
                )?;
            }
            Value::Null(_) => {
                writeln!(out, "{}NULL", " ".repeat(indent))?;
            }
            Value::Fallback(tlv) => {
                let tag = tlv.tag();
                if tag.is_constructed() {
                    writeln!(
                        out,
                        "{}[{:?} {}]",
                        " ".repeat(indent),
                        tag.class(),
                        tag.value()
                    )?;
                    asn1::parse_single::<Value<'_>>(tlv.data())?.render(out, indent + 2)?;
                } else {
                    writeln!(
                        out,
                        "{}[{:?} {} PRIMITIVE]: {:?}",
                        " ".repeat(indent),
                        tag.class(),
                        tag.value(),
                        tlv.data()
                    )?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Value;

    #[test]
    fn test_render() {
        for (der, expected) in [
            (b"\x01\x01\xff" as &[u8], "BOOLEAN: true\n"),
            (b"\x17\x0d910506234540Z", "UTC TIME: 1991-05-06 23:45:40\n"),
            (b"\x13\x03abc", "PRINTABLE STRING: \"abc\"\n"),
            (b"\x16\x03abc", "IA5 STRING: \"abc\"\n"),
            (b"\x03\x03\x04\x81\xf0", "BIT STRING: \"81f0\"\n"),
            (b"\x02\x01\x00", "INTEGER: 0x0\n"),
            (b"\x02\x01\x02", "INTEGER: 0x2\n"),
            (b"\x02\x01\x80", "INTEGER: -0x80\n"),
        ] {
            let v = asn1::parse_single::<Value<'_>>(der).unwrap();
            let mut output = vec![];
            v.render(&mut output, 0).unwrap();
            assert_eq!(std::str::from_utf8(&output).unwrap(), expected);
        }
    }
}
