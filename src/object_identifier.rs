use alloc::borrow::Cow;
use alloc::fmt;
use alloc::vec;
use alloc::vec::Vec;

/// Represents an ASN.1 `OBJECT IDENTIFIER`. ObjectIdentifiers are opaque, the only thing may be
/// done with them is test if they are equal to another `ObjectIdentifier`. The generally
/// recommended practice for handling them is to create some `ObjectIdentifier` constants with
/// `ObjectIdentifier::from_string` and then compare ObjectIdentifiers you get from parsing to
/// those.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ObjectIdentifier<'a> {
    // Store the OID as DER encoded. This means we can 0-copy on parse.
    der_encoded: Cow<'a, [u8]>,
}

fn _read_base128_int<I: Iterator<Item = u8>>(mut reader: I) -> Option<u32> {
    let mut ret = 0u32;
    for _ in 0..4 {
        let b = reader.next()?;
        ret <<= 7;
        ret |= u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(ret);
        }
    }
    None
}

fn _write_base128_int(data: &mut Vec<u8>, n: u32) {
    if n == 0 {
        data.push(0);
        return;
    }

    let mut l = 0;
    let mut i = n;
    while i > 0 {
        l += 1;
        i >>= 7;
    }

    for i in (0..l).rev() {
        let mut o = (n >> (i * 7)) as u8;
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        data.push(o);
    }
}

impl<'a> ObjectIdentifier<'a> {
    /// Parses an OID from a dotted string, e.g. `"1.2.840.113549"`.
    pub fn from_string(oid: &str) -> Option<ObjectIdentifier<'a>> {
        let mut parts = oid.split('.');

        let first = parts.next()?.parse::<u32>().ok()?;
        let second = parts.next()?.parse::<u32>().ok()?;
        if first > 2 || (first < 2 && second >= 40) {
            return None;
        }

        let mut der_data = vec![];
        _write_base128_int(&mut der_data, 40 * first + second);
        for part in parts {
            _write_base128_int(&mut der_data, part.parse::<u32>().ok()?);
        }
        Some(ObjectIdentifier {
            der_encoded: Cow::Owned(der_data),
        })
    }

    /// Creates an `ObjectIdentifier` from its DER representation. This does
    /// not perform any allocations or copies.
    pub fn from_der(data: &'a [u8]) -> Option<ObjectIdentifier<'a>> {
        if data.is_empty() {
            return None;
        }
        let mut cursor = data.iter().copied();
        while cursor.len() > 0 {
            _read_base128_int(&mut cursor)?;
        }

        Some(ObjectIdentifier {
            der_encoded: Cow::Borrowed(data),
        })
    }

    pub(crate) fn as_der(&self) -> &[u8] {
        &self.der_encoded
    }
}

impl fmt::Display for ObjectIdentifier<'_> {
    /// Converts an `ObjectIdentifier` to a dotted string, e.g.
    /// "1.2.840.113549".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut cursor = self.der_encoded.iter().copied();

        let first = _read_base128_int(&mut cursor).unwrap();
        if first < 80 {
            write!(f, "{}.{}", first / 40, first % 40)?;
        } else {
            write!(f, "2.{}", first - 80)?;
        }

        while cursor.len() > 0 {
            let digit = _read_base128_int(&mut cursor).unwrap();
            write!(f, ".{}", digit)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::ObjectIdentifier;

    #[test]
    fn test_object_identifier_from_string() {
        for val in &[
            "",
            "1",
            "3.10",
            "1.50",
            "2.12.a3.4",
            "a.4",
            "1.a",
            ".2.5",
            "2..5",
            "2.5.",
        ] {
            assert_eq!(ObjectIdentifier::from_string(val), None);
        }

        for val in &[
            "2.5",
            "2.5.2",
            "1.2.840.113549",
            "1.2.3.4",
            "1.2.840.133549.1.1.5",
            "2.100.3",
        ] {
            assert!(ObjectIdentifier::from_string(val).is_some());
        }
    }

    #[test]
    fn test_to_string() {
        for val in &[
            "0.4",
            "2.5",
            "2.5.2",
            "1.2.840.113549",
            "1.2.3.4",
            "1.2.840.133549.1.1.5",
            "2.100.3",
        ] {
            assert_eq!(
                &ObjectIdentifier::from_string(val).unwrap().to_string(),
                val
            );
        }
    }
}
