use crate::parser::{ParseError, ParseErrorKind, ParseResult};
use alloc::fmt;

const MAX_OID_LENGTH: usize = 32;

/// Represents an ASN.1 `OBJECT IDENTIFIER`. ObjectIdentifiers are opaque, the only thing may be
/// done with them is test if they are equal to another `ObjectIdentifier`. The generally
/// recommended practice for handling them is to create some `ObjectIdentifier` constants with
/// `asn1::oid!()` and then compare ObjectIdentifiers you get from parsing to
/// those.
///
/// `asn1::oid!()` takes a series of arcs, for example: `asn1::oid!(1.2.3)`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ObjectIdentifier {
    // Store the OID as DER encoded.
    der_encoded: [u8; MAX_OID_LENGTH],
    der_encoded_len: u8,
}

fn _read_base128_int<I: Iterator<Item = u8>>(mut reader: I) -> ParseResult<u32> {
    let mut ret = 0u32;
    for _ in 0..4 {
        let b = reader
            .next()
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))?;
        ret <<= 7;
        ret |= u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(ret);
        }
    }
    Err(ParseError::new(ParseErrorKind::InvalidValue))
}

fn _write_base128_int(data: &mut [u8], data_len: &mut usize, n: u32) -> Option<()> {
    if n == 0 {
        if *data_len >= data.len() {
            return None;
        }
        data[*data_len] = 0;
        *data_len += 1;
        return Some(());
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
        if *data_len >= data.len() {
            return None;
        }
        data[*data_len] = o;
        *data_len += 1;
    }

    Some(())
}

impl ObjectIdentifier {
    /// Parses an OID from a dotted string, e.g. `"1.2.840.113549"`.
    /// ``asn1::oid!(1.2.3)`` is preferred for compile-time constants.
    pub fn from_string(oid: &str) -> Option<ObjectIdentifier> {
        let mut parts = oid.split('.');

        let first = parts.next()?.parse::<u32>().ok()?;
        let second = parts.next()?.parse::<u32>().ok()?;
        if first > 2 || (first < 2 && second >= 40) {
            return None;
        }

        let mut der_data = [0; MAX_OID_LENGTH];
        let mut der_data_len = 0;
        _write_base128_int(&mut der_data, &mut der_data_len, 40 * first + second)?;
        for part in parts {
            _write_base128_int(&mut der_data, &mut der_data_len, part.parse::<u32>().ok()?)?;
        }
        Some(ObjectIdentifier {
            der_encoded: der_data,
            der_encoded_len: der_data_len as u8,
        })
    }

    /// Creates an `ObjectIdentifier` from its DER representation. This does
    /// not perform any allocations or copies.
    pub fn from_der(data: &[u8]) -> ParseResult<ObjectIdentifier> {
        if data.is_empty() {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        } else if data.len() > MAX_OID_LENGTH {
            return Err(ParseError::new(ParseErrorKind::OidTooLong));
        }
        let mut cursor = data.iter().copied();
        while cursor.len() > 0 {
            _read_base128_int(&mut cursor)?;
        }

        let mut storage = [0; MAX_OID_LENGTH];
        storage[..data.len()].copy_from_slice(data);

        Ok(ObjectIdentifier {
            der_encoded: storage,
            der_encoded_len: data.len() as u8,
        })
    }

    /// Creates an `ObjectIdentifier` from its DER representation. Does not
    /// check that the DER is valid. Intended only for use from the `oid!()`
    /// macro. Do not use yourself!
    #[doc(hidden)]
    pub const fn from_der_unchecked(data: [u8; MAX_OID_LENGTH], data_len: u8) -> ObjectIdentifier {
        ObjectIdentifier {
            der_encoded: data,
            der_encoded_len: data_len,
        }
    }

    pub(crate) fn as_der(&self) -> &[u8] {
        &self.der_encoded[..self.der_encoded_len as usize]
    }
}

impl fmt::Display for ObjectIdentifier {
    /// Converts an `ObjectIdentifier` to a dotted string, e.g.
    /// "1.2.840.113549".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut cursor = self.as_der().iter().copied();

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
    use crate::{ObjectIdentifier, ParseError, ParseErrorKind};

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
            "1.3.6.1.4.1.1248.1.1.2.1.3.21.69.112.115.111.110.32.83.116.121.108.117.115.32.80.114.111.32.52.57.48.48.123.124412.31.213321.123",
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
    fn test_from_der() {
        assert_eq!(ObjectIdentifier::from_der(b"\x06\x2b\x2b\x06\x01\x04\x01\x89\x60\x01\x01\x02\x01\x03\x15\x45\x70\x73\x6f\x6e\x20\x53\x74\x79\x6c\x75\x73\x20\x50\x72\x6f\x20\x34\x39\x30\x30\x7b\x87\xcb\x7c\x1f\x8d\x82\x49\x7b"), Err(ParseError::new(ParseErrorKind::OidTooLong)));
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
