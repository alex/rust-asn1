/// Represents an ASN.1 `BIT STRING`.
#[derive(Debug, PartialEq)]
pub struct BitString<'a> {
    data: &'a [u8],
    padding_bits: u8,
}

impl<'a> BitString<'a> {
    pub(crate) fn new(data: &'a [u8], padding_bits: u8) -> Option<BitString<'a>> {
        if padding_bits > 7 || (data.is_empty() && padding_bits != 0) {
            return None;
        }
        if padding_bits > 0 && data[data.len() - 1] & ((1 << padding_bits) - 1) != 0 {
            return None;
        }

        Some(BitString { data, padding_bits })
    }

    /// Returns a sequence of bytes representing the data in the `BIT STRING`. Padding bits will
    /// always be 0.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Returns the number of padding bits. Will always be in [0, 8).
    pub fn padding_bits(&self) -> u8 {
        self.padding_bits
    }
}

#[cfg(test)]
mod tests {
    use crate::BitString;

    #[test]
    fn test_bitstring_new() {
        assert_eq!(BitString::new(b"abc", 8), None);
        assert_eq!(BitString::new(b"", 2), None);
        assert_eq!(BitString::new(b"\xff", 1), None);

        assert!(BitString::new(b"\xff", 0).is_some());
        assert!(BitString::new(b"\xfe", 1).is_some());
    }

    #[test]
    fn test_bitstring_as_bytes() {
        let bs = BitString::new(b"\xfe", 1).unwrap();
        assert_eq!(bs.as_bytes(), b"\xfe");
    }

    #[test]
    fn test_bitstring_padding_bits() {
        let bs = BitString::new(b"\xfe", 1).unwrap();
        assert_eq!(bs.padding_bits(), 1);
        let bs = BitString::new(b"\xe0", 5).unwrap();
        assert_eq!(bs.padding_bits(), 5);
    }
}
