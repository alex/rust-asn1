#[derive(Debug, PartialEq, Eq)]
pub struct ObjectIdentifier {
    pub parts: Vec<u32>,
}

impl ObjectIdentifier {
    pub fn new(oid: Vec<u32>) -> Option<ObjectIdentifier> {
        if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
            return None;
        }

        return Some(ObjectIdentifier { parts: oid });
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BitString {
    data: Vec<u8>,
    bit_length: usize,
}

impl BitString {
    pub fn new(data: Vec<u8>, bit_length: usize) -> Option<BitString> {
        match (data.len(), bit_length) {
            (0, 0) => (),
            (_, 0) | (0, _) => return None,
            (i, j) if (i * 8 < j) || (i - 1) * 8 > j => return None,
            _ => (),
        }

        let padding_bits = data.len() * 8 - bit_length;
        if padding_bits > 0 && data[data.len() - 1] & ((1 << padding_bits) - 1) != 0 {
            return None;
        }

        return Some(BitString {
            data: data,
            bit_length: bit_length,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{BitString, ObjectIdentifier};

    #[test]
    fn test_object_identifier_new() {
        assert!(ObjectIdentifier::new(vec![]).is_none());
        assert!(ObjectIdentifier::new(vec![3, 10]).is_none());
        assert!(ObjectIdentifier::new(vec![1, 50]).is_none());
    }

    #[test]
    fn test_bit_string_new() {
        assert!(BitString::new(b"".to_vec(), 1).is_none());
        assert!(BitString::new(b"\x00".to_vec(), 0).is_none());
        assert!(BitString::new(b"\x00".to_vec(), 9).is_none());
        assert!(BitString::new(b"\xff".to_vec(), 3).is_none());
    }
}
