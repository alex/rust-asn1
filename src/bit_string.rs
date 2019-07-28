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

        return Some(BitString { data, padding_bits });
    }
}
