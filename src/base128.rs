use crate::parser::{ParseError, ParseErrorKind, ParseResult};

const INT_MAX_BYTES: u32 = u128::BITS.div_ceil(7);

pub(crate) fn read_base128_int(mut data: &[u8]) -> ParseResult<(u128, &[u8])> {
    let mut ret = 0u128;
    for i in 0..INT_MAX_BYTES {
        let b = match data.first() {
            Some(b) => *b,
            None => return Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
        };
        data = &data[1..];
        if ret > u128::MAX >> 7 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        ret <<= 7;
        ret |= u128::from(b & 0x7f);
        // Integers must be minimally encoded. `i == 0 && 0x80` would mean
        // that the first byte had a value of 0, which is non-minimal.
        if i == 0 && b == 0x80 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        if b & 0x80 == 0 {
            return Ok((ret, data));
        }
    }
    Err(ParseError::new(ParseErrorKind::InvalidValue))
}

pub(crate) fn base128_length(n: u128) -> usize {
    // Equivalent to: let bits = if n != 0 { 128 - n.leading_zeros() } else { 1 };
    let bits = u128::BITS - (n | 1).leading_zeros();
    let bytes = bits.div_ceil(7);
    bytes as usize
}

pub(crate) fn write_base128_int(mut data: &mut [u8], n: u128) -> Option<usize> {
    let length = base128_length(n);

    if data.len() < length {
        return None;
    }

    if n == 0 {
        data[0] = 0;
        return Some(1);
    }

    for i in (0..length).rev() {
        let mut o = (n >> (i * 7)) as u8;
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        data[0] = o;
        data = &mut data[1..];
    }

    Some(length)
}

#[cfg(test)]
mod tests {
    use super::{read_base128_int, write_base128_int};

    #[test]
    fn test_read_overflow() {
        let bufs = [
            [
                0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                0x80, 0x80, 0x80, 0x80, 0x80,
            ],
            [
                0x83, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0x80,
            ],
        ];
        for buf in bufs {
            let result = read_base128_int(&buf);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_roundtrip() {
        for i in [0, 10, u128::MAX] {
            let mut buf = [0; 32];
            let length = write_base128_int(&mut buf, i).unwrap();
            let (val, remainder) = read_base128_int(&buf[..length]).unwrap();
            assert_eq!(i, val);
            assert!(remainder.is_empty());
        }
    }
}
