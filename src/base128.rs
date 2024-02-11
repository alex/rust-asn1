use crate::parser::{ParseError, ParseErrorKind, ParseResult};

pub(crate) fn read_base128_int(mut data: &[u8]) -> ParseResult<(u32, &[u8])> {
    let mut ret = 0u32;
    for i in 0..5 {
        let b = match data.first() {
            Some(b) => *b,
            None => return Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
        };
        data = &data[1..];
        if ret > u32::MAX >> 7 {
            return Err(ParseError::new(ParseErrorKind::InvalidValue));
        }
        ret <<= 7;
        ret |= u32::from(b & 0x7f);
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

pub(crate) fn base128_length(n: u32) -> usize {
    // Equivalent to: let bits = if n != 0 { 32 - n.leading_zeros() } else { 1 };
    let bits = u32::BITS - (n | 1).leading_zeros();
    let bytes = (bits + 6) / 7;
    bytes as usize
}

pub(crate) fn write_base128_int(mut data: &mut [u8], n: u32) -> Option<usize> {
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
        let buf = [0x90, 0x80, 0x80, 0x80, 0x0];
        let result = read_base128_int(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        for i in [0, 10, u32::MAX] {
            let mut buf = [0; 16];
            let length = write_base128_int(&mut buf, i).unwrap();
            let (val, remainder) = read_base128_int(&buf[..length]).unwrap();
            assert_eq!(i, val);
            assert!(remainder.is_empty());
        }
    }
}
