use crate::parser::{ParseError, ParseErrorKind, ParseResult};

pub(crate) fn read_base128_int(mut data: &[u8]) -> ParseResult<(u32, &[u8])> {
    let mut ret = 0u32;
    for _ in 0..4 {
        let b = match data.first() {
            Some(b) => b,
            None => return Err(ParseError::new(ParseErrorKind::InvalidValue)),
        };
        data = &data[1..];
        ret <<= 7;
        ret |= u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok((ret, data));
        }
    }
    Err(ParseError::new(ParseErrorKind::InvalidValue))
}

pub(crate) fn write_base128_int(mut data: &mut [u8], n: u32) -> Option<usize> {
    if n == 0 {
        if data.is_empty() {
            return None;
        }
        data[0] = 0;
        return Some(1);
    }

    let mut length = 0;
    let mut i = n;
    while i > 0 {
        length += 1;
        i >>= 7;
    }

    for i in (0..length).rev() {
        let mut o = (n >> (i * 7)) as u8;
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        if data.is_empty() {
            return None;
        }
        data[0] = o;
        data = &mut data[1..];
    }

    Some(length)
}
