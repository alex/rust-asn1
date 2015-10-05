use std::{mem};

use deserializer::{DeserializationError, DeserializationResult};


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectIdentifier {
    pub parts: Vec<u32>
}

impl ObjectIdentifier {
    pub fn new(oid: Vec<u32>) -> Option<ObjectIdentifier> {
        if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
            return None;
        }

        return Some(ObjectIdentifier{
            parts: oid,
        });
    }
}

fn _int_length(v: i64) -> usize {
    let mut num_bytes = 1;
    let mut i = v;

    while i > 127 || i < -128 {
        num_bytes += 1;
        i >>= 8;
    }
    return num_bytes;
}


pub trait Integer: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(Vec<u8>) -> DeserializationResult<Self>;
}

macro_rules! primitive_integer {
    ($Int:ident) => {
        impl Integer for $Int {
            fn encode(&self) -> Vec<u8> {
                let n = _int_length(*self as i64);
                let mut result = Vec::with_capacity(n);
                for i in (1..n+1).rev() {
                    result.push((self >> ((i - 1) * 8)) as u8);
                }
                return result;
            }

            fn decode(data: Vec<u8>) -> DeserializationResult<$Int> {
                if data.len() > mem::size_of::<$Int>() {
                    return Err(DeserializationError::IntegerOverflow);
                } else if data.is_empty() {
                    return Err(DeserializationError::InvalidValue);
                }

                let mut ret = 0;
                for b in data.iter() {
                    ret <<= 8;
                    ret |= *b as i64;
                }
                // Shift up and down in order to sign extend the result.
                ret <<= 64 - data.len() * 8;
                ret >>= 64 - data.len() * 8;
                return Ok(ret as $Int);
            }
        }
    }
}

primitive_integer!(i8);
primitive_integer!(i32);
primitive_integer!(i64);

#[cfg(test)]
mod tests {
    use super::{ObjectIdentifier};

    #[test]
    fn test_object_identifier_new() {
        assert!(ObjectIdentifier::new(vec![]).is_none());
        assert!(ObjectIdentifier::new(vec![3, 10]).is_none());
        assert!(ObjectIdentifier::new(vec![1, 50]).is_none());
    }
}
