use crate::base128;
use crate::parser::{ParseError, ParseErrorKind, ParseResult};
use crate::writer::{WriteBuf, WriteResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    value: u32,
    constructed: bool,
    class: TagClass,
}

pub(crate) const CONSTRUCTED: u8 = 0x20;

impl Tag {
    /// Parses a `Tag` from bytes and returns either the `Tag` and the
    /// remaining bytes from the input or an error.
    pub fn from_bytes(mut data: &[u8]) -> ParseResult<(Tag, &[u8])> {
        let tag = match data.first() {
            Some(&b) => b,
            None => return Err(ParseError::new(ParseErrorKind::ShortData { needed: 1 })),
        };
        data = &data[1..];
        let mut value = u32::from(tag & 0x1f);
        let constructed = tag & CONSTRUCTED == CONSTRUCTED;

        let tag_class_bits = tag >> 6;
        let class = if tag_class_bits == TagClass::Universal as u8 {
            TagClass::Universal
        } else if tag_class_bits == TagClass::Application as u8 {
            TagClass::Application
        } else if tag_class_bits == TagClass::ContextSpecific as u8 {
            TagClass::ContextSpecific
        } else {
            assert!(tag_class_bits == TagClass::Private as u8);
            TagClass::Private
        };

        // Long form tag
        if value == 0x1f {
            let large_value;
            (large_value, data) = base128::read_base128_int(data).map_err(|e| {
                if matches!(e.kind(), ParseErrorKind::ShortData { .. }) {
                    e
                } else {
                    ParseError::new(ParseErrorKind::InvalidTag)
                }
            })?;
            value = large_value
                .try_into()
                .map_err(|_| ParseError::new(ParseErrorKind::InvalidTag))?;
            // Tags must be encoded in minimal form.
            if value < 0x1f {
                return Err(ParseError::new(ParseErrorKind::InvalidTag));
            }
        }

        Ok((
            Tag {
                value,
                constructed,
                class,
            },
            data,
        ))
    }

    pub(crate) const fn new(tag: u32, class: TagClass, constructed: bool) -> Tag {
        Tag {
            value: tag,
            constructed,
            class,
        }
    }

    /// This is `pub` for use in tests but is not considered part of the
    /// supported API.
    #[doc(hidden)]
    pub const fn primitive(tag: u32) -> Tag {
        Tag::new(tag, TagClass::Universal, false)
    }

    pub(crate) const fn constructed(tag: u32) -> Tag {
        Tag::new(tag, TagClass::Universal, true)
    }

    /// Returns the tag's representation (including tag class and constructed
    /// bits) as a `u8` if the `value` component fits in a short form
    /// (value < 31) or `None` if this is a long-form tag.
    pub fn as_u8(self) -> Option<u8> {
        if self.value >= 0x1f {
            return None;
        }
        Some(
            ((self.class as u8) << 6)
                | if self.constructed { CONSTRUCTED } else { 0 }
                | (self.value as u8),
        )
    }

    pub(crate) fn write_bytes(self, dest: &mut WriteBuf) -> WriteResult {
        let mut b = ((self.class as u8) << 6) | if self.constructed { CONSTRUCTED } else { 0 };
        if self.value >= 0x1f {
            b |= 0x1f;
            dest.push_byte(b)?;
            let len = base128::base128_length(self.value.into());
            let orig_len = dest.len();
            for _ in 0..len {
                dest.push_byte(0)?;
            }
            base128::write_base128_int(&mut dest.as_mut_slice()[orig_len..], self.value.into());
        } else {
            b |= self.value as u8;
            dest.push_byte(b)?;
        }

        Ok(())
    }

    pub const fn is_constructed(self) -> bool {
        self.constructed
    }

    pub fn class(self) -> TagClass {
        self.class
    }

    pub fn value(self) -> u32 {
        self.value
    }

    /// Get the number of bytes needed to encode this tag.
    pub(crate) fn encoded_length(self) -> usize {
        if self.value >= 0x1f {
            // Long form: 1 byte for the initial tag byte + base128 encoding of the value
            1 + crate::base128::base128_length(self.value.into())
        } else {
            // Short form: 1 byte
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Tag, TagClass, CONSTRUCTED};

    #[test]
    fn test_constructed() {
        for i in 0..31 {
            let tag = Tag::constructed(u32::from(i));
            assert_eq!(tag.as_u8(), Some(CONSTRUCTED | i));
            assert!(tag.is_constructed());
        }
    }

    #[test]
    fn test_as_u8() {
        for (t, expected) in &[
            (Tag::new(5, TagClass::Application, true), Some(0x65)),
            (Tag::new(5, TagClass::Universal, false), Some(0x05)),
            (Tag::new(0x1f, TagClass::Universal, false), None),
        ] {
            assert_eq!(&t.as_u8(), expected);
        }
    }

    #[test]
    fn test_class() {
        assert_eq!(
            Tag::new(5, TagClass::Application, true).class(),
            TagClass::Application
        );
    }

    #[test]
    fn test_value() {
        assert_eq!(Tag::new(5, TagClass::Application, true).value(), 5);
    }
}
