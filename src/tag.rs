use crate::base128;
use crate::parser::{ParseError, ParseErrorKind, ParseResult};
use alloc::vec::Vec;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TagClass {
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

pub(crate) const CONSTRUCTED: u32 = 0x20;

impl Tag {
    /// Parses a `Tag` from bytes and returns either the `Tag and the
    /// remaining bytes from the input or an error.
    pub fn from_bytes(mut data: &[u8]) -> ParseResult<(Tag, &[u8])> {
        let tag = match data.first() {
            Some(&b) => b as u32,
            None => return Err(ParseError::new(ParseErrorKind::ShortData)),
        };
        data = &data[1..];
        let mut value = tag & 0x1f;
        let constructed = tag & CONSTRUCTED == CONSTRUCTED;
        let class = match tag >> 6 {
            0b00 => TagClass::Universal,
            0b01 => TagClass::Application,
            0b10 => TagClass::ContextSpecific,
            0b11 => TagClass::Private,
            _ => unreachable!(),
        };

        // Long form tag
        if value == 0x1f {
            let result = base128::read_base128_int(data)
                .map_err(|_| ParseError::new(ParseErrorKind::InvalidTag))?;
            // Rust 1.47 doesn't support writing `(value, data) = ...;`
            value = result.0;
            data = result.1;
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

    /// Returns the tag's value as a `u8` if the `value` component fits in a
    /// short form (value < 31) or `None` if this is a long-form tag.
    pub fn as_u8(&self) -> Option<u8> {
        if self.value >= 0x1f {
            return None;
        }
        Some(
            ((self.class as u8) << 6)
                | if self.constructed {
                    CONSTRUCTED as u8
                } else {
                    0
                }
                | (self.value as u8),
        )
    }

    pub(crate) fn write_bytes(&self, dest: &mut Vec<u8>) {
        let mut b = ((self.class as u8) << 6)
            | if self.constructed {
                CONSTRUCTED as u8
            } else {
                0
            };
        if self.value >= 0x1f {
            b |= 0x1f;
            dest.push(b);
            let len = base128::base128_length(self.value);
            let orig_len = dest.len();
            dest.resize(dest.len() + len, 0);
            base128::write_base128_int(&mut dest[orig_len..], self.value);
        } else {
            b |= self.value as u8;
            dest.push(b);
        }
    }

    pub(crate) const fn is_constructed(&self) -> bool {
        self.constructed
    }
}
