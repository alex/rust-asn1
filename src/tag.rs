#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    value: u8,
    constructed: bool,
    class: TagClass,
}

pub(crate) const CONSTRUCTED: u8 = 0x20;

impl Tag {
    // TODO: update API to support long-form tags.
    pub(crate) fn from_u8(tag: u8) -> Option<Tag> {
        let value = tag & 0x1f;
        let constructed = tag & CONSTRUCTED == CONSTRUCTED;
        let class = match tag >> 6 {
            0b00 => TagClass::Universal,
            0b01 => TagClass::Application,
            0b10 => TagClass::ContextSpecific,
            0b11 => TagClass::Private,
            _ => unreachable!(),
        };

        // Long form, not yet supported.
        if value == 0x1f {
            return None;
        }

        Some(Tag {
            value,
            constructed,
            class,
        })
    }

    pub(crate) const fn new(tag: u8, class: TagClass, constructed: bool) -> Tag {
        Tag {
            value: tag,
            constructed,
            class,
        }
    }

    /// This is `pub` for use in tests but is not considered part of the
    /// supported API.
    #[doc(hidden)]
    pub const fn primitive(tag: u8) -> Tag {
        Tag::new(tag, TagClass::Universal, false)
    }

    pub(crate) const fn constructed(tag: u8) -> Tag {
        Tag::new(tag, TagClass::Universal, true)
    }

    // TODO: update API to support long-form tags.
    pub(crate) const fn as_u8(&self) -> u8 {
        self.value | ((self.class as u8) << 6) | (if self.constructed { CONSTRUCTED } else { 0 })
    }

    pub(crate) const fn is_constructed(&self) -> bool {
        self.constructed
    }
}
