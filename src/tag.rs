pub(crate) enum TagClass {
    Universal = 0b00,
    // Application = 0b01,
    ContextSpecific = 0b10,
    // Private = 0b11,
}

// TODO: stop making the internals pub(crate).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Tag(pub(crate) u8);

pub(crate) const CONSTRUCTED: u8 = 0x20;

impl Tag {
    pub(crate) const fn new(tag: u8, class: TagClass, constructed: bool) -> Tag {
        Tag(tag | ((class as u8) << 6) | (if constructed { CONSTRUCTED } else { 0 }))
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

    pub(crate) const fn is_constructed(&self) -> bool {
        (self.0 & CONSTRUCTED) == CONSTRUCTED
    }
}
