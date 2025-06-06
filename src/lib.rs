#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

//! This crate provides you with the ability to generate and parse ASN.1
//! encoded data. More precisely, it provides you with the ability to generate
//! and parse data encoded with ASN.1's DER (Distinguished Encoding Rules)
//! encoding. It does not support BER (Basic Encoding Rules), CER (Canonical
//! Encoding Rules), XER (XML Encoding Rules), CXER (Canonical XML Encoding
//! Rules), or any other alphabet soup encodings -- and it never will.
//!
//! If you wanted to parse an ASN.1 structure like this:
//! ```text
//! Signature ::= SEQUENCE {
//!     r INTEGER,
//!     s INTEGER
//! }
//! ```
//!
//! Then you'd write the following code:
//! ```
//! # let data = b"";
//! let result: asn1::ParseResult<_> = asn1::parse(data, |d| {
//!     return d.read_element::<asn1::Sequence>()?.parse(|d| {
//!         let r = d.read_element::<u64>()?;
//!         let s = d.read_element::<u64>()?;
//!         return Ok((r, s));
//!     })
//! });
//! ```
//!
//! In general everything about parsing is driven by providing different type
//! parameters to `Parser.read_element`. Some types implement the
//! `Asn1Readable` trait directly on a basic type, as seen with `u64` or
//! `&[u8]` (`OCTET STRING`), while others use wrapper types which simply
//! provide ASN.1 encoding and decoding for some other type (`PrintableString`
//! or `UtcTime`). There are also types such as `Implicit` and `Explicit` for
//! handling tagged values, `Choice1`, `Choice2`, and `Choice3` available for
//! choices, and `Option<T>` for handling `OPTIONAL` values.
//!
//! To serialize DER for the `Sequence` structure, you'd write the following:
//! ```
//! # let r = 0u64;
//! # let s = 0u64;
//! let result = asn1::write(|w| {
//!     w.write_element(&asn1::SequenceWriter::new(&|w| {
//!         w.write_element(&r)?;
//!         w.write_element(&s)?;
//!         Ok(())
//!     }))
//! });
//! ```
//!
//! # Derive
//!
//! When built with the `derive` feature (enabled by default), these can also
//! be expressed as Rust structs:
//! ```
//! #[derive(asn1::Asn1Read, asn1::Asn1Write)]
//! struct Signature {
//!     r: u64,
//!     s: u64,
//! }
//!
//! # let data = b"";
//! # let r = 0u64;
//! # let s = 0u64;
//! let sig = asn1::parse_single::<Signature>(data);
//! let result = asn1::write_single(&Signature{r, s});
//! ```
//!
//! Fields may be marked as `EXPLICIT` or `IMPLICIT` either by struct members
//! having the types [`Explicit`] and [`Implicit`] or via the use of
//! `#[explicit]` and `#[implicit]` annotations:
//! ```
//! #[derive(asn1::Asn1Read, asn1::Asn1Write)]
//! struct SomeSequence<'a> {
//!     #[implicit(0)]
//!     a: Option<&'a [u8]>,
//!     #[explicit(1)]
//!     b: Option<u64>,
//! }
//! ```
//!
//! Fields can also be annotated with `#[default(VALUE)]` to indicate ASN.1
//! `OPTIONAL DEFAULT` values. In this case, the field's type should be `T`,
//! and not `Option<T>`.
//!
//! These derives may also be used with `enum`s to generate `CHOICE`
//! implementations.
//! ```
//! #[derive(asn1::Asn1Read, asn1::Asn1Write)]
//! enum Time {
//!     UTCTime(asn1::UtcTime),
//!     X509GeneralizedTime(asn1::X509GeneralizedTime)
//! }
//! ```
//!
//! All variants must have a single un-named field.
//!
//! ## DEFINED BY
//!
//! rust-asn1 also provides utilities for more easily handling the case of
//! `ANY DEFINED BY` in an ASN.1 structure. For example, given the following
//! ASN.1;
//!
//! ```text
//! MySequence ::= SEQUENCE {
//!     contentType OBJECT IDENTIFIER,
//!     content ANY DEFINED BY contentType
//! }
//!```
//!
//! This can be represented by:
//!
//! ```
//! # const SOME_OID_CONSTANT: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3);
//! #[derive(asn1::Asn1Read, asn1::Asn1Write)]
//! struct MySequence {
//!     content_type: asn1::DefinedByMarker<asn1::ObjectIdentifier>,
//!     #[defined_by(content_type)]
//!     content: Content,
//! }
//!
//! #[derive(asn1::Asn1DefinedByRead, asn1::Asn1DefinedByWrite)]
//! enum Content {
//!     #[defined_by(SOME_OID_CONSTANT)]
//!     SomeVariant(i32),
//! }
//! ```
//!
//! # Design philosophy
//!
//! As we have designed the `asn1` crate, we value the following things, in
//! this order:
//!
//! - **Security**
//! - **Correctness**
//! - **Performance**
//! - **Generality**
//! - **Ergonomics**

extern crate alloc;

mod base128;
mod bit_string;
mod object_identifier;
mod parser;
mod tag;
mod types;
mod writer;

pub use crate::bit_string::{BitString, OwnedBitString};
pub use crate::object_identifier::ObjectIdentifier;
pub use crate::parser::{
    parse, parse_single, strip_tlv, ParseError, ParseErrorKind, ParseLocation, ParseResult, Parser,
};
pub use crate::tag::Tag;
pub use crate::types::{
    Asn1DefinedByReadable, Asn1DefinedByWritable, Asn1Readable, Asn1Writable, BMPString, BigInt,
    BigUint, Choice1, Choice2, Choice3, DateTime, DefinedByMarker, Enumerated, Explicit,
    GeneralizedTime, IA5String, Implicit, Null, OctetStringEncoded, OwnedBigInt, OwnedBigUint,
    PrintableString, Sequence, SequenceOf, SequenceOfWriter, SequenceWriter, SetOf, SetOfWriter,
    SimpleAsn1Readable, SimpleAsn1Writable, Tlv, UniversalString, UtcTime, Utf8String,
    VisibleString, X509GeneralizedTime,
};
pub use crate::writer::{write, write_single, WriteBuf, WriteError, WriteResult, Writer};

pub use asn1_derive::{oid, Asn1DefinedByRead, Asn1DefinedByWrite, Asn1Read, Asn1Write};

/// Decodes an `OPTIONAL` ASN.1 value which has a `DEFAULT`. Generaly called
/// immediately after [`Parser::read_element`].
pub fn from_optional_default<T: PartialEq>(v: Option<T>, default: T) -> ParseResult<T> {
    match v {
        Some(v) if v == default => Err(ParseError::new(ParseErrorKind::EncodedDefault)),
        Some(v) => Ok(v),
        None => Ok(default),
    }
}

/// Prepares an `OPTIONAL` ASN.1 value which has a `DEFAULT` for writing.
/// Generally called immediately before [`Writer::write_element`].
pub fn to_optional_default<'a, T: PartialEq>(v: &'a T, default: &'a T) -> Option<&'a T> {
    if v == default {
        None
    } else {
        Some(v)
    }
}

/// This API is public so that it may be used from macros, but should not be
/// considered a part of the supported API surface.
#[doc(hidden)]
pub const fn implicit_tag(tag: u32, inner_tag: Tag) -> Tag {
    Tag::new(
        tag,
        tag::TagClass::ContextSpecific,
        inner_tag.is_constructed(),
    )
}

/// This API is public so that it may be used from macros, but should not be
/// considered a part of the supported API surface.
#[doc(hidden)]
pub const fn explicit_tag(tag: u32) -> Tag {
    Tag::new(tag, tag::TagClass::ContextSpecific, true)
}

/// Utility for use in `asn1_derive`. Not considered part of the public API.
#[doc(hidden)]
pub trait OptionExt {
    type T;
}

#[doc(hidden)]
impl<T> OptionExt for Option<T> {
    type T = T;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_implicit_tag() {
        let t = crate::implicit_tag(3, crate::Tag::primitive(2));
        assert_eq!(t.as_u8(), Some(0x83));
        let t = crate::implicit_tag(3, crate::Tag::constructed(2));
        assert_eq!(t.as_u8(), Some(0xa3));
    }
}
