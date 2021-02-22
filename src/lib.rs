#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

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
//! parameters to `Parser.read_element`. Some types directly implement the
//! `Asn1Element` trait, as seen with `u64` or `&[u8]` (`OCTET STRING`), while
//! others use placeholder types which differ from the return type
//! (`PrintableString` or `UtcTime`). There are also types such as `Implicit`
//! and `Explicit` for handling tagged values, `Choice1`, `Choice2`, and
//! `Choice3` available for choices, and `Option<T>` for handling `OPTIONAL`
//!  values.
//!
//! To serialize DER for the `Sequence` structure, you'd write the following:
//! ```
//! # let r = 0u64;
//! # let s = 0u64;
//! let result = asn1::write(|w| {
//!     w.write_element_with_type::<asn1::Sequence>(&|w| {
//!         w.write_element(r);
//!         w.write_element(s);
//!     });
//! });
//! ```

extern crate alloc;

mod bit_string;
mod object_identitifer;
mod parser;
mod types;
mod writer;

pub use crate::bit_string::BitString;
pub use crate::object_identitifer::ObjectIdentifier;
pub use crate::parser::{parse, ParseError, ParseResult};
pub use crate::types::{Choice1, Choice2, Choice3, PrintableString, Sequence, SequenceOf, UtcTime};
#[cfg(feature = "const-generics")]
pub use crate::types::{Explicit, Implicit};
pub use crate::writer::{write, Writer};
