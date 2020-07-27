#![allow(incomplete_features)]
#![feature(const_generics)]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! This crate provides you with the ability to parse ASN.1 encoded data. More precisely, it
//! provides you with the ability to parse data encoded with ASN.1's DER (Distinguished Encoding
//! Rules) encoding. It does not support BER (Basic Encoding Rules), CER (Canonical Encoding
//! Rules), XER (XML Encoding Rules), CXER (Canonical XML Encoding Rules), or any other alphabet
//! soup encodings -- and it never will.
//!
//! This crate does not, yet, provide the ability to generate ASN.1, only parse it.
//!
//! If you wanted to parse an ASN.1 structure like this:
//! ```text
//! Signature ::= SEQUENCE {
//!     r INTEGER,
//!     s INTEGER
//! }
//!
//! Then you'd write the following code:
//! ```
//! use asn1;
//! let result = asn1::parse(data, |d| {
//!     return d.read_element::<asn1::Sequence>()?.parse(|d| {
//!         let r = d.read_element::<u64>()?;
//!         let s = d.read_element::<u64>()?;
//!         return Ok((r, s));
//!     })
//! });
//!
//! In general everything about parsing is driven by providing different type parameters to
//! `Parser.read_element`. Some types directly implement the `Asn1Element` trait, as seen with
//! `u64` or `&[u8]` (`OCTET STRING`), while others use placeholder types which differ from the
//! return type (`PrintableString` or `UtcTime`). There are also types such as `Implicit` and
//! `Explicit` for handling tagged values, `Choice1`, `Choice2`, and `Choice3` available for
//! choices, and `Option<T>` for handling `OPTIONAL` values.

extern crate alloc;

mod bit_string;
mod object_identitifer;
mod parser;
mod types;
mod writer;

pub use crate::bit_string::BitString;
pub use crate::object_identitifer::ObjectIdentifier;
pub use crate::parser::{parse, ParseError};
pub use crate::types::{
    Choice1, Choice2, Choice3, Explicit, Implicit, PrintableString, Sequence, UtcTime,
};
pub use crate::writer::{write, Writer};
