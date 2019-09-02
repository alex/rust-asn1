#![allow(incomplete_features)]
#![feature(const_generics)]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod bit_string;
mod object_identitifer;
mod parser;

pub use crate::bit_string::BitString;
pub use crate::object_identitifer::ObjectIdentifier;
pub use crate::parser::{
    parse, Choice1, Choice2, Choice3, Explicit, Implicit, ParseError, ParseResult, PrintableString,
    Sequence, UTCTime,
};
