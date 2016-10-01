// https://github.com/rust-lang/rust/issues/29646
#![feature(associated_consts)]

extern crate byteorder;
extern crate num;

mod common;
mod parser;

pub use common::{BitString, ObjectIdentifier, Tag};
pub use parser::{parse, Parser, ParseError, ParseResult};
