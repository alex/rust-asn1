// https://github.com/rust-lang/rust/issues/29646
#![feature(associated_consts)]

extern crate byteorder;

mod parser;

pub use parser::{parse, Parser, ParseError, ParseResult};
