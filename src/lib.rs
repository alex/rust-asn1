// https://github.com/rust-lang/rust/issues/29646
#![feature(associated_consts)]

extern crate byteorder;
extern crate num;

mod parser;

pub use parser::{parse, Parser, ParseError, ParseResult};
