mod object_identitifer;
mod parser;

pub use crate::object_identitifer::ObjectIdentifier;
pub use crate::parser::{parse, ParseError, ParseResult};
