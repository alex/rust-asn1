#[derive(PartialEq, Eq, Debug)]
struct FieldDescription {
    name: &'static str,
    asn1_type: &'static str,
    rust_type: &'static str,
    tag: FieldTag,
    optional: bool,
    default: Option<&'static str>,
}

#[derive(PartialEq, Eq, Debug)]
pub enum FieldTag {
    None,
    Explicit(i8),
    Implicit(i8),
}

macro_rules! asn1 {
    // These are utility "functions" rather than part of the tt-munching state machine. They're
    // inside asn1 because of how scoping and macro imports work.
    (@tag_type EXPLICIT $tag:expr) => (
        $crate::macros::FieldTag::Explicit($tag);
    );
    (@tag_type IMPLICIT $tag:expr) => (
        $crate::macros::FieldTag::Implicit($tag);
    );
    (@tag_type None $tag:expr) => (
        $crate::macros::FieldTag::None;
    );

    (@rust_field_type $field_rust_type:ty, true) => (
        Option<$field_rust_type>;
    );
    (@rust_field_type $field_rust_type:ty, false) => (
        $field_rust_type;
    );

    (@write_field $d:ident, $value:expr, $field_type:ident, true) => (
        match $value {
            Some(v) => asn1!(@write_field $d, v, $field_type, false),
            None => {}
        }
    );
    (@write_field $d:ident, $value:expr, INTEGER, false) => (
        $d.write_int($value);
    );
    (@write_field $d:ident, $value:expr, BOOLEAN, false) => (
        $d.write_bool($value);
    );
    (@write_field $d:ident, $value:expr, OCTETSTRING, false) => (
        $d.write_octet_string(&$value);
    );
    (@write_field $d:ident, $value:expr, BITSTRING, false) => (
        $d.write_bit_string(&$value);
    );

    (@read_field $d:ident, $field_type:ident, true) => (
        // TODO: actually handle optional values.
        Some(asn1!(@read_field $d, $field_type, false));
    );
    (@read_field $d:ident, INTEGER, false) => (
        try!($d.read_int());
    );
    (@read_field $d:ident, BOOLEAN, false) => (
        try!($d.read_bool());
    );
    (@read_field $d:ident, OCTETSTRING, false) => (
        try!($d.read_octet_string());
    );
    (@read_field $d:ident, BITSTRING, false) => (
        try!($d.read_bit_string());
    );

    (@default_stringify None) => (None);
    (@default_stringify $default:ident) => (Some(stringify!($default)));

    // Base case, we have parsed everything.
    (@field_start [$($parsed:tt)*] []) => (
        asn1!(@complete $($parsed)*);
    );
    (@field_start [$($parsed:tt)*] [$field_name:ident $($rest:tt)*]) => (
        asn1!(@field_tag [$($parsed)* , @name $field_name] [$($rest)*]);
    );

    (@field_tag [$($parsed:tt)*] [[ $tag:expr ] EXPLICIT $($rest:tt)*]) => (
        asn1!(@field_type [$($parsed)* @tag EXPLICIT $tag ; ] [$($rest)*]);
    );
    (@field_tag [$($parsed:tt)*] [[ $tag:expr ] IMPLICIT $($rest:tt)*]) => (
        asn1!(@field_type [$($parsed)* @tag IMPLICIT $tag ; ] [$($rest)*]);
    );
    (@field_tag [$($parsed:tt)*] [$($rest:tt)*]) => (
        asn1!(@field_type [$($parsed)* @tag None None ; ] [$($rest)*]);
    );

    (@field_type [$($parsed:tt)*] [INTEGER $($rest:tt)*]) => (
        // TODO: i64 is incorrect, figure out the right way for a caller to express their integer
        // type preference.
        asn1!(@field_end [$($parsed)* @type INTEGER @rust_type i64 ; ] [$($rest)*]);
    );
    (@field_type [$($parsed:tt)*] [BOOLEAN $($rest:tt)*]) => (
        asn1!(@field_end [$($parsed)* @type BOOLEAN @rust_type bool ; ] [$($rest)*]);
    );
    (@field_type [$($parsed:tt)*] [OCTET STRING $($rest:tt)*]) => (
        asn1!(@field_end [$($parsed)* @type OCTETSTRING @rust_type Vec<u8> ;] [$($rest)*]);
    );
    (@field_type [$($parsed:tt)*] [BIT STRING $($rest:tt)*]) => (
        asn1!(@field_end [$($parsed)* @type BITSTRING @rust_type $crate::BitString ;] [$($rest)*]);
    );

    (@field_end [$($parsed:tt)*] [OPTIONAL, $($rest:tt)*]) => (
        asn1!(@field_start [$($parsed)* @optional true @default None] [$($rest)*]);
    );
    (@field_end [$($parsed:tt)*] [DEFAULT $default:ident, $($rest:tt)*]) => (
        asn1!(@field_start [$($parsed)* @optional false @default $default] [$($rest)*]);
    );
    (@field_end [$($parsed:tt)*] [, $($rest:tt)*]) => (
        asn1!(@field_start [$($parsed)* @optional false @default None] [$($rest)*]);
    );

    // Special case empty SEQUENCE until https://github.com/rust-lang/rust/issues/29720 is
    // resolved
    (@complete $name:ident) => {
        #[derive(PartialEq, Eq, Debug)]
        struct $name;

        #[allow(dead_code)]
        impl $name {
            fn asn1_description() -> Vec<$crate::macros::FieldDescription> {
                return vec![];
            }

            fn to_der(&self) -> Vec<u8> {
                return $crate::to_vec(|d| {
                    d.write_sequence(|_| {});
                });
            }

            fn from_der(data: &[u8]) -> $crate::DeserializationResult<$name> {
                return $crate::from_vec(data, |d| {
                    d.read_sequence(|_| {
                        return Ok($name);
                    })
                })
            }
        }
    };

    (@complete $name:ident $(, @name $field_name:ident @tag $tag_type:ident $tag_value:expr ;  @type $field_type:ident @rust_type $field_rust_type:ty ; @optional $optional:ident @default $default:ident)*) => {
        #[derive(PartialEq, Eq, Debug)]
        struct $name {
            $(
                $field_name: asn1!(@rust_field_type $field_rust_type, $optional),
            )*
        }

        #[allow(dead_code)]
        impl $name {
            fn asn1_description() -> Vec<$crate::macros::FieldDescription> {
                let mut description = vec![];
                $(
                    description.push($crate::macros::FieldDescription{
                        name: stringify!($field_name),
                        asn1_type: stringify!($field_type),
                        // TODO: this doesn't show the true native type because of optional.
                        rust_type: stringify!($field_rust_type),
                        tag: asn1!(@tag_type $tag_type $tag_value),
                        optional: $optional,
                        default: asn1!(@default_stringify $default),
                    });
                )*
                return description;
            }

            fn to_der(&self) -> Vec<u8> {
                $crate::to_vec(|d| {
                    d.write_sequence(|d| {
                        $(
                            asn1!(@write_field d, self.$field_name, $field_type, $optional);
                        )*
                    })
                })
            }

            fn from_der(data: &[u8]) -> $crate::DeserializationResult<$name> {
                return $crate::from_vec(data, |d| {
                    d.read_sequence(|d| {
                        return Ok($name{
                            $(
                                $field_name: asn1!(@read_field d, $field_type, $optional),
                            )*
                        });
                    })
                });
            }
        }
    };
    // This rule must be at the bottom because @word matches as an ident and macro parsing has no
    // backtracking.
    ($name:ident ::= SEQUENCE { $($rest:tt)* }) => (
        asn1!(@field_start [$name] [$($rest)*]);
    );
}

#[cfg(test)]
mod tests {
    use common::{Tag};
    use deserializer::{DeserializationError};
    use utils::{BitString};

    use super::{FieldDescription, FieldTag};

    #[test]
    fn test_empty_sequence() {
        asn1!(
            Empty ::= SEQUENCE {}
        );

        assert_eq!(Empty::asn1_description().len(), 0);
    }

    #[test]
    fn test_one_field() {
        asn1!(
            Single ::= SEQUENCE {
                x INTEGER,
            }
        );

        assert_eq!(Single::asn1_description(), vec![
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64", tag: FieldTag::None, optional: false, default: None},
        ]);
    }

    #[test]
    fn test_two_fields() {
        asn1!(
            Double ::= SEQUENCE {
                x INTEGER,
                y BOOLEAN,
            }
        );

        assert_eq!(Double::asn1_description(), vec![
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64", tag: FieldTag::None, optional: false, default: None},
            FieldDescription{name: "y", asn1_type: "BOOLEAN", rust_type: "bool", tag: FieldTag::None, optional: false, default: None},
        ])
    }

    #[test]
    fn test_struct() {
        asn1!(
            Double ::= SEQUENCE {
                x INTEGER,
                y BOOLEAN,
            }
        );

        let d = Double{x: 3, y: true};
        assert_eq!(d.x, 3);
        assert_eq!(d.y, true);
    }

    #[test]
    fn test_empty_struct() {
        asn1!(
            Empty ::= SEQUENCE {}
        );

        assert_eq!(Empty, Empty);
    }

    #[test]
    fn test_explicit_optional() {
        asn1!(
            Single ::= SEQUENCE {
                value [0] EXPLICIT INTEGER OPTIONAL,
            }
        );

        assert_eq!(Single::asn1_description(), vec![
            FieldDescription{
                name: "value",
                asn1_type: "INTEGER",
                // TODO: should be "Option<i64>"
                rust_type: "i64",
                tag: FieldTag::Explicit(0),
                optional: true,
                default: None,
            },
        ]);

        assert_eq!(Single{value: None}, Single{value: None});
        assert_eq!(Single{value: Some(3)}, Single{value: Some(3)});
    }

    #[test]
    fn test_implicit_optional() {
        asn1!(
            Single ::= SEQUENCE {
                value [3] IMPLICIT INTEGER OPTIONAL,
            }
        );

        assert_eq!(Single::asn1_description(), vec![
            FieldDescription{
                name: "value",
                asn1_type: "INTEGER",
                // TODO: should be "Option<i64>"
                rust_type: "i64",
                tag: FieldTag::Implicit(3),
                optional: true,
                default: None
            },
        ]);

        assert_eq!(Single{value: None}, Single{value: None});
        assert_eq!(Single{value: Some(3)}, Single{value: Some(3)});
    }

    #[test]
    fn test_default() {
        asn1!(
            Single ::= SEQUENCE {
                critical BOOLEAN DEFAULT FALSE,
            }
        );

        assert_eq!(Single::asn1_description(), vec![
            FieldDescription{
                name: "critical",
                asn1_type: "BOOLEAN",
                rust_type: "bool",
                tag: FieldTag::None,
                optional: false,
                default: Some("FALSE"),
            }
        ]);
    }

    #[test]
    fn test_empty_sequence_to_der() {
        asn1!(
            Empty ::= SEQUENCE {}
        );

        assert_eq!(Empty.to_der(), b"\x30\x00")
    }

    #[test]
    fn test_simple_sequence_to_der() {
        asn1!(
            Point ::= SEQUENCE {
                x INTEGER,
                y INTEGER,
            }
        );

        assert_eq!(Point{x: 3, y: 4}.to_der(), b"\x30\x06\x02\x01\x03\x02\x01\x04");
    }

    #[test]
    fn test_sequence_optional_to_der() {
        asn1!(
            Value ::= SEQUENCE {
                x BOOLEAN OPTIONAL,
                y INTEGER,
            }
        );

        assert_eq!(Value{x: None, y: 3}.to_der(), b"\x30\x03\x02\x01\x03");
        assert_eq!(Value{x: Some(true), y: 3}.to_der(), b"\x30\x06\x01\x01\xff\x02\x01\x03");
    }

    #[test]
    fn test_empty_sequence_from_der() {
        asn1!(
            Empty ::= SEQUENCE {}
        );

        assert_eq!(Empty::from_der(b"\x30\x00"), Ok(Empty));
        assert_eq!(Empty::from_der(b"\x31\x00"), Err(DeserializationError::UnexpectedTag {expected: Tag::Sequence as u8, actual: 0x31}));
        assert_eq!(Empty::from_der(b"\x30\x01"), Err(DeserializationError::ShortData));
    }

    #[test]
    fn test_simple_sequence_from_der() {
        asn1!(
            Point ::= SEQUENCE {
                x INTEGER,
                y INTEGER,
            }
        );

        assert_eq!(Point::from_der(b"\x30\x06\x02\x01\x03\x02\x01\x04"), Ok(Point{x: 3, y: 4}));
    }

    #[test]
    fn test_octet_string() {
        asn1!(
            S ::= SEQUENCE {
                x OCTET STRING,
            }
        );

        assert_eq!(S::asn1_description(), vec![
            FieldDescription{
                name: "x",
                asn1_type: "OCTETSTRING",
                rust_type: "Vec<u8>",
                tag: FieldTag::None,
                optional: false,
                default: None,
            }
        ]);

        assert_eq!(S{x: b"abc".to_vec()}.to_der(), b"\x30\x05\x04\x03abc");
        assert_eq!(S::from_der(b"\x30\x05\x04\x03abc"), Ok(S{x: b"abc".to_vec()}));
    }

    #[test]
    fn test_bit_string() {
        asn1!(
            S ::= SEQUENCE {
                x BIT STRING,
            }
        );

        assert_eq!(S::asn1_description(), vec![
            FieldDescription{
                name: "x",
                asn1_type: "BITSTRING",
                rust_type: "::BitString",
                tag: FieldTag::None,
                optional: false,
                default: None,
            }
        ]);

        assert_eq!(S{x: BitString::new(b"\x81\xf0".to_vec(), 12).unwrap()}.to_der(), b"\x30\x05\x03\x03\x04\x81\xf0");
        assert_eq!(S::from_der(b"\x30\x05\x03\x03\x04\x81\xf0"), Ok(S{x: BitString::new(b"\x81\xf0".to_vec(), 12).unwrap()}));
    }
}
