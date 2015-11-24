#[derive(PartialEq, Eq, Debug)]
struct FieldDescription {
    name: &'static str,
    asn1_type: &'static str,
    rust_type: &'static str,
    tag: Tag,
    optional: bool,
    default: Option<&'static str>,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Tag {
    None,
    Explicit(i8),
    Implicit(i8),
}

macro_rules! asn1 {
    (@tag_type EXPLICIT $tag:expr) => (
        $crate::macros::Tag::Explicit($tag);
    );
    (@tag_type IMPLICIT $tag:expr) => (
        $crate::macros::Tag::Implicit($tag);
    );
    (@tag_type None $tag:expr) => (
        $crate::macros::Tag::None;
    );

    (@rust_field_type $field_rust_type:ty, true) => (
        Option<$field_rust_type>;
    );
    (@rust_field_type $field_rust_type:ty, false) => (
        $field_rust_type;
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
        asn1!(@field_end [$($parsed)* @type INTEGER @rust_type i64 ; ] [$($rest)*]);
    );
    (@field_type [$($parsed:tt)*] [BOOLEAN $($rest:tt)*]) => (
        asn1!(@field_end [$($parsed)* @type BOOLEAN @rust_type bool ; ] [$($rest)*]);
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

        impl $name {
            fn asn1_description() -> Vec<$crate::macros::FieldDescription> {
                return vec![];
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
    use super::{FieldDescription, Tag};

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
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64", tag: Tag::None, optional: false, default: None},
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
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64", tag: Tag::None, optional: false, default: None},
            FieldDescription{name: "y", asn1_type: "BOOLEAN", rust_type: "bool", tag: Tag::None, optional: false, default: None},
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
                tag: Tag::Explicit(0),
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
                tag: Tag::Implicit(3),
                optional: true,
                default: None
            },
        ]);

        assert_eq!(Single{value: None}, Single{value: None});
        assert_eq!(Single{value: Some(3)}, Single{value: Some(3)});
    }

    fn test_default() {
        asn1!(
            Single ::= SEQUENCE {
                critical BOOLEAN DEFAULT FALSE,
            }
        );

        assert_eq!(Single::asn1_description(), vec![
            FieldDescription{
                name: "value",
                asn1_type: "BOOLEAN",
                rust_type: "bool",
                tag: Tag::None,
                optional: false,
                default: Some("FALSE"),
            }
        ]);
    }
}
