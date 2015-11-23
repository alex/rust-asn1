#[derive(PartialEq, Eq, Debug)]
struct FieldDescription {
    name: &'static str,
    asn1_type: &'static str,
    rust_type: &'static str,
}

macro_rules! asn1 {
    // Base case, we have parsed everything.
    (@field_name [$($parsed:tt)*] []) => (
        asn1!(@complete $($parsed)*);
    );
    (@field_name [$($parsed:tt)*] [$field_name:ident $($rest:tt)*]) => (
        asn1!(@field_type [$($parsed)* , @name $field_name] [$($rest)*]);
    );

    (@field_type [$($parsed:tt)*] [INTEGER, $($rest:tt)*]) => (
        asn1!(@field_name [$($parsed)* @type INTEGER @rust_type i64] [$($rest)*]);
    );
    (@field_type [$($parsed:tt)*] [BOOLEAN, $($rest:tt)*]) => (
        asn1!(@field_name [$($parsed)* @type BOOLEAN @rust_type bool] [$($rest)*]);
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

    (@complete $name:ident $(, @name $field_name:ident @type $field_type:ident @rust_type $field_rust_type:ty)*) => {
        struct $name {
            $(
                $field_name: $field_rust_type,
            )*
        }

        impl $name {
            fn asn1_description() -> Vec<$crate::macros::FieldDescription> {
                let mut description = vec![];
                $(
                    description.push($crate::macros::FieldDescription{
                        name: stringify!($field_name),
                        asn1_type: stringify!($field_type),
                        rust_type: stringify!($field_rust_type)
                    });
                )*
                return description;
            }
        }
    };
    // This rule must be at the bottom because @word matches as an ident and macro parsing has no
    // backtracking.
    ($name:ident ::= SEQUENCE { $($rest:tt)* }) => (
        asn1!(@field_name [$name] [$($rest)*]);
    );
}

#[cfg(test)]
mod tests {
    use super::{FieldDescription};

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
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64"},
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
            FieldDescription{name: "x", asn1_type: "INTEGER", rust_type: "i64"},
            FieldDescription{name: "y", asn1_type: "BOOLEAN", rust_type: "bool"},
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
}
