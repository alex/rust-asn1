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

    (@complete $name:ident $(, @name $field_name:ident @type $field_type:ident @rust_type $field_rust_type:ty)*) => {
        struct $name {
            $(
                $field_name: $field_rust_type,
            )*
        }

        impl $name {
            fn asn1_description() -> Vec<(&'static str, &'static str)> {
                let mut description = vec![];
                $(
                    description.push((stringify!($field_name), stringify!($field_type)));
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

        assert_eq!(Single::asn1_description(), vec![("x", "INTEGER")]);
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
            ("x", "INTEGER"),
            ("y", "BOOLEAN"),
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
