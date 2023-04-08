use asn1::{explicit_tag, explicit_tag_class, implicit_tag, implicit_tag_class, TagClass};

#[test]
fn const_generic_shall_behave_the_same() {
    let inner_tag = explicit_tag(21);

    assert_eq!(
        implicit_tag(0, inner_tag),
        implicit_tag_class(0, TagClass::ContextSpecific, inner_tag)
    );
    assert_eq!(
        explicit_tag(11),
        explicit_tag_class(11, TagClass::ContextSpecific)
    );
}
