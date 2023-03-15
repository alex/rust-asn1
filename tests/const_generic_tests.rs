#[cfg(feature = "const-generics")]
use asn1::{
    explicit_tag, explicit_tag_application, explicit_tag_class, implicit_tag,
    implicit_tag_application, implicit_tag_class, TagClass,
};

#[cfg(feature = "const-generics")]
#[test]
fn const_generic_shall_behave_the_same() {
    let inner_tag = explicit_tag(21);
    const CONTEXT_SPECIFIC_TAG: u8 = TagClass::ContextSpecific as u8;
    const APPLICATION_TAG: u8 = TagClass::Application as u8;

    assert_eq!(
        implicit_tag(0, inner_tag),
        implicit_tag_class::<CONTEXT_SPECIFIC_TAG>(0, inner_tag)
    );
    assert_eq!(
        implicit_tag_application(0, inner_tag),
        implicit_tag_class::<APPLICATION_TAG>(0, inner_tag)
    );
    assert_eq!(
        explicit_tag(11),
        explicit_tag_class::<CONTEXT_SPECIFIC_TAG>(11)
    );
    assert_eq!(
        explicit_tag_application(11),
        explicit_tag_class::<APPLICATION_TAG>(11)
    )
}
