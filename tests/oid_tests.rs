#[test]
fn test_oid_value() {
    assert_eq!(
        asn1::oid!(1, 2, 3, 4),
        asn1::ObjectIdentifier::from_string("1.2.3.4").unwrap()
    );
}

#[test]
fn test_match_statement() {
    const OID1: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3, 4);
    const OID2: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3, 5);

    let oid = asn1::ObjectIdentifier::from_string("1.2.3.4").unwrap();
    assert!(matches!(oid, OID1));
    assert!(!matches!(oid, OID2));
}
