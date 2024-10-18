#[test]
fn test_oid_value() {
    assert_eq!(
        asn1::oid!(1, 2, 3, 4),
        asn1::ObjectIdentifier::from_string("1.2.3.4").unwrap()
    );
}

#[test]
fn test_oid_with_uuid() {
    const OID_STR: &str = "2.25.223663413560230117710484359924050447509";

    let oid1 = asn1::oid!(2, 25, 223663413560230117710484359924050447509);
    let oid2 = asn1::ObjectIdentifier::from_string(OID_STR).unwrap();

    assert_eq!(oid1, oid2);
    assert_eq!(oid1.to_string(), OID_STR.to_owned());
    assert_eq!(oid2.to_string(), OID_STR.to_owned());
}

#[test]
fn test_match_statement() {
    const OID1: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3, 4);
    const OID2: asn1::ObjectIdentifier = asn1::oid!(1, 2, 3, 5);

    let oid = asn1::ObjectIdentifier::from_string("1.2.3.4").unwrap();
    assert!(matches!(oid, OID1));
    assert!(!matches!(oid, OID2));
}
