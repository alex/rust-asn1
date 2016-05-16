//! Encode the following ASN1 structure:
//!
//!     Example ::= SEQUENCE {
//!         b BOOLEAN,
//!         i INTEGER
//!     }

extern crate asn1;

fn main() {
    let data = asn1::to_vec(|s| {
        s.write_sequence(|new_s| {
            new_s.write_bool(true);
            new_s.write_int(42);
        });
    });
    assert_eq!(data, [48, 6, 1, 1, 255, 2, 1, 42]);

    let hexstr: String = data.iter().map(|b| format!("{:02X} ", b)).collect::<Vec<_>>().concat();
    println!("Encoded: {}", hexstr);
}
