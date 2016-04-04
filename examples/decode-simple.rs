//! Decode the following ASN1 structure:
//!
//!     Example ::= SEQUENCE {
//!         b BOOLEAN,
//!         i INTEGER
//!     }
//!

extern crate asn1;

fn main() {
    let data = vec![48, 6, 1, 1, 255, 2, 1, 42];
    let result = asn1::from_vec(&data, |d| {
        return d.read_sequence(|d| {
            let b: bool = try!(d.read_bool());
            let i: i32 = try!(d.read_int());
            return Ok((b, i))
        });
    });

    match result {
        Ok((b, i)) => println!("Decoded: b={}, i={}", b, i),
        Err(_) => println!("Error!"),
    }
}
