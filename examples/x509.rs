extern crate asn1;

use std::fs::{File};
use std::io::{Read};


mod raw {
    use asn1;

    #[derive(Debug)]
    pub struct Certificate {
        pub tbs_certificate: TBSCertificate,
        pub signature_algorithm: AlgorithmIdentifier,
        pub signature: asn1::BitString,
    }
    #[derive(Debug)]
    pub struct TBSCertificate {
        pub version: u8,
    }
    #[derive(Debug)]
    pub struct AlgorithmIdentifier {
        pub algorithm: asn1::ObjectIdentifier,
        // TODO
        pub parameters: (),
    }

    // RFC 5280 4.1
    pub fn parse_certificate(data: &[u8]) -> asn1::DeserializationResult<Certificate> {
        return asn1::from_vec(data, |d| {
            return d.read_sequence(|d| {
                return Ok(Certificate{
                    tbs_certificate: try!(parse_tbs_certificate(d)),
                    signature_algorithm: try!(parse_algorithm_identifier(d)),
                    signature: try!(d.read_bit_string()),
                });
            });
        })
    }

    fn parse_tbs_certificate(d: &mut asn1::Deserializer) -> asn1::DeserializationResult<TBSCertificate> {
        return d.read_sequence(|d| {
            return Ok(TBSCertificate{
                // TODO: EXPLICIT
                version: panic!("TBSCertificate.version"),
            });
        });
    }

    // RFC 5280 4.1.1.2
    fn parse_algorithm_identifier(d: &mut asn1::Deserializer) -> asn1::DeserializationResult<AlgorithmIdentifier> {
        return d.read_sequence(|d| {
            return Ok(AlgorithmIdentifier{
                algorithm: try!(d.read_object_identifier()),
                // TODO: how to handle ANY?
                parameters: panic!("AlgorithmIdentifier.parameters"),
            })
        });
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let mut f = File::open(path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let cert = raw::parse_certificate(&data[..]).unwrap();
    println!("{:?}", cert);
}
