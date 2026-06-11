use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Clone)]
struct BasicStruct<'a> {
    integer_field: u64,
    bool_field: bool,
    octet_string_field: &'a [u8],
}

// 42 encodes as a single byte, 0x7FFF_FFFF encodes as 4 bytes.
const INTEGER_VALUES: [(&str, u64); 2] = [("small", 42), ("large", 0x7FFF_FFFF)];

fn bench_parse_basic_struct(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_basic_struct");

    for size in [0, 100, 10000] {
        for (int_name, int_value) in INTEGER_VALUES {
            let octet_data = vec![0x42u8; size];
            let test_data = asn1::write_single(&BasicStruct {
                integer_field: int_value,
                bool_field: true,
                octet_string_field: &octet_data,
            })
            .unwrap();

            group.bench_with_input(format!("size_{size}_int_{int_name}"), &size, |b, _| {
                b.iter(|| {
                    let result = asn1::parse_single::<BasicStruct>(black_box(&test_data)).unwrap();
                    black_box(result)
                })
            });
        }
    }
    group.finish();
}

fn bench_serialize_basic_struct(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_basic_struct");

    for size in [0, 100, 10000] {
        for (int_name, int_value) in INTEGER_VALUES {
            let octet_data = vec![0x42u8; size];
            let test_struct = BasicStruct {
                integer_field: int_value,
                bool_field: true,
                octet_string_field: &octet_data,
            };

            group.bench_with_input(format!("size_{size}_int_{int_name}"), &size, |b, _| {
                b.iter(|| {
                    let result = asn1::write_single(black_box(&test_struct)).unwrap();
                    black_box(result)
                })
            });
        }
    }
    group.finish();
}
criterion_group!(
    benches,
    bench_parse_basic_struct,
    bench_serialize_basic_struct,
);
criterion_main!(benches);
