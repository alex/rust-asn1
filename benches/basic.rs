use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, PartialEq, Clone)]
struct BasicStruct<'a> {
    integer_field: u64,
    bool_field: bool,
    octet_string_field: &'a [u8],
}

fn bench_parse_basic_struct(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_basic_struct");

    for size in [0, 100, 10000] {
        let octet_data = vec![0x42u8; size];
        let test_data = asn1::write_single(&BasicStruct {
            integer_field: 42,
            bool_field: true,
            octet_string_field: &octet_data,
        })
        .unwrap();

        group.bench_with_input(format!("size_{size}"), &size, |b, _| {
            b.iter(|| {
                let result = asn1::parse_single::<BasicStruct>(black_box(&test_data)).unwrap();
                black_box(result)
            })
        });
    }
    group.finish();
}

fn bench_serialize_basic_struct(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_basic_struct");

    for size in [0, 100, 10000] {
        let octet_data = vec![0x42u8; size];
        let test_struct = BasicStruct {
            integer_field: 42,
            bool_field: true,
            octet_string_field: &octet_data,
        };

        group.bench_with_input(format!("size_{size}"), &size, |b, _| {
            b.iter(|| {
                let result = asn1::write_single(black_box(&test_struct)).unwrap();
                black_box(result)
            })
        });
    }
    group.finish();
}
criterion_group!(
    benches,
    bench_parse_basic_struct,
    bench_serialize_basic_struct,
);
criterion_main!(benches);
