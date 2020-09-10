# rust-asn1

[![Build Status][travis-image]][travis-link]
[![Dependency Status][deps-rs-image]][deps-rs-link]

This is a Rust library for parsing ASN.1 data (DER only).

## Installation

Add `asn1` to the `[dependencies]` section of your `Cargo.toml`:

```toml
[dependencies]
asn1 = "0.3"
```

A recent Rust nightly is currently required for `const` generics.

## Usage

To parse a structure like:

```
Signature ::= SEQUENCE {
    r INTEGER,
    s INTEGER
}
```

you would write:

```rust
let result = asn1::parse(data, |d| {
    return d.read_element::<asn1::Sequence>()?.parse(|d| {
        let r = d.read_element::<u64>()?;
        let s = d.read_element::<u64>()?;
        return Ok((r, s));
    })
});

match result {
    Ok((r, s)) => println!("r={}, s={}", r, s),
    Err(e) => println!("Error! {:?}", e),
}
```

And to write that structure, you would do:

```rust
let result = asn1::write(|w| {
	w.write_element_with_type::<asn1::Sequence>(&|w: &mut asn1::Writer| {
		w.write_element(r);
		w.write_element(s);
	})
});
```

[travis-image]: https://travis-ci.org/alex/rust-asn1.svg?branch=master
[travis-link]: https://travis-ci.org/alex/rust-asn1
[deps-rs-image]: https://deps.rs/repo/github/alex/rust-asn1/status.svg
[deps-rs-link]: https://deps.rs/repo/github/alex/rust-asn1

