# rust-asn1

[![Dependency Status][deps-rs-image]][deps-rs-link]

This is a Rust library for parsing and generating ASN.1 data (DER only).

## Installation

Add `asn1` to the `[dependencies]` section of your `Cargo.toml`:

```toml
[dependencies]
asn1 = "0.3"
```

Builds on Rust 1.41.0 and newer. However `Implicit` and `Explicit` require `const` generics, which require Rust 1.51.0 or greater and specifying the `const-generics` feature.

`rust-asn1` is compatible with `#![no_std]` environments:

```toml
asn1 = { version = "0.3", default-features = false }
```

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

[deps-rs-image]: https://deps.rs/repo/github/alex/rust-asn1/status.svg
[deps-rs-link]: https://deps.rs/repo/github/alex/rust-asn1

