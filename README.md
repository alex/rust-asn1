# rust-asn1

[![Dependency Status][deps-rs-image]][deps-rs-link]
[![Documentation][docs-rs-image]][docs-rs-link]

This is a Rust library for parsing and generating ASN.1 data (DER only).

## Installation

Add `asn1` to the `[dependencies]` section of your `Cargo.toml`:

```toml
[dependencies]
asn1 = "0.12"
```

Builds on Rust 1.47.0 and newer, but versions older than 1.51.0 require disabling the `const-generics` feature, which allows using the `Implicit` and `Explicit` types.

`rust-asn1` is compatible with `#![no_std]` environments:

```toml
asn1 = { version = "0.12", default-features = false }
```

[deps-rs-image]: https://deps.rs/repo/github/alex/rust-asn1/status.svg
[deps-rs-link]: https://deps.rs/repo/github/alex/rust-asn1
[docs-rs-image]: https://docs.rs/asn1/badge.svg
[docs-rs-link]: https://docs.rs/asn1/
