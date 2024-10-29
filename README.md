# rust-asn1

[![Dependency Status][deps-rs-image]][deps-rs-link]
[![Documentation][docs-rs-image]][docs-rs-link]

This is a Rust library for parsing and generating ASN.1 data (DER only).

## Installation

Add `asn1` to the `[dependencies]` section of your `Cargo.toml`:

```toml
[dependencies]
asn1 = "0.18"
```

Builds on Rust 1.59.0 and newer.

`rust-asn1` is compatible with `#![no_std]` environments:

```toml
asn1 = { version = "0.18", default-features = false }
```

## Changelog

### [0.19.0]

#### :rotating_light: Breaking changes

- `GeneralizedTime` has been renamed to `X509GeneralizedTime`. Indeed, for X.509, RFC5280
 stipulates that GeneralizedTime must not include fractionals but DER encoding allows 
 them ( [494](https://github.com/alex/rust-asn1/pull/494) )

[deps-rs-image]: https://deps.rs/repo/github/alex/rust-asn1/status.svg
[deps-rs-link]: https://deps.rs/repo/github/alex/rust-asn1
[docs-rs-image]: https://docs.rs/asn1/badge.svg
[docs-rs-link]: https://docs.rs/asn1/
